#include "headers/sniffer.h"

Sniffer::Sniffer() : handle(nullptr), pcap_dumper(nullptr) {
    running = false;
}

Sniffer::~Sniffer() {
    stop();
}

std::string Sniffer::get_current_datetime() {
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d_%H-%M-%S", &tstruct);
    return std::string(buf);
}

// Start the sniffer in a background thread
void Sniffer::start(Session* session) {
    if (running) return;
    
    // 1. Create Directory if not exists
    system("mkdir -p sniffs");

    // 2. Generate Filename
    std::string filename = "sniffs/" + get_current_datetime() + ".pcap";

    running = true;
    // Launch the capture loop in a background thread
    sniffer_thread = std::thread(&Sniffer::capture_loop, this, session, filename);
}

// Join the thread and stop capturing
void Sniffer::stop() {
    if (running) {
        running = false;
        if (sniffer_thread.joinable()) {
            sniffer_thread.join();
        }
    }
}

// This is where the magic happens
void Sniffer::capture_loop(Session* session, std::string filename) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // 1. Open Interface
    handle = pcap_open_live(session->interface.c_str(), 65536, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << C_RED << "Could not open device " << session->interface << ": " << errbuf << C_RESET << std::endl;
        return;
    }

    // 2. Open PCAP Dump File
    pcap_dumper = pcap_dump_open(handle, filename.c_str());
    if (pcap_dumper == nullptr) {
        std::cerr << C_RED << "Could not open output file: " << filename << C_RESET << std::endl;
        pcap_close(handle);
        return;
    }

    // change file ownership to original user if ran with sudo
    // Sudo sets SUDO_UID and SUDO_GID to the original user's ID.
    const char* sudo_uid = std::getenv("SUDO_UID");
    const char* sudo_gid = std::getenv("SUDO_GID");

    if (sudo_uid && sudo_gid) {
        uid_t uid = std::stoi(sudo_uid);
        gid_t gid = std::stoi(sudo_gid);
        
        // chown(path, owner, group)
        if (chown(filename.c_str(), uid, gid) < 0) {
            // Optional: Print warning if it fails, but usually silent is fine
            // perror("Failed to change file ownership");
        }
    }

    std::cout << C_GREEN << "[*] Sniffer started. Saving to: " << C_BOLD << filename << C_RESET << std::endl;
    std::cout << C_YELLOW << "[!] Press [Enter] to stop capturing..." << C_RESET << "\n" << std::endl;
    
    // Table Header
    std::cout << C_BLUE << "================================================================================" << C_RESET << std::endl;
    std::cout << C_BOLD << " PROTOCOL  |   SOURCE IP        |   DESTINATION IP   |   SIZE   |   INFO" << C_RESET << std::endl;
    std::cout << C_BLUE << "================================================================================" << C_RESET << std::endl;

    // 3. Capture Loop
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    while (running && (res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) continue; // Timeout

        // Save to file
        pcap_dump((u_char*)pcap_dumper, header, packet);

        // Parse and Print
        struct ip* ip_header = (struct ip*)(packet + 14); // Skip Ethernet header (14 bytes)
        
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        std::string proto = "OTHER";
        if (ip_header->ip_p == IPPROTO_TCP) proto = "TCP";
        else if (ip_header->ip_p == IPPROTO_UDP) proto = "UDP";
        else if (ip_header->ip_p == IPPROTO_ICMP) proto = "ICMP";

        // --- HIGHLIGHT LOGIC ---
        // If the packet belongs to our Target, print in YELLOW. Otherwise WHITE.
        std::string color = C_RESET;
        if (!session->target_ip.empty() && (session->target_ip == src_ip || session->target_ip == dst_ip)) {
            color = C_YELLOW;
        }

        // Print formatted output
        std::cout << color 
                  << std::left << std::setw(10) << proto 
                  << " | " << std::setw(18) << src_ip 
                  << " | " << std::setw(18) << dst_ip 
                  << " | " << std::setw(8) << header->len 
                  << " | " << "Packet Captured" 
                  << C_RESET << std::endl;
    }

    // Cleanup
    pcap_dump_close(pcap_dumper);
    pcap_close(handle);
    std::cout << C_GREEN << "\n[+] Capture saved to: " << filename << C_RESET << std::endl;
}