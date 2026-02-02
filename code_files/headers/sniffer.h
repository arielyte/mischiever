#ifndef SNIFFER_H
#define SNIFFER_H

#include <string>
#include <atomic>
#include <thread>
#include <pcap.h>
#include <iostream>
#include <fstream>
#include <ctime>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <unistd.h> // For chown
#include <cstdlib>  // For getenv
#include "session.h" // Access the session structure

class Sniffer {
private:
    std::atomic<bool> running; // running state flag
    std::thread sniffer_thread; // background thread for sniffing
    pcap_t* handle; // pcap handle
    pcap_dumper_t* pcap_dumper; // pcap dumper for writing to file

    // Helper to get current datetime for filename
    std::string get_current_datetime();
    
    // The main loop that runs in the background
    void capture_loop(Session* session, std::string filename);

    // Packet processing
    void process_packet(u_char* user, const struct pcap_pkthdr* header, const u_char* packet, Session* session);

public:
    Sniffer();
    ~Sniffer();
    void start(Session* session);
    void stop();
};

#endif