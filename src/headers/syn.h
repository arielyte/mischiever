#ifndef SYN_H
#define SYN_H

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <ctime>

#include "attack_module.h"

// The SYN class now inherits from AttackModule
class SYN : public AttackModule {
public:
    enum Mode {
        FLOOD
    };

    SYN(Mode mode);
    ~SYN();

    // Implement the virtual functions from the base class
    void run(Session* session) override;
    void stop() override;
    std::string get_name() override;

private:
    // Module-specific parameters
    int target_port;
    int packet_count;
    Mode current_mode;
    
    // Threading and control
    std::thread attack_thread;
    std::atomic<bool> stop_flag;

    // Private helper function for the attack logic
    void syn_flood_loop(std::string target_ip);

    // Pseudo-header structure for TCP checksum calculation
    struct PseudoHeader {
        uint32_t source_ip;
        uint32_t dest_ip;
        uint8_t reserved;
        uint8_t protocol;
        uint16_t tcp_length;
    };

    unsigned short checksum(void* data, int len);
};

#endif // SYN_H
