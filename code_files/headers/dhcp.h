#ifndef DHCP_H
#define DHCP_H

#include "attack_module.h"
#include <vector>
#include <thread>
#include <atomic>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

// --- Custom DHCP Header Structure ---
struct __attribute__((packed)) dhcp_header { 
    // Packed to prevent padding issues
    uint8_t op;      // Message op code / message type. 1 = BOOTREQUEST, 2 = BOOTREPLY
    uint8_t htype;   // Hardware address type (e.g.  1 = 10Mb Ethernet)
    uint8_t hlen;    // Hardware address length (e.g.  6 for 10Mb Ethernet)
    uint8_t hops;    // Client sets to zero, optionally used by relay agents
    uint32_t xid;    // Transaction ID, a random number chosen by the client
    uint16_t secs;   // Seconds elapsed since client began address acquisition or renewal process
    uint16_t flags;  // Flags
    uint32_t ciaddr; // Client IP address; only filled in if client is in BOUND, RENEW or REBINDING state
    uint32_t yiaddr; // 'your' (client) IP address
    uint32_t siaddr; // IP address of next server to use in bootstrap
    uint32_t giaddr; // Relay agent IP address
    uint8_t chaddr[16]; // Client hardware address
    uint8_t sname[64];  // Optional server host name
    uint8_t file[128];  // Boot file name
    uint32_t cookie;    // Magic cookie (0x63825363)
    // Options follow dynamically...
};

class DHCP : public AttackModule {
public:
    enum Mode {
        STARVATION, // Flood with random MACs to exhaust IP pool
        RELEASE     // Force specific target offline (Coming soon)
    };

    DHCP(Mode mode);
    ~DHCP();

    void run(Session* session) override;
    void stop() override;
    std::string get_name() override;

private:
    Mode current_mode;
    std::vector<std::thread> attack_threads;
    std::atomic<bool> stop_flag;

    // The Logic Loops
    void starvation_loop(std::string interface);
    
    // Helper to randomize MACs
    void generate_random_mac(uint8_t* mac);
    
    // Packet Builder
    void send_dhcp_discover(int sock, int ifindex, const uint8_t* mac);
};

#endif