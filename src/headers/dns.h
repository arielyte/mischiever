#ifndef DNS_H
#define DNS_H

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "attack_module.h"

class DNS : public AttackModule {
public:
    enum Mode {
        SPOOFING
    };

    DNS(Mode mode);
    ~DNS();

    // Implementation of the AttackModule interface
    void run(Session* session) override;
    void stop() override;
    std::string get_name() override;

    // Configuration for the attack
    void set_target_domain(std::string domain);

private:
    std::vector<std::thread> attack_threads;
    Mode current_mode;
    std::atomic<bool> stop_flag;
    
    
    // Attack specific variables
    std::string target_domain; // e.g., "neverssl.com"
    std::string spoof_ip;      // The IP we want them to visit (Attacker IP)

    // The core DNS spoofing logic
    void spoof_loop(std::string interface);

    // Private helpers
    bool is_dns_query(uint8_t* buffer, ssize_t len);
    std::string parse_dns_name(uint8_t* buffer, int* offset, ssize_t max_len);
    void forge_response(int sock, uint8_t* buffer, ssize_t len, std::string spoof_ip);

    // Structure for DNS Header
    struct __attribute__((packed)) dns_header {
        uint16_t id;         // Transaction ID
        uint16_t flags;      // Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
        uint16_t q_count;    // Number of Questions
        uint16_t ans_count;  // Number of Answers
        uint16_t auth_count; // Number of Authority Records
        uint16_t add_count;  // Number of Additional Records
    };

    // Structure for the fixed part of a DNS Resource Record (Answer)
    // (The name part is variable length, so it's not included here)
    struct __attribute__((packed)) dns_rr_tail {
        uint16_t type;       // Type (A = 1)
        uint16_t _class;     // Class (IN = 1)
        uint32_t ttl;        // Time To Live
        uint16_t data_len;   // Length of Data (4 bytes for IPv4)
    };
};

#endif // DNS_H