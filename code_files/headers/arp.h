#ifndef ARP_H
#define ARP_H

#include <string>
#include <thread>
#include <atomic>
#include <vector>

#include "../headers/attack_module.h"

class ARP : public AttackModule {
public:
    ARP();
    ~ARP();

    // Implementation of the AttackModule interface
    void run(Session* session) override;
    void stop() override;
    std::string get_name() override;

private:
    std::vector<std::thread> attack_threads;
    std::atomic<bool> stop_flag;
    std::string interface;

    // The core ARP spoofing logic, now runs in a loop
    void spoof_loop(std::string iface, std::string target_ip, std::string spoof_ip, std::string target_mac);

    // Private helpers
    void parse_mac(const char* mac_str, uint8_t* mac_out);
    void get_my_mac(const char* iface, uint8_t* mac);

    // Structure for ARP header
    struct __attribute__((packed)) arp_header {
        uint16_t htype;
        uint16_t ptype;
        uint8_t hlen;
        uint8_t plen;
        uint16_t oper;
        uint8_t sha[6];
        uint8_t spa[4];
        uint8_t tha[6];
        uint8_t tpa[4];
    };
};

#endif // ARP_H
