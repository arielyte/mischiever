#ifndef ICMP_H
#define ICMP_H

#include <string>
#include <thread>
#include <atomic>
#include <vector>

#include "attack_module.h"

class ICMP : public AttackModule {
public:
    enum Mode {
        FLOOD
    };

    ICMP(Mode mode);
    ~ICMP();

    // Implementation of the AttackModule interface
    void run(Session* session) override;
    void stop() override;
    std::string get_name() override;

private:
    // Module-specific parameters
    int packet_count;
    Mode current_mode;

    // Threading and control
    std::thread attack_thread;
    std::atomic<bool> stop_flag;
    // Private helper for the attack logic
    void flood_loop(std::string target_ip);

    // The standard Internet Checksum algorithm
    unsigned short checksum(void* b, int len);
};

#endif // ICMP_H
