#ifndef NAT_H
#define NAT_H

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <cstdint>
#include "attack_module.h"
#include "../headers/session.h"

class NAT : public AttackModule {
public:
    enum AttackMode { EXHAUSTION };

    NAT(AttackMode mode);
    ~NAT();

    std::string get_name() override;
    void run(Session* session) override;
    void stop() override;

private:
    void exhaust_loop(std::string local_ip, std::string interface_name, std::vector<uint8_t> gateway_mac, int thread_id);
    std::string generate_random_local_ip(const std::string& local_ip);
    std::string generate_random_public_ip();

    std::atomic<bool> running;
    std::vector<std::thread> attack_threads;
    AttackMode mode;
};

#endif // NAT_H
