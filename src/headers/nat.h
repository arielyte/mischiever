#ifndef NAT_H
#define NAT_H

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <cstdint>
#include <chrono>
#include <mutex>
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
    enum StopReason {
        STOP_NONE = 0,
        STOP_USER,
        STOP_MAX_DURATION,
        STOP_MAX_PACKETS
    };

    void exhaust_loop(std::string local_ip, std::string interface_name, int ifindex,
                      std::vector<uint8_t> gateway_mac, int thread_id, int packets_per_second);
    std::string generate_random_local_ip(const std::string& local_ip);
    std::string generate_random_public_ip();
    void reset_stats();
    void request_stop(StopReason reason);
    const char* stop_reason_text() const;
    void print_summary();
    void print_backpressure_note();
    void log_unexpected_send_error(int thread_id, int error_code,
                                   std::chrono::steady_clock::time_point& last_error_log);

    std::atomic<bool> running;
    std::atomic<long> attempted_packets;
    std::atomic<long> sent_packets;
    std::atomic<long> failed_packets;
    std::atomic<long> backpressure_count;
    std::atomic<long> enobufs_count;
    std::atomic<bool> backpressure_note_printed;
    std::atomic<int> stop_reason;
    std::mutex log_mutex;
    std::vector<std::thread> attack_threads;
    AttackMode mode;
    int worker_count;
    int max_duration_seconds;
    long max_packets_total;
    int packets_per_second_total;
    int enobufs_backoff_ms;
    std::chrono::steady_clock::time_point start_time;
    bool summary_printed;
};

#endif // NAT_H
