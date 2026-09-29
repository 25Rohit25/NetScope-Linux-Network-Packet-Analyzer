#pragma once

#include "netscope/parser.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <tuple>
#include <vector>

namespace netscope {

struct Counter {
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;
};

struct FlowKey {
    std::string source_ip;
    std::string destination_ip;
    std::uint16_t source_port = 0;
    std::uint16_t destination_port = 0;
    TransportProtocol protocol = TransportProtocol::unknown;

    bool operator<(const FlowKey& other) const {
        return std::tie(source_ip, destination_ip, source_port, destination_port, protocol) <
               std::tie(other.source_ip, other.destination_ip, other.source_port, other.destination_port, other.protocol);
    }
};

struct FlowStats {
    Counter traffic;
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_seen;
    std::string tcp_state = "OBSERVED";
};

struct Snapshot {
    std::uint64_t captured = 0;
    std::uint64_t processed = 0;
    std::uint64_t queue_dropped = 0;
    std::uint64_t malformed = 0;
    std::uint64_t captured_bytes = 0;
    std::uint64_t processed_bytes = 0;
    std::uint64_t tcp = 0;
    std::uint64_t udp = 0;
    std::uint64_t icmp = 0;
    std::uint64_t arp = 0;
    std::uint64_t ipv4 = 0;
    std::uint64_t ipv6 = 0;
    std::size_t queue_depth = 0;
    std::size_t max_queue_depth = 0;
    std::size_t flows = 0;
    std::uint64_t untracked_flows = 0;
    std::uint64_t latency_samples = 0;
    std::uint64_t total_latency_ns = 0;
    std::uint64_t max_latency_ns = 0;
    double elapsed_seconds = 0;
    std::vector<std::pair<std::string, Counter>> top_hosts;
    std::vector<std::pair<std::uint16_t, Counter>> top_ports;
    std::vector<std::pair<FlowKey, FlowStats>> top_flows;
};

class Statistics {
public:
    explicit Statistics(std::size_t flow_limit = 100000);
    void note_captured(std::size_t bytes, std::size_t queue_depth);
    void note_queue_drop();
    void record(const PacketInfo& packet, std::chrono::system_clock::time_point timestamp,
                std::chrono::nanoseconds latency = std::chrono::nanoseconds::zero());
    Snapshot snapshot(std::size_t queue_depth) const;
    std::map<FlowKey, FlowStats> flows() const;

private:
    const std::size_t flow_limit_;
    const std::chrono::steady_clock::time_point started_;
    mutable std::mutex mutex_;
    Snapshot totals_;
    std::map<std::string, Counter> hosts_;
    std::map<std::uint16_t, Counter> ports_;
    std::map<FlowKey, FlowStats> flows_;
};

std::string format_snapshot(const Snapshot& snapshot);

}  // namespace netscope
