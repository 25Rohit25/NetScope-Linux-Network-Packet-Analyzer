#include "netscope/statistics.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace netscope {
namespace {

template <typename Key>
std::vector<std::pair<Key, Counter>> top_five(const std::map<Key, Counter>& counters) {
    std::vector<std::pair<Key, Counter>> result(counters.begin(), counters.end());
    std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) {
        if (a.second.bytes != b.second.bytes) return a.second.bytes > b.second.bytes;
        return a.first < b.first;
    });
    if (result.size() > 5) result.resize(5);
    return result;
}

std::string tcp_state(std::uint8_t flags, const std::string& previous) {
    if (flags & 0x04) return "RESET";
    if (flags & 0x01) return "CLOSING";
    if ((flags & 0x12) == 0x12) return "SYN_RECEIVED";
    if (flags & 0x02) return "SYN_SENT";
    if ((flags & 0x10) && previous != "CLOSING" && previous != "RESET") return "ESTABLISHED";
    return previous;
}

}  // namespace

Statistics::Statistics(std::size_t flow_limit)
    : flow_limit_(flow_limit), started_(std::chrono::steady_clock::now()) {}

void Statistics::note_captured(std::size_t bytes, std::size_t queue_depth) {
    std::lock_guard<std::mutex> lock(mutex_);
    ++totals_.captured;
    totals_.captured_bytes += bytes;
    totals_.max_queue_depth = std::max(totals_.max_queue_depth, queue_depth);
}

void Statistics::note_queue_drop() {
    std::lock_guard<std::mutex> lock(mutex_);
    ++totals_.queue_dropped;
}

void Statistics::record(const PacketInfo& packet, std::chrono::system_clock::time_point timestamp) {
    std::lock_guard<std::mutex> lock(mutex_);
    ++totals_.processed;
    totals_.processed_bytes += packet.captured_bytes;
    if (!packet.valid) {
        ++totals_.malformed;
        return;
    }
    if (packet.network == NetworkProtocol::ipv4) ++totals_.ipv4;
    if (packet.network == NetworkProtocol::ipv6) ++totals_.ipv6;
    if (packet.network == NetworkProtocol::arp) ++totals_.arp;
    if (packet.transport == TransportProtocol::tcp) ++totals_.tcp;
    if (packet.transport == TransportProtocol::udp) ++totals_.udp;
    if (packet.transport == TransportProtocol::icmp || packet.transport == TransportProtocol::icmpv6) ++totals_.icmp;
    if (!packet.source_ip.empty()) {
        auto& host = hosts_[packet.source_ip];
        ++host.packets;
        host.bytes += packet.captured_bytes;
    }
    if (packet.transport != TransportProtocol::tcp && packet.transport != TransportProtocol::udp) return;
    auto& port = ports_[packet.destination_port];
    ++port.packets;
    port.bytes += packet.captured_bytes;
    FlowKey key{packet.source_ip, packet.destination_ip, packet.source_port, packet.destination_port, packet.transport};
    auto it = flows_.find(key);
    if (it == flows_.end()) {
        if (flows_.size() >= flow_limit_) {
            ++totals_.untracked_flows;
            return;
        }
        it = flows_.emplace(std::move(key), FlowStats{}).first;
        it->second.first_seen = timestamp;
    }
    auto& flow = it->second;
    ++flow.traffic.packets;
    flow.traffic.bytes += packet.captured_bytes;
    flow.last_seen = timestamp;
    if (packet.transport == TransportProtocol::tcp)
        flow.tcp_state = tcp_state(packet.tcp_flags, flow.tcp_state);
}

Snapshot Statistics::snapshot(std::size_t queue_depth) const {
    std::lock_guard<std::mutex> lock(mutex_);
    Snapshot result = totals_;
    result.queue_depth = queue_depth;
    result.flows = flows_.size();
    result.elapsed_seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started_).count();
    result.top_hosts = top_five(hosts_);
    result.top_ports = top_five(ports_);
    return result;
}

std::map<FlowKey, FlowStats> Statistics::flows() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return flows_;
}

std::string format_snapshot(const Snapshot& s) {
    std::ostringstream out;
    out << "\nNetScope statistics (" << std::fixed << std::setprecision(1) << s.elapsed_seconds << " s)\n"
        << "Captured: " << s.captured << "  Processed: " << s.processed
        << "  Queue dropped: " << s.queue_dropped << "  Malformed: " << s.malformed << '\n'
        << "Bytes captured: " << s.captured_bytes << "  Bytes processed: " << s.processed_bytes << '\n'
        << "IPv4: " << s.ipv4 << "  IPv6: " << s.ipv6 << "  ARP: " << s.arp
        << "  TCP: " << s.tcp << "  UDP: " << s.udp << "  ICMP: " << s.icmp << '\n'
        << "Queue depth/peak: " << s.queue_depth << '/' << s.max_queue_depth
        << "  Flows: " << s.flows << "  Flow-limit skips: " << s.untracked_flows << '\n';
    if (s.elapsed_seconds > 0) {
        out << "Average capture/processing rate: " << std::setprecision(0)
            << s.captured / s.elapsed_seconds << '/' << s.processed / s.elapsed_seconds << " packets/s\n";
    }
    if (!s.top_hosts.empty()) {
        out << "Top source hosts (packets, bytes):\n";
        for (const auto& entry : s.top_hosts)
            out << "  " << entry.first << "  " << entry.second.packets << "  " << entry.second.bytes << '\n';
    }
    if (!s.top_ports.empty()) {
        out << "Top destination ports (packets, bytes):\n";
        for (const auto& entry : s.top_ports)
            out << "  " << entry.first << "  " << entry.second.packets << "  " << entry.second.bytes << '\n';
    }
    return out.str();
}

}  // namespace netscope
