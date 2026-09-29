#include "netscope/statistics.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace netscope {
namespace {

template <typename Key, typename Value, typename Bytes>
std::vector<std::pair<Key, Value>> top_five(const std::map<Key, Value>& counters, Bytes bytes) {
    std::vector<std::pair<Key, Value>> result;
    const auto better = [&](const auto& a, const auto& b) {
        if (bytes(a.second) != bytes(b.second)) return bytes(a.second) > bytes(b.second);
        return a.first < b.first;
    };
    for (const auto& entry : counters) {
        if (result.size() == 5 && !better(entry, result.back())) continue;
        const auto where = std::lower_bound(result.begin(), result.end(), entry, better);
        result.insert(where, entry);
        if (result.size() > 5) result.pop_back();
    }
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

void Statistics::record(const PacketInfo& packet, std::chrono::system_clock::time_point timestamp,
                        std::chrono::nanoseconds latency) {
    std::lock_guard<std::mutex> lock(mutex_);
    ++totals_.processed;
    totals_.processed_bytes += packet.captured_bytes;
    if (latency.count() > 0) {
        const auto elapsed = static_cast<std::uint64_t>(latency.count());
        ++totals_.latency_samples;
        totals_.total_latency_ns += elapsed;
        totals_.max_latency_ns = std::max(totals_.max_latency_ns, elapsed);
    }
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
    result.top_hosts = top_five(hosts_, [](const Counter& count) { return count.bytes; });
    result.top_ports = top_five(ports_, [](const Counter& count) { return count.bytes; });
    result.top_flows = top_five(flows_, [](const FlowStats& flow) { return flow.traffic.bytes; });
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
            << s.captured / s.elapsed_seconds << '/' << s.processed / s.elapsed_seconds << " packets/s\n"
            << "Average captured/processed throughput: "
            << s.captured_bytes / s.elapsed_seconds << '/' << s.processed_bytes / s.elapsed_seconds << " bytes/s\n";
    }
    if (s.latency_samples > 0) {
        out << "Queue plus parse latency avg/max: " << std::setprecision(3)
            << static_cast<double>(s.total_latency_ns) / s.latency_samples / 1000000.0 << '/'
            << static_cast<double>(s.max_latency_ns) / 1000000.0 << " ms\n";
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
    if (!s.top_flows.empty()) {
        out << "Top directional flows (packets, bytes, TCP state):\n";
        for (const auto& entry : s.top_flows) {
            const auto& key = entry.first;
            const auto& flow = entry.second;
            out << "  " << transport_name(key.protocol) << ' ' << key.source_ip << ':' << key.source_port
                << " -> " << key.destination_ip << ':' << key.destination_port << "  "
                << flow.traffic.packets << "  " << flow.traffic.bytes;
            if (key.protocol == TransportProtocol::tcp) out << "  " << flow.tcp_state;
            out << '\n';
        }
    }
    return out.str();
}

}  // namespace netscope
