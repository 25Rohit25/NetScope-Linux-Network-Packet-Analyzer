#include "netscope/concurrent_queue.hpp"
#include "netscope/statistics.hpp"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

void expect(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void test_queue() {
    netscope::ConcurrentQueue<int> queue(2);
    std::size_t depth = 0;
    expect(queue.try_push(1, &depth) && depth == 1 && queue.try_push(2, &depth) && depth == 2,
           "queue insert and exact depth");
    expect(!queue.try_push(3) && queue.size() == 2, "bounded queue");
    int value = 0;
    expect(queue.pop(value) && value == 1, "FIFO first");
    queue.close();
    expect(queue.pop(value) && value == 2, "close drains queued items");
    expect(!queue.pop(value) && !queue.try_push(4), "closed queue");

    netscope::ConcurrentQueue<int> concurrent(1);
    std::thread consumer([&] { expect(concurrent.pop(value) && value == 7, "worker received packet"); });
    expect(concurrent.try_push(7), "producer insert");
    consumer.join();
    concurrent.close();
}

void test_statistics_and_flows() {
    netscope::Statistics stats(1);
    const auto now = std::chrono::system_clock::now();
    netscope::PacketInfo packet;
    packet.valid = true;
    packet.captured_bytes = 54;
    packet.network = netscope::NetworkProtocol::ipv4;
    packet.transport = netscope::TransportProtocol::tcp;
    packet.source_ip = "192.0.2.1";
    packet.destination_ip = "198.51.100.2";
    packet.source_port = 12345;
    packet.destination_port = 443;
    packet.tcp_flags = 0x02;
    stats.note_captured(54, 1);
    stats.record(packet, now, std::chrono::microseconds(250));
    auto flows = stats.flows();
    expect(flows.size() == 1 && flows.begin()->second.tcp_state == "SYN_SENT", "SYN flow state");
    packet.tcp_flags = 0x10;
    stats.note_captured(54, 2);
    stats.record(packet, now + std::chrono::seconds(1));
    flows = stats.flows();
    expect(flows.begin()->second.traffic.packets == 2, "flow packet count");
    expect(flows.begin()->second.tcp_state == "ESTABLISHED", "ACK flow state");
    expect(flows.begin()->second.last_seen == now + std::chrono::seconds(1), "flow timestamps");

    packet.source_port = 12346;
    stats.record(packet, now);
    netscope::PacketInfo malformed;
    malformed.captured_bytes = 12;
    stats.record(malformed, now);
    stats.note_queue_drop();
    const auto snapshot = stats.snapshot(0);
    expect(snapshot.captured == 2 && snapshot.processed == 4 && snapshot.queue_dropped == 1, "pipeline counts");
    expect(snapshot.malformed == 1 && snapshot.untracked_flows == 1, "malformed and flow limit");
    expect(snapshot.tcp == 3 && snapshot.ipv4 == 3 && snapshot.flows == 1, "protocol counts");
    expect(snapshot.top_hosts.size() == 1 && snapshot.top_hosts[0].second.bytes == 162, "top hosts");
    expect(snapshot.top_ports.size() == 1 && snapshot.top_ports[0].first == 443, "top ports");
    expect(snapshot.max_queue_depth == 2, "peak queue depth");
    expect(snapshot.latency_samples == 1 && snapshot.max_latency_ns == 250000, "processing latency");
    expect(snapshot.top_flows.size() == 1 && snapshot.top_flows[0].second.traffic.packets == 2, "visible flows");
    expect(netscope::format_snapshot(snapshot).find("Queue dropped: 1") != std::string::npos, "formatted report");
    expect(netscope::format_snapshot(snapshot).find("ESTABLISHED") != std::string::npos, "flow report");
    auto later = snapshot;
    later.elapsed_seconds += 2;
    later.captured += 20;
    later.processed += 18;
    expect(netscope::format_interval(later, snapshot).find("10/9 packets/s") != std::string::npos,
           "interval rates");
    packet.source_ip = "203.0.113.9";
    stats.record(packet, now);
    expect(stats.snapshot(0).untracked_hosts == 1, "source host capacity");

    netscope::Statistics reordered;
    packet.source_ip = "192.0.2.1";
    packet.source_port = 12345;
    packet.tcp_flags = 0x10;
    reordered.record(packet, now + std::chrono::seconds(2), {}, 2);
    packet.tcp_flags = 0x02;
    reordered.record(packet, now, {}, 1);
    const auto ordered_flow = reordered.flows().begin()->second;
    expect(ordered_flow.first_seen == now && ordered_flow.last_seen == now + std::chrono::seconds(2),
           "out-of-order worker timestamps");
    expect(ordered_flow.tcp_state == "ESTABLISHED", "capture-order TCP state");

    netscope::PacketInfo truncated;
    truncated.captured_bytes = 20;
    truncated.wire_bytes = 54;
    truncated.capture_truncated = true;
    truncated.error = "truncated IPv4 header";
    reordered.record(truncated, now);
    const auto truncated_snapshot = reordered.snapshot(0);
    expect(truncated_snapshot.truncated == 1 && truncated_snapshot.malformed == 0,
           "capture truncation is distinct from malformed input");
    expect(netscope::packet_summary(truncated).find("TRUNCATED:") == 0, "truncation summary");
}

}  // namespace

int main() {
    try {
        test_queue();
        test_statistics_and_flows();
        std::cout << "Pipeline tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << "Pipeline test failed: " << error.what() << '\n';
        return 1;
    }
}
