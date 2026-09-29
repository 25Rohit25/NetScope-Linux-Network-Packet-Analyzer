#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace netscope {

enum class NetworkProtocol { unknown, arp, ipv4, ipv6 };
enum class TransportProtocol { unknown, tcp, udp, icmp, icmpv6 };

struct PacketInfo {
    bool valid = false;
    std::string error;
    std::size_t captured_bytes = 0;
    std::string source_mac;
    std::string destination_mac;
    NetworkProtocol network = NetworkProtocol::unknown;
    TransportProtocol transport = TransportProtocol::unknown;
    std::string source_ip;
    std::string destination_ip;
    std::uint8_t ttl = 0;
    std::uint8_t ip_protocol = 0;
    std::uint16_t source_port = 0;
    std::uint16_t destination_port = 0;
    std::uint32_t tcp_sequence = 0;
    std::uint32_t tcp_acknowledgment = 0;
    std::uint8_t tcp_flags = 0;
    std::uint16_t tcp_window = 0;
    std::uint16_t udp_length = 0;
    std::uint8_t icmp_type = 0;
    std::uint8_t icmp_code = 0;
    std::uint16_t arp_operation = 0;
    bool fragmented = false;
    std::string application;
};

PacketInfo parse_packet(const std::uint8_t* bytes, std::size_t length);
std::string packet_summary(const PacketInfo& packet);
std::string transport_name(TransportProtocol protocol);

}  // namespace netscope
