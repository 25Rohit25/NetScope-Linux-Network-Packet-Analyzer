#include "netscope/parser.hpp"

#include <cstdint>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

using netscope::NetworkProtocol;
using netscope::TransportProtocol;

namespace {

void expect(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

std::vector<std::uint8_t> ipv4_tcp() {
    std::vector<std::uint8_t> bytes(54, 0);
    bytes[12] = 0x08;
    bytes[13] = 0x00;
    bytes[14] = 0x45;
    bytes[16] = 0;
    bytes[17] = 40;
    bytes[22] = 64;
    bytes[23] = 6;
    bytes[26] = 192; bytes[27] = 168; bytes[28] = 1; bytes[29] = 2;
    bytes[30] = 8; bytes[31] = 8; bytes[32] = 8; bytes[33] = 8;
    bytes[34] = 0xc3; bytes[35] = 0x50;  // 50000
    bytes[36] = 1; bytes[37] = 0xbb;      // 443
    bytes[38] = 0x01; bytes[39] = 0x02; bytes[40] = 0x03; bytes[41] = 0x04;
    bytes[46] = 0x50; bytes[47] = 0x02;  // data offset 5, SYN
    bytes[48] = 0x20; bytes[49] = 0x00;
    return bytes;
}

void test_tcp() {
    const auto bytes = ipv4_tcp();
    const auto packet = netscope::parse_packet(bytes.data(), bytes.size());
    expect(packet.valid, packet.error);
    expect(packet.network == NetworkProtocol::ipv4, "IPv4 classification");
    expect(packet.transport == TransportProtocol::tcp, "TCP classification");
    expect(packet.source_ip == "192.168.1.2" && packet.destination_ip == "8.8.8.8", "IP addresses");
    expect(packet.ttl == 64 && packet.source_port == 50000 && packet.destination_port == 443, "IPv4/TCP fields");
    expect(packet.tcp_sequence == 0x01020304 && packet.tcp_flags == 0x02, "TCP sequence and SYN");
    expect(packet.tcp_window == 8192 && packet.application == "HTTPS", "TCP window and application");
    expect(packet.ipv4_checksum == 0, "IPv4 checksum field");
    expect(netscope::packet_summary(packet).find("192.168.1.2:50000") != std::string::npos, "summary");
    expect(netscope::packet_summary(packet).find("flags=SYN") != std::string::npos, "TCP flag summary");

    auto ack = bytes;
    ack[47] = 0x10;
    ack[45] = 7;
    expect(netscope::parse_packet(ack.data(), ack.size()).tcp_acknowledgment == 7, "TCP ACK number");
    expect(netscope::parse_packet(ack.data(), ack.size()).tcp_flags == 0x10, "TCP ACK flag");
}

void test_udp() {
    auto bytes = ipv4_tcp();
    bytes.resize(46);
    bytes[17] = 32;
    bytes[23] = 17;
    bytes[36] = 0; bytes[37] = 53;
    bytes[38] = 0; bytes[39] = 12;
    const auto packet = netscope::parse_packet(bytes.data(), bytes.size());
    expect(packet.valid && packet.transport == TransportProtocol::udp, "UDP packet");
    expect(packet.destination_port == 53 && packet.udp_length == 12 && packet.udp_checksum == 0x0304 && packet.application == "DNS", "UDP fields");
    bytes[39] = 13;
    expect(!netscope::parse_packet(bytes.data(), bytes.size()).valid, "truncated UDP payload");
}

void test_icmp_and_arp() {
    auto bytes = ipv4_tcp();
    bytes.resize(42);
    bytes[17] = 28;
    bytes[23] = 1;
    bytes[34] = 8;
    bytes[35] = 0;
    auto packet = netscope::parse_packet(bytes.data(), bytes.size());
    expect(packet.valid && packet.transport == TransportProtocol::icmp && packet.icmp_type == 8, "ICMP echo request");

    std::vector<std::uint8_t> arp(42, 0);
    arp[12] = 0x08; arp[13] = 0x06;
    arp[15] = 1; arp[16] = 0x08; arp[17] = 0x00;
    arp[18] = 6; arp[19] = 4; arp[21] = 1;
    arp[28] = 10; arp[29] = 0; arp[30] = 0; arp[31] = 1;
    arp[38] = 10; arp[39] = 0; arp[40] = 0; arp[41] = 2;
    packet = netscope::parse_packet(arp.data(), arp.size());
    expect(packet.valid && packet.network == NetworkProtocol::arp && packet.arp_operation == 1, "ARP request");
    expect(packet.source_ip == "10.0.0.1" && packet.destination_ip == "10.0.0.2", "ARP addresses");
}

void test_ipv6() {
    std::vector<std::uint8_t> bytes(62, 0);
    bytes[12] = 0x86; bytes[13] = 0xdd;
    bytes[14] = 0x60;
    bytes[19] = 8;
    bytes[20] = 17;
    bytes[21] = 42;
    bytes[22] = 0x20; bytes[23] = 1;
    bytes[38] = 0x20; bytes[39] = 1;
    bytes[54] = 0; bytes[55] = 53;
    bytes[56] = 0x30; bytes[57] = 0x39;
    bytes[59] = 8;
    const auto packet = netscope::parse_packet(bytes.data(), bytes.size());
    expect(packet.valid && packet.network == NetworkProtocol::ipv6 && packet.transport == TransportProtocol::udp, "IPv6 UDP");
    expect(packet.source_ip.substr(0, 4) == "2001" && packet.ttl == 42, "IPv6 fields");

    // A Hop-by-Hop header precedes the UDP header.
    auto extended = bytes;
    extended.resize(70);
    extended[19] = 16;
    extended[20] = 0;
    extended[54] = 17;
    extended[55] = 0;
    for (int i = 56; i < 62; ++i) extended[i] = 0;
    extended[62] = 0; extended[63] = 53;
    extended[64] = 0x30; extended[65] = 0x39;
    extended[66] = 0; extended[67] = 8;
    auto parsed = netscope::parse_packet(extended.data(), extended.size());
    expect(parsed.valid && parsed.transport == TransportProtocol::udp && parsed.source_port == 53,
           "IPv6 extension to UDP");
    extended[55] = 2;
    expect(!netscope::parse_packet(extended.data(), extended.size()).valid, "oversized IPv6 extension");

    extended[20] = 44;
    extended[54] = 17;
    extended[55] = 0;
    extended[57] = 1;  // More-fragments bit.
    parsed = netscope::parse_packet(extended.data(), extended.size());
    expect(parsed.valid && parsed.fragmented && parsed.transport == TransportProtocol::unknown,
           "IPv6 fragment skips transport");
    extended.resize(60);
    extended[19] = 6;
    expect(!netscope::parse_packet(extended.data(), extended.size()).valid, "short IPv6 extension");
}

void test_malformed() {
    auto bytes = ipv4_tcp();
    expect(!netscope::parse_packet(nullptr, 0).valid, "null input");
    expect(!netscope::parse_packet(bytes.data(), 13).valid, "short Ethernet frame");
    bytes[14] = 0x65;
    expect(!netscope::parse_packet(bytes.data(), bytes.size()).valid, "wrong IP version");
    bytes[14] = 0x44;
    expect(!netscope::parse_packet(bytes.data(), bytes.size()).valid, "short IPv4 header length");
    bytes[14] = 0x45;
    bytes[17] = 100;
    expect(!netscope::parse_packet(bytes.data(), bytes.size()).valid, "truncated IPv4 total length");
    bytes[17] = 40;
    bytes[46] = 0x40;
    expect(!netscope::parse_packet(bytes.data(), bytes.size()).valid, "short TCP header length");
    bytes[46] = 0x60;
    expect(!netscope::parse_packet(bytes.data(), bytes.size()).valid, "TCP options beyond packet");

    bytes = ipv4_tcp();
    bytes[20] = 0x20;  // More fragments: skip L4 interpretation.
    const auto fragment = netscope::parse_packet(bytes.data(), bytes.size());
    expect(fragment.valid && fragment.fragmented && fragment.transport == TransportProtocol::unknown, "fragment handling");

    std::vector<std::uint8_t> vlan(26, 0);
    vlan[12] = 0x81; vlan[13] = 0x00;
    vlan[16] = 0x81; vlan[17] = 0x00;
    vlan[20] = 0x81; vlan[21] = 0x00;
    expect(!netscope::parse_packet(vlan.data(), vlan.size()).valid, "excessive VLAN nesting");

    std::mt19937 random(42);
    std::uniform_int_distribution<int> octet(0, 255);
    std::vector<std::uint8_t> fuzz(128);
    for (int trial = 0; trial < 10000; ++trial) {
        for (auto& byte : fuzz) byte = static_cast<std::uint8_t>(octet(random));
        netscope::parse_packet(fuzz.data(), static_cast<std::size_t>(trial % 129));
    }
}

}  // namespace

int main() {
    try {
        test_tcp();
        test_udp();
        test_icmp_and_arp();
        test_ipv6();
        test_malformed();
        std::cout << "Parser tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << "Parser test failed: " << error.what() << '\n';
        return 1;
    }
}
