#include "netscope/parser.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <utility>

namespace netscope {
namespace {

std::uint16_t read16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((static_cast<unsigned>(p[0]) << 8) | p[1]);
}

std::uint32_t read32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | p[3];
}

std::string mac_address(const std::uint8_t* p) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i) out << ':';
        out << std::setw(2) << static_cast<unsigned>(p[i]);
    }
    return out.str();
}

std::string ipv4_address(const std::uint8_t* p) {
    std::ostringstream out;
    out << static_cast<unsigned>(p[0]) << '.' << static_cast<unsigned>(p[1]) << '.'
        << static_cast<unsigned>(p[2]) << '.' << static_cast<unsigned>(p[3]);
    return out.str();
}

std::string ipv6_address(const std::uint8_t* p) {
    std::ostringstream out;
    out << std::hex;
    for (int i = 0; i < 16; i += 2) {
        if (i) out << ':';
        out << read16(p + i);
    }
    return out.str();
}

std::string application_name(std::uint16_t source, std::uint16_t destination) {
    for (const auto port : {source, destination}) {
        switch (port) {
            case 20: case 21: return "FTP";
            case 22: return "SSH";
            case 25: return "SMTP";
            case 53: return "DNS";
            case 80: return "HTTP";
            case 443: return "HTTPS";
            default: break;
        }
    }
    return {};
}

std::string icmp_message_name(NetworkProtocol network, std::uint8_t type) {
    if (network == NetworkProtocol::ipv4) {
        switch (type) {
            case 0: return "Echo Reply";
            case 3: return "Destination Unreachable";
            case 8: return "Echo Request";
            case 11: return "Time Exceeded";
            default: return {};
        }
    }
    switch (type) {
        case 1: return "Destination Unreachable";
        case 2: return "Packet Too Big";
        case 3: return "Time Exceeded";
        case 128: return "Echo Request";
        case 129: return "Echo Reply";
        default: return {};
    }
}

bool parse_transport(PacketInfo& info, const std::uint8_t* p, std::size_t length) {
    if (info.ip_protocol == 6) {
        if (length < 20) { info.error = "truncated TCP header"; return false; }
        const std::size_t header_length = static_cast<std::size_t>(p[12] >> 4) * 4;
        if (header_length < 20 || header_length > length) {
            info.error = "invalid TCP header length";
            return false;
        }
        info.transport = TransportProtocol::tcp;
        info.source_port = read16(p);
        info.destination_port = read16(p + 2);
        info.tcp_sequence = read32(p + 4);
        info.tcp_acknowledgment = read32(p + 8);
        info.tcp_flags = p[13];
        info.tcp_window = read16(p + 14);
        info.application = application_name(info.source_port, info.destination_port);
    } else if (info.ip_protocol == 17) {
        if (length < 8) { info.error = "truncated UDP header"; return false; }
        const auto udp_length = read16(p + 4);
        if (udp_length < 8 || udp_length > length) {
            info.error = "invalid or truncated UDP length";
            return false;
        }
        info.transport = TransportProtocol::udp;
        info.source_port = read16(p);
        info.destination_port = read16(p + 2);
        info.udp_length = udp_length;
        info.udp_checksum = read16(p + 6);
        info.application = application_name(info.source_port, info.destination_port);
    } else if ((info.network == NetworkProtocol::ipv4 && info.ip_protocol == 1) ||
               (info.network == NetworkProtocol::ipv6 && info.ip_protocol == 58)) {
        if (length < 4) { info.error = "truncated ICMP header"; return false; }
        const bool echo = info.network == NetworkProtocol::ipv4 ? (p[0] == 0 || p[0] == 8) :
                                                            (p[0] == 128 || p[0] == 129);
        if (echo && length < 8) { info.error = "truncated ICMP echo header"; return false; }
        info.transport = info.network == NetworkProtocol::ipv4 ? TransportProtocol::icmp : TransportProtocol::icmpv6;
        info.icmp_type = p[0];
        info.icmp_code = p[1];
        info.icmp_message = icmp_message_name(info.network, info.icmp_type);
    }
    return true;
}

}  // namespace

PacketInfo parse_packet(const std::uint8_t* bytes, std::size_t length) {
    PacketInfo info;
    info.captured_bytes = length;
    info.wire_bytes = length;
    if (bytes == nullptr || length < 14) {
        info.error = "truncated Ethernet header";
        return info;
    }
    info.destination_mac = mac_address(bytes);
    info.source_mac = mac_address(bytes + 6);
    std::size_t offset = 14;
    auto ether_type = read16(bytes + 12);
    for (int tags = 0; tags < 2 && (ether_type == 0x8100 || ether_type == 0x88a8); ++tags) {
        if (length - offset < 4) { info.error = "truncated VLAN tag"; return info; }
        ether_type = read16(bytes + offset + 2);
        offset += 4;
    }
    if (ether_type == 0x8100 || ether_type == 0x88a8) {
        info.error = "more than two VLAN tags";
        return info;
    }
    const auto* p = bytes + offset;
    const auto available = length - offset;

    if (ether_type == 0x0800) {
        info.network = NetworkProtocol::ipv4;
        if (available < 20) { info.error = "truncated IPv4 header"; return info; }
        if ((p[0] >> 4) != 4) { info.error = "invalid IPv4 version"; return info; }
        const std::size_t header_length = static_cast<std::size_t>(p[0] & 0x0f) * 4;
        if (header_length < 20 || header_length > available) {
            info.error = "invalid IPv4 header length";
            return info;
        }
        const auto total_length = read16(p + 2);
        if (total_length < header_length || total_length > available) {
            info.error = "invalid or truncated IPv4 total length";
            return info;
        }
        info.ttl = p[8];
        info.ip_protocol = p[9];
        info.ipv4_checksum = read16(p + 10);
        info.source_ip = ipv4_address(p + 12);
        info.destination_ip = ipv4_address(p + 16);
        info.fragmented = (read16(p + 6) & 0x3fff) != 0;
        if (!info.fragmented && !parse_transport(info, p + header_length, total_length - header_length)) return info;
    } else if (ether_type == 0x86dd) {
        info.network = NetworkProtocol::ipv6;
        if (available < 40) { info.error = "truncated IPv6 header"; return info; }
        if ((p[0] >> 4) != 6) { info.error = "invalid IPv6 version"; return info; }
        const auto payload_length = read16(p + 4);
        if (static_cast<std::size_t>(payload_length) > available - 40) {
            info.error = "truncated IPv6 payload";
            return info;
        }
        info.ip_protocol = p[6];
        info.ttl = p[7];
        info.source_ip = ipv6_address(p + 8);
        info.destination_ip = ipv6_address(p + 24);
        const auto* payload = p + 40;
        std::size_t remaining = payload_length;
        int extensions = 0;
        while (info.ip_protocol == 0 || info.ip_protocol == 43 || info.ip_protocol == 44 ||
               info.ip_protocol == 51 || info.ip_protocol == 60) {
            if (++extensions > 16) { info.error = "too many IPv6 extension headers"; return info; }
            const bool fragment_header = info.ip_protocol == 44;
            if (remaining < (fragment_header ? 8u : 2u)) {
                info.error = "truncated IPv6 extension header";
                return info;
            }
            std::size_t extension_length = fragment_header ? 8u :
                (info.ip_protocol == 51 ? static_cast<std::size_t>(payload[1] + 2) * 4 :
                                          static_cast<std::size_t>(payload[1] + 1) * 8);
            if (extension_length > remaining || extension_length < (fragment_header ? 8u : 2u)) {
                info.error = "invalid IPv6 extension length";
                return info;
            }
            if (fragment_header)
                info.fragmented = (read16(payload + 2) & 0xfff9) != 0;
            info.ip_protocol = payload[0];
            payload += extension_length;
            remaining -= extension_length;
            if (info.fragmented) break;  // Transport header may be incomplete even in the first fragment.
        }
        // ESP is encrypted and 59 means no next header; neither exposes transport fields.
        if (!info.fragmented && info.ip_protocol != 50 && info.ip_protocol != 59 &&
            !parse_transport(info, payload, remaining)) return info;
    } else if (ether_type == 0x0806) {
        info.network = NetworkProtocol::arp;
        if (available < 28) { info.error = "truncated ARP packet"; return info; }
        if (read16(p) != 1 || read16(p + 2) != 0x0800 || p[4] != 6 || p[5] != 4) {
            info.error = "unsupported ARP address format";
            return info;
        }
        info.arp_operation = read16(p + 6);
        info.arp_sender_mac = mac_address(p + 8);
        info.arp_target_mac = mac_address(p + 18);
        info.source_ip = ipv4_address(p + 14);
        info.destination_ip = ipv4_address(p + 24);
    }
    info.valid = true;
    return info;
}

std::string transport_name(TransportProtocol protocol) {
    switch (protocol) {
        case TransportProtocol::tcp: return "TCP";
        case TransportProtocol::udp: return "UDP";
        case TransportProtocol::icmp: return "ICMP";
        case TransportProtocol::icmpv6: return "ICMPv6";
        default: return "Other";
    }
}

std::string packet_summary(const PacketInfo& packet) {
    if (!packet.valid)
        return (packet.capture_truncated ? "TRUNCATED: " : "MALFORMED: ") + packet.error;
    std::ostringstream out;
    if (packet.network == NetworkProtocol::arp) {
        out << "ARP op=" << packet.arp_operation;
    } else if (packet.network == NetworkProtocol::ipv4) {
        out << "IPv4 " << transport_name(packet.transport);
    } else if (packet.network == NetworkProtocol::ipv6) {
        out << "IPv6 " << transport_name(packet.transport);
    } else {
        out << "Ethernet Other";
    }
    if (!packet.source_ip.empty()) {
        out << ' ' << packet.source_ip;
        if (packet.transport == TransportProtocol::tcp || packet.transport == TransportProtocol::udp)
            out << ':' << packet.source_port;
        out << " -> " << packet.destination_ip;
        if (packet.transport == TransportProtocol::tcp || packet.transport == TransportProtocol::udp)
            out << ':' << packet.destination_port;
    }
    if (!packet.application.empty()) out << " [" << packet.application << ']';
    if (packet.fragmented) out << " [fragmented]";
    if (packet.capture_truncated)
        out << " [capture truncated " << packet.captured_bytes << '/' << packet.wire_bytes << " bytes]";
    if (packet.network == NetworkProtocol::ipv4 || packet.network == NetworkProtocol::ipv6)
        out << " ttl=" << static_cast<unsigned>(packet.ttl);
    if (packet.transport == TransportProtocol::tcp) {
        out << " seq=" << packet.tcp_sequence << " ack=" << packet.tcp_acknowledgment
            << " flags=";
        const char* separator = "";
        for (const auto& flag : {std::pair<std::uint8_t, const char*>{0x02, "SYN"},
                                 {0x10, "ACK"}, {0x01, "FIN"}, {0x04, "RST"},
                                 {0x08, "PSH"}, {0x20, "URG"}})
            if (packet.tcp_flags & flag.first) {
                out << separator << flag.second;
                separator = ",";
            }
        if (*separator == '\0') out << '-';
        out << " win=" << packet.tcp_window;
    } else if (packet.transport == TransportProtocol::udp) {
        out << " udp_len=" << packet.udp_length;
    } else if (packet.transport == TransportProtocol::icmp || packet.transport == TransportProtocol::icmpv6) {
        out << " type=" << static_cast<unsigned>(packet.icmp_type)
            << " code=" << static_cast<unsigned>(packet.icmp_code);
        if (!packet.icmp_message.empty()) out << " (" << packet.icmp_message << ')';
    }
    return out.str();
}

}  // namespace netscope
