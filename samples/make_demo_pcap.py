"""Regenerate the small, checksummed Ethernet demo capture in this directory."""

import ipaddress
import pathlib
import struct


SOURCE_IP = ipaddress.IPv4Address("192.0.2.10").packed
DESTINATION_IP = ipaddress.IPv4Address("198.51.100.20").packed
SOURCE_MAC = bytes.fromhex("66778899aabb")
DESTINATION_MAC = bytes.fromhex("001122334455")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(protocol: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0,
                         64, protocol, 0, SOURCE_IP, DESTINATION_IP)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return DESTINATION_MAC + SOURCE_MAC + b"\x08\x00" + header + payload


def transport_checksum(protocol: int, payload: bytes) -> int:
    pseudo = SOURCE_IP + DESTINATION_IP + struct.pack("!BBH", 0, protocol, len(payload))
    return checksum(pseudo + payload)


def udp_frame() -> bytes:
    dns = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")
    header = struct.pack("!HHHH", 53000, 53, 8 + len(dns), 0)
    checked = header[:6] + struct.pack("!H", transport_checksum(17, header + dns))
    return ipv4(17, checked + dns)


def tcp_frame() -> bytes:
    header = struct.pack("!HHIIBBHHH", 50000, 443, 12345, 0, 0x50, 0x02, 64240, 0, 0)
    checked = header[:16] + struct.pack("!H", transport_checksum(6, header)) + header[18:]
    return ipv4(6, checked)


def icmp_frame() -> bytes:
    message = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"netscope"
    message = message[:2] + struct.pack("!H", checksum(message)) + message[4:]
    return ipv4(1, message)


def arp_frame() -> bytes:
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
    arp += SOURCE_MAC + SOURCE_IP + bytes(6) + ipaddress.IPv4Address("192.0.2.1").packed
    return bytes(6) + SOURCE_MAC + b"\x08\x06" + arp


def main() -> None:
    output = pathlib.Path(__file__).with_name("demo.pcap")
    with output.open("wb") as capture:
        capture.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate((udp_frame(), tcp_frame(), icmp_frame(), arp_frame())):
            capture.write(struct.pack("<IIII", 1760000000 + index, 0, len(frame), len(frame)))
            capture.write(frame)
    print(output)


if __name__ == "__main__":
    main()
