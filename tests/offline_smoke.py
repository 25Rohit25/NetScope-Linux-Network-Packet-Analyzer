"""Exercise the real libpcap reader, BPF filter, workers, and final report."""

import pathlib
import struct
import subprocess
import sys
import tempfile


def ethernet_ipv4_udp() -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    ipv4 = bytes.fromhex("450000200000000040110000c0000201c6336402")
    udp = struct.pack("!HHHH", 12345, 53, 12, 0) + b"test"
    return ethernet + ipv4 + udp


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        capture = pathlib.Path(directory) / "sample.pcap"
        packet = ethernet_ipv4_udp()
        # Classic PCAP, little endian, microsecond timestamps, Ethernet link type.
        capture.write_bytes(
            struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            + struct.pack("<IIII", 1, 0, len(packet), len(packet))
            + packet
        )
        completed = subprocess.run(
            [sys.argv[1], "--file", str(capture), "--filter", "udp port 53", "--workers", "2"],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        )
        output = completed.stdout
        for expected in ("Captured: 1", "Processed: 1", "UDP: 1", "53  1"):
            if expected not in output:
                raise AssertionError(f"Missing {expected!r} in NetScope output:\n{output}")


if __name__ == "__main__":
    main()
