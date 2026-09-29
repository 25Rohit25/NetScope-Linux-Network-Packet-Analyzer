"""Replay many packets and verify that processing plus drops equals capture."""

import argparse
import pathlib
import re
import struct
import subprocess
import tempfile
import time


def packet() -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    ipv4 = bytes.fromhex("450000200000000040110000c0000201c6336402")
    udp = struct.pack("!HHHH", 12345, 53, 12, 0) + b"test"
    return ethernet + ipv4 + udp


def run(executable: str, count: int, workers: int, queue_size: int) -> None:
    frame = packet()
    record = struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame
    with tempfile.TemporaryDirectory() as directory:
        capture = pathlib.Path(directory) / "load.pcap"
        with capture.open("wb") as output:
            output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for _ in range(count):
                output.write(record)
        started = time.perf_counter()
        completed = subprocess.run(
            [executable, "--file", str(capture), "--workers", str(workers),
             "--queue-size", str(queue_size), "--interval", "3600"],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
        elapsed = time.perf_counter() - started
    matches = re.findall(r"Captured: (\d+)  Processed: (\d+)  Queue dropped: (\d+)  Malformed: (\d+)", completed.stdout)
    if not matches:
        raise AssertionError(f"No final report:\n{completed.stdout}\n{completed.stderr}")
    captured, processed, dropped, malformed = map(int, matches[-1])
    if captured != count or processed + dropped != count or malformed != 0:
        raise AssertionError(f"Bad accounting: captured={captured}, processed={processed}, "
                             f"dropped={dropped}, malformed={malformed}\n{completed.stdout}")
    print(f"{captured} captured, {processed} processed, {dropped} queue drops, "
          f"{elapsed:.3f} s wall time, {processed / elapsed:,.0f} processed packets/s")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable")
    parser.add_argument("--packets", type=int, default=20000)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--queue-size", type=int, default=4096)
    options = parser.parse_args()
    if options.packets < 1 or options.workers < 1 or options.queue_size < 1:
        parser.error("packets, workers, and queue-size must be positive")
    run(options.executable, options.packets, options.workers, options.queue_size)
