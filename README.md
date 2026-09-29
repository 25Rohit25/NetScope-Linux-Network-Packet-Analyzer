# NetScope

NetScope is a C++17 packet analyzer for Linux. It captures live Ethernet traffic or reads a classic PCAP file with libpcap, decodes common protocols with bounds checks, and sends packet copies through a bounded queue to parser workers. It reports protocol counts, top source hosts and destination ports, directional flows, malformed packets, queue drops, and average packet rates.

## Build on Ubuntu

```bash
sudo apt-get install build-essential cmake libpcap-dev python3
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The parser library and unit tests can build without libpcap; the `netscope` executable requires its development headers and library. GitHub Actions builds and tests the full program on Ubuntu with AddressSanitizer and UndefinedBehaviorSanitizer.

## Use

```bash
./build/netscope --interfaces
sudo ./build/netscope -i eth0 --workers 4 --queue-size 4096 --interval 5
sudo ./build/netscope -i eth0 --filter 'tcp port 443' --verbose
./build/netscope --file traffic.pcap --filter 'udp port 53'
```

Use Ctrl+C to stop a live capture. NetScope stops reading, closes the queue, lets workers process its remaining packets, and prints the final report. A full queue drops incoming packets instead of delaying the capture thread. `Queue dropped` counts these application drops; live captures also show the kernel's libpcap drop count where available. Live capture normally needs root or packet-capture capabilities.

`--verbose` prints one summary per packet, including malformed-packet reasons. The default view prints periodic statistics every five seconds and a final report. Rates are averages since capture start. Flow keys are directional five-tuples; TCP state is an observation-based summary rather than a full TCP state machine. Flow storage is capped at 100,000 distinct flows, and the report counts packets whose new flows could not be stored.

## Protocol coverage and limits

- Ethernet and up to two 802.1Q/802.1ad VLAN tags
- IPv4, IPv6, and Ethernet/IPv4 ARP
- TCP, UDP, ICMP, and ICMPv6; common application names inferred from well-known ports
- IPv4 fragments remain visible but are not decoded as transport packets; IPv6 extension headers remain visible without transport decoding
- Ethernet link type only; no TCP reassembly, application payload parsing, or IPv4 checksum validation

The parser rejects truncated or inconsistent supported headers before accessing fields. Packet bytes are copied before libpcap advances, so workers never hold a pointer into libpcap's reused capture buffer.

## Project layout

`src/parser.cpp` decodes packets, `include/netscope/concurrent_queue.hpp` supplies the bounded producer-consumer queue, `src/statistics.cpp` aggregates traffic and flow data, and `src/main.cpp` owns libpcap and the CLI. `tests/` has byte-array parser tests, queue/statistics tests, and an offline PCAP integration smoke test.
