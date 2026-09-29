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
./build/netscope --file samples/demo.pcap --verbose
sudo ./build/netscope -i eth0 --count 1000
```

Use Ctrl+C to stop a live capture. NetScope stops reading, closes the queue, lets workers process its remaining packets, and prints the final report. A full queue drops incoming packets instead of delaying the capture thread. `Queue dropped` counts these application drops; live captures also show the kernel's libpcap drop count where available. Capture truncation (`caplen < len`) is counted separately from malformed packet data. Live capture normally needs root or packet-capture capabilities.

`--verbose` prints one summary per packet, including malformed-packet reasons. The default view prints periodic statistics every five seconds and a final report. It shows both averages since capture start and rates for each reporting interval; latency measures time from enqueue through parsing. `--count` stops after the specified number of captured packets, making repeatable captures and benchmarks easier. The report includes the five largest directional flows by bytes. Flow keys are directional five-tuples; TCP state is an observation-based summary rather than a full TCP state machine. Flow and source-host storage are each capped at 100,000 distinct entries, and the report counts packets whose new entries could not be stored.

## Protocol coverage and limits

- Ethernet and up to two 802.1Q/802.1ad VLAN tags
- IPv4, IPv6, and Ethernet/IPv4 ARP
- TCP, UDP, ICMP, and ICMPv6; common application names inferred from well-known ports
- IPv4 and IPv6 fragments remain visible but are not decoded as transport packets; common IPv6 extension headers are traversed with length and depth checks
- Ethernet link type only; no TCP reassembly, application payload parsing, or IPv4 checksum validation

The parser rejects truncated or inconsistent supported headers before accessing fields. It extracts IPv4 and UDP checksum fields but does not validate checksum integrity. Packet bytes are copied before libpcap advances, so workers never hold a pointer into libpcap's reused capture buffer. `samples/demo.pcap` contains checksummed DNS, TCP SYN, ICMP echo, and ARP frames and can be regenerated with `python3 samples/make_demo_pcap.py`.

Warnings are written to stderr with UTC timestamps. Packet warnings are limited to the first ten per run; the summary still counts every malformed or truncated packet. Capture sequence numbers keep TCP flow state in capture order even if workers finish in a different order.

## Load test and benchmark

The offline load test replays 20,000 generated UDP packets and checks that every captured packet was either processed or counted as a queue drop. Run a larger local benchmark with:

```bash
python3 tests/offline_load.py ./build/netscope --packets 100000 --workers 4 --queue-size 8192
```

The script prints wall time, processed packets per second, and queue drops. Compare runs with the same machine, compiler settings, and packet count; this synthetic replay measures NetScope's offline pipeline rather than live network capture. CI also runs a privileged loopback smoke test that exercises live capture and `--count`.

## Project layout

`src/parser.cpp` decodes packets, `include/netscope/concurrent_queue.hpp` supplies the bounded producer-consumer queue, `src/statistics.cpp` aggregates traffic and flow data, and `src/main.cpp` owns libpcap and the CLI. `tests/` has byte-array parser tests, queue/statistics tests, and an offline PCAP integration smoke test.
