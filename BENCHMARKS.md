# NetScope benchmark

The `Offline benchmark` GitHub Actions workflow builds NetScope in Release mode and replays a generated classic PCAP containing 200,000 identical 46-byte Ethernet/IPv4/UDP frames. It checks that `processed + queue dropped = captured` and that no frame is classified as malformed. This is an offline pipeline workload; it excludes kernel capture and real network traffic.

## Baseline run

[GitHub Actions run 36618766515](https://github.com/25Rohit25/NetScope-Linux-Network-Packet-Analyzer/actions/runs/36618766515), Ubuntu runner, GCC 13.3.0, Release build, 200,000 frames:

| Workers | Queue capacity | Processed | Queue drops | Wall time | Processed rate |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 8,192 | 54,720 | 145,280 | 0.064 s | 857,934 packets/s |
| 4 | 8,192 | 197,077 | 2,923 | 0.139 s | 1,416,508 packets/s |

Four workers processed more of the burst, but the 8,192-packet queue still filled briefly. The default queue was increased to 32,768 packets to absorb larger bursts. A larger queue does not increase sustained parsing capacity; compare packet drops and memory use under your own traffic. These short, synthetic runs are not a guaranteed live capture throughput figure, and timings vary across GitHub runners.

Run the same benchmark locally with `python3 tests/offline_load.py ./build/netscope --packets 200000 --workers 4 --queue-size 32768`. The workflow also includes this larger-queue configuration for comparison.
