# NetScope benchmark

The `Offline benchmark` GitHub Actions workflow builds NetScope in Release mode and replays a generated classic PCAP containing 200,000 identical 46-byte Ethernet/IPv4/UDP frames. It checks that `processed + queue dropped = captured` and that no frame is classified as malformed. This is an offline pipeline workload; it excludes kernel capture and real network traffic.

## Release run

[GitHub Actions run 36619225415](https://github.com/25Rohit25/NetScope-Linux-Network-Packet-Analyzer/actions/runs/36619225415), Ubuntu runner, GCC 13.3.0, Release build, 200,000 frames:

| Workers | Queue capacity | Processed | Queue drops | Wall time | Processed rate |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 8,192 | 35,500 | 164,500 | 0.061 s | 580,700 packets/s |
| 4 | 8,192 | 177,065 | 22,935 | 0.189 s | 934,475 packets/s |
| 4 | 32,768 | 200,000 | 0 | 0.226 s | 883,253 packets/s |

Four workers processed more of the burst than one worker. The 32,768-packet queue absorbed the whole burst in this run, so it became the default. A larger queue does not increase sustained parsing capacity; compare packet drops and memory use under your own traffic. The smaller-queue runs finish sooner partly because they discard packets, so their processed-per-second figures are not directly comparable with a no-drop run. These short, synthetic timings vary: an [earlier run](https://github.com/25Rohit25/NetScope-Linux-Network-Packet-Analyzer/actions/runs/36618766515) processed 197,077 packets with four workers and an 8,192-packet queue. None of these figures guarantees live capture throughput.

Run the same benchmark locally with `python3 tests/offline_load.py ./build/netscope --packets 200000 --workers 4 --queue-size 32768`. The workflow includes all three configurations for comparison.
