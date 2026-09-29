#include "netscope/concurrent_queue.hpp"
#include "netscope/parser.hpp"
#include "netscope/statistics.hpp"

#include <pcap.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

volatile std::sig_atomic_t stop_requested = 0;

extern "C" void on_signal(int) { stop_requested = 1; }

struct Options {
    bool interfaces = false;
    bool verbose = false;
    bool help = false;
    std::string interface_name;
    std::string file_name;
    std::string filter;
    std::size_t workers = 4;
    std::size_t queue_capacity = 4096;
    unsigned interval_seconds = 5;
};

struct RawPacket {
    std::chrono::system_clock::time_point timestamp;
    std::vector<std::uint8_t> bytes;
};

std::size_t positive_number(const std::string& value, std::size_t maximum, const char* option) {
    std::size_t used = 0;
    std::size_t number = 0;
    try {
        number = std::stoull(value, &used);
    } catch (const std::exception&) {
        throw std::invalid_argument(std::string("invalid value for ") + option);
    }
    if (used != value.size() || number == 0 || number > maximum)
        throw std::invalid_argument(std::string("invalid value for ") + option);
    return number;
}

Options parse_options(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") options.help = true;
        else if (arg == "--interfaces") options.interfaces = true;
        else if (arg == "--verbose" || arg == "-v") options.verbose = true;
        else {
            if (i + 1 == argc) throw std::invalid_argument("missing value for " + arg);
            const std::string value = argv[++i];
            if (arg == "-i" || arg == "--interface") options.interface_name = value;
            else if (arg == "--file") options.file_name = value;
            else if (arg == "--filter") options.filter = value;
            else if (arg == "--workers") options.workers = positive_number(value, 128, "--workers");
            else if (arg == "--queue-size") options.queue_capacity = positive_number(value, 1000000, "--queue-size");
            else if (arg == "--interval") options.interval_seconds = static_cast<unsigned>(positive_number(value, 3600, "--interval"));
            else throw std::invalid_argument("unknown option: " + arg);
        }
    }
    if (!options.help && !options.interfaces && (options.interface_name.empty() == options.file_name.empty()))
        throw std::invalid_argument("provide exactly one of -i/--interface or --file");
    return options;
}

void print_help() {
    std::cout << "NetScope - Linux packet analyzer\n"
              << "Usage: netscope --interfaces\n"
              << "       netscope -i INTERFACE [--filter BPF] [--workers N] [--queue-size N] [--interval SEC] [-v]\n"
              << "       netscope --file CAPTURE.pcap [same options]\n"
              << "       netscope --help\n";
}

int list_interfaces() {
    pcap_if_t* devices = nullptr;
    char error[PCAP_ERRBUF_SIZE] = {};
    if (pcap_findalldevs(&devices, error) != 0) {
        std::cerr << "Interface discovery failed: " << error << '\n';
        return 1;
    }
    std::cout << "Available interfaces:\n";
    int number = 0;
    for (auto* device = devices; device != nullptr; device = device->next) {
        std::cout << ++number << ". " << device->name;
        if (device->description) std::cout << " (" << device->description << ')';
        std::cout << '\n';
    }
    pcap_freealldevs(devices);
    return 0;
}

using PcapHandle = std::unique_ptr<pcap_t, decltype(&pcap_close)>;

PcapHandle open_capture(const Options& options) {
    char error[PCAP_ERRBUF_SIZE] = {};
    pcap_t* raw = options.file_name.empty()
        ? pcap_open_live(options.interface_name.c_str(), 65535, 1, 250, error)
        : pcap_open_offline(options.file_name.c_str(), error);
    if (!raw) throw std::runtime_error(std::string("capture open failed: ") + error);
    PcapHandle handle(raw, pcap_close);
    if (pcap_datalink(handle.get()) != DLT_EN10MB)
        throw std::runtime_error("only Ethernet link-layer captures are supported");
    if (!options.filter.empty()) {
        struct bpf_program program{};
        if (pcap_compile(handle.get(), &program, options.filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0)
            throw std::runtime_error(std::string("invalid BPF filter: ") + pcap_geterr(handle.get()));
        const int result = pcap_setfilter(handle.get(), &program);
        pcap_freecode(&program);
        if (result < 0) throw std::runtime_error(std::string("BPF filter failed: ") + pcap_geterr(handle.get()));
    }
    return handle;
}

int run(const Options& options) {
    auto capture = open_capture(options);
    netscope::ConcurrentQueue<RawPacket> queue(options.queue_capacity);
    netscope::Statistics stats;
    std::mutex output_mutex;
    std::vector<std::thread> workers;
    workers.reserve(options.workers);
    for (std::size_t i = 0; i < options.workers; ++i) {
        workers.emplace_back([&] {
            RawPacket raw;
            while (queue.pop(raw)) {
                const auto packet = netscope::parse_packet(raw.bytes.data(), raw.bytes.size());
                stats.record(packet, raw.timestamp);
                if (options.verbose) {
                    std::lock_guard<std::mutex> lock(output_mutex);
                    std::cout << netscope::packet_summary(packet) << '\n';
                }
            }
        });
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::cout << "Capturing " << (options.file_name.empty() ? options.interface_name : options.file_name)
              << " with " << options.workers << " workers. Press Ctrl+C to stop.\n";
    auto next_report = std::chrono::steady_clock::now() + std::chrono::seconds(options.interval_seconds);
    bool queue_warning = false;
    int exit_code = 0;
    while (!stop_requested) {
        struct pcap_pkthdr* header = nullptr;
        const u_char* bytes = nullptr;
        const int result = pcap_next_ex(capture.get(), &header, &bytes);
        if (result == 1) {
            RawPacket packet;
            packet.timestamp = std::chrono::system_clock::from_time_t(header->ts.tv_sec) +
                std::chrono::microseconds(header->ts.tv_usec);
            packet.bytes.assign(bytes, bytes + header->caplen);
            const auto packet_size = packet.bytes.size();
            if (!queue.try_push(std::move(packet))) stats.note_queue_drop();
            const auto depth = queue.size();
            stats.note_captured(packet_size, depth);
            if (depth * 5 >= options.queue_capacity * 4 && !queue_warning) {
                std::cerr << "WARN packet queue at least 80% full\n";
                queue_warning = true;
            } else if (depth * 2 < options.queue_capacity) {
                queue_warning = false;
            }
        } else if (result == -2) {
            break;  // End of offline capture.
        } else if (result == -1) {
            std::cerr << "Capture failed: " << pcap_geterr(capture.get()) << '\n';
            exit_code = 1;
            break;
        }
        if (std::chrono::steady_clock::now() >= next_report) {
            std::lock_guard<std::mutex> lock(output_mutex);
            std::cout << netscope::format_snapshot(stats.snapshot(queue.size())) << std::flush;
            next_report = std::chrono::steady_clock::now() + std::chrono::seconds(options.interval_seconds);
        }
    }

    queue.close();
    for (auto& worker : workers) worker.join();
    {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::cout << netscope::format_snapshot(stats.snapshot(queue.size()));
    }
    if (options.file_name.empty()) {
        struct pcap_stat capture_stats{};
        if (pcap_stats(capture.get(), &capture_stats) == 0)
            std::cout << "libpcap received: " << capture_stats.ps_recv
                      << "  kernel dropped: " << capture_stats.ps_drop << '\n';
    }
    return exit_code;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const auto options = parse_options(argc, argv);
        if (options.help) { print_help(); return 0; }
        if (options.interfaces) return list_interfaces();
        return run(options);
    } catch (const std::exception& error) {
        std::cerr << "NetScope: " << error.what() << '\n';
        print_help();
        return 1;
    }
}
