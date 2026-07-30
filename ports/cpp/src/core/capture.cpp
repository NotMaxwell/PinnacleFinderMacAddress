#include "capture.hpp"
#include "radiotap.hpp"
#include "sysiface.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <span>

#include <pcap/pcap.h>

namespace pf {

using steady = std::chrono::steady_clock;

namespace {

// Open a capture handle, trying monitor (rfmon) mode first, then promisc.
std::expected<pcap_t*, std::string> open_capture(std::string_view iface, int timeout_ms) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    std::string ifs(iface);

    auto try_open = [&](bool rfmon) -> std::expected<pcap_t*, std::string> {
        pcap_t* p = pcap_create(ifs.c_str(), errbuf);
        if (!p)
            return std::unexpected(std::string("pcap_create: ") + errbuf);
        if (rfmon)
            pcap_set_rfmon(p, 1);
        pcap_set_promisc(p, 1);
        pcap_set_snaplen(p, 65535);
        pcap_set_timeout(p, timeout_ms);
        if (int rc = pcap_activate(p); rc < 0) {
            std::string e = pcap_statustostr(rc);
            pcap_close(p);
            return std::unexpected("pcap_activate: " + e);
        }
        return p;
    };

    if (auto p = try_open(true))
        return p;
    else if (auto p2 = try_open(false))
        return p2;
    else
        return std::unexpected("open failed (rfmon and promisc): " + p2.error());
}

} // namespace

std::vector<std::string> list_devices() {
    std::vector<std::string> names;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t* alldevs = nullptr;
    if (pcap_findalldevs(&alldevs, errbuf) == 0 && alldevs) {
        for (pcap_if_t* d = alldevs; d; d = d->next)
            if (d->name)
                names.emplace_back(d->name);
        pcap_freealldevs(alldevs);
    }
    return names;
}

ScanSession::ScanSession(std::string iface, Mac target)
    : iface_(std::move(iface)), target_(target),
      thread_([this](std::stop_token st) { run(st); }) {}

void ScanSession::stop() { thread_.request_stop(); }

ScanUpdate ScanSession::snapshot() const {
    std::lock_guard lk(mtx_);
    return latest_;
}

void ScanSession::run(std::stop_token st) {
    auto cap = open_capture(iface_, 300);
    if (!cap)
        return; // a dead session simply produces no updates
    pcap_t* handle = *cap;

    uint64_t total_frames = 0, hits = 0;
    std::optional<int8_t> last_rssi;

    while (!st.stop_requested()) {
        pcap_pkthdr* hdr = nullptr;
        const u_char* data = nullptr;
        int rc = pcap_next_ex(handle, &hdr, &data);
        if (rc == 1) {
            ++total_frames;
            std::span<const uint8_t> bytes(data, hdr->caplen);
            if (auto parsed = extract_80211_src_mac_and_rssi(bytes)) {
                if (parsed->first == target_) {
                    last_rssi = parsed->second;
                    ++hits;
                }
            } else if (bytes.size() >= 6 && packet_contains_mac(bytes, target_)) {
                ++hits;
            }
            std::lock_guard lk(mtx_);
            latest_ = {total_frames, hits, last_rssi};
        } else if (rc == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        } else {
            break;
        }
    }

    std::lock_guard lk(mtx_);
    latest_ = {total_frames, hits, last_rssi};
    pcap_close(handle);
}

// --- auto channel selection ---

static std::optional<uint8_t> channel_sweep_detect(std::string_view iface, const Mac& target) {
    static constexpr uint8_t candidates[] = {1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161};
    std::optional<uint8_t> best_ch;
    uint64_t best_hits = 0;

    for (uint8_t ch : candidates) {
        if (!set_channel_system(iface, ch))
            continue;
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        auto cap = open_capture(iface, 400);
        if (!cap)
            continue;
        pcap_t* handle = *cap;

        uint64_t local_hits = 0;
        int packets = 0;
        auto deadline = steady::now() + std::chrono::milliseconds(450);
        while (packets < 200 && steady::now() < deadline) {
            pcap_pkthdr* hdr = nullptr;
            const u_char* data = nullptr;
            int rc = pcap_next_ex(handle, &hdr, &data);
            if (rc == 1) {
                ++packets;
                if (packet_contains_mac(std::span(data, hdr->caplen), target)) {
                    if (++local_hits > best_hits) {
                        best_hits = local_hits;
                        best_ch = ch;
                    }
                }
            } else {
                break;
            }
        }
        pcap_close(handle);
    }
    return best_ch;
}

std::expected<std::optional<uint8_t>, std::string>
auto_select_channel(std::string_view iface, const Mac& target) {
    std::string target_s = format_mac_bytes(target);
    std::ranges::transform(target_s, target_s.begin(),
                           [](char c) { return static_cast<char>(std::tolower((unsigned char)c)); });

    if (auto rows = scan_system_channels(iface)) {
        for (auto& [bssid, ch] : *rows) {
            std::string b = bssid;
            std::ranges::transform(b, b.begin(),
                                   [](char c) { return static_cast<char>(std::tolower((unsigned char)c)); });
            if (b == target_s) {
                if (auto e = set_channel_system(iface, ch); !e)
                    return std::unexpected(e.error());
                return std::optional<uint8_t>(ch);
            }
        }
    }

    if (auto ch = channel_sweep_detect(iface, target)) {
        if (auto e = set_channel_system(iface, *ch); !e)
            return std::unexpected(e.error());
        return ch;
    }
    return std::optional<uint8_t>(std::nullopt);
}

} // namespace pf
