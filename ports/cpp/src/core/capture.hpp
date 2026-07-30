#pragma once
// libpcap capture: device enumeration, a background scan thread (std::jthread),
// and auto channel selection (C++23).

#include <cstdint>
#include <expected>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "mac.hpp"

namespace pf {

// Snapshot of scan progress delivered to the UI thread.
struct ScanUpdate {
    uint64_t total_frames = 0;
    uint64_t hits = 0;
    std::optional<int8_t> last_rssi;
};

// List capture-capable interface names (via pcap_findalldevs).
[[nodiscard]] std::vector<std::string> list_devices();

// Runs a capture in a background std::jthread and exposes the latest snapshot.
// The jthread's stop_token replaces the Rust Arc<AtomicBool>; the destructor
// requests stop and joins automatically.
class ScanSession {
public:
    ScanSession(std::string iface, Mac target);

    ScanSession(const ScanSession&) = delete;
    ScanSession& operator=(const ScanSession&) = delete;

    [[nodiscard]] ScanUpdate snapshot() const;
    void stop();

private:
    void run(std::stop_token st);

    std::string iface_;
    Mac target_;
    mutable std::mutex mtx_;
    ScanUpdate latest_;
    std::jthread thread_; // declared last: started after other members are set
};

// Sweep candidate channels, or use a system scan, to lock onto the target's
// channel. Mirrors the Rust `Result<Option<u8>, String>` exactly.
[[nodiscard]] std::expected<std::optional<uint8_t>, std::string>
auto_select_channel(std::string_view iface, const Mac& target);

} // namespace pf
