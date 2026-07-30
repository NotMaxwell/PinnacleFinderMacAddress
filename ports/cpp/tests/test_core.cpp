// Headless unit tests for the portable core (no ncurses / libpcap needed).
// Build:  g++ -std=c++23 -I src tests/test_core.cpp src/core/mac.cpp src/core/radiotap.cpp -o test_core
#include <cstdint>
#include <print>
#include <span>
#include <vector>

#include "core/mac.hpp"
#include "core/radiotap.hpp"

using namespace pf;

static int failures = 0;
#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::println("FAIL: {} (line {})", #cond, __LINE__);               \
            ++failures;                                                        \
        }                                                                      \
    } while (0)

static void test_mac() {
    auto m = parse_mac("AA:BB:CC:DD:EE:FF");
    CHECK(m.has_value());
    CHECK((*m)[0] == 0xAA && (*m)[5] == 0xFF);
    CHECK(parse_mac("aa:bb:cc:dd:ee:ff").has_value()); // lowercase ok
    CHECK(!parse_mac("AA:BB:CC:DD:EE").has_value());   // too short
    CHECK(!parse_mac("AA:BB:CC:DD:EE:FF:00").has_value()); // too long
    CHECK(!parse_mac("GG:BB:CC:DD:EE:FF").has_value());    // non-hex
    CHECK(!parse_mac("AABBCCDDEEFF").has_value());         // no separators

    Mac bytes = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB};
    CHECK(format_mac_bytes(bytes) == "01:23:45:67:89:AB");

    CHECK(format_mac_from_hex("0123456789ab") == "01:23:45:67:89:AB");
    CHECK(format_mac_from_hex("aa-bb-cc") == "AA:BB:CC");
    CHECK(format_mac_from_hex("0123456789abCDEF99") == "01:23:45:67:89:AB"); // capped at 12
}

static void test_freq() {
    CHECK(freq_to_channel(2412) == std::optional<uint8_t>(1));
    CHECK(freq_to_channel(2437) == std::optional<uint8_t>(6));
    CHECK(freq_to_channel(2462) == std::optional<uint8_t>(11));
    CHECK(freq_to_channel(5180) == std::optional<uint8_t>(36));
    CHECK(!freq_to_channel(1000).has_value());
}

static void test_radiotap() {
    // radiotap: version 0, len 9, present=bit5 (antenna signal), rssi byte.
    // then a 24-byte 802.11 mgmt frame with addr2 = target.
    Mac target = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    std::vector<uint8_t> f(9 + 24, 0);
    f[0] = 0;           // version
    f[1] = 0;           // pad
    f[2] = 9; f[3] = 0; // radiotap length = 9 (LE)
    f[4] = 0x20;        // present bitmap: bit 5 set
    f[5] = f[6] = f[7] = 0;
    f[8] = 0xD6;        // rssi byte 0xD6 -> int8 -42

    uint8_t* hdr = f.data() + 9;
    hdr[0] = 0x00; hdr[1] = 0x00; // frame_control: mgmt, to_ds=from_ds=0
    // addr2 lives at hdr[10..16]
    for (int i = 0; i < 6; ++i)
        hdr[10 + i] = target[i];

    std::span<const uint8_t> frame(f);
    auto r = extract_80211_src_mac_and_rssi(frame);
    CHECK(r.has_value());
    CHECK(r->first == target);
    CHECK(r->second == -42);

    CHECK(packet_contains_mac(frame, target));
    Mac other = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    CHECK(!packet_contains_mac(frame, other));

    // Truncated / malformed inputs must be rejected, not crash.
    CHECK(!extract_80211_src_mac_and_rssi(frame.first(4)).has_value());
    uint8_t bad_version[16] = {0xFF};
    CHECK(!extract_80211_src_mac_and_rssi(std::span(bad_version)).has_value());
}

int main() {
    test_mac();
    test_freq();
    test_radiotap();
    if (failures == 0)
        std::println("all C++ core tests passed");
    return failures == 0 ? 0 : 1;
}
