#include "radiotap.hpp"

#include <algorithm>
#include <bit>
#include <cstring>
#include <vector>

namespace pf {

static uint16_t le16(std::span<const uint8_t> d, size_t i) {
    return static_cast<uint16_t>(d[i]) | (static_cast<uint16_t>(d[i + 1]) << 8);
}

static uint32_t le32(std::span<const uint8_t> d, size_t i) {
    return static_cast<uint32_t>(d[i]) | (static_cast<uint32_t>(d[i + 1]) << 8) |
           (static_cast<uint32_t>(d[i + 2]) << 16) | (static_cast<uint32_t>(d[i + 3]) << 24);
}

std::optional<uint8_t> freq_to_channel(uint32_t freq) {
    if (freq >= 2412 && freq <= 2484)
        return static_cast<uint8_t>((static_cast<int32_t>(freq) - 2407) / 5);
    if (freq >= 5000 && freq <= 6000)
        return static_cast<uint8_t>((static_cast<int32_t>(freq) - 5000) / 5);
    return std::nullopt;
}

std::optional<std::pair<Mac, int8_t>>
extract_80211_src_mac_and_rssi(std::span<const uint8_t> data) {
    if (data.size() < 8)
        return std::nullopt;
    if (data[0] != 0) // radiotap version
        return std::nullopt;

    size_t radiotap_len = le16(data, 2);
    if (radiotap_len < 8 || radiotap_len > data.size())
        return std::nullopt;

    // Collect present bitmaps (chained via bit 31).
    std::vector<uint32_t> present_maps;
    size_t present_offset = 4;
    while (true) {
        if (present_offset + 4 > data.size())
            return std::nullopt;
        uint32_t word = le32(data, present_offset);
        present_maps.push_back(word);
        present_offset += 4;
        if ((word & (1u << 31)) == 0)
            break;
    }

    size_t offset = present_offset;
    std::optional<int8_t> rssi_opt;

    for (size_t map_idx = 0; map_idx < present_maps.size(); ++map_idx) {
        uint32_t present = present_maps[map_idx];
        for (int bit = 0; bit < 32; ++bit) {
            if ((present & (1u << bit)) == 0)
                continue;
            size_t field_index = map_idx * 32 + static_cast<size_t>(bit);

            size_t size = 0, align = 1;
            switch (field_index) {
                case 0:  size = 8; align = 8; break; // TSFT
                case 1:  size = 1; align = 1; break; // Flags
                case 2:  size = 1; align = 1; break; // Rate
                case 3:  size = 4; align = 2; break; // Channel
                case 4:  size = 2; align = 2; break; // FHSS
                case 5:  size = 1; align = 1; break; // Antenna signal (RSSI)
                case 6:  size = 1; align = 1; break; // Antenna noise
                case 7:  size = 2; align = 2; break; // Lock quality
                case 8:  size = 2; align = 2; break; // TX power
                case 9:  size = 1; align = 1; break; // Antenna
                case 10: size = 1; align = 1; break; // DB antenna signal
                case 11: size = 1; align = 1; break; // DB antenna noise
                case 12: size = 2; align = 2; break; // RX flags
                case 13: size = 2; align = 2; break; // TX flags
                case 14: size = 1; align = 1; break; // RTS retries
                case 15: size = 1; align = 1; break; // Data retries
                default: continue;
            }

            size_t aligned = align > 1 ? ((offset + (align - 1)) & ~(align - 1)) : offset;
            if (aligned + size > radiotap_len || aligned + size > data.size())
                return std::nullopt;

            if (field_index == 5)
                rssi_opt = std::bit_cast<int8_t>(data[aligned]);

            offset = aligned + size;
        }
    }

    if (!rssi_opt)
        return std::nullopt;
    int8_t rssi = *rssi_opt;

    auto hdr = data.subspan(radiotap_len);
    if (hdr.size() < 24)
        return std::nullopt;

    uint16_t frame_control = le16(hdr, 0);
    if (((frame_control >> 2) & 0x3) == 1) // control frame
        return std::nullopt;

    bool to_ds = (frame_control & 0x0100) != 0;
    bool from_ds = (frame_control & 0x0200) != 0;

    size_t min_len = (to_ds && from_ds) ? 30 : 24;
    if (hdr.size() < min_len)
        return std::nullopt;

    size_t base;
    if (to_ds && from_ds)
        base = 24; // WDS: addr4
    else if (to_ds)
        base = 10; // STA->AP: addr2
    else if (from_ds)
        base = 16; // AP->STA: addr3
    else
        base = 10; // ad-hoc/mgmt: addr2

    Mac src{};
    std::ranges::copy(hdr.subspan(base, 6), src.begin());
    return std::make_pair(src, rssi);
}

bool packet_contains_mac(std::span<const uint8_t> data, const Mac& target) {
    if (auto parsed = extract_80211_src_mac_and_rssi(data); parsed && parsed->first == target)
        return true;
    if (data.size() < 6)
        return false;
    for (size_t i = 0; i + 6 <= data.size(); ++i)
        if (std::equal(target.begin(), target.end(), data.begin() + i))
            return true;
    return false;
}

} // namespace pf
