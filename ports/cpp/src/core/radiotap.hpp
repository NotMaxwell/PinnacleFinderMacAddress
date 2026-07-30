#pragma once
// Radiotap + 802.11 frame parsing (C++23, std::span-based).
// Port of `extract_80211_src_mac_and_rssi`, `freq_to_channel`, `packet_contains_mac`.

#include <cstdint>
#include <optional>
#include <span>
#include <utility>

#include "mac.hpp"

namespace pf {

// Parse a captured frame (radiotap header + 802.11 frame) and return the
// transmitter MAC together with the antenna-signal RSSI (dBm). nullopt if the
// frame cannot be parsed or has no signal field.
[[nodiscard]] std::optional<std::pair<Mac, int8_t>>
extract_80211_src_mac_and_rssi(std::span<const uint8_t> data);

// Map a WiFi frequency (MHz) to a channel number for 2.4 / 5 GHz bands.
[[nodiscard]] std::optional<uint8_t> freq_to_channel(uint32_t freq);

// True if the target MAC is the parsed source, or appears verbatim in the bytes.
[[nodiscard]] bool packet_contains_mac(std::span<const uint8_t> data, const Mac& target);

} // namespace pf
