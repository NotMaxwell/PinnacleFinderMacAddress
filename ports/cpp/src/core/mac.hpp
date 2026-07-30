#pragma once
// MAC address parsing / formatting helpers (C++23).
// Port of `parse_mac`, `format_mac_bytes` and `format_mac_from_hex`.

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace pf {

using Mac = std::array<uint8_t, 6>;

// Parse "AA:BB:CC:DD:EE:FF" into 6 bytes. nullopt on any malformed input.
[[nodiscard]] std::optional<Mac> parse_mac(std::string_view s);

// Format 6 bytes as uppercase colon-separated hex ("AA:BB:CC:DD:EE:FF").
[[nodiscard]] std::string format_mac_bytes(const Mac& mac);

// Keep only hex digits (max 12), uppercase, regroup into colon-separated pairs.
[[nodiscard]] std::string format_mac_from_hex(std::string_view raw);

} // namespace pf
