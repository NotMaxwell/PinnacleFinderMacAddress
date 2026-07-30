#pragma once
// Interaction with platform networking tools (iw / iwconfig / iwlist / ip,
// and airport on macOS). C++23: errors reported via std::expected.

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace pf {

// True if `cmd` is found in PATH (results cached, like the Rust version).
[[nodiscard]] bool command_exists(std::string_view cmd);

// Set the wireless channel via the platform-appropriate tool.
[[nodiscard]] std::expected<void, std::string> set_channel_system(std::string_view iface,
                                                                  uint8_t channel);

// Scan for nearby APs, returning (BSSID, channel) pairs, or nullopt on failure.
[[nodiscard]] std::optional<std::vector<std::pair<std::string, uint8_t>>>
scan_system_channels(std::string_view iface);

// Enable / disable monitor mode (Linux only).
[[nodiscard]] std::expected<void, std::string> enable_monitor_mode(std::string_view iface);
[[nodiscard]] std::expected<void, std::string> disable_monitor_mode(std::string_view iface);

} // namespace pf
