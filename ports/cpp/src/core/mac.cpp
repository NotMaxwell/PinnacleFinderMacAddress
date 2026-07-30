#include "mac.hpp"

#include <cctype>
#include <format>

namespace pf {

static bool is_hex(char c) {
    return std::isxdigit(static_cast<unsigned char>(c)) != 0;
}

std::optional<Mac> parse_mac(std::string_view s) {
    Mac out{};
    size_t part = 0;
    size_t i = 0;
    while (part < 6) {
        if (i + 1 >= s.size())
            return std::nullopt;
        char a = s[i];
        char b = s[i + 1];
        if (!is_hex(a) || !is_hex(b))
            return std::nullopt;

        auto val = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return c - 'A' + 10;
        };
        out[part] = static_cast<uint8_t>(val(a) * 16 + val(b));
        i += 2;
        ++part;

        if (part < 6) {
            if (i >= s.size() || s[i] != ':')
                return std::nullopt;
            ++i;
        }
    }
    if (i != s.size())
        return std::nullopt;
    return out;
}

std::string format_mac_bytes(const Mac& mac) {
    return std::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", mac[0], mac[1],
                       mac[2], mac[3], mac[4], mac[5]);
}

std::string format_mac_from_hex(std::string_view raw) {
    std::string hex;
    for (char c : raw) {
        if (is_hex(c)) {
            hex.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
            if (hex.size() == 12)
                break;
        }
    }
    std::string out;
    for (size_t i = 0; i < hex.size(); i += 2) {
        if (i > 0)
            out.push_back(':');
        out.push_back(hex[i]);
        if (i + 1 < hex.size())
            out.push_back(hex[i + 1]);
    }
    return out;
}

} // namespace pf
