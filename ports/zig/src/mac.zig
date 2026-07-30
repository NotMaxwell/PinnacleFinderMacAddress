//! MAC address parsing / formatting.
//! Port of `parse_mac`, `format_mac_bytes` and `format_mac_from_hex`.
const std = @import("std");

pub const Mac = [6]u8;

fn hexVal(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// Parse "AA:BB:CC:DD:EE:FF" into 6 bytes; null on any malformed input.
pub fn parseMac(s: []const u8) ?Mac {
    var out: Mac = undefined;
    var i: usize = 0;
    var part: usize = 0;
    while (part < 6) : (part += 1) {
        if (i + 1 >= s.len) return null;
        const hi = hexVal(s[i]) orelse return null;
        const lo = hexVal(s[i + 1]) orelse return null;
        out[part] = hi * 16 + lo;
        i += 2;
        if (part != 5) {
            if (i >= s.len or s[i] != ':') return null;
            i += 1;
        }
    }
    if (i != s.len) return null; // reject trailing garbage
    return out;
}

const HEX = "0123456789ABCDEF";

/// Format 6 bytes as "AA:BB:CC:DD:EE:FF" into `buf`, returning the used slice.
pub fn formatMacBytes(mac: Mac, buf: *[17]u8) []const u8 {
    var j: usize = 0;
    for (mac, 0..) |byte, idx| {
        if (idx > 0) {
            buf[j] = ':';
            j += 1;
        }
        buf[j] = HEX[byte >> 4];
        buf[j + 1] = HEX[byte & 0x0F];
        j += 2;
    }
    return buf[0..j];
}

/// Keep only hex digits (max 12), uppercase, regroup into colon-separated pairs.
pub fn formatMacFromHex(raw: []const u8, buf: *[17]u8) []const u8 {
    var hex: [12]u8 = undefined;
    var n: usize = 0;
    for (raw) |c| {
        if (std.ascii.isHex(c)) {
            hex[n] = std.ascii.toUpper(c);
            n += 1;
            if (n == 12) break;
        }
    }
    var j: usize = 0;
    var i: usize = 0;
    while (i < n) : (i += 2) {
        if (i > 0) {
            buf[j] = ':';
            j += 1;
        }
        buf[j] = hex[i];
        j += 1;
        if (i + 1 < n) {
            buf[j] = hex[i + 1];
            j += 1;
        }
    }
    return buf[0..j];
}

test "parseMac accepts well-formed addresses" {
    const m = parseMac("AA:BB:CC:DD:EE:FF").?;
    try std.testing.expectEqual(@as(u8, 0xAA), m[0]);
    try std.testing.expectEqual(@as(u8, 0xFF), m[5]);
    try std.testing.expect(parseMac("aa:bb:cc:dd:ee:ff") != null);
}

test "parseMac rejects malformed addresses" {
    try std.testing.expect(parseMac("AA:BB:CC:DD:EE") == null);
    try std.testing.expect(parseMac("AA:BB:CC:DD:EE:FF:00") == null);
    try std.testing.expect(parseMac("GG:BB:CC:DD:EE:FF") == null);
    try std.testing.expect(parseMac("AABBCCDDEEFF") == null);
}

test "formatMacBytes / formatMacFromHex" {
    var buf: [17]u8 = undefined;
    const bytes = Mac{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB };
    try std.testing.expectEqualStrings("01:23:45:67:89:AB", formatMacBytes(bytes, &buf));
    try std.testing.expectEqualStrings("01:23:45:67:89:AB", formatMacFromHex("0123456789ab", &buf));
    try std.testing.expectEqualStrings("AA:BB:CC", formatMacFromHex("aa-bb-cc", &buf));
    try std.testing.expectEqualStrings("01:23:45:67:89:AB", formatMacFromHex("0123456789abCDEF99", &buf));
}
