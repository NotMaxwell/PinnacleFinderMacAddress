//! Radiotap + 802.11 frame parsing.
//! Port of `extract_80211_src_mac_and_rssi`, `freq_to_channel`, `packet_contains_mac`.
const std = @import("std");
const mac = @import("mac.zig");
pub const Mac = mac.Mac;

pub const SrcRssi = struct { mac: Mac, rssi: i8 };

fn le16(p: []const u8, i: usize) u16 {
    return @as(u16, p[i]) | (@as(u16, p[i + 1]) << 8);
}
fn le32(p: []const u8, i: usize) u32 {
    return @as(u32, p[i]) | (@as(u32, p[i + 1]) << 8) |
        (@as(u32, p[i + 2]) << 16) | (@as(u32, p[i + 3]) << 24);
}

/// Map a WiFi frequency (MHz) to a channel number.
pub fn freqToChannel(freq: u32) ?u8 {
    if (freq >= 2412 and freq <= 2484) {
        return @intCast(@divTrunc(@as(i32, @intCast(freq)) - 2407, 5));
    }
    if (freq >= 5000 and freq <= 6000) {
        return @intCast(@divTrunc(@as(i32, @intCast(freq)) - 5000, 5));
    }
    return null;
}

const FieldSpec = struct { size: usize, alignv: usize };

fn fieldSpec(index: usize) ?FieldSpec {
    return switch (index) {
        0 => .{ .size = 8, .alignv = 8 }, // TSFT
        1 => .{ .size = 1, .alignv = 1 }, // Flags
        2 => .{ .size = 1, .alignv = 1 }, // Rate
        3 => .{ .size = 4, .alignv = 2 }, // Channel
        4 => .{ .size = 2, .alignv = 2 }, // FHSS
        5 => .{ .size = 1, .alignv = 1 }, // Antenna signal (RSSI)
        6 => .{ .size = 1, .alignv = 1 }, // Antenna noise
        7 => .{ .size = 2, .alignv = 2 }, // Lock quality
        8 => .{ .size = 2, .alignv = 2 }, // TX power
        9 => .{ .size = 1, .alignv = 1 }, // Antenna
        10 => .{ .size = 1, .alignv = 1 }, // DB antenna signal
        11 => .{ .size = 1, .alignv = 1 }, // DB antenna noise
        12 => .{ .size = 2, .alignv = 2 }, // RX flags
        13 => .{ .size = 2, .alignv = 2 }, // TX flags
        14 => .{ .size = 1, .alignv = 1 }, // RTS retries
        15 => .{ .size = 1, .alignv = 1 }, // Data retries
        else => null,
    };
}

/// Parse a captured frame into (transmitter MAC, RSSI). Null if unparseable.
pub fn extract80211SrcMacAndRssi(data: []const u8) ?SrcRssi {
    if (data.len < 8) return null;
    if (data[0] != 0) return null; // radiotap version

    const radiotap_len: usize = le16(data, 2);
    if (radiotap_len < 8 or radiotap_len > data.len) return null;

    // Collect present bitmaps (chained via bit 31).
    var present_maps: [16]u32 = undefined;
    var map_count: usize = 0;
    var present_offset: usize = 4;
    while (true) {
        if (present_offset + 4 > data.len) return null;
        const word = le32(data, present_offset);
        if (map_count < present_maps.len) {
            present_maps[map_count] = word;
            map_count += 1;
        }
        present_offset += 4;
        if ((word & (@as(u32, 1) << 31)) == 0) break;
    }

    var offset: usize = present_offset;
    var rssi_opt: ?i8 = null;

    var map_idx: usize = 0;
    while (map_idx < map_count) : (map_idx += 1) {
        const present = present_maps[map_idx];
        var bit: usize = 0;
        while (bit < 32) : (bit += 1) {
            if ((present & (@as(u32, 1) << @intCast(bit))) == 0) continue;
            const field_index = map_idx * 32 + bit;
            const spec = fieldSpec(field_index) orelse continue;

            const aligned = if (spec.alignv > 1)
                (offset + (spec.alignv - 1)) & ~(spec.alignv - 1)
            else
                offset;

            if (aligned + spec.size > radiotap_len or aligned + spec.size > data.len)
                return null;

            if (field_index == 5)
                rssi_opt = @bitCast(data[aligned]);

            offset = aligned + spec.size;
        }
    }

    const rssi = rssi_opt orelse return null;

    // 802.11 frame header follows the radiotap header.
    const hdr = data[radiotap_len..];
    if (hdr.len < 24) return null;

    const frame_control = le16(hdr, 0);
    const frame_type = (frame_control >> 2) & 0x3;
    if (frame_type == 1) return null; // control frame

    const to_ds = (frame_control & 0x0100) != 0;
    const from_ds = (frame_control & 0x0200) != 0;

    const min_len: usize = if (to_ds and from_ds) 30 else 24;
    if (hdr.len < min_len) return null;

    const base: usize = if (to_ds and from_ds)
        24 // WDS: addr4
    else if (to_ds)
        10 // STA->AP: addr2
    else if (from_ds)
        16 // AP->STA: addr3
    else
        10; // ad-hoc/mgmt: addr2

    var src: Mac = undefined;
    @memcpy(&src, hdr[base..][0..6]);
    return SrcRssi{ .mac = src, .rssi = rssi };
}

/// True if `target` is the parsed source, or appears verbatim in the raw bytes.
pub fn packetContainsMac(data: []const u8, target: Mac) bool {
    if (extract80211SrcMacAndRssi(data)) |sr| {
        if (std.mem.eql(u8, &sr.mac, &target)) return true;
    }
    if (data.len < 6) return false;
    var i: usize = 0;
    while (i + 6 <= data.len) : (i += 1) {
        if (std.mem.eql(u8, data[i..][0..6], &target)) return true;
    }
    return false;
}

test "freqToChannel" {
    try std.testing.expectEqual(@as(?u8, 1), freqToChannel(2412));
    try std.testing.expectEqual(@as(?u8, 6), freqToChannel(2437));
    try std.testing.expectEqual(@as(?u8, 11), freqToChannel(2462));
    try std.testing.expectEqual(@as(?u8, 36), freqToChannel(5180));
    try std.testing.expectEqual(@as(?u8, null), freqToChannel(1000));
}

test "extract RSSI + source MAC from a synthetic frame" {
    const target = Mac{ 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 };
    var f = [_]u8{0} ** (9 + 24);
    f[0] = 0; // version
    f[2] = 9; // radiotap length (LE) = 9
    f[4] = 0x20; // present bitmap: bit 5 (antenna signal)
    f[8] = 0xD6; // rssi 0xD6 -> -42
    // 802.11 header at offset 9; addr2 at hdr[10..16]
    var k: usize = 0;
    while (k < 6) : (k += 1) f[9 + 10 + k] = target[k];

    const r = extract80211SrcMacAndRssi(&f).?;
    try std.testing.expectEqual(target, r.mac);
    try std.testing.expectEqual(@as(i8, -42), r.rssi);
    try std.testing.expect(packetContainsMac(&f, target));

    const other = Mac{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    try std.testing.expect(!packetContainsMac(&f, other));
    try std.testing.expect(extract80211SrcMacAndRssi(f[0..4]) == null);
}
