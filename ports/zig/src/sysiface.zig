//! Platform networking tools (iw / iwconfig / iwlist / ip), driven entirely
//! through `std` — `std.process.Child.run` for subprocesses. No libc calls.
//!
//! There is no `commandExists` helper anymore: `Child.run` returns
//! `error.FileNotFound` when a tool is missing, so we simply try a command and
//! fall back to the next one, which is both simpler and more std-idiomatic.
const std = @import("std");
const builtin = @import("builtin");
const radiotap = @import("radiotap.zig");

const RunResult = struct { code: u8, stdout: []u8 };

/// Run a command and capture stdout. Returns null if the command could not be
/// spawned (e.g. not installed); otherwise the caller owns `stdout`.
fn runCommand(gpa: std.mem.Allocator, io: std.Io, argv: []const []const u8) ?RunResult {
    const res = std.process.run(gpa, io, .{ .argv = argv }) catch return null;
    gpa.free(res.stderr);
    const code: u8 = switch (res.term) {
        .exited => |c| c,
        else => 255,
    };
    return .{ .code = code, .stdout = res.stdout };
}

/// Run one step of a multi-command sequence. Returns null on success or an error
/// message (written into `err_buf`) on failure / missing tool.
fn runStep(
    gpa: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    err_buf: *[256]u8,
    label: []const u8,
) ?[]const u8 {
    if (runCommand(gpa, io, argv)) |r| {
        defer gpa.free(r.stdout);
        if (r.code != 0)
            return std.fmt.bufPrint(err_buf, "{s} failed (status {d})", .{ label, r.code }) catch label;
        return null;
    }
    return std.fmt.bufPrint(err_buf, "{s} not found", .{label}) catch label;
}

/// Set the wireless channel. Returns null on success, or an error message.
pub fn setChannelSystem(
    gpa: std.mem.Allocator,
    io: std.Io,
    iface: []const u8,
    channel: u8,
    err_buf: *[256]u8,
) ?[]const u8 {
    var chbuf: [4]u8 = undefined;
    const ch = std.fmt.bufPrint(&chbuf, "{d}", .{channel}) catch "0";

    if (runCommand(gpa, io, &.{ "iw", "dev", iface, "set", "channel", ch })) |r| {
        defer gpa.free(r.stdout);
        if (r.code != 0)
            return std.fmt.bufPrint(err_buf, "iw returned status {d}", .{r.code}) catch "iw error";
        return null;
    }
    if (runCommand(gpa, io, &.{ "iwconfig", iface, "channel", ch })) |r| {
        defer gpa.free(r.stdout);
        if (r.code != 0)
            return std.fmt.bufPrint(err_buf, "iwconfig returned status {d}", .{r.code}) catch "iwconfig error";
        return null;
    }
    return std.fmt.bufPrint(err_buf, "no supported tool found to set channel (need iw or iwconfig)", .{}) catch "no tool";
}

pub const Row = struct { bssid: [18]u8, bssid_len: usize, channel: u8 };

/// Scan for nearby APs, returning (BSSID, channel) rows. Caller frees the slice.
pub fn scanSystemChannels(gpa: std.mem.Allocator, io: std.Io, iface: []const u8) ?[]Row {
    var rows: std.ArrayList(Row) = .empty;
    defer rows.deinit(gpa);

    if (runCommand(gpa, io, &.{ "iw", "dev", iface, "scan" })) |r| {
        defer gpa.free(r.stdout);
        if (r.code == 0) {
            var cur: ?[]const u8 = null;
            var lines = std.mem.splitScalar(u8, r.stdout, '\n');
            while (lines.next()) |line| {
                const trimmed = std.mem.trimStart(u8, line, " \t");
                if (std.mem.startsWith(u8, trimmed, "BSS ")) {
                    var toks = std.mem.tokenizeAny(u8, trimmed, " \t");
                    _ = toks.next(); // "BSS"
                    if (toks.next()) |b| {
                        const paren = std.mem.indexOfScalar(u8, b, '(') orelse b.len;
                        cur = b[0..paren];
                    }
                }
                if (cur != null and std.mem.startsWith(u8, trimmed, "freq:")) {
                    var toks = std.mem.tokenizeAny(u8, trimmed, " \t");
                    _ = toks.next(); // "freq:"
                    if (toks.next()) |fs| {
                        if (std.fmt.parseInt(u32, fs, 10) catch null) |freq| {
                            if (radiotap.freqToChannel(freq)) |ch| appendRow(gpa, &rows, cur.?, ch);
                        }
                    }
                    cur = null;
                }
            }
        }
    }

    if (rows.items.len == 0) {
        if (runCommand(gpa, io, &.{ "iwlist", iface, "scanning" })) |r| {
            defer gpa.free(r.stdout);
            if (r.code == 0) {
                var cur: ?[]const u8 = null;
                var lines = std.mem.splitScalar(u8, r.stdout, '\n');
                while (lines.next()) |line| {
                    const t = std.mem.trim(u8, line, " \t\r");
                    if (std.mem.startsWith(u8, t, "Cell ")) {
                        if (std.mem.indexOf(u8, t, "Address:")) |idx| {
                            cur = std.mem.trim(u8, t[idx + 8 ..], " \t");
                        }
                    }
                    if (cur != null and std.mem.startsWith(u8, t, "Channel:")) {
                        if (std.mem.indexOfScalar(u8, t, ':')) |colon| {
                            const chs = std.mem.trim(u8, t[colon + 1 ..], " \t");
                            if (std.fmt.parseInt(u8, chs, 10) catch null) |ch|
                                appendRow(gpa, &rows, cur.?, ch);
                        }
                        cur = null;
                    }
                }
            }
        }
    }

    if (rows.items.len == 0) return null;
    return rows.toOwnedSlice(gpa) catch null;
}

fn appendRow(gpa: std.mem.Allocator, rows: *std.ArrayList(Row), bssid: []const u8, channel: u8) void {
    var row = Row{ .bssid = undefined, .bssid_len = 0, .channel = channel };
    const n = @min(bssid.len, row.bssid.len);
    @memcpy(row.bssid[0..n], bssid[0..n]);
    row.bssid_len = n;
    rows.append(gpa, row) catch {};
}

fn setIfaceType(
    gpa: std.mem.Allocator,
    io: std.Io,
    iface: []const u8,
    kind: []const u8,
    err_buf: *[256]u8,
) ?[]const u8 {
    if (builtin.os.tag != .linux)
        return std.fmt.bufPrint(err_buf, "monitor-mode management only implemented on Linux", .{}) catch "unsupported";

    if (runStep(gpa, io, &.{ "ip", "link", "set", iface, "down" }, err_buf, "ip down")) |e| return e;
    if (runStep(gpa, io, &.{ "iw", "dev", iface, "set", "type", kind }, err_buf, "iw set type")) |e| return e;
    if (runStep(gpa, io, &.{ "ip", "link", "set", iface, "up" }, err_buf, "ip up")) |e| return e;
    return null;
}

pub fn enableMonitorMode(gpa: std.mem.Allocator, io: std.Io, iface: []const u8, err_buf: *[256]u8) ?[]const u8 {
    return setIfaceType(gpa, io, iface, "monitor", err_buf);
}
pub fn disableMonitorMode(gpa: std.mem.Allocator, io: std.Io, iface: []const u8, err_buf: *[256]u8) ?[]const u8 {
    return setIfaceType(gpa, io, iface, "managed", err_buf);
}
