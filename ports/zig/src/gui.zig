//! ncurses front-end. Terminal-UI equivalent of the original egui GUI.
const std = @import("std");
const mac = @import("mac.zig");
const capture = @import("capture.zig");
const sysiface = @import("sysiface.zig");
const clock = @import("clock.zig");
const builtin = @import("builtin");

const nc = @cImport({
    @cInclude("ncurses.h");
});

// ncurses attribute / key constants. translate-c cannot render ncurses'
// function-like macros, so we spell out the stable bit layout ourselves.
const A_BOLD: c_uint = 0x00200000;
const A_UNDERLINE: c_uint = 0x00020000;
const A_REVERSE: c_uint = 0x00040000;
fn colorPair(n: c_uint) c_uint {
    return (n << 8) & 0xff00;
}
const KEY_UP: c_int = 0o403;
const KEY_DOWN: c_int = 0o402;
const KEY_ENTER: c_int = 0o527;
const KEY_BACKSPACE: c_int = 0o407;
const ESC: c_int = 27;

const COLOR_RED: c_short = 1;
const COLOR_GREEN: c_short = 2;
const COLOR_YELLOW: c_short = 3;
const COLOR_WHITE: c_short = 7;

const CP_GOLD: c_uint = 1;
const CP_GREEN: c_uint = 2;
const CP_YELLOW: c_uint = 3;
const CP_RED: c_uint = 4;
const CP_DIM: c_uint = 5;

const Mode = enum { normal, iface_select, mac_edit };

fn on(attr: c_uint) void {
    _ = nc.attron(@intCast(attr));
}
fn off(attr: c_uint) void {
    _ = nc.attroff(@intCast(attr));
}
fn rssiToStrength(rssi: f32) f32 {
    const mn: f32 = -100.0;
    const mx: f32 = -30.0;
    return std.math.clamp((rssi - mn) / (mx - mn), 0.0, 1.0);
}
fn strengthColor(s: f32) c_uint {
    if (s > 0.66) return CP_GREEN;
    if (s > 0.33) return CP_YELLOW;
    return CP_RED;
}
fn monitorSupported() bool {
    return builtin.os.tag == .linux;
}

const App = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
    interfaces: [][]u8,
    selected_iface: ?usize = null,
    iface_cursor: usize = 0,

    mac_input: [17]u8 = undefined,
    mac_len: usize = 0,
    mac_valid: bool = false,

    last_rssi: ?i8 = null,
    smoothed: ?f32 = null,

    auto_channel_enabled: bool = true,
    manage_monitor: bool = false,
    monitor_managed_by_app: bool = false,

    scanning: bool = false,
    total_frames: u64 = 0,
    hits: u64 = 0,
    start_ms: ?i64 = null,

    auto_channel: ?u8 = null,
    note: [256]u8 = undefined,
    note_len: usize = 0,
    has_note: bool = false,
    err: [256]u8 = undefined,
    err_len: usize = 0,
    has_err: bool = false,

    session: ?*capture.ScanSession = null,
    mode: Mode = .normal,

    fn macSlice(self: *App) []const u8 {
        return self.mac_input[0..self.mac_len];
    }
    fn setMac(self: *App, s: []const u8) void {
        const n = @min(s.len, self.mac_input.len);
        @memcpy(self.mac_input[0..n], s[0..n]);
        self.mac_len = n;
        self.mac_valid = mac.parseMac(self.macSlice()) != null;
    }
    fn setNote(self: *App, s: []const u8) void {
        const n = @min(s.len, self.note.len);
        @memcpy(self.note[0..n], s[0..n]);
        self.note_len = n;
        self.has_note = true;
    }
    fn setErr(self: *App, s: []const u8) void {
        const n = @min(s.len, self.err.len);
        @memcpy(self.err[0..n], s[0..n]);
        self.err_len = n;
        self.has_err = true;
    }
    fn ifaceName(self: *App) ?[]const u8 {
        if (self.selected_iface) |i| {
            if (i < self.interfaces.len) return self.interfaces[i];
        }
        return null;
    }
};

fn pollSession(a: *App) void {
    const sess = a.session orelse return;
    const u = sess.snapshot();
    a.total_frames = u.total_frames;
    a.hits = u.hits;
    a.last_rssi = u.last_rssi;
    if (u.last_rssi) |r| {
        const alpha: f32 = 0.2;
        const rf: f32 = @floatFromInt(r);
        a.smoothed = if (a.smoothed) |prev| prev * (1.0 - alpha) + rf * alpha else rf;
    }
}

fn startScan(a: *App) void {
    a.has_err = false;
    a.total_frames = 0;
    a.hits = 0;
    a.auto_channel = null;
    a.has_note = false;
    a.smoothed = null;
    a.last_rssi = null;

    const iface = a.ifaceName() orelse {
        a.setErr("Select a network interface first.");
        return;
    };
    if (!a.mac_valid) {
        a.setErr("Invalid MAC address format.");
        return;
    }
    const target = mac.parseMac(a.macSlice()) orelse {
        a.setErr("Invalid MAC address format.");
        return;
    };

    var err_buf: [256]u8 = undefined;
    if (a.auto_channel_enabled) {
        var had_error: bool = false;
        const ch = capture.autoSelectChannel(a.alloc, a.io, iface, target, &err_buf, &had_error);
        if (had_error) {
            var b: [300]u8 = undefined;
            a.setNote(std.fmt.bufPrint(&b, "Auto channel failed: {s}", .{err_buf[0..std.mem.indexOfScalar(u8, &err_buf, 0) orelse err_buf.len]}) catch "Auto channel failed");
        } else if (ch) |c| {
            var b: [64]u8 = undefined;
            a.setNote(std.fmt.bufPrint(&b, "Locked channel {d} via auto-test", .{c}) catch "Locked channel");
            a.auto_channel = c;
        } else {
            a.setNote("Auto channel: no signal; staying on current channel");
        }
    } else {
        a.setNote("Auto channel selection disabled");
    }

    if (a.manage_monitor) {
        if (monitorSupported()) {
            if (sysiface.enableMonitorMode(a.alloc, a.io, iface, &err_buf)) |_| {
                var b: [300]u8 = undefined;
                a.setErr(std.fmt.bufPrint(&b, "Failed to enable monitor mode: {s}", .{err_buf[0..std.mem.indexOfScalar(u8, &err_buf, 0) orelse err_buf.len]}) catch "monitor enable failed");
                return;
            }
            a.monitor_managed_by_app = true;
            a.setNote("monitor mode enabled");
        } else {
            a.setNote("Monitor mode management not available on this OS");
        }
    }

    a.session = capture.ScanSession.start(a.alloc, a.io, iface, target) catch {
        a.setErr("Failed to start capture thread.");
        return;
    };
    a.start_ms = clock.nowMs(a.io);
    a.scanning = true;
}

fn stopScan(a: *App) void {
    if (a.session) |sess| {
        sess.deinit();
        a.session = null;
    }
    a.scanning = false;
    if (a.monitor_managed_by_app) {
        if (a.ifaceName()) |iface| {
            var err_buf: [256]u8 = undefined;
            if (sysiface.disableMonitorMode(a.alloc, a.io, iface, &err_buf)) |_| {
                a.setNote("Monitor disable failed");
            } else {
                a.setNote("Monitor mode disabled; interface restored");
            }
        }
        a.monitor_managed_by_app = false;
    }
}

fn line(row: c_int, col: c_int, comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const s = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    _ = nc.mvprintw(row, col, "%s", s.ptr);
}

fn drawSignal(a: *App, row: c_int) void {
    const rssi: f32 = a.smoothed orelse (if (a.last_rssi) |r| @floatFromInt(r) else 0.0);
    const have = a.smoothed != null or a.last_rssi != null;
    const strength = if (have) rssiToStrength(rssi) else 0.0;
    const cpx = strengthColor(strength);

    on(A_BOLD | colorPair(CP_GOLD));
    _ = nc.mvprintw(row, 2, "Signal Strength");
    off(A_BOLD | colorPair(CP_GOLD));

    if (have) line(row, 20, "{d:>6.0} dBm", .{rssi}) else _ = nc.mvprintw(row, 20, "  -- dBm");

    _ = nc.mvaddch(row, 32, '[');
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        const frac = @as(f32, @floatFromInt(i + 1)) / 5.0;
        if (strength >= frac) {
            on(colorPair(cpx));
            _ = nc.addstr("###");
            off(colorPair(cpx));
        } else {
            on(colorPair(CP_DIM));
            _ = nc.addstr("...");
            off(colorPair(CP_DIM));
        }
        _ = nc.addch(' ');
    }
    line(row, 52, "] {d:>3.0}%", .{strength * 100.0});
}

fn draw(a: *App) void {
    _ = nc.erase();
    var row: c_int = 0;

    on(A_BOLD | colorPair(CP_GOLD));
    _ = nc.mvprintw(row, 2, "PinnacleFinder - MAC Hunter (TUI / Zig)");
    off(A_BOLD | colorPair(CP_GOLD));
    row += 2;

    drawSignal(a, row);
    row += 2;

    const iface = a.ifaceName() orelse "<none selected>";
    line(row, 2, "Interface [i]: {s}", .{iface});
    row += 1;

    if (a.mode == .iface_select) {
        _ = nc.mvprintw(row, 4, "-- select interface (Up/Down, Enter, Esc) --");
        row += 1;
        for (a.interfaces, 0..) |name, idx| {
            const cur = idx == a.iface_cursor;
            if (cur) on(A_REVERSE);
            line(row, 6, "{s} {s}", .{ if (cur) ">" else " ", name });
            if (cur) off(A_REVERSE);
            row += 1;
        }
    }

    line(row, 2, "Auto channel [a]: {s}    Manage monitor [o]: {s}{s}", .{
        if (a.auto_channel_enabled) "ON " else "OFF",
        if (a.manage_monitor) "ON " else "OFF",
        if (monitorSupported()) "" else " (unsupported OS)",
    });
    row += 1;

    const editing = a.mode == .mac_edit;
    _ = nc.mvprintw(row, 2, "Target MAC [e]: ");
    if (editing) on(A_UNDERLINE);
    line(row, 18, "{s: <17}", .{a.macSlice()});
    if (editing) off(A_UNDERLINE);
    if (editing) {
        _ = nc.mvprintw(row, 38, "(type hex, Backspace, Enter/Esc)");
    } else if (a.mac_len > 0 and !a.mac_valid) {
        on(colorPair(CP_RED));
        _ = nc.mvprintw(row, 38, "INVALID");
        off(colorPair(CP_RED));
    } else if (a.mac_valid) {
        on(colorPair(CP_GREEN));
        _ = nc.mvprintw(row, 38, "ok");
        off(colorPair(CP_GREEN));
    }
    row += 2;

    on(A_BOLD);
    line(row, 2, "[s] {s}", .{if (a.scanning) "STOP SCAN" else "START SCAN"});
    off(A_BOLD);
    row += 2;

    if (a.has_err) {
        on(colorPair(CP_RED));
        line(row, 2, "Error: {s}", .{a.err[0..a.err_len]});
        off(colorPair(CP_RED));
        row += 1;
    }

    var elapsed: f32 = 0.0;
    if (a.start_ms) |t|
        elapsed = @as(f32, @floatFromInt(clock.nowMs(a.io) - t)) / 1000.0;
    const hit_rate: f32 = if (elapsed > 0.0) @as(f32, @floatFromInt(a.hits)) / elapsed else 0.0;

    on(A_BOLD | colorPair(CP_GOLD));
    _ = nc.mvprintw(row, 2, "Stats");
    off(A_BOLD | colorPair(CP_GOLD));
    row += 1;
    line(row, 4, "Frames seen : {d}", .{a.total_frames});
    row += 1;
    line(row, 4, "Matches     : {d}", .{a.hits});
    row += 1;
    line(row, 4, "Elapsed     : {d:.1} s", .{elapsed});
    row += 1;
    line(row, 4, "Hit rate    : {d:.2} hits/s", .{hit_rate});
    row += 1;
    if (a.auto_channel) |ch| {
        line(row, 4, "Channel     : {d} (auto)", .{ch});
        row += 1;
    }
    if (a.has_note) {
        line(row, 4, "Note        : {s}", .{a.note[0..a.note_len]});
        row += 1;
    }
    line(row, 4, "Interfaces  : {d}", .{a.interfaces.len});
    row += 2;

    on(colorPair(CP_DIM));
    _ = nc.mvprintw(row, 2, "[q] quit  [i] iface  [e] mac  [a] auto  [o] monitor  [s] scan");
    off(colorPair(CP_DIM));

    _ = nc.refresh();
}

fn macEditKey(a: *App, ch: c_int) void {
    var raw: [12]u8 = undefined;
    var n: usize = 0;
    for (a.macSlice()) |cc| {
        if (std.ascii.isHex(cc)) {
            raw[n] = cc;
            n += 1;
        }
    }
    if (ch == KEY_BACKSPACE or ch == 127 or ch == 8) {
        if (n > 0) n -= 1;
    } else if (ch >= 0 and ch < 128 and std.ascii.isHex(@intCast(ch))) {
        if (n < 12) {
            raw[n] = @intCast(ch);
            n += 1;
        }
    }
    var buf: [17]u8 = undefined;
    a.setMac(mac.formatMacFromHex(raw[0..n], &buf));
}

pub fn runTui(alloc: std.mem.Allocator, io: std.Io) void {
    _ = nc.initscr();
    _ = nc.cbreak();
    _ = nc.noecho();
    _ = nc.keypad(nc.stdscr, true);
    _ = nc.curs_set(0);
    nc.timeout(100);

    if (nc.has_colors()) {
        _ = nc.start_color();
        _ = nc.use_default_colors();
        _ = nc.init_pair(@intCast(CP_GOLD), COLOR_YELLOW, -1);
        _ = nc.init_pair(@intCast(CP_GREEN), COLOR_GREEN, -1);
        _ = nc.init_pair(@intCast(CP_YELLOW), COLOR_YELLOW, -1);
        _ = nc.init_pair(@intCast(CP_RED), COLOR_RED, -1);
        _ = nc.init_pair(@intCast(CP_DIM), COLOR_WHITE, -1);
    }

    var a = App{ .alloc = alloc, .io = io, .interfaces = capture.listDevices(alloc) };

    var running = true;
    while (running) {
        pollSession(&a);
        draw(&a);

        const ch = nc.getch();
        if (ch == nc.ERR) continue;

        switch (a.mode) {
            .iface_select => switch (ch) {
                KEY_UP => {
                    if (a.iface_cursor > 0) a.iface_cursor -= 1;
                },
                KEY_DOWN => {
                    if (a.iface_cursor + 1 < a.interfaces.len) a.iface_cursor += 1;
                },
                '\n', KEY_ENTER => {
                    if (a.interfaces.len > 0) a.selected_iface = a.iface_cursor;
                    a.mode = .normal;
                },
                ESC => a.mode = .normal,
                else => {},
            },
            .mac_edit => {
                if (ch == '\n' or ch == KEY_ENTER or ch == ESC) {
                    a.mode = .normal;
                } else {
                    macEditKey(&a, ch);
                }
            },
            .normal => switch (ch) {
                'q', 'Q' => running = false,
                'i', 'I' => {
                    if (a.interfaces.len > 0) {
                        a.iface_cursor = a.selected_iface orelse 0;
                        a.mode = .iface_select;
                    }
                },
                'e', 'E' => a.mode = .mac_edit,
                'a', 'A' => a.auto_channel_enabled = !a.auto_channel_enabled,
                'o', 'O' => {
                    if (monitorSupported()) a.manage_monitor = !a.manage_monitor;
                },
                's', 'S' => {
                    if (a.scanning) stopScan(&a) else startScan(&a);
                },
                else => {},
            },
        }
    }

    if (a.scanning) stopScan(&a);
    _ = nc.endwin();

    for (a.interfaces) |name| alloc.free(name);
    alloc.free(a.interfaces);
}
