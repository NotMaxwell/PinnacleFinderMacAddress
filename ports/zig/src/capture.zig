//! libpcap capture: device list, background scan thread, auto channel select.
const std = @import("std");
const mac = @import("mac.zig");
const radiotap = @import("radiotap.zig");
const sysiface = @import("sysiface.zig");
const clock = @import("clock.zig");

pub const Mac = mac.Mac;

const c = @cImport({
    @cInclude("pcap/pcap.h");
});

/// Tiny spinlock: std.Thread.Mutex was relocated by the 0.16 std.Io overhaul,
/// and contention here is negligible (10 Hz reader vs. per-packet writer).
const Spin = struct {
    flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    fn lock(self: *Spin) void {
        while (self.flag.swap(true, .acquire)) {}
    }
    fn unlock(self: *Spin) void {
        self.flag.store(false, .release);
    }
};

pub const ScanUpdate = struct {
    total_frames: u64 = 0,
    hits: u64 = 0,
    last_rssi: ?i8 = null,
};

/// Open a capture handle, trying monitor (rfmon) mode first, then promisc.
fn openCapture(iface_z: [:0]const u8, timeout_ms: c_int) ?*c.pcap_t {
    var errbuf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;

    const attempt = struct {
        fn go(name: [:0]const u8, tmo: c_int, rfmon: bool, eb: [*c]u8) ?*c.pcap_t {
            const p = c.pcap_create(name.ptr, eb) orelse return null;
            if (rfmon) _ = c.pcap_set_rfmon(p, 1);
            _ = c.pcap_set_promisc(p, 1);
            _ = c.pcap_set_snaplen(p, 65535);
            _ = c.pcap_set_timeout(p, tmo);
            if (c.pcap_activate(p) < 0) {
                c.pcap_close(p);
                return null;
            }
            return p;
        }
    };

    if (attempt.go(iface_z, timeout_ms, true, &errbuf)) |p| return p;
    if (attempt.go(iface_z, timeout_ms, false, &errbuf)) |p| return p;
    return null;
}

/// List capture-capable interface names. Caller frees each name and the slice.
pub fn listDevices(alloc: std.mem.Allocator) [][]u8 {
    var names: std.ArrayList([]u8) = .empty;
    var errbuf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
    var alldevs: [*c]c.pcap_if_t = undefined;
    if (c.pcap_findalldevs(&alldevs, &errbuf) == 0) {
        var d = alldevs;
        while (d != null) : (d = d.*.next) {
            if (d.*.name) |name| {
                const owned = alloc.dupe(u8, std.mem.span(name)) catch continue;
                names.append(alloc, owned) catch {
                    alloc.free(owned);
                };
            }
        }
        c.pcap_freealldevs(alldevs);
    }
    return names.toOwnedSlice(alloc) catch &[_][]u8{};
}

pub const ScanSession = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
    iface_z: [:0]u8,
    target: Mac,
    stop_flag: std.atomic.Value(bool),
    lock: Spin,
    latest: ScanUpdate,
    thread: ?std.Thread,

    pub fn start(alloc: std.mem.Allocator, io: std.Io, iface: []const u8, target: Mac) !*ScanSession {
        const self = try alloc.create(ScanSession);
        self.* = .{
            .alloc = alloc,
            .io = io,
            .iface_z = try alloc.dupeZ(u8, iface),
            .target = target,
            .stop_flag = std.atomic.Value(bool).init(false),
            .lock = .{},
            .latest = .{},
            .thread = null,
        };
        self.thread = try std.Thread.spawn(.{}, run, .{self});
        return self;
    }

    pub fn snapshot(self: *ScanSession) ScanUpdate {
        self.lock.lock();
        defer self.lock.unlock();
        return self.latest;
    }

    /// Signal the capture thread, join it, and release resources.
    pub fn deinit(self: *ScanSession) void {
        self.stop_flag.store(true, .seq_cst);
        if (self.thread) |t| t.join();
        self.alloc.free(self.iface_z);
        const a = self.alloc;
        a.destroy(self);
    }

    fn publish(self: *ScanSession, u: ScanUpdate) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.latest = u;
    }

    fn run(self: *ScanSession) void {
        const handle = openCapture(self.iface_z, 300) orelse return;
        defer c.pcap_close(handle);

        var u = ScanUpdate{};
        while (!self.stop_flag.load(.seq_cst)) {
            var hdr: [*c]c.struct_pcap_pkthdr = undefined;
            var data: [*c]const u8 = undefined;
            const rc = c.pcap_next_ex(handle, &hdr, &data);
            if (rc == 1) {
                u.total_frames += 1;
                const len: usize = hdr.*.caplen;
                const bytes = data[0..len];
                if (radiotap.extract80211SrcMacAndRssi(bytes)) |sr| {
                    if (std.mem.eql(u8, &sr.mac, &self.target)) {
                        u.last_rssi = sr.rssi;
                        u.hits += 1;
                    }
                } else if (len >= 6 and radiotap.packetContainsMac(bytes, self.target)) {
                    u.hits += 1;
                }
                self.publish(u);
            } else if (rc == 0) {
                clock.sleepMs(self.io, 5); // idle backoff
            } else {
                break; // error / EOF
            }
        }
        self.publish(u);
    }
};

const candidates = [_]u8{ 1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161 };

fn channelSweepDetect(alloc: std.mem.Allocator, io: std.Io, iface_z: [:0]const u8, iface: []const u8, target: Mac) ?u8 {
    var best_ch: ?u8 = null;
    var best_hits: u64 = 0;
    var err_buf: [256]u8 = undefined;

    for (candidates) |ch| {
        if (sysiface.setChannelSystem(alloc, io, iface, ch, &err_buf) != null) continue;
        clock.sleepMs(io, 250);

        const handle = openCapture(iface_z, 400) orelse continue;
        defer c.pcap_close(handle);

        var local_hits: u64 = 0;
        var packets: u32 = 0;
        const deadline = clock.nowMs(io) + 450;
        while (packets < 200 and clock.nowMs(io) < deadline) {
            var hdr: [*c]c.struct_pcap_pkthdr = undefined;
            var data: [*c]const u8 = undefined;
            const rc = c.pcap_next_ex(handle, &hdr, &data);
            if (rc == 1) {
                packets += 1;
                const bytes = data[0..hdr.*.caplen];
                if (radiotap.packetContainsMac(bytes, target)) {
                    local_hits += 1;
                    if (local_hits > best_hits) {
                        best_hits = local_hits;
                        best_ch = ch;
                    }
                }
            } else break;
        }
    }
    return best_ch;
}

/// Lock onto the target's channel via a system scan or a channel sweep.
/// Returns the channel, or null. On error, writes to `err_buf` and returns null.
pub fn autoSelectChannel(
    alloc: std.mem.Allocator,
    io: std.Io,
    iface: []const u8,
    target: Mac,
    err_buf: *[256]u8,
    had_error: *bool,
) ?u8 {
    had_error.* = false;
    const iface_z = alloc.dupeZ(u8, iface) catch {
        had_error.* = true;
        _ = std.fmt.bufPrint(err_buf, "out of memory", .{}) catch {};
        return null;
    };
    defer alloc.free(iface_z);

    var tbuf: [17]u8 = undefined;
    const target_s = mac.formatMacBytes(target, &tbuf);
    var lower: [17]u8 = undefined;
    for (target_s, 0..) |ch, i| lower[i] = std.ascii.toLower(ch);
    const target_lower = lower[0..target_s.len];

    // Fast path: a system scan already listing the target's BSSID/channel.
    if (sysiface.scanSystemChannels(alloc, io, iface)) |rows| {
        defer alloc.free(rows);
        for (rows) |row| {
            var bbuf: [18]u8 = undefined;
            const b = row.bssid[0..row.bssid_len];
            for (b, 0..) |ch, i| bbuf[i] = std.ascii.toLower(ch);
            if (std.mem.eql(u8, bbuf[0..row.bssid_len], target_lower)) {
                if (sysiface.setChannelSystem(alloc, io, iface, row.channel, err_buf)) |_| {
                    had_error.* = true;
                    return null;
                }
                return row.channel;
            }
        }
    }

    // Fallback: sweep candidate channels.
    if (channelSweepDetect(alloc, io, iface_z, iface, target)) |ch| {
        if (sysiface.setChannelSystem(alloc, io, iface, ch, err_buf)) |_| {
            had_error.* = true;
            return null;
        }
        return ch;
    }
    return null;
}
