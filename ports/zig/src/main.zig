//! PinnacleFinder MAC Hunter — Zig/ncurses port entry point.
const std = @import("std");
const gui = @import("gui.zig");

pub fn main() void {
    // A single std.Io instance (threaded backend) drives all subprocess and
    // timing calls via std, so the port avoids libc except for the pcap/ncurses
    // C libraries it wraps.
    const gpa = std.heap.smp_allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    gui.runTui(gpa, threaded.io());
}
