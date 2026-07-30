//! Monotonic clock + sleep via `std.Io` (Zig 0.16). No libc.
//! The 0.16 std moved timing behind the `Io` interface; we pass in the process's
//! `Io` (a `std.Io.Threaded` instance created in `main`).
const std = @import("std");

/// Milliseconds from the monotonic (`.awake`) clock.
pub fn nowMs(io: std.Io) i64 {
    return std.Io.Timestamp.now(io, .awake).toMilliseconds();
}

/// Sleep for `ms` milliseconds.
pub fn sleepMs(io: std.Io, ms: u32) void {
    const dur: std.Io.Duration = .{ .nanoseconds = @as(i96, ms) * std.time.ns_per_ms };
    std.Io.sleep(io, dur, .awake) catch {};
}
