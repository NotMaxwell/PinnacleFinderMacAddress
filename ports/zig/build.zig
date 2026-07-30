const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Default to ReleaseSafe. Debug native builds use Zig's self-hosted
    // incremental linker, which (on this GCC 16 host) cannot relocate the
    // crt objects' .sframe sections; Release modes use the system linker.
    const optimize = b.option(std.builtin.OptimizeMode, "optimize", "Optimization mode") orelse .ReleaseSafe;

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    exe_mod.linkSystemLibrary("pcap", .{});
    exe_mod.linkSystemLibrary("ncursesw", .{});

    const exe = b.addExecutable(.{
        .name = "pinnaclefinder",
        .root_module = exe_mod,
        // Use the system linker rather than Zig's bundled LLD. On this host
        // (GCC 16 + glibc 2.43) LLD chokes on the crt objects' .sframe sections,
        // and the system libncursesw needs very new glibc symbols that Zig's
        // bundled glibc stubs do not provide. The system ld handles both.
        .use_lld = false,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Build and run the TUI");
    run_step.dependOn(&run_cmd.step);

    // Headless unit tests for the pure core (mac + radiotap).
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/radiotap.zig"),
        .target = target,
        .optimize = optimize,
    });
    const unit_tests = b.addTest(.{ .root_module = test_mod, .use_lld = false });
    const run_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
