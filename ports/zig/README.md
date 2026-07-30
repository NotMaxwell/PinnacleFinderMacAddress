# PinnacleFinder — Zig port

A Zig 0.16 terminal-UI (ncurses) port of the original Rust `src/main.rs` egui
app: sniff 802.11 frames with libpcap, hunt for a target MAC, and show a live
signal-strength meter with auto channel selection and monitor-mode management.

## Layout

```
src/mac.zig        MAC parse / format          (has `test` blocks)
src/radiotap.zig   radiotap + 802.11 decoding  (has `test` blocks)
src/sysiface.zig   iw / iwconfig / iwlist / ip via std.process.run
src/capture.zig    libpcap device list, background scan thread, auto channel
src/clock.zig      monotonic clock + sleep via std.Io
src/gui.zig        ncurses front-end
src/main.zig       entry point — builds std.Io.Threaded instance
```

## Dependencies

- **libpcap** — equivalent of the Rust `pcap` crate (used via `@cImport`).
- **ncursesw** — equivalent of `eframe`/`egui`, in a TUI (used via `@cImport`).
- **Zig 0.16** — compiler + build system + package manager (all-in-one).

All subprocess and timing logic uses **Zig std** (`std.process.run` + `std.Io`),
not libc. Only the libpcap and ncurses C libraries are wrapped via `@cImport`.

## Build & run

```sh
zig build                     # -> zig-out/bin/pinnaclefinder (ReleaseSafe)
zig build test                # headless core tests (mac + radiotap)
zig build -Doptimize=ReleaseSmall
sudo ./zig-out/bin/pinnaclefinder
```

`sudo` (or `CAP_NET_RAW`) is required for packet capture and monitor mode.

## Toolchain notes (bleeding-edge host: GCC 16 + glibc 2.43 + Zig 0.16)

- The build uses the **system linker** (`.use_lld = false`). Zig's bundled LLD
  cannot relocate GCC 16's `.sframe` crt sections, and Zig's bundled glibc stubs
  predate this host's glibc 2.43 (needed by the system ncurses).
- The **default optimize mode is ReleaseSafe.** A `Debug` native build uses
  Zig's self-hosted incremental linker, which also trips on the `.sframe`
  sections; the Release pipeline uses the system linker and works. On an older
  toolchain, `-Doptimize=Debug` is fine.
- **Zig 0.16 std.Io approach:** subprocess (`std.process.run`) and timing
  (`std.Io.Timestamp`) moved behind an `std.Io` handle. This port embraces it —
  builds one `std.Io.Threaded` in `main` and threads it through sysiface/capture.
  This keeps everything in std, but adds binary size (~180 KiB vs 47 KiB with libc
  fork/exec) and signature noise (an extra `io` parameter). See COMPARISON.md.

## Keys

`i` select interface · `e` edit MAC · `a` toggle auto-channel ·
`o` toggle monitor-mode management · `s` start/stop scan · `q` quit
