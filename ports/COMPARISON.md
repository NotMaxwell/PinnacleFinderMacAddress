# PinnacleFinder — Rust / C++ / Zig comparison

Three implementations of the same **terminal-UI** app: sniff 802.11 frames with
**libpcap**, decode radiotap + 802.11 headers for a transmitter MAC + RSSI, hunt
for a target MAC, drive auto channel selection and monitor-mode management via
`iw`/`iwconfig`/`iwlist`/`ip`, and render a live signal meter.

| | Where | Build | UI | Core error type |
|---|---|---|---|---|
| **Rust** | `../src/` | `cargo` | raw termios + ANSI (`libc`) | `Result<T, String>` |
| **C++23** | `cpp/` | CMake / Make | ncursesw | `std::expected<T, std::string>` |
| **Zig 0.16** | `zig/` | `zig build` | ncursesw | out-param `?[]const u8` + error unions |

Each is split into a UI-free core (`mac` · `radiotap` · `sysiface` · `capture`)
plus a thin UI layer; the pure logic is unit-tested in every language. Making all
three TUIs (the original was an egui **GUI**) removes the biggest
apples-to-oranges axis, so the remaining differences are about the *languages*.

- Rust: `mac.rs`, `radiotap.rs`, `sysiface.rs`, `capture.rs`, `tui.rs`, `main.rs`
  (the original single-file `main.rs` monolith was broken up to match the ports).
- C++: `src/core/{mac,radiotap,sysiface,capture}.*`, `src/tui/app.cpp`, `main.cpp`.
- Zig: `src/{mac,radiotap,sysiface,capture,clock,gui,main}.zig`.

---

## Developer experience: the same task, three ways

The snippets below are lifted (lightly condensed) from the real code so the
comparison is concrete rather than hand-wavy.

### 1. Error propagation — `set_channel_system`

**Rust** — `Result<(), String>`, `?` propagates, `.map_err` adds context:

```rust
pub fn set_channel_system(iface: &str, channel: u8) -> Result<(), String> {
    if command_exists("iw") {
        let output = Command::new("iw")
            .arg("dev").arg(iface).arg("set").arg("channel").arg(channel.to_string())
            .output()
            .map_err(|e| format!("failed to run iw: {e}"))?;
        if !output.status.success() {
            return Err(format!("iw returned status {} ...", output.status));
        }
        return Ok(());
    }
    Err("no supported tool found to set channel ...".into())
}
```

**C++23** — `std::expected<void, std::string>`; `std::unexpected` + `std::format`:

```cpp
std::expected<void, std::string> set_channel_system(std::string_view iface, uint8_t channel) {
    std::string ch = std::to_string(channel), ifs(iface);
    if (command_exists("iw")) {
        auto r = run_command({"iw", "dev", ifs, "set", "channel", ch});
        if (!r.ran)           return std::unexpected("failed to run iw");
        if (r.exit_code != 0) return std::unexpected(std::format("iw returned status {}", r.exit_code));
        return {};
    }
    return std::unexpected("no supported tool found to set channel ...");
}
```

**Zig 0.16** — no allocator in a leaf function, so error text is written into a
caller-supplied buffer and returned as `?[]const u8` (**null = success**). A
missing tool is detected by `std.process.run` returning `error.FileNotFound`, so
there is no separate `commandExists` — just try the next command:

```zig
pub fn setChannelSystem(gpa, io: std.Io, iface, channel: u8, err_buf: *[256]u8) ?[]const u8 {
    var chbuf: [4]u8 = undefined;
    const ch = std.fmt.bufPrint(&chbuf, "{d}", .{channel}) catch "0";
    // runCommand wraps std.process.run; null = couldn't spawn -> fall through to the next tool
    if (runCommand(gpa, io, &.{ "iw", "dev", iface, "set", "channel", ch })) |r| {
        defer gpa.free(r.stdout);
        if (r.code != 0)
            return std.fmt.bufPrint(err_buf, "iw returned status {d}", .{r.code}) catch "iw error";
        return null;
    }
    // ... else try iwconfig, else "no supported tool found" ...
}
```

> **DX takeaway.** Rust and C++ have a first-class fallible-return type that reads
> the same at definition and call site. Zig *has* error unions (`!T`), but they
> can't carry a formatted message without an allocator — so a leaf function ends
> up threading a `*[256]u8` and inverting the convention to "null means ok",
> which is easy to misread. This was the single most annoying Zig pattern here.

### 2. The payoff at the call site — `Result<Option<u8>>`

`auto_select_channel` returns "found a channel / found nothing / failed":

```rust
match auto_select_channel(&iface, &mac) {              // Rust
    Ok(Some(ch)) => { self.auto_channel = Some(ch); /* locked */ }
    Ok(None)     => { /* no signal, stay put */ }
    Err(e)       => { self.channel_note = Some(format!("Auto channel failed: {e}")); }
}
```

```cpp
auto res = auto_select_channel(*iface, *mac);          // C++23: expected<optional<u8>,string>
if (!res)      a.channel_note = "Auto channel failed: " + res.error();
else if (*res) a.auto_channel = *res;                  // locked
else           /* no signal, stay put */;
```

```zig
var had_error = false;                                  // Zig: out-params
const ch = capture.autoSelectChannel(a.alloc, iface, target, &err_buf, &had_error);
if (had_error)   a.setNote(/* err_buf */);
else if (ch) |c| a.auto_channel = c;                    // locked
else             /* no signal, stay put */;
```

Rust's `Result<Option<u8>, String>` collapses three outcomes into one exhaustive
`match`. C++'s `std::expected<std::optional<uint8_t>, std::string>` is a near-exact
transcription. Zig splits the three outcomes across a `bool` out-param, an
optional return, and a shared buffer.

### 3. Background capture thread + shutdown

**Rust** — `mpsc` channel + `Arc<AtomicBool>`; the borrow checker guarantees the
hand-off is race-free:

```rust
let (tx, rx) = mpsc::channel::<ScanUpdate>();
let stop_flag = Arc::new(AtomicBool::new(false));
let stop_clone = stop_flag.clone();
std::thread::spawn(move || capture_loop(iface, mac, tx, stop_clone));
// UI thread: while let Ok(u) = rx.try_recv() { /* update stats */ }
```

**C++23** — `std::jthread` + `std::stop_token`: the destructor requests stop and
joins automatically (RAII shutdown), a real upgrade over C++17's manual flag+join:

```cpp
class ScanSession {
    std::jthread thread_;                                  // dtor: request_stop() + join()
    ScanSession(std::string iface, Mac t)
        : /* ... */, thread_([this](std::stop_token st) { run(st); }) {}
    void run(std::stop_token st) { while (!st.stop_requested()) { /* ... */ } }
    void stop() { thread_.request_stop(); }
};
```

**Zig 0.16** — `std.Thread.spawn` still works, but `std.Thread.Mutex` was moved by
the `std.Io` overhaul, so the snapshot lock is a hand-rolled spinlock:

```zig
const Spin = struct {                                      // Mutex went missing in 0.16
    flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    fn lock(self: *Spin) void { while (self.flag.swap(true, .acquire)) {} }
    fn unlock(self: *Spin) void { self.flag.store(false, .release); }
};
self.thread = try std.Thread.spawn(.{}, run, .{self});
```

### 4. Run a subprocess and capture stdout

**Rust** — one line and you have status + captured output:

```rust
let output = Command::new("iw").arg("dev").arg(iface).arg("scan").output()?;
if output.status.success() { let s = String::from_utf8_lossy(&output.stdout); /* parse */ }
```

**C++** hand-rolls `fork`/`exec`/`pipe` (~40 lines) — there is no subprocess
helper in the standard library. **Zig** *has* one, but in 0.16 it (and all
timing) lives behind the new `std.Io` interface: you build one `Io` up front and
thread it everywhere. The payoff is real std subprocess with zero plumbing:

```zig
// main.zig — one Io for the whole program (a threaded backend)
var threaded = std.Io.Threaded.init(gpa, .{});
defer threaded.deinit();
gui.runTui(gpa, threaded.io());

// sysiface.zig — std subprocess: no libc, no fork/exec/pipe by hand
const res = std.process.run(gpa, io, .{ .argv = argv }) catch return null; // FileNotFound = tool missing
const code: u8 = switch (res.term) { .exited => |c| c, else => 255 };
```

> **DX takeaway.** Rust is a one-liner; C++ writes POSIX plumbing by hand; Zig
> gets a std helper *if* you accept threading an `Io` (and a `gpa`) through nearly
> every signature — and a notable binary-size cost (see Metrics).

### 5. Parsing raw bytes safely

Signatures — Rust `&[u8]`, C++ `std::span<const uint8_t>` (C++23 upgrade from raw
`ptr,len`), Zig `[]const u8`. The signed-RSSI cast reads nicely in all three:

```rust
rssi_opt = Some(data[aligned] as i8);                    // Rust
```
```cpp
if (field_index == 5) rssi_opt = std::bit_cast<int8_t>(data[aligned]);   // C++23
```
```zig
if (field_index == 5) rssi_opt = @bitCast(data[aligned]);                // Zig -> i8
```

### 6. Tests

Rust and Zig ship a **built-in test runner** (`cargo test` = 34 tests; `zig build
test`), with tests inline next to the code:

```rust
#[cfg(test)]
mod tests { use super::*;
    #[test] fn parse_mac_valid_uppercase() {
        assert_eq!(parse_mac("AA:BB:CC:DD:EE:FF"), Some([0xAA,0xBB,0xCC,0xDD,0xEE,0xFF]));
    }
}
```
```zig
test "parseMac accepts well-formed addresses" {
    try std.testing.expectEqual(@as(u8, 0xAA), parseMac("AA:BB:CC:DD:EE:FF").?[0]);
}
```

C++ has **no standard test framework**, so the port carries a separate
`tests/test_core.cpp` harness and an extra build target.

---

## Pain points, per language

### Rust — smoothest DX; friction was environmental
- **No network for crates.io in this sandbox** → couldn't pull `ratatui`/`crossterm`,
  so the TUI is hand-rolled ANSI over a small `unsafe` `libc` termios shim.
- A few `unsafe` FFI blocks for raw-mode setup; everything else was safe and
  mechanical. Disjoint-field borrows let `poll()` mutate stats while holding
  `&self.rx` without a fight. Breaking the monolith into modules was trivial.

### C++23 — clean translation, but rough edges remain
- **No built-in tests or package manager**: separate harness; CMake dependency
  discovery is per-distro fiddly (vcpkg is a bolt-on).
- **`.hpp`/`.cpp` duplication** doubles the file count and keeps signatures in two
  places.
- **C++23 availability + cost**: needs GCC 14+/Clang 18+; `<format>`/`<print>`/
  `<expected>` roughly **doubled** the binary (95 KiB → 207 KiB).
- Safety is still manual: `run_command` must remember to `close()` both pipe ends;
  the radiotap walk is bounds-checked by hand (`std::span` helps, but doesn't
  enforce it). Net: `span`/`expected`/`jthread` made it *much* closer to Rust/Zig.

### Zig 0.16 — most capable C interop, most churn
- **The `std.Io` overhaul is pervasive**: `sleep`, timestamps, and
  `std.process.run` all live behind an `Io` handle. The port embraces it — build
  one `std.Io.Threaded` in `main` and **thread `io` (and `gpa`) through nearly
  every function** (sysiface, capture, gui). It works and keeps the code in std,
  but the signatures get noisy and every call site grows two parameters.
- **Binary-size cost of "use std, not libc"**: pulling in the `std.Io` /
  `std.process.run` async + MultiReader stack roughly **quadrupled** the smallest
  binary (ReleaseSmall 47 → **180 KiB**) and blew up ReleaseFast (84 → **582 KiB**).
  Here, going through std is *much* heavier than the ~50 lines of libc fork/exec
  it replaced — a genuine trade-off, not a free win.
- **`Thread.Mutex` also moved**, so the capture snapshot uses a hand-rolled spinlock.
- **More std churn to chase, each a compile error**: `ArrayList` is now unmanaged
  (`.empty`, allocator per call), `mem.trimLeft`→`trimStart`, `posix.access`/
  `posix.getenv` gone (the last two dodged by dropping `commandExists` in favour of
  the `error.FileNotFound` fallback).
- **No allocator in leaf functions** → the `*[256]u8` error-buffer convention above.
- **`translate-c` can't expand function-like macros** (`COLOR_PAIR`, `A_BOLD`,
  `KEY_UP`) → ncurses constants are re-declared by hand.
- **Bleeding-edge toolchain friction**: GCC 16 `.sframe` crt sections + glibc 2.43
  vs Zig's bundled LLD/glibc stubs → `build.zig` sets `.use_lld = false` and
  defaults to a Release mode (Debug native uses Zig's incremental linker, which
  also trips on `.sframe`).
- **Upside**: `@cImport` on `pcap.h`/`ncurses.h` needs *zero* hand-written bindings;
  the port now uses **std for everything except those two C libraries**; and one
  tool is compiler + build system + package manager + test runner.

### DX scorecard (subjective, this task, this host)

| Aspect | Rust | C++23 | Zig 0.16 |
|---|---|---|---|
| Build & dependencies | cargo — excellent | CMake/Make + vcpkg — ok | zig build — good, but std churn |
| Error handling ergonomics | `Result` — excellent | `expected` — very good | out-param buffers — awkward |
| Concurrency & shutdown | mpsc/`Arc` — excellent | `jthread`/`stop_token` — very good | manual spinlock — ok |
| C library interop | good (crate/FFI) | native — excellent | `@cImport` — excellent (macros ✗) |
| Testing | built-in — excellent | external harness — poor | built-in — excellent |
| Memory safety | excellent | manual (helped by span) | good (runtime checks) |
| Toolchain stability | excellent | very good | poor (0.16 is bleeding edge) |

---

## Balanced pros / cons

### Rust (TUI via termios/ANSI, `cargo`)
**Pros** — safest; `cargo` + inline `#[cfg(test)]` are frictionless; the
`mpsc`/`Arc<AtomicBool>` capture design is idiomatic and race-free; breaking the
monolith into modules was mechanical. **Cons** — larger release binary than the
C++/Zig TUIs; raw-termios/ANSI is more manual than ncurses (no library was
fetchable offline); `libc` `unsafe` blocks for terminal setup.

### C++23 (ncurses, CMake/Make)
**Pros** — direct use of the C libpcap/ncurses APIs; C++23 (`span`/`expected`/
`jthread`) makes the translation clean and closer to Rust/Zig semantics; smallest
of the "safe" builds. **Cons** — no borrow checker; C++23 conveniences noticeably
inflate the binary; CMake dependency discovery is per-distro fiddly without vcpkg;
`.hpp`/`.cpp` duplication.

### Zig 0.16 (ncurses, `zig build`)
**Pros** — `@cImport` needs zero hand-written bindings; one tool is compiler +
build system + package manager + test runner; the port stays in std for
subprocess and timing (`std.process.run` + `std.Io`), touching C only for the
libpcap/ncurses libraries it wraps; `ReleaseSmall` is still the smallest binary.
**Cons** — heavy 0.16 std churn (the `std.Io` overhaul moved
`sleep`/timestamps/`process.run`/`Mutex`; `ArrayList`/`trim*`/`posix.access`/
`getenv` changed) means threading an `Io` everywhere and a **big binary-size cost**
for using std over libc; bleeding-edge toolchain friction (GCC 16 `.sframe` +
glibc 2.43) meant using the system linker and defaulting to a Release build;
`translate-c` can't render ncurses' function-like macros.

### Memory safety (qualitative)

- **Rust** — strongest: ownership/borrow checking; the `mpsc` channel makes the
  capture→UI hand-off provably race-free.
- **Zig** — middle: `Debug`/`ReleaseSafe` insert bounds/overflow checks; explicit
  allocators; no borrow checker.
- **C++23** — improved over C++17 here: `std::span` replaces raw pointer+length in
  the radiotap parser, `std::expected` replaces error out-params, and
  `std::jthread`/`std::stop_token` remove the hand-rolled stop flag and the
  destructor join. Still no borrow checker; the byte walking is bounds-checked by
  hand, as in the original.

---

## What "latest C++" bought (C++17 → C++23)

| Feature | Used for | Replaces |
|---|---|---|
| `std::span<const uint8_t>` | every frame-parsing signature | raw `(ptr, len)` — now bounds-aware, like Zig slices |
| `std::expected<T, std::string>` | `set_channel`, monitor mode, `auto_select_channel` | `optional<string>`-as-error / out-params — mirrors Rust `Result` |
| `std::jthread` + `std::stop_token` | the capture thread | `std::thread` + `std::atomic<bool>` + manual join |
| `std::print` / `std::format` | test output, MAC formatting | `printf` / manual string building |
| monadic `optional`, `std::bit_cast`, `std::ranges` | small cleanups | C-style casts, index loops |

`auto_select_channel` now returns `std::expected<std::optional<uint8_t>,
std::string>` — a near-exact transcription of the Rust `Result<Option<u8>, String>`.

---

## Equivalent libraries

| Concern | Rust | C++23 | Zig 0.16 |
|---|---|---|---|
| Packet capture | `pcap` crate | libpcap C API | libpcap via `@cImport` |
| Terminal UI | raw termios + ANSI (`libc`) | ncursesw | ncursesw via `@cImport` |
| `PATH` lookup | `which` crate | manual scan + `access` | none — spawn `error.FileNotFound` fallback |
| Subprocess | `std::process::Command` | POSIX `fork`/`exec`/`pipe` | `std.process.run(gpa, io, …)` |
| Background scan | `thread` + `mpsc` + `Arc<AtomicBool>` | `jthread` + `stop_token` + mutex | `Thread` + spinlock + `atomic.Value` |
| Time / sleep | `std::time::Instant` | `std::chrono` | `std.Io` (`Timestamp.now`/`sleep`) |

The Zig port uses **std for everything except the two C libraries it wraps**
(libpcap + ncurses, via `@cImport`) — see the note under Pain points on what that
costs in binary size.

Idiomatic *retained* TUI libraries (skipped — no network to fetch): **ratatui**
(Rust), **FTXUI** (C++), **libvaxis** (Zig).

## Build & package systems

| | Tool | Dependency story |
|---|---|---|
| **Rust** | `cargo` | `Cargo.toml`; here `pcap`, `which`, `libc`. |
| **C++** | **CMake** (primary) + **Makefile** | `pkg-config`/`find_library`; vcpkg optional. |
| **Zig** | **`zig build`** (`build.zig` + `.zon`) | Build system *is* the package manager; C libs from system. |

## Metrics

### Source size (`wc -l`, includes comments/blanks + inline tests)

| | Files | Total lines |
|---|---:|---:|
| Rust | 6 | **1,437** |
| C++ | 11 src (+1 test) | **1,297** |
| Zig | 7 | **1,158** |

### Release binary size (stripped, dynamically linked)

| Build | Size | Links |
|---|---:|---|
| Zig `ReleaseSmall` | **180 KiB** | libpcap, ncursesw, libc |
| C++ `g++ -O2 -std=c++23` | **207 KiB** | libpcap, ncursesw |
| Zig `ReleaseFast` | **582 KiB** | libpcap, ncursesw, libc |
| Rust `--release` | **588 KiB** | libpcap, libc |
| Zig `ReleaseSafe` (default) | **613 KiB** | libpcap, ncursesw, libc |

Notes:
- The old egui/eframe Rust build pulled **hundreds** of crates and a GPU/windowing
  stack. The TUI rewrite links just **libpcap + libc** and a handful of crates
  (`pcap`, `which` → `regex`, `libc`).
- Upgrading the C++ port from C++17 → **C++23** grew the binary from ~95 KiB to
  ~207 KiB: `<format>`/`<print>`/`<expected>` instantiate more libstdc++ code.
- **Preferring std over libc in Zig has a real size cost**: routing subprocess +
  timing through `std.Io`/`std.process.run` (instead of the earlier libc
  fork/exec) took ReleaseSmall from 47 → 180 KiB and ReleaseFast from 84 → 582 KiB.
  The std.Io async/MultiReader machinery is large; `ReleaseSmall` still wins overall.

### Dependency / toolchain footprint

| | Deps to fetch | Compiler here |
|---|---|---|
| Rust | `pcap`, `which`, `libc` (+ their small trees) | rustc/cargo 1.95 |
| C++ | 0 (system libpcap + ncurses) | g++ 16 |
| Zig | 0 (system libpcap + ncurses) | zig 0.16 |

## How this was verified on this machine

| | Tests | Build | UI |
|---|---|---|---|
| Rust | `cargo test` → **34 passed** | `cargo build --release` → 588 KiB | renders under a pty |
| C++ | `make test` → core passes | `make` → links libpcap + ncursesw | renders under a pty |
| Zig | `zig build test` → passes | `zig build` → links the same libs | renders under a pty |

Live capture needs `sudo`/`CAP_NET_RAW` and a Wi-Fi interface, so only build,
link, the parsing core, and UI startup were exercised here.
