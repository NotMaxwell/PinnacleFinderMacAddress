# PinnacleFinder Ports — Rust, C++, and Zig

Three independent implementations of a WiFi MAC-hunter TUI app: sniff 802.11
frames with libpcap, hunt for a target MAC address, and display live signal
strength with auto channel selection and monitor-mode management.

**See [`COMPARISON.md`](COMPARISON.md)** for pros/cons, DX metrics, binary sizes,
and code examples across all three.

---

## Quick Reference: Build / Run / Test

### Rust (original, at root)

```sh
# Build (offline, no crates.io)
cargo build --offline --release

# Run (requires sudo or CAP_NET_RAW)
sudo ./target/release/PinnacleFinderMacAddress

# Test
cargo test --offline
```

**Location:** `../src/main.rs` (monolithic TUI module)  
**Binary:** `target/release/PinnacleFinderMacAddress` (~588 KiB)

### C++ (C++23, at `cpp/`)

```sh
# Build with Makefile (simpler, recommended)
cd cpp && make

# Or with CMake
cd cpp && cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build

# Run (requires sudo or CAP_NET_RAW)
sudo ./build/pinnaclefinder   # or ./cpp/build/pinnaclefinder

# Test
cd cpp && make test           # Makefile
# or: ctest --test-dir cpp/build  # CMake
```

**Location:** `cpp/src/core/` (portable modules) + `cpp/src/tui/` (ncurses UI)  
**Binary:** `cpp/build/pinnaclefinder` (~207 KiB)  
**Features:** C++23 (`std::span`, `std::expected`, `std::jthread`, `std::format`, `std::print`)

### Zig (0.16, at `zig/`)

```sh
# Build (ReleaseSafe is default)
cd zig && zig build

# Or ReleaseSmall (most compact)
cd zig && zig build -Doptimize=ReleaseSmall

# Run (requires sudo or CAP_NET_RAW)
sudo ./zig-out/bin/pinnaclefinder

# Test (unit tests in mac.zig, radiotap.zig)
cd zig && zig build test
```

**Location:** `zig/src/*.zig` (pure Zig + `@cImport` pcap/ncurses)  
**Binary:**  
  - ReleaseSafe: ~613 KiB  
  - ReleaseFast: ~582 KiB  
  - ReleaseSmall: ~180 KiB ✓ (smallest)
  
**Features:** `std.process.run`, `std.Io`, `std.ArrayList`, raw termios/ANSI

---

## Dependencies

All three need **libpcap** and **ncursesw** at runtime:

```sh
# Arch Linux
sudo pacman -S libpcap ncurses

# Debian / Ubuntu
sudo apt install libpcap-dev libncursesw5-dev

# Fedora
sudo dnf install libpcap-devel ncurses-devel
```

Additional build requirements:
- **Rust:** `cargo` (1.95+), `rustc`
- **C++:** `g++` (16+) or `clang++` (22+), `make` (Makefile) or `cmake`
- **Zig:** `zig` (0.16), system linker (`use_lld = false` due to GCC 16 `.sframe` incompatibility)

---

## Key Controls

All three ports use the same keybindings:

- `i` — select interface
- `e` — edit target MAC address
- `a` — toggle auto channel selection
- `o` — toggle monitor-mode management (Linux only, requires sudo)
- `s` — start/stop scan
- `q` — quit

---

## Runtime Requirements

All require **`sudo` or `CAP_NET_RAW`** for:
- Packet capture via libpcap
- Entering monitor mode (Linux only)

Run without sudo if you have set the capability:
```sh
sudo setcap cap_net_raw=ep ./target/release/pinnaclefinder  # Rust
sudo setcap cap_net_raw=ep ./cpp/build/pinnaclefinder       # C++
sudo setcap cap_net_raw=ep ./zig-out/bin/pinnaclefinder     # Zig
```

---

## Detailed Build Instructions

For full instructions, see:
- **Rust:** no dedicated README (modular; see `src/` files inline)
- **C++:** [`cpp/README.md`](cpp/README.md)
- **Zig:** [`zig/README.md`](zig/README.md)

## Comparison & Design

**[`COMPARISON.md`](COMPARISON.md)** documents:
- Developer experience (DX) scorecard
- Code snippets (error handling, threading, subprocess, timing)
- Memory safety analysis
- Binary size metrics & LOC counts
- Pros/cons for each language/port
- Equivalent libraries and C standard comparisons
