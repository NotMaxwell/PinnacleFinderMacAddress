# PinnacleFinder — C++ port

A **C++23** terminal-UI (ncurses) port of the original Rust app: sniff 802.11
frames with libpcap, hunt for a target MAC, and show a live signal-strength
meter with auto channel selection and monitor-mode management.

Uses modern C++23: `std::span` for frame buffers, `std::expected<T,std::string>`
for errors, `std::jthread`+`std::stop_token` for the capture thread, plus
`std::print`/`std::format`, monadic `std::optional`, and `std::bit_cast`.
Requires a C++23 compiler (GCC 14+ / Clang 18+).

## Layout

```
src/core/    portable logic, no UI (unit-tested headless)
  mac.*        MAC parse / format
  radiotap.*   radiotap + 802.11 frame decoding, freq→channel
  sysiface.*   iw / iwconfig / iwlist / ip subprocess helpers
  capture.*    libpcap device list, background scan thread, auto channel
src/tui/     ncurses front-end (app.cpp)
src/main.cpp entry point
tests/       headless unit tests for the pure core
```

## Dependencies

- **libpcap** (packet capture) — the equivalent of the Rust `pcap` crate.
- **ncursesw** (terminal UI) — the equivalent of `eframe`/`egui`, in a TUI.
- A C++17 compiler and either `make` or CMake.

Install dev packages:
- Arch: `sudo pacman -S libpcap ncurses`
- Debian/Ubuntu: `sudo apt install libpcap-dev libncursesw5-dev`
- Fedora: `sudo dnf install libpcap-devel ncurses-devel`

## Build & run

**Makefile** (simpler, no CMake required):

```sh
make                    # -> build/pinnaclefinder (Release)
make test               # headless core tests (no pcap/ncurses needed)
sudo ./build/pinnaclefinder
```

**CMake** (if Makefile is unavailable; deps discovered via pkg-config /
`find_library`; `vcpkg` can supply them on systems without dev packages):

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
sudo ./build/pinnaclefinder
```

`sudo` (or `CAP_NET_RAW`) is required for packet capture and monitor mode.

## Keys

`i` select interface · `e` edit MAC · `a` toggle auto-channel ·
`o` toggle monitor-mode management · `s` start/stop scan · `q` quit
