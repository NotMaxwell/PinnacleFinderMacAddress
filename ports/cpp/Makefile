# Simple, dependency-light build. Uses pkg-config to locate libpcap + ncursesw.
# `make`        -> build the binary (build/pinnaclefinder)
# `make test`   -> build & run the headless core tests
# `make clean`

CXX      ?= g++
CXXFLAGS ?= -std=c++23 -O2 -Wall -Wextra
CPPFLAGS += -Isrc

PKGS      := ncursesw
PKG_CFLAGS := $(shell pkg-config --cflags $(PKGS) 2>/dev/null)
PKG_LIBS   := $(shell pkg-config --libs $(PKGS) 2>/dev/null)
# libpcap has no reliable .pc on every distro; link directly.
LIBS      := $(PKG_LIBS) -lpcap -lpthread

BUILD := build
CORE  := src/core/mac.cpp src/core/radiotap.cpp src/core/sysiface.cpp src/core/capture.cpp
SRCS  := $(CORE) src/tui/app.cpp src/main.cpp
OBJS  := $(patsubst src/%.cpp,$(BUILD)/%.o,$(SRCS))
BIN   := $(BUILD)/pinnaclefinder

.PHONY: all test clean
all: $(BIN)

$(BIN): $(OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

$(BUILD)/%.o: src/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(PKG_CFLAGS) -c $< -o $@

test: $(BUILD)/test_core
	$(BUILD)/test_core

# The core tests only exercise the pure logic (mac + radiotap), so they need
# no external libraries — handy for CI without pcap/ncurses dev packages.
$(BUILD)/test_core: tests/test_core.cpp src/core/mac.cpp src/core/radiotap.cpp
	@mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@

clean:
	rm -rf $(BUILD)
