# Idiomatic C++ build + dependency discovery.
#
#   cmake -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build
#   ctest --test-dir build        # runs the headless core tests
#
# Dependencies (libpcap, ncursesw) are resolved from the system via
# pkg-config / find_library. On distros without dev packages, install:
#   Debian/Ubuntu : libpcap-dev libncursesw5-dev
#   Arch          : libpcap ncurses
#   Fedora        : libpcap-devel ncurses-devel
# For a fully self-contained toolchain you can instead pull deps with vcpkg
# (see README.md) — CMake will pick them up transparently.
cmake_minimum_required(VERSION 3.16)
project(PinnacleFinderCpp CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(PkgConfig)
find_package(Threads REQUIRED)

# --- ncursesw ---
if(PkgConfig_FOUND)
  pkg_check_modules(NCURSES IMPORTED_TARGET ncursesw)
endif()
if(NOT NCURSES_FOUND)
  find_library(NCURSES_LIB NAMES ncursesw ncurses REQUIRED)
endif()

# --- libpcap ---
find_path(PCAP_INCLUDE_DIR pcap/pcap.h)
find_library(PCAP_LIB NAMES pcap REQUIRED)

add_library(pf_core STATIC
  src/core/mac.cpp
  src/core/radiotap.cpp
  src/core/sysiface.cpp
  src/core/capture.cpp)
target_include_directories(pf_core PUBLIC src ${PCAP_INCLUDE_DIR})
target_link_libraries(pf_core PUBLIC ${PCAP_LIB} Threads::Threads)
target_compile_options(pf_core PRIVATE -Wall -Wextra)

add_executable(pinnaclefinder src/main.cpp src/tui/app.cpp)
target_link_libraries(pinnaclefinder PRIVATE pf_core)
if(NCURSES_FOUND)
  target_link_libraries(pinnaclefinder PRIVATE PkgConfig::NCURSES)
else()
  target_link_libraries(pinnaclefinder PRIVATE ${NCURSES_LIB})
endif()

enable_testing()
add_executable(test_core tests/test_core.cpp)
target_link_libraries(test_core PRIVATE pf_core)
add_test(NAME core COMMAND test_core)
