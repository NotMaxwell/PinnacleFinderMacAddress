#include "app.hpp"

#include "core/capture.hpp"
#include "core/mac.hpp"
#include "core/sysiface.hpp"

#include <algorithm>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <ncurses.h>

namespace pf {

namespace {

using clock_t_ = std::chrono::steady_clock;

enum class Mode { Normal, IfaceSelect, MacEdit };

// Colour pair ids.
constexpr short CP_GOLD = 1;
constexpr short CP_GREEN = 2;
constexpr short CP_YELLOW = 3;
constexpr short CP_RED = 4;
constexpr short CP_DIM = 5;

float rssi_to_strength(float rssi) {
    const float min = -100.0f, max = -30.0f;
    float s = (rssi - min) / (max - min);
    return std::clamp(s, 0.0f, 1.0f);
}

struct App {
    std::vector<std::string> interfaces;
    std::optional<size_t> selected_iface;
    size_t iface_cursor = 0;

    std::string mac_input;
    bool mac_valid = false;

    std::optional<int8_t> last_rssi;
    std::optional<float> smoothed_rssi;

    bool auto_channel_enabled = true;
    bool manage_monitor = false;
    bool monitor_managed_by_app = false;

    bool scanning = false;
    uint64_t total_frames = 0;
    uint64_t hits = 0;
    std::optional<clock_t_::time_point> start_time;

    std::optional<uint8_t> auto_channel;
    std::optional<std::string> channel_note;
    std::optional<std::string> error;

    std::unique_ptr<ScanSession> session;
    Mode mode = Mode::Normal;

    App() { interfaces = list_devices(); }

    std::optional<std::string> iface_name() const {
        if (selected_iface && *selected_iface < interfaces.size())
            return interfaces[*selected_iface];
        return std::nullopt;
    }
};

bool monitor_supported() {
#if defined(__linux__)
    return true;
#else
    return false;
#endif
}

void poll_session(App& a) {
    if (!a.session)
        return;
    ScanUpdate u = a.session->snapshot();
    a.total_frames = u.total_frames;
    a.hits = u.hits;
    a.last_rssi = u.last_rssi;
    if (u.last_rssi) {
        const float alpha = 0.2f;
        float r = static_cast<float>(*u.last_rssi);
        a.smoothed_rssi = a.smoothed_rssi ? (*a.smoothed_rssi * (1.0f - alpha) + r * alpha) : r;
    }
}

void start_scan(App& a) {
    a.error.reset();
    a.total_frames = 0;
    a.hits = 0;
    a.auto_channel.reset();
    a.channel_note.reset();
    a.smoothed_rssi.reset();
    a.last_rssi.reset();

    auto iface = a.iface_name();
    if (!iface) {
        a.error = "Select a network interface first.";
        return;
    }
    if (!a.mac_valid) {
        a.error = "Invalid MAC address format.";
        return;
    }
    auto mac = parse_mac(a.mac_input);
    if (!mac) {
        a.error = "Invalid MAC address format.";
        return;
    }

    if (a.auto_channel_enabled) {
        // Mirrors the Rust `Result<Option<u8>, String>`.
        auto res = auto_select_channel(*iface, *mac);
        if (!res) {
            a.channel_note = "Auto channel failed: " + res.error();
        } else if (*res) {
            a.auto_channel = *res;
            a.channel_note = "Locked channel " + std::to_string(**res) + " via auto-test";
        } else {
            a.channel_note = "Auto channel: no signal; staying on current channel";
        }
    } else {
        a.channel_note = "Auto channel selection disabled";
    }

    if (a.manage_monitor) {
        if (monitor_supported()) {
            if (auto e = enable_monitor_mode(*iface); !e) {
                a.error = "Failed to enable monitor mode: " + e.error();
                return;
            }
            a.monitor_managed_by_app = true;
            a.channel_note = (a.channel_note ? *a.channel_note + "; " : std::string()) +
                             "monitor mode enabled";
        } else {
            a.channel_note = "Monitor mode management not available on this OS";
        }
    }

    a.session = std::make_unique<ScanSession>(*iface, *mac);
    a.start_time = clock_t_::now();
    a.scanning = true;
}

void stop_scan(App& a) {
    a.session.reset(); // joins the capture thread
    a.scanning = false;
    if (a.monitor_managed_by_app) {
        if (auto iface = a.iface_name()) {
            if (auto e = disable_monitor_mode(*iface); !e)
                a.channel_note = "Monitor disable failed: " + e.error();
            else
                a.channel_note = "Monitor mode disabled; interface restored";
        }
        a.monitor_managed_by_app = false;
    }
}

short strength_color(float s) {
    if (s > 0.66f) return CP_GREEN;
    if (s > 0.33f) return CP_YELLOW;
    return CP_RED;
}

void draw_signal(App& a, int row) {
    float rssi = a.smoothed_rssi ? *a.smoothed_rssi
                                 : (a.last_rssi ? static_cast<float>(*a.last_rssi) : 0.0f);
    bool have = a.smoothed_rssi || a.last_rssi;
    float strength = have ? rssi_to_strength(rssi) : 0.0f;
    short cp = strength_color(strength);

    attron(A_BOLD | COLOR_PAIR(CP_GOLD));
    mvprintw(row, 2, "Signal Strength");
    attroff(A_BOLD | COLOR_PAIR(CP_GOLD));

    if (have)
        mvprintw(row, 20, "%6.0f dBm", rssi);
    else
        mvprintw(row, 20, "  -- dBm");

    // 5-segment bar (mirrors the egui draw_signal_bars widget).
    const int n = 5;
    mvaddch(row, 32, '[');
    for (int i = 0; i < n; ++i) {
        float frac = static_cast<float>(i + 1) / n;
        if (strength >= frac) {
            attron(COLOR_PAIR(cp));
            addstr("###");
            attroff(COLOR_PAIR(cp));
        } else {
            attron(COLOR_PAIR(CP_DIM));
            addstr("...");
            attroff(COLOR_PAIR(CP_DIM));
        }
        addch(' ');
    }
    printw("] %3.0f%%", strength * 100.0f);
}

void draw(App& a) {
    erase();
    int row = 0;

    attron(A_BOLD | COLOR_PAIR(CP_GOLD));
    mvprintw(row++, 2, "PinnacleFinder - MAC Hunter (TUI / C++)");
    attroff(A_BOLD | COLOR_PAIR(CP_GOLD));
    row++;

    draw_signal(a, row);
    row += 2;

    // Interface.
    std::string iface = a.iface_name().value_or("<none selected>");
    mvprintw(row++, 2, "Interface [i]: %s", iface.c_str());

    if (a.mode == Mode::IfaceSelect) {
        mvprintw(row++, 4, "-- select interface (Up/Down, Enter, Esc) --");
        for (size_t i = 0; i < a.interfaces.size(); ++i) {
            bool cur = (i == a.iface_cursor);
            if (cur) attron(A_REVERSE);
            mvprintw(row++, 6, "%s %s", cur ? ">" : " ", a.interfaces[i].c_str());
            if (cur) attroff(A_REVERSE);
        }
    }

    // Toggles.
    mvprintw(row++, 2, "Auto channel [a]: %s    Manage monitor [o]: %s%s",
             a.auto_channel_enabled ? "ON " : "OFF",
             a.manage_monitor ? "ON " : "OFF",
             monitor_supported() ? "" : " (unsupported OS)");

    // MAC input.
    bool editing = (a.mode == Mode::MacEdit);
    mvprintw(row, 2, "Target MAC [e]: ");
    if (editing) attron(A_UNDERLINE);
    printw("%-17s", a.mac_input.c_str());
    if (editing) attroff(A_UNDERLINE);
    if (editing)
        printw("  (type hex, Backspace, Enter/Esc)");
    else if (!a.mac_input.empty() && !a.mac_valid) {
        attron(COLOR_PAIR(CP_RED));
        printw("  INVALID");
        attroff(COLOR_PAIR(CP_RED));
    } else if (a.mac_valid) {
        attron(COLOR_PAIR(CP_GREEN));
        printw("  ok");
        attroff(COLOR_PAIR(CP_GREEN));
    }
    row += 2;

    // Scan button / status.
    attron(A_BOLD);
    mvprintw(row++, 2, "[s] %s", a.scanning ? "STOP SCAN" : "START SCAN");
    attroff(A_BOLD);
    row++;

    if (a.error) {
        attron(COLOR_PAIR(CP_RED));
        mvprintw(row++, 2, "Error: %s", a.error->c_str());
        attroff(COLOR_PAIR(CP_RED));
    }

    // Stats.
    float elapsed = 0.0f;
    if (a.start_time)
        elapsed = std::chrono::duration<float>(clock_t_::now() - *a.start_time).count();
    float hit_rate = elapsed > 0.0f ? static_cast<float>(a.hits) / elapsed : 0.0f;

    attron(A_BOLD | COLOR_PAIR(CP_GOLD));
    mvprintw(row++, 2, "Stats");
    attroff(A_BOLD | COLOR_PAIR(CP_GOLD));
    mvprintw(row++, 4, "Frames seen : %llu", (unsigned long long)a.total_frames);
    mvprintw(row++, 4, "Matches     : %llu", (unsigned long long)a.hits);
    mvprintw(row++, 4, "Elapsed     : %.1f s", elapsed);
    mvprintw(row++, 4, "Hit rate    : %.2f hits/s", hit_rate);
    if (a.auto_channel)
        mvprintw(row++, 4, "Channel     : %d (auto)", (int)*a.auto_channel);
    if (a.channel_note)
        mvprintw(row++, 4, "Note        : %s", a.channel_note->c_str());
    mvprintw(row++, 4, "Interfaces  : %zu", a.interfaces.size());

    row++;
    attron(COLOR_PAIR(CP_DIM));
    mvprintw(row++, 2, "[q] quit  [i] iface  [e] mac  [a] auto  [o] monitor  [s] scan");
    attroff(COLOR_PAIR(CP_DIM));

    refresh();
}

// Append a single typed character to the MAC input using the on-screen-keyboard
// reformatting rules from the Rust source.
void mac_edit_key(App& a, int ch) {
    auto raw_of = [](const std::string& s) {
        std::string r;
        for (char c : s)
            if (std::isxdigit((unsigned char)c))
                r.push_back(c);
        return r;
    };
    if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
        std::string raw = raw_of(a.mac_input);
        if (!raw.empty())
            raw.pop_back();
        a.mac_input = format_mac_from_hex(raw);
    } else if (std::isxdigit(ch)) {
        std::string raw = raw_of(a.mac_input);
        if (raw.size() < 12) {
            raw.push_back(static_cast<char>(ch));
            a.mac_input = format_mac_from_hex(raw);
        }
    }
    a.mac_valid = parse_mac(a.mac_input).has_value();
}

} // namespace

int run_tui() {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    timeout(100); // ~10 fps poll of the capture thread

    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(CP_GOLD, COLOR_YELLOW, -1);
        init_pair(CP_GREEN, COLOR_GREEN, -1);
        init_pair(CP_YELLOW, COLOR_YELLOW, -1);
        init_pair(CP_RED, COLOR_RED, -1);
        init_pair(CP_DIM, COLOR_WHITE, -1);
    }

    App a;
    bool running = true;
    while (running) {
        poll_session(a);
        draw(a);

        int ch = getch();
        if (ch == ERR)
            continue;

        if (a.mode == Mode::IfaceSelect) {
            switch (ch) {
                case KEY_UP:
                    if (a.iface_cursor > 0) a.iface_cursor--;
                    break;
                case KEY_DOWN:
                    if (a.iface_cursor + 1 < a.interfaces.size()) a.iface_cursor++;
                    break;
                case '\n': case KEY_ENTER:
                    if (!a.interfaces.empty()) a.selected_iface = a.iface_cursor;
                    a.mode = Mode::Normal;
                    break;
                case 27: // Esc
                    a.mode = Mode::Normal;
                    break;
            }
            continue;
        }

        if (a.mode == Mode::MacEdit) {
            if (ch == '\n' || ch == KEY_ENTER || ch == 27) {
                a.mode = Mode::Normal;
            } else {
                mac_edit_key(a, ch);
            }
            continue;
        }

        // Normal mode.
        switch (ch) {
            case 'q': case 'Q':
                running = false;
                break;
            case 'i': case 'I':
                if (!a.interfaces.empty()) {
                    a.iface_cursor = a.selected_iface.value_or(0);
                    a.mode = Mode::IfaceSelect;
                }
                break;
            case 'e': case 'E':
                a.mode = Mode::MacEdit;
                break;
            case 'a': case 'A':
                a.auto_channel_enabled = !a.auto_channel_enabled;
                break;
            case 'o': case 'O':
                if (monitor_supported())
                    a.manage_monitor = !a.manage_monitor;
                break;
            case 's': case 'S':
                if (a.scanning)
                    stop_scan(a);
                else
                    start_scan(a);
                break;
        }
    }

    if (a.scanning)
        stop_scan(a);
    endwin();
    return 0;
}

} // namespace pf
