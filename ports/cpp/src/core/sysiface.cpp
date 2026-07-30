#include "sysiface.hpp"
#include "radiotap.hpp" // freq_to_channel

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <format>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>

#include <sys/wait.h>
#include <unistd.h>

namespace pf {

namespace {

struct CmdResult {
    bool ran = false;
    int exit_code = -1;
    std::string out;
};

// Run a command (argv style, no shell) and capture stdout.
CmdResult run_command(const std::vector<std::string>& args) {
    CmdResult res;
    if (args.empty())
        return res;

    int pipefd[2];
    if (pipe(pipefd) != 0)
        return res;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return res;
    }
    if (pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (const auto& a : args)
            argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        execvp(argv[0], argv.data());
        _exit(127);
    }

    close(pipefd[1]);
    char buf[4096];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
        res.out.append(buf, static_cast<size_t>(n));
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    res.ran = true;
    res.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return res;
}

std::string trim(std::string_view s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return std::string(s.substr(b, e - b));
}

std::vector<std::string> split_ws(const std::string& s) {
    std::vector<std::string> out;
    std::istringstream iss(s);
    std::string tok;
    while (iss >> tok)
        out.push_back(tok);
    return out;
}

} // namespace

bool command_exists(std::string_view cmd) {
    static std::mutex mtx;
    static std::unordered_map<std::string, bool> cache;

    std::lock_guard lk(mtx);
    std::string key(cmd);
    if (auto it = cache.find(key); it != cache.end())
        return it->second;

    bool found = false;
    if (const char* path = std::getenv("PATH")) {
        std::string p(path);
        size_t start = 0;
        while (start <= p.size()) {
            size_t colon = p.find(':', start);
            std::string dir = p.substr(start, colon == std::string::npos ? colon : colon - start);
            if (!dir.empty()) {
                std::string full = dir + "/" + key;
                if (access(full.c_str(), X_OK) == 0) {
                    found = true;
                    break;
                }
            }
            if (colon == std::string::npos)
                break;
            start = colon + 1;
        }
    }
    cache.emplace(key, found);
    return found;
}

std::expected<void, std::string> set_channel_system(std::string_view iface, uint8_t channel) {
    std::string ch = std::to_string(channel);
    std::string ifs(iface);

#ifdef __APPLE__
    if (auto r = run_command(
            {"/System/Library/PrivateFrameworks/Apple80211.framework/Versions/"
             "Current/Resources/airport",
             ifs, "--channel", ch});
        r.ran) {
        if (r.exit_code != 0)
            return std::unexpected(std::format("airport returned status {}: {}", r.exit_code, trim(r.out)));
        return {};
    }
#endif

    if (command_exists("iw")) {
        auto r = run_command({"iw", "dev", ifs, "set", "channel", ch});
        if (!r.ran)
            return std::unexpected("failed to run iw");
        if (r.exit_code != 0)
            return std::unexpected(std::format("iw returned status {}: {}", r.exit_code, trim(r.out)));
        return {};
    }
    if (command_exists("iwconfig")) {
        auto r = run_command({"iwconfig", ifs, "channel", ch});
        if (!r.ran)
            return std::unexpected("failed to run iwconfig");
        if (r.exit_code != 0)
            return std::unexpected(std::format("iwconfig returned status {}: {}", r.exit_code, trim(r.out)));
        return {};
    }
    return std::unexpected("no supported tool found to set channel (need `iw` or `iwconfig`)");
}

std::optional<std::vector<std::pair<std::string, uint8_t>>>
scan_system_channels(std::string_view iface) {
    using Rows = std::vector<std::pair<std::string, uint8_t>>;
    std::string ifs(iface);

    if (command_exists("iw")) {
        auto r = run_command({"iw", "dev", ifs, "scan"});
        if (r.ran && r.exit_code == 0) {
            Rows rows;
            std::istringstream iss(r.out);
            std::string line, cur_bssid;
            bool have_bssid = false;
            while (std::getline(iss, line)) {
                std::string trimmed = line;
                if (size_t nb = trimmed.find_first_not_of(" \t"); nb != std::string::npos)
                    trimmed = trimmed.substr(nb);
                else
                    trimmed.clear();
                if (trimmed.starts_with("BSS ")) {
                    if (auto parts = split_ws(trimmed); parts.size() >= 2) {
                        cur_bssid = parts[1];
                        if (size_t paren = cur_bssid.find('('); paren != std::string::npos)
                            cur_bssid = cur_bssid.substr(0, paren);
                        have_bssid = true;
                    }
                }
                if (have_bssid && trimmed.starts_with("freq:")) {
                    if (auto parts = split_ws(trimmed); parts.size() >= 2) {
                        if (long freq = std::strtol(parts[1].c_str(), nullptr, 10); freq > 0)
                            if (auto c = freq_to_channel(static_cast<uint32_t>(freq)))
                                rows.emplace_back(cur_bssid, *c);
                    }
                    have_bssid = false;
                }
            }
            if (!rows.empty())
                return rows;
        }
    }

    if (command_exists("iwlist")) {
        auto r = run_command({"iwlist", ifs, "scanning"});
        if (r.ran && r.exit_code == 0) {
            Rows rows;
            std::istringstream iss(r.out);
            std::string line, cur_bssid;
            bool have_bssid = false;
            while (std::getline(iss, line)) {
                std::string t = trim(line);
                if (t.starts_with("Cell ") && t.find("Address:") != std::string::npos) {
                    size_t idx = t.find("Address:");
                    cur_bssid = trim(t.substr(idx + 8));
                    have_bssid = true;
                }
                if (have_bssid && t.starts_with("Channel:")) {
                    if (size_t colon = t.find(':'); colon != std::string::npos) {
                        std::string chs = trim(t.substr(colon + 1));
                        if (long c = std::strtol(chs.c_str(), nullptr, 10); c >= 0 && c <= 255)
                            rows.emplace_back(cur_bssid, static_cast<uint8_t>(c));
                    }
                    have_bssid = false;
                }
            }
            if (!rows.empty())
                return rows;
        }
    }
    return std::nullopt;
}

static std::expected<void, std::string> set_iface_type(std::string_view iface, std::string_view type) {
#if defined(__linux__)
    std::string ifs(iface), ty(type);
    if (!command_exists("ip") || !command_exists("iw"))
        return std::unexpected("`ip` or `iw` not found; cannot change interface mode");

    if (auto r = run_command({"ip", "link", "set", ifs, "down"}); !r.ran || r.exit_code != 0)
        return std::unexpected(std::format("ip down failed (status {})", r.exit_code));
    if (auto r = run_command({"iw", "dev", ifs, "set", "type", ty}); !r.ran || r.exit_code != 0)
        return std::unexpected(std::format("iw set type {} failed (status {})", ty, r.exit_code));
    if (auto r = run_command({"ip", "link", "set", ifs, "up"}); !r.ran || r.exit_code != 0)
        return std::unexpected(std::format("ip up failed (status {})", r.exit_code));
    return {};
#elif defined(__APPLE__)
    (void)iface; (void)type;
    return std::unexpected("automatic monitor-mode management is not implemented on macOS");
#else
    (void)iface; (void)type;
    return std::unexpected("monitor-mode management not supported on this OS");
#endif
}

std::expected<void, std::string> enable_monitor_mode(std::string_view iface) {
    return set_iface_type(iface, "monitor");
}
std::expected<void, std::string> disable_monitor_mode(std::string_view iface) {
    return set_iface_type(iface, "managed");
}

} // namespace pf
