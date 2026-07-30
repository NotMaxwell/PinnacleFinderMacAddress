//! Debug logging + interaction with platform networking tools
//! (iw / iwconfig / iwlist / ip, and airport on macOS).
use std::collections::HashMap;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use crate::radiotap::freq_to_channel;

static DEBUG_FLAG: OnceLock<bool> = OnceLock::new();
static COMMAND_CHECK_CACHE: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();

pub fn debug_enabled() -> bool {
    *DEBUG_FLAG.get_or_init(|| {
        std::env::var("PF_DEBUG")
            .map(|v| {
                let v = v.trim();
                v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false)
    })
}

pub fn log_debug(msg: &str) {
    if debug_enabled() {
        eprintln!("[DEBUG] {msg}");
    }
}

/// Check whether a program exists in PATH.
pub fn command_exists(cmd: &str) -> bool {
    let cache = COMMAND_CHECK_CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    if let Ok(mut map) = cache.lock() {
        if let Some(&cached) = map.get(cmd) {
            return cached;
        }
        let found = which::which(cmd).is_ok();
        map.insert(cmd.to_string(), found);
        found
    } else {
        which::which(cmd).is_ok()
    }
}

/// Set wireless channel using platform-appropriate tools.
pub fn set_channel_system(iface: &str, channel: u8) -> Result<(), String> {
    if cfg!(target_os = "macos") {
        if let Ok(output) = Command::new("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport")
            .arg(iface)
            .arg("--channel")
            .arg(channel.to_string())
            .output()
        {
            if !output.status.success() {
                return Err(format!(
                    "airport returned status {} with stderr: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            return Ok(());
        }
    }

    if command_exists("iw") {
        let output = Command::new("iw")
            .arg("dev").arg(iface).arg("set").arg("channel").arg(channel.to_string())
            .output()
            .map_err(|e| format!("failed to run iw: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "iw returned status {} with stderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        return Ok(());
    }

    if command_exists("iwconfig") {
        let output = Command::new("iwconfig")
            .arg(iface).arg("channel").arg(channel.to_string())
            .output()
            .map_err(|e| format!("failed to run iwconfig: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "iwconfig returned status {} with stderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        return Ok(());
    }

    Err("no supported tool found to set channel (need `iw` or `iwconfig` on Linux, or `airport` on macOS)".into())
}

/// Scan for nearby APs and return (BSSID, channel) tuples using platform tools.
pub fn scan_system_channels(iface: &str) -> Option<Vec<(String, u8)>> {
    if cfg!(target_os = "macos") {
        if let Ok(output) = Command::new("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport")
            .arg("-s")
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut rows = Vec::new();
                for line in stdout.lines().skip(1) {
                    let tokens: Vec<&str> = line.split_whitespace().collect();
                    let mut bssid_idx = None;
                    for (i, t) in tokens.iter().enumerate() {
                        if t.len() == 17 && t.matches(':').count() == 5 {
                            bssid_idx = Some(i);
                            break;
                        }
                    }
                    let Some(idx) = bssid_idx else { continue };
                    if idx + 1 >= tokens.len() { continue; }
                    let bssid = tokens[idx].to_string();
                    if let Ok(ch) = tokens[idx + 1].parse::<u8>() {
                        rows.push((bssid, ch));
                    }
                }
                if !rows.is_empty() { return Some(rows); }
            }
        }
    }

    // `iw dev <iface> scan` (preferred on Linux)
    if command_exists("iw") {
        if let Ok(output) = Command::new("iw").arg("dev").arg(iface).arg("scan").output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut rows = Vec::new();
                let mut cur_bssid: Option<String> = None;
                for line in stdout.lines() {
                    let trimmed = line.trim_start();
                    if trimmed.starts_with("BSS ") {
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let b = parts[1].split('(').next().unwrap_or(parts[1]);
                            cur_bssid = Some(b.trim().to_string());
                        }
                    }
                    if let Some(bssid) = &cur_bssid {
                        if trimmed.starts_with("freq:") {
                            if let Some(freq_s) = trimmed.split_whitespace().nth(1) {
                                if let Ok(freq) = freq_s.parse::<u32>() {
                                    if let Some(ch) = freq_to_channel(freq) {
                                        rows.push((bssid.clone(), ch));
                                    }
                                }
                            }
                            cur_bssid = None;
                        }
                    }
                }
                if !rows.is_empty() {
                    return Some(rows);
                }
            }
        }
    }

    // Fallback to `iwlist <iface> scanning`
    if command_exists("iwlist") {
        if let Ok(output) = Command::new("iwlist").arg(iface).arg("scanning").output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut rows = Vec::new();
                let mut cur_bssid: Option<String> = None;
                for line in stdout.lines() {
                    let t = line.trim();
                    if t.starts_with("Cell ") && t.contains("Address:") {
                        if let Some(idx) = t.find("Address:") {
                            cur_bssid = Some(t[idx + 8..].trim().to_string());
                        }
                    }
                    if let Some(bssid) = &cur_bssid {
                        if t.starts_with("Channel:") {
                            if let Some(chs) = t.split(':').nth(1) {
                                if let Ok(ch) = chs.trim().parse::<u8>() {
                                    rows.push((bssid.clone(), ch));
                                }
                            }
                            cur_bssid = None;
                        }
                    }
                }
                if !rows.is_empty() {
                    return Some(rows);
                }
            }
        }
    }

    None
}

/// Enable monitor mode on the provided interface (Linux only).
pub fn enable_monitor_mode(iface: &str) -> Result<(), String> {
    set_iface_type(iface, "monitor")
}

/// Disable monitor mode (restore managed mode) on the provided interface (Linux only).
pub fn disable_monitor_mode(iface: &str) -> Result<(), String> {
    set_iface_type(iface, "managed")
}

fn set_iface_type(iface: &str, kind: &str) -> Result<(), String> {
    if cfg!(target_os = "linux") {
        if !command_exists("ip") || !command_exists("iw") {
            return Err("`ip` or `iw` not found; cannot change interface mode".into());
        }
        run_status(Command::new("ip").arg("link").arg("set").arg(iface).arg("down"), "ip down")?;
        run_status(Command::new("iw").arg("dev").arg(iface).arg("set").arg("type").arg(kind), "iw set type")?;
        run_status(Command::new("ip").arg("link").arg("set").arg(iface).arg("up"), "ip up")?;
        Ok(())
    } else if cfg!(target_os = "macos") {
        Err("automatic monitor-mode management is not implemented on macOS".into())
    } else {
        Err("monitor-mode management not supported on this OS".into())
    }
}

fn run_status(cmd: &mut Command, label: &str) -> Result<(), String> {
    let s = cmd.status().map_err(|e| format!("failed to run {label}: {e}"))?;
    if !s.success() {
        return Err(format!("{label} returned status {s}"));
    }
    Ok(())
}
