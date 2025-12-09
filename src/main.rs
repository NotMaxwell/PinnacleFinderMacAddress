use eframe::{egui, run_native, NativeOptions};
use pcap::{Active, Capture, Device};

use std::sync::{mpsc, Arc, OnceLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::fmt::Write as FmtWrite;
use std::process::Command;

#[derive(Clone, Debug)]
struct ScanUpdate {
    total_frames: u64,
    hits: u64,
    last_rssi: Option<i8>,
}

struct GuiApp {
    interfaces: Vec<String>,
    selected_iface: Option<String>,
    show_iface_list: bool,

    mac_input: String,
    mac_valid: bool,
    last_rssi: Option<i8>,

    smoothed_rssi: Option<f32>,

    // Controls for auto channel selection and monitor-mode management
    auto_channel_enabled: bool,
    manage_monitor: bool,
    // Whether this app enabled monitor mode and should attempt to restore
    monitor_managed_by_app: bool,

    scanning: bool,
    total_frames: u64,
    hits: u64,
    start_time: Option<Instant>,

    auto_channel: Option<u8>,
    channel_note: Option<String>,

    rx: Option<mpsc::Receiver<ScanUpdate>>,
    stop_flag: Option<Arc<AtomicBool>>,
    error: Option<String>,
}

static DEBUG_FLAG: OnceLock<bool> = OnceLock::new();

fn debug_enabled() -> bool {
    *DEBUG_FLAG.get_or_init(|| {
        std::env::var("PF_DEBUG")
            .map(|v| {
                let v = v.trim();
                v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false)
    })
}

fn log_debug(msg: &str) {
    if debug_enabled() {
        println!("[DEBUG] {msg}");
    }
}

fn open_capture(iface: &str, timeout_ms: i32) -> Result<Capture<Active>, String> {
    // Try monitor mode first; fall back to promisc only if monitor fails
    let try_rfmon = Capture::from_device(iface)
        .map_err(|e| format!("from_device: {e}"))?
        .rfmon(true)
        .promisc(true)
        .timeout(timeout_ms)
        .open();

    match try_rfmon {
        Ok(c) => Ok(c),
        Err(e1) => {
            log_debug(&format!("rfmon open failed (will retry promisc): {e1}"));
            Capture::from_device(iface)
                .map_err(|e| format!("from_device: {e}"))?
                .promisc(true)
                .timeout(timeout_ms)
                .open()
                .map_err(|e2| format!("open: {e2}"))
        }
    }
}

/// Check whether a program exists in PATH
fn command_exists(cmd: &str) -> bool {
    which::which(cmd).is_ok()
}

/// Set wireless channel using platform-appropriate tools.
fn set_channel_system(iface: &str, channel: u8) -> Result<(), String> {
    // Prefer `airport` on macOS if present
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

    // On Linux prefer `iw` then fall back to `iwconfig`
    if command_exists("iw") {
        let output = Command::new("iw")
            .arg("dev")
            .arg(iface)
            .arg("set")
            .arg("channel")
            .arg(channel.to_string())
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
            .arg(iface)
            .arg("channel")
            .arg(channel.to_string())
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
fn scan_system_channels(iface: &str) -> Option<Vec<(String, u8)>> {
    // macOS airport first
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
                if rows.is_empty() { None } else { return Some(rows); }
            }
        }
    }

    // Try `iw` on Linux (preferred)
    if command_exists("iw") {
        if let Ok(output) = Command::new("iw").arg("dev").arg(iface).arg("scan").output() {
            if !output.status.success() {
                // fall through to iwlist
            } else {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut rows = Vec::new();
                let mut cur_bssid: Option<String> = None;
                for line in stdout.lines() {
                    let trimmed = line.trim_start();
                    if trimmed.starts_with("BSS ") {
                        // Example: "BSS aa:bb:cc:dd:ee:ff(on wlan0)"
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 2 {
                            cur_bssid = Some(parts[1].trim().to_string());
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
                if !rows.is_empty() { return Some(rows); }
            }
        }
    }

    // Fallback to `iwlist <iface> scanning` which is available on many distros
    if command_exists("iwlist") {
        if let Ok(output) = Command::new("iwlist").arg(iface).arg("scanning").output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut rows = Vec::new();
                let mut cur_bssid: Option<String> = None;
                for line in stdout.lines() {
                    let t = line.trim();
                    if t.starts_with("Cell ") && t.contains("Address:") {
                        // Example: Cell 01 - Address: aa:bb:cc:dd:ee:ff
                        if let Some(idx) = t.find("Address:") {
                            let b = t[idx + 8..].trim();
                            cur_bssid = Some(b.to_string());
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
                if rows.is_empty() { None } else { return Some(rows); }
            }
        }
    }

    None
}

fn freq_to_channel(freq: u32) -> Option<u8> {
    // 2.4 GHz: channel = (freq - 2407) / 5
    if freq >= 2412 && freq <= 2484 {
        let ch = ((freq as i32 - 2407) / 5) as u8;
        return Some(ch);
    }
    // 5 GHz common mapping: channel = (freq - 5000) / 5
    if freq >= 5000 && freq <= 6000 {
        let ch = ((freq as i32 - 5000) / 5) as u8;
        return Some(ch);
    }
    None
}

fn packet_contains_mac(data: &[u8], target: &[u8; 6]) -> bool {
    if let Some((src, _)) = extract_80211_src_mac_and_rssi(data) {
        if &src == target {
            return true;
        }
    }
    data.windows(6).any(|w| w == target)
}

/// Enable monitor mode on the provided interface (Linux only).
fn enable_monitor_mode(iface: &str) -> Result<(), String> {
    if cfg!(target_os = "linux") {
        if !command_exists("ip") || !command_exists("iw") {
            return Err("`ip` or `iw` not found; cannot enable monitor mode".into());
        }
        // ip link set <iface> down
        let s = Command::new("ip")
            .arg("link")
            .arg("set")
            .arg(iface)
            .arg("down")
            .status()
            .map_err(|e| format!("failed to run ip down: {}", e))?;
        if !s.success() {
            return Err(format!("ip down returned status {}", s));
        }

        // iw dev <iface> set type monitor
        let s = Command::new("iw")
            .arg("dev")
            .arg(iface)
            .arg("set")
            .arg("type")
            .arg("monitor")
            .status()
            .map_err(|e| format!("failed to run iw set type monitor: {}", e))?;
        if !s.success() {
            return Err(format!("iw set type returned status {}", s));
        }

        // ip link set <iface> up
        let s = Command::new("ip")
            .arg("link")
            .arg("set")
            .arg(iface)
            .arg("up")
            .status()
            .map_err(|e| format!("failed to run ip up: {}", e))?;
        if !s.success() {
            return Err(format!("ip up returned status {}", s));
        }

        Ok(())
    } else if cfg!(target_os = "macos") {
        Err("automatic monitor-mode management is not implemented on macOS".into())
    } else {
        Err("monitor-mode management not supported on this OS".into())
    }
}

/// Disable monitor mode (restore managed mode) on the provided interface (Linux only).
fn disable_monitor_mode(iface: &str) -> Result<(), String> {
    if cfg!(target_os = "linux") {
        if !command_exists("ip") || !command_exists("iw") {
            return Err("`ip` or `iw` not found; cannot disable monitor mode".into());
        }
        // ip link set <iface> down
        let s = Command::new("ip")
            .arg("link")
            .arg("set")
            .arg(iface)
            .arg("down")
            .status()
            .map_err(|e| format!("failed to run ip down: {}", e))?;
        if !s.success() {
            return Err(format!("ip down returned status {}", s));
        }

        // iw dev <iface> set type managed
        let s = Command::new("iw")
            .arg("dev")
            .arg(iface)
            .arg("set")
            .arg("type")
            .arg("managed")
            .status()
            .map_err(|e| format!("failed to run iw set type managed: {}", e))?;
        if !s.success() {
            return Err(format!("iw set type returned status {}", s));
        }

        // ip link set <iface> up
        let s = Command::new("ip")
            .arg("link")
            .arg("set")
            .arg(iface)
            .arg("up")
            .status()
            .map_err(|e| format!("failed to run ip up: {}", e))?;
        if !s.success() {
            return Err(format!("ip up returned status {}", s));
        }

        Ok(())
    } else if cfg!(target_os = "macos") {
        Err("automatic monitor-mode management is not implemented on macOS".into())
    } else {
        Err("monitor-mode management not supported on this OS".into())
    }
}

fn channel_sweep_detect(iface: &str, target: &[u8; 6]) -> Option<u8> {
    let candidates: &[u8] = &[1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161];
    let mut best_ch = None;
    let mut best_hits = 0u64;

    for &ch in candidates {
        if let Err(e) = set_channel_system(iface, ch) {
            log_debug(&format!("Channel {} set failed: {}", ch, e));
            continue;
        }
        // Allow the interface to settle on the new channel
        std::thread::sleep(Duration::from_millis(250));

        let mut local_hits = 0u64;
        if let Ok(mut cap) = open_capture(iface, 400) {
            let mut packets = 0u32;
            let sweep_deadline = Instant::now() + Duration::from_millis(450);
            while packets < 200 && Instant::now() < sweep_deadline {
                match cap.next_packet() {
                    Ok(pkt) => {
                        packets += 1;
                        if packet_contains_mac(pkt.data, target) {
                            local_hits += 1;
                            if local_hits > best_hits {
                                best_hits = local_hits;
                                best_ch = Some(ch);
                            }
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => break,
                    Err(_) => break,
                }
            }
        }

        log_debug(&format!("Channel {} sweep hits: {}", ch, local_hits));
    }

    best_ch
}

fn auto_select_channel(iface: &str, target: &[u8; 6]) -> Result<Option<u8>, String> {
    let target_s = format_mac_bytes(target).to_lowercase();

    // First try fast path: use airport scan to find BSSID exact match
    if let Some(rows) = scan_system_channels(iface) {
        log_debug(&format!("airport -s found {} entries", rows.len()));
        for (bssid, ch) in &rows {
            if bssid.to_lowercase() == target_s {
                log_debug(&format!("airport -s matched target on channel {}", ch));
                if let Err(e) = set_channel_system(iface, *ch) {
                    return Err(format!("failed to set channel {}: {}", ch, e));
                }
                return Ok(Some(*ch));
            }
        }
    }

    // Fallback: sweep candidate channels with short sniff windows
    let sweep = channel_sweep_detect(iface, target);
    if let Some(ch) = sweep {
        if let Err(e) = set_channel_airport(iface, ch) {
            return Err(format!("failed to set channel {}: {}", ch, e));
        }
        return Ok(Some(ch));
    }

    Ok(None)
}

impl Default for GuiApp {
    fn default() -> Self {
        let interfaces = Device::list()
            .unwrap_or_default()
            .into_iter()
            .map(|d| d.name)
            .collect::<Vec<_>>();

        Self {
            interfaces,
            selected_iface: None,
            show_iface_list: false,
            mac_input: String::new(),
            mac_valid: false,
            auto_channel_enabled: true,
            manage_monitor: false,
            monitor_managed_by_app: false,
            scanning: false,
            total_frames: 0,
            hits: 0,
            start_time: None,
            auto_channel: None,
            channel_note: None,
            rx: None,
            stop_flag: None,
            error: None,
            last_rssi: None,
            smoothed_rssi: None,
        }
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll updates from capture thread
        if let Some(rx) = &self.rx {
            let mut got = false;
            while let Ok(u) = rx.try_recv() {
                self.total_frames = u.total_frames;
                self.hits = u.hits;
                self.last_rssi = u.last_rssi;
                // Update smoothed RSSI via exponential moving average
                if let Some(r) = u.last_rssi {
                    let r_f = r as f32;
                    const ALPHA: f32 = 0.2; // smoothing factor (0..1)
                    self.smoothed_rssi = Some(match self.smoothed_rssi {
                        Some(prev) => prev * (1.0 - ALPHA) + r_f * ALPHA,
                        None => r_f,
                    });
                }
                got = true;
            }
            if got {
                // Ensure UI repaints immediately when new data arrives
                ctx.request_repaint();
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("PinnacleFinder — MAC Hunter");
            ui.add_space(12.0);
            // Prominent signal indicator placed above the Stats section so it's visible
            ui.group(|ui| {
                ui.vertical_centered(|ui| {
                    ui.heading("Signal Strength");
                    ui.add_space(6.0);
                    let rssi_opt2 = self.smoothed_rssi.or(self.last_rssi.map(|r| r as f32));
                    let strength2 = rssi_opt2.map(|v| rssi_f32_to_strength(v)).unwrap_or(0.0);
                    let color2 = if strength2 > 0.66 {
                        egui::Color32::from_rgb(212, 175, 55) // gold accent
                    } else if strength2 > 0.33 {
                        egui::Color32::from_rgb(240, 200, 60)
                    } else {
                        egui::Color32::from_rgb(220, 60, 60)
                    };
                    ui.horizontal(|ui| {
                        if let Some(v) = rssi_opt2 {
                            ui.label(format!("{:.0} dBm", v));
                        } else {
                            ui.label("-- dBm");
                        }
                        ui.add(egui::ProgressBar::new(strength2).show_percentage());
                    });
                    ui.add_space(6.0);
                    // Draw a larger bar widget
                    draw_signal_bars(ui, strength2, color2, egui::Vec2::new(220.0, 72.0));
                });
            });

            ui.heading("Network interface (pcap)");
            // Large touch-friendly selector button
            let label = self.selected_iface.clone().unwrap_or_else(|| "Select interface".into());
            let btn_size = egui::Vec2::new(ui.available_width(), 56.0);
            if ui.add_sized(btn_size, egui::Button::new(label)).clicked() {
                self.show_iface_list = !self.show_iface_list;
            }

            // Show a large, scrollable list of interfaces when requested
            if self.show_iface_list {
                egui::Frame::popup(ui.style()).show(ui, |ui| {
                    ui.set_min_height(200.0);
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        for iface in &self.interfaces {
                            let iface_btn_size = egui::Vec2::new(ui.available_width() - 8.0, 56.0);
                            if ui.add_sized(iface_btn_size, egui::Button::new(iface)).clicked() {
                                self.selected_iface = Some(iface.clone());
                                self.show_iface_list = false;
                            }
                            ui.add_space(6.0);
                        }
                    });
                });
            }

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.auto_channel_enabled, "Auto channel select");
                ui.add_space(8.0);
                ui.checkbox(&mut self.manage_monitor, "Manage monitor mode");
            });

            ui.add_space(8.0);

            ui.label("Target MAC address (AA:BB:CC:DD:EE:FF)");
            // Single input box for the full MAC address (legacy behavior)
            let resp = ui.add(egui::TextEdit::singleline(&mut self.mac_input).desired_width(340.0));
            if resp.changed() {
                self.mac_input = format_mac_from_raw(&self.mac_input);
            }

            ui.add_space(6.0);
            // Always-visible on-screen hex keyboard for touchscreen users
            ui.label("On-screen keyboard:");
            ui.add_space(4.0);
            let keys_rows: &[&[&str]] = &[
                &["1","2","3","4","5","6","7","8","9","0"],
                &["A","B","C","D","E","F","<-","Clr"],
            ];

            for row in keys_rows {
                ui.horizontal(|ui| {
                    for &k in *row {
                        let btn = egui::Button::new(k).min_size(egui::Vec2::new(48.0, 48.0));
                        if ui.add_sized(egui::Vec2::new(64.0, 64.0), btn).clicked() {
                            match k {
                                "<-" => {
                                    // remove last hex digit (ignore colons)
                                    let raw = self.mac_input.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>();
                                    if raw.is_empty() {
                                        self.mac_input.clear();
                                    } else {
                                        let mut new_raw = raw;
                                        new_raw.pop();
                                        self.mac_input = format_mac_from_raw(&new_raw);
                                    }
                                }
                                "Clr" => {
                                    self.mac_input.clear();
                                }
                                ch => {
                                    // append hex char if under 12 hex digits
                                    let mut raw = self.mac_input.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>();
                                    if raw.len() < 12 {
                                        raw.push_str(ch);
                                        self.mac_input = format_mac_from_raw(&raw);
                                    }
                                }
                            }
                        }
                    }
                });
                ui.add_space(6.0);
            }

            let mac_str = self.mac_input.clone();
            self.mac_valid = parse_mac(&mac_str).is_some();
            if !self.mac_input.is_empty() && !self.mac_valid {
                ui.colored_label(egui::Color32::from_rgb(200, 50, 50), "Invalid MAC format");
            }

            ui.add_space(12.0);

            let button_text = if self.scanning { "Stop Scan" } else { "Start Scan" };
            let desired = egui::Vec2::new(ui.available_width(), 64.0);
            if ui.add_sized(desired, egui::Button::new(button_text)).clicked() {
                if self.scanning {
                    if let Some(flag) = &self.stop_flag {
                        flag.store(true, Ordering::Relaxed);
                    }
                    self.scanning = false;
                    self.stop_flag = None;
                    // If we enabled monitor mode, attempt to restore managed mode
                    if self.monitor_managed_by_app {
                        if let Some(iface_name) = &self.selected_iface {
                            match disable_monitor_mode(iface_name) {
                                Ok(()) => {
                                    self.channel_note = Some("Monitor mode disabled; interface restored".into());
                                }
                                Err(e) => {
                                    self.channel_note = Some(format!("Monitor disable failed: {}", e));
                                }
                            }
                        }
                        self.monitor_managed_by_app = false;
                    }
                    self.channel_note = None;
                } else {
                    // Start
                    self.error = None;
                    self.total_frames = 0;
                    self.hits = 0;
                    self.start_time = Some(Instant::now());
                    self.auto_channel = None;
                    self.channel_note = None;

                    let iface = match &self.selected_iface {
                        Some(i) => i.clone(),
                        None => {
                            self.error = Some("Select a network interface first.".into());
                            return;
                        }
                    };

                    if !self.mac_valid {
                        self.error = Some("Invalid MAC address format.".into());
                        return;
                    }

                    let mac_str = self.mac_input.clone();
                    let mac_bytes = match parse_mac(&mac_str) {
                        Some(m) => m,
                        None => {
                            self.error = Some("Invalid MAC address format.".into());
                            return;
                        }
                    };

                    // Attempt auto channel selection (if enabled)
                    if self.auto_channel_enabled {
                        match auto_select_channel(&iface, &mac_bytes) {
                            Ok(Some(ch)) => {
                                self.auto_channel = Some(ch);
                                self.channel_note = Some(format!("Locked channel {} via auto-test", ch));
                            }
                            Ok(None) => {
                                self.channel_note = Some("Auto channel: no signal detected; staying on current channel".into());
                            }
                            Err(e) => {
                                self.channel_note = Some(format!("Auto channel failed: {e}"));
                            }
                        }
                    } else {
                        self.channel_note = Some("Auto channel selection disabled".into());
                    }

                    // If requested, attempt to enable monitor mode before launching capture
                    if self.manage_monitor {
                        match enable_monitor_mode(&iface) {
                            Ok(()) => {
                                self.monitor_managed_by_app = true;
                                // inform the user
                                self.channel_note = Some(match &self.channel_note {
                                    Some(n) => format!("{}; monitor mode enabled", n),
                                    None => "monitor mode enabled".into(),
                                });
                            }
                            Err(e) => {
                                self.error = Some(format!("Failed to enable monitor mode: {}", e));
                                return;
                            }
                        }
                    }

                    let (tx, rx) = mpsc::channel::<ScanUpdate>();
                    let stop_flag = Arc::new(AtomicBool::new(false));
                    let stop_clone = stop_flag.clone();
                    std::thread::spawn(move || {
                        capture_loop(iface, mac_bytes, tx, stop_clone);
                    });

                    self.rx = Some(rx);
                    self.stop_flag = Some(stop_flag);
                    self.scanning = true;
                }
            }

            ui.add_space(12.0);

            if let Some(err) = &self.error {
                ui.colored_label(egui::Color32::from_rgb(220, 40, 40), err);
            }

            ui.heading("Stats");
            let elapsed = self.start_time.map(|t| t.elapsed().as_secs_f32()).unwrap_or(0.0);
            let hit_rate = if elapsed > 0.0 { self.hits as f32 / elapsed } else { 0.0 };
            ui.label(format!("Frames seen: {}", self.total_frames));
            ui.label(format!("Matches: {}", self.hits));
            ui.label(format!("Elapsed: {:.1} s", elapsed));
            ui.label(format!("Hit rate: {:.2} hits/s", hit_rate));

            if let Some(ch) = self.auto_channel {
                ui.label(format!("Channel: {} (auto)", ch));
            }
            if let Some(note) = &self.channel_note {
                ui.small(note);
            }

            ui.add_space(8.0);
            // RSSI / signal strength indicator (uses smoothed RSSI when available)
            let rssi_opt = self.smoothed_rssi.or(self.last_rssi.map(|r| r as f32));
            // Compute strength (0..1). If no RSSI yet, show 0 so bars are visible but empty.
            let strength = rssi_opt.map(|v| rssi_f32_to_strength(v)).unwrap_or(0.0);
            // Color: red->yellow->green (kept for compatibility)
            let _color = if strength > 0.66 {
                egui::Color32::from_rgb(80, 200, 50)
            } else if strength > 0.33 {
                egui::Color32::from_rgb(240, 200, 60)
            } else {
                egui::Color32::from_rgb(220, 60, 60)
            };

            ui.horizontal(|ui| {
                if let Some(rssi_f) = rssi_opt {
                    ui.label(format!("Signal: {:.0} dBm", rssi_f));
                } else {
                    ui.label("Signal: -- dBm");
                }
                // Progress bar removed from bottom per request.
            });

            // (Smaller/bottom signal indicators removed; primary indicator remains above.)

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label("Interfaces found:");
                ui.label(format!("{}", self.interfaces.len()));
            });
            });
        });
    }
}

// --- Capture thread + helpers ---

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }

    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return None;
        }
        if let Ok(b) = u8::from_str_radix(part, 16) {
            bytes[i] = b;
        } else {
            return None;
        }
    }
    Some(bytes)
}

fn capture_loop(iface: String, mac: [u8; 6], tx: mpsc::Sender<ScanUpdate>, stop_flag: Arc<AtomicBool>) {
    let target = mac.to_vec();

    let debug_on = debug_enabled();
    if debug_on {
        log_debug(&format!(
            "Starting scan for MAC {} on interface {}",
            format_mac_bytes(&mac),
            iface
        ));
    }
    
    println!("\n[Capture] Starting scan for MAC: {}", format_mac_bytes(&mac));
    println!("[Capture] Interface: {}", iface);

    let mut cap = match open_capture(&iface, 1000) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ERROR] Failed to open device: {}", e);
            return;
        }
    };

    if debug_on {
        log_debug("Device opened in promiscuous mode with 1000ms timeout");
    }

    let mut total_frames: u64 = 0;
    let mut hits: u64 = 0;
    let mut last_rssi: Option<i8> = None;
    let mut last_seen_mac: Option<[u8; 6]> = None;
    let mut last_send = Instant::now();
    let mut last_debug = Instant::now();
    let mut parse_failures: u64 = 0;
    let mut raw_matches: u64 = 0;
    let mut timeouts: u64 = 0;
    let scan_start = Instant::now();

    while !stop_flag.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(pkt) => {
                total_frames += 1;

                // Try to parse 802.11 + radiotap to get src MAC and RSSI
                if let Some((src, rssi)) = extract_80211_src_mac_and_rssi(pkt.data) {
                    last_rssi = Some(rssi); // track latest RSSI even if not the target
                    last_seen_mac = Some(src);

                    if debug_on {
                        println!(
                            "[SEEN] MAC: {} | RSSI: {} dBm",
                            format_mac_bytes(&src),
                            rssi
                        );
                    }

                    if src.to_vec() == target {
                        hits += 1;
                        
                        // Print packet match to terminal
                        let elapsed = scan_start.elapsed().as_secs_f32();
                        println!(
                            "[MATCH] Hit #{} - MAC: {} | RSSI: {} dBm | Elapsed: {:.2}s",
                            hits,
                            format_mac_bytes(&src),
                            rssi,
                            elapsed
                        );
                    }
                } else {
                    parse_failures += 1;
                    // Fallback: if we can't parse radiotap, still try a raw match
                    if pkt.data.len() >= 6 {
                        if pkt.data.windows(6).any(|w| w == target.as_slice()) {
                            hits += 1;
                            raw_matches += 1;
                            let elapsed = scan_start.elapsed().as_secs_f32();
                            println!(
                                "[MATCH] Hit #{} - MAC: {} | RSSI: Not available | Elapsed: {:.2}s (parsed as raw match)",
                                hits,
                                format_mac_bytes(&mac),
                                elapsed
                            );
                        }
                    }
                }

                // Send update to UI every 100ms
                if last_send.elapsed() >= std::time::Duration::from_millis(100) {
                    let _ = tx.send(ScanUpdate { total_frames, hits, last_rssi });
                    last_send = Instant::now();
                }

                // Periodic debug heartbeat
                if debug_on && last_debug.elapsed() >= std::time::Duration::from_secs(2) {
                    let last_rssi_display = last_rssi
                        .map(|r| r.to_string())
                        .unwrap_or_else(|| "--".to_string());
                    let last_seen_display = last_seen_mac
                        .map(|m| format_mac_bytes(&m))
                        .unwrap_or_else(|| "--".to_string());
                    log_debug(&format!(
                        "Frames: {total_frames}, Hits: {hits}, Parse misses: {parse_failures}, Raw matches: {raw_matches}, Timeouts: {timeouts}, Last RSSI: {last_rssi_display} dBm, Last seen: {last_seen_display}"
                    ));
                    last_debug = Instant::now();
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                timeouts += 1;
                if debug_on && timeouts % 20 == 0 {
                    log_debug("pcap timeout (no packet received in interval)");
                }
            }
            Err(e) => {
                eprintln!("[WARNING] Packet capture error: {}", e);
            }
        }
    }

    // Send final update
    let _ = tx.send(ScanUpdate { total_frames, hits, last_rssi });
    
    println!(
        "\n[Capture] Scan complete. Total frames: {}, Matches: {}",
        total_frames, hits
    );

    if debug_on {
        log_debug("Capture loop exited after stop flag set");
    }
}

/// Parse Radiotap + 802.11 header.
/// Returns (transmitter MAC, RSSI) if we can parse both.
fn extract_80211_src_mac_and_rssi(data: &[u8]) -> Option<([u8; 6], i8)> {
    // Radiotap header minimum is 8 bytes
    if data.len() < 8 {
        return None;
    }

    // Check radiotap header version (should be 0)
    if data[0] != 0 {
        return None;
    }

    let radiotap_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    
    // Validate radiotap length is reasonable
    if radiotap_len < 8 || radiotap_len > data.len() {
        return None;
    }

    let present = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    
    // Skip if extended bitmap is present (bit 31)
    if (present & (1 << 31)) != 0 {
        return None;
    }

    let mut offset = 8_usize;
    let mut rssi_opt: Option<i8> = None;

    // Parse radiotap fields according to IEEE 802.11-2020 radiotap specification
    for field in 0..31 {
        if (present & (1 << field)) == 0 {
            continue;
        }

        // Field sizes and alignments according to radiotap spec
        let (size, align) = match field {
            0 => (8, 8),   // TSFT: u64 timestamp
            1 => (1, 1),   // Flags: u8
            2 => (1, 1),   // Rate: u8 (500 kbps units)
            3 => (4, 2),   // Channel: u16 frequency, u16 flags
            4 => (2, 2),   // FHSS: u8 hop set, u8 hop pattern
            5 => (1, 1),   // Antenna signal (RSSI): i8 or u8 in dBm
            6 => (1, 1),   // Antenna noise: i8 in dBm
            7 => (2, 2),   // Lock quality: u16
            8 => (2, 2),   // TX power: u16
            9 => (1, 1),   // Antenna: u8
            10 => (1, 1),  // DB antenna signal: u8 in dBm
            11 => (1, 1),  // DB antenna noise: u8 in dBm
            12 => (2, 2),  // RX flags: u16
            13 => (2, 2),  // TX flags: u16
            14 => (1, 1),  // RTS retries: u8
            15 => (1, 1),  // Data retries: u8
            _ => {
                // Unknown field, skip it - but we can't determine its size
                // so we must return None to be safe
                return None;
            }
        };

        // Apply alignment padding
        let aligned = if align > 1 {
            (offset + (align - 1)) & !(align - 1)
        } else {
            offset
        };

        // Bounds check
        if aligned + size > radiotap_len || aligned + size > data.len() {
            return None;
        }

        // Extract RSSI from field 5 (antenna signal)
        if field == 5 {
            // RSSI is typically signed, convert to i8
            rssi_opt = Some(data[aligned] as i8);
        }

        offset = aligned + size;
    }

    // RSSI is required for a valid match
    let rssi = rssi_opt?;

    // Now parse the 802.11 frame header
    let hdr = &data[radiotap_len..];

    // Minimum 802.11 frame: 24 bytes (basic header without QoS/HT)
    if hdr.len() < 24 {
        return None;
    }

    let frame_control = u16::from_le_bytes([hdr[0], hdr[1]]);
    let frame_type = (frame_control >> 2) & 0x3;

    // Frame type 1 = Control frame (not what we want for source MAC extraction)
    // We want management (0) or data (2) frames
    if frame_type == 1 {
        return None;
    }

    let to_ds = (frame_control & 0x0100) != 0;
    let from_ds = (frame_control & 0x0200) != 0;

    // Need address 4 when both DS bits are set
    let min_len = if to_ds && from_ds { 30 } else { 24 };
    if hdr.len() < min_len {
        return None;
    }

    // Address layout per 802.11:
    // addr1 @ 4..10, addr2 @ 10..16, addr3 @ 16..22, addr4 @ 24..30 (if present)
    let mut src = [0u8; 6];
    if to_ds && from_ds {
        // WDS frame: source is addr4
        src.copy_from_slice(&hdr[24..30]);
    } else if to_ds {
        // To DS (STA -> AP): source is addr2
        src.copy_from_slice(&hdr[10..16]);
    } else if from_ds {
        // From DS (AP -> STA): source is addr3
        src.copy_from_slice(&hdr[16..22]);
    } else {
        // Ad-hoc / mgmt: source is addr2
        src.copy_from_slice(&hdr[10..16]);
    }

    Some((src, rssi))
}


// (legacy integer RSSI helper removed — f32-based helper `rssi_f32_to_strength` used)

/// Format MAC bytes as a colon-separated hex string
fn format_mac_bytes(mac: &[u8; 6]) -> String {
    let mut result = String::new();
    for (i, &byte) in mac.iter().enumerate() {
        if i > 0 {
            result.push(':');
        }
        let _ = write!(result, "{:02X}", byte);
    }
    result
}

fn rssi_f32_to_strength(rssi: f32) -> f32 {
    let min = -100.0_f32;
    let max = -30.0_f32;
    ((rssi - min) / (max - min)).clamp(0.0, 1.0)
}

fn draw_signal_bars(ui: &mut egui::Ui, strength: f32, color: egui::Color32, desired: egui::Vec2) {
    // Draw 5 vertical rounded bars like a Wi-Fi/signal indicator using `desired` size
    let n = 5usize;
    let (rect, _resp) = ui.allocate_exact_size(desired, egui::Sense::hover());
    let painter = ui.painter();
    let spacing = 8.0_f32;
    let bar_width = (rect.width() - spacing * (n as f32 - 1.0)) / n as f32;
    for i in 0..n {
        let frac = (i + 1) as f32 / n as f32; // 0.2 .. 1.0
        let bar_h = rect.height() * frac;
        let x = rect.left_top().x + i as f32 * (bar_width + spacing);
        let y = rect.bottom() - bar_h;
        let bar_rect = egui::Rect::from_min_size(egui::pos2(x, y), egui::vec2(bar_width, bar_h));
        let fill = if strength >= frac { color } else { egui::Color32::from_gray(80) };
        // Slightly larger corner radius
        painter.rect_filled(bar_rect, egui::CornerRadius::same(6u8), fill);
    }
}

/// Format a raw hex string into uppercase colon-separated MAC pairs, max 6 bytes.
fn format_mac_from_raw(raw: &str) -> String {
    let mut r = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>();
    if r.len() > 12 { r.truncate(12); }
    let mut parts: Vec<String> = Vec::new();
    let mut idx = 0usize;
    while idx < r.len() {
        let end = usize::min(idx + 2, r.len());
        parts.push(r[idx..end].to_string());
        idx += 2;
    }
    if parts.is_empty() {
        String::new()
    } else {
        parts.join(":").to_uppercase()
    }
}

fn main() {
    let options = NativeOptions::default();
    if let Err(e) = run_native(
        "PinnacleFinder MAC Hunter",
        options,
        Box::new(|cc| {
            apply_pinnacle_theme(&cc.egui_ctx);
            Ok(Box::new(GuiApp::default()))
        }),
    ) {
        eprintln!("Failed to start GUI: {e}");
    }
}

/// Apply a black-and-gold 'Pinnacle' color scheme to `egui`.
fn apply_pinnacle_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    // Start from dark visuals and tweak colors
    style.visuals = egui::Visuals::dark();

    let gold = egui::Color32::from_rgb(212, 175, 55);
    let black = egui::Color32::from_rgb(8, 8, 8);
    let panel = egui::Color32::from_rgb(14, 14, 14);
    let widget_hover = egui::Color32::from_rgb(32, 32, 32);
    let widget_active = egui::Color32::from_rgb(60, 50, 20);

    style.visuals.override_text_color = Some(egui::Color32::from_rgb(230, 230, 230));
    style.visuals.window_fill = black;
    style.visuals.panel_fill = panel;
    style.visuals.widgets.inactive.bg_fill = panel;
    style.visuals.widgets.hovered.bg_fill = widget_hover;
    style.visuals.widgets.active.bg_fill = widget_active;
    style.visuals.selection.bg_fill = gold;
    style.visuals.widgets.inactive.fg_stroke.color = egui::Color32::from_rgb(200, 200, 200);
    style.visuals.widgets.hovered.fg_stroke.color = gold;
    style.visuals.widgets.active.fg_stroke.color = gold;

    // no additional text-style tweaks for now

    // Slightly larger spacing for touch
    style.spacing.item_spacing = egui::vec2(12.0, 12.0);

    ctx.set_style(style);
}

