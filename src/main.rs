use eframe::{egui, run_native, NativeOptions};
use pcap::{Capture, Device};

use std::sync::{mpsc, Arc};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

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

    scanning: bool,
    total_frames: u64,
    hits: u64,
    start_time: Option<Instant>,

    rx: Option<mpsc::Receiver<ScanUpdate>>,
    stop_flag: Option<Arc<AtomicBool>>,
    error: Option<String>,
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
            scanning: false,
            total_frames: 0,
            hits: 0,
            start_time: None,
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
                } else {
                    // Start
                    self.error = None;
                    self.total_frames = 0;
                    self.hits = 0;
                    self.start_time = Some(Instant::now());

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

    let mut cap = match Capture::from_device(iface.as_str()).and_then(|d| d.promisc(true).timeout(1000).open()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[capture] Failed to open device: {e}");
            return;
        }
    };

    let mut total_frames: u64 = 0;
    let mut hits: u64 = 0;
    let mut last_rssi: Option<i8> = None;
    let mut last_send = std::time::Instant::now();

    while !stop_flag.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(pkt) => {
                total_frames += 1;

                // Try to parse 802.11 + radiotap to get src MAC and RSSI
                if let Some((src, rssi)) = extract_80211_src_mac_and_rssi(pkt.data) {
                    if src.to_vec() == target {
                        hits += 1;
                        last_rssi = Some(rssi);
                    }
                } else {
                    // Fallback: if we can't parse, still try a raw match
                    if pkt.data.len() >= 6 {
                        if pkt.data.windows(6).any(|w| w == target.as_slice()) {
                            hits += 1;
                        }
                    }
                }

                if last_send.elapsed() >= std::time::Duration::from_millis(100) {
                    let _ = tx.send(ScanUpdate { total_frames, hits, last_rssi });
                    last_send = std::time::Instant::now();
                }
            }
            Err(_) => {
                // timeout or transient error
            }
        }
    }

    let _ = tx.send(ScanUpdate { total_frames, hits, last_rssi });
}

/// Parse Radiotap + 802.11 header.
/// Returns (transmitter MAC, RSSI) if we can parse both.
fn extract_80211_src_mac_and_rssi(data: &[u8]) -> Option<([u8; 6], i8)> {
    if data.len() < 8 { return None; }
    let radiotap_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    if radiotap_len > data.len() { return None; }
    let present = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if (present & (1 << 31)) != 0 { return None; }

    let mut offset = 8_usize;
    let mut rssi_opt: Option<i8> = None;

    for field in 0..32 {
        if (present & (1 << field)) == 0 { continue; }
        let (size, align) = match field {
            0 => (8, 8), 1 => (1,1), 2 => (1,1), 3 => (4,2), 4 => (2,1),
            5 => (1,1), 6 => (1,1), 7 => (2,2), 8 => (2,2), 9 => (2,2),
            10 => (1,1), 11 => (1,1), 12 => (1,1), 13 => (1,1),
            _ => { return None; }
        };

        let aligned = if align > 1 { (offset + (align - 1)) & !(align - 1) } else { offset };
        if aligned + size > radiotap_len || aligned + size > data.len() { return None; }
        if field == 5 {
            rssi_opt = Some(data[aligned] as i8);
        }
        offset = aligned + size;
    }

    let rssi = rssi_opt?;
    let hdr = &data[radiotap_len..];
    if hdr.len() < 24 { return None; }
    let frame_control = u16::from_le_bytes([hdr[0], hdr[1]]);
    let frame_type = (frame_control >> 2) & 0x3;
    if frame_type == 1 { return None; }
    let mut src = [0u8;6];
    src.copy_from_slice(&hdr[10..16]);
    Some((src, rssi))
}


// (legacy integer RSSI helper removed — f32-based helper `rssi_f32_to_strength` used)

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

