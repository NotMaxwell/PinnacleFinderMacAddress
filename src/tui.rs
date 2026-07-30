//! Terminal-UI front-end (raw termios + ANSI escapes via libc).
//! Replaces the original egui/eframe GUI for an apples-to-apples TUI comparison.
use std::fmt::Write as FmtWrite;
use std::io::Write as IoWrite;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Instant;

use pcap::Device;

use crate::capture::{ScanUpdate, auto_select_channel, capture_loop};
use crate::mac::{format_mac_from_hex, parse_mac};
use crate::sysiface::{disable_monitor_mode, enable_monitor_mode};

const ALPHA: f32 = 0.2; // RSSI smoothing factor

const GOLD: &str = "\x1b[33m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const DIM: &str = "\x1b[90m";
const BOLD: &str = "\x1b[1m";
const REV: &str = "\x1b[7m";
const UND: &str = "\x1b[4m";
const RESET: &str = "\x1b[0m";

fn monitor_supported() -> bool {
    cfg!(target_os = "linux")
}

pub fn rssi_f32_to_strength(rssi: f32) -> f32 {
    let min = -100.0_f32;
    let max = -30.0_f32;
    ((rssi - min) / (max - min)).clamp(0.0, 1.0)
}

fn strength_color(s: f32) -> &'static str {
    if s > 0.66 {
        GREEN
    } else if s > 0.33 {
        YELLOW
    } else {
        RED
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Normal,
    IfaceSelect,
    MacEdit,
}

enum Key {
    Up,
    Down,
    Enter,
    Esc,
    Backspace,
    Char(u8),
    Nothing,
}

// --- terminal raw mode (restored on drop) ---

struct RawMode {
    orig: libc::termios,
}

impl RawMode {
    fn enable() -> Self {
        unsafe {
            let mut term: libc::termios = std::mem::zeroed();
            libc::tcgetattr(libc::STDIN_FILENO, &mut term);
            let orig = term;
            term.c_lflag &= !(libc::ICANON | libc::ECHO);
            term.c_cc[libc::VMIN] = 0;
            term.c_cc[libc::VTIME] = 1; // 0.1s read timeout -> ~10 Hz poll
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &term);
            RawMode { orig }
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.orig);
        }
    }
}

fn read_key() -> Key {
    let mut buf = [0u8; 8];
    let n = unsafe {
        libc::read(
            libc::STDIN_FILENO,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if n <= 0 {
        return Key::Nothing;
    }
    let n = n as usize;
    match buf[0] {
        0x1b => {
            if n >= 3 && buf[1] == b'[' {
                match buf[2] {
                    b'A' => Key::Up,
                    b'B' => Key::Down,
                    _ => Key::Esc,
                }
            } else {
                Key::Esc
            }
        }
        b'\n' | b'\r' => Key::Enter,
        0x7f | 0x08 => Key::Backspace,
        c => Key::Char(c),
    }
}

// --- screen buffer ---

struct Screen {
    buf: String,
}

impl Screen {
    fn new() -> Self {
        Screen {
            buf: String::from("\x1b[2J"),
        }
    }
    fn put(&mut self, row: usize, col: usize, s: &str) {
        let _ = write!(self.buf, "\x1b[{row};{col}H{s}");
    }
    fn flush(&self) {
        let mut so = std::io::stdout();
        let _ = so.write_all(self.buf.as_bytes());
        let _ = so.flush();
    }
}

// --- application state ---

struct App {
    interfaces: Vec<String>,
    selected_iface: Option<usize>,
    iface_cursor: usize,

    mac_input: String,
    mac_valid: bool,

    last_rssi: Option<i8>,
    smoothed: Option<f32>,

    auto_channel_enabled: bool,
    manage_monitor: bool,
    monitor_managed_by_app: bool,

    scanning: bool,
    total_frames: u64,
    hits: u64,
    start_time: Option<Instant>,

    auto_channel: Option<u8>,
    channel_note: Option<String>,
    error: Option<String>,

    rx: Option<mpsc::Receiver<ScanUpdate>>,
    stop_flag: Option<Arc<AtomicBool>>,
    mode: Mode,
}

impl App {
    fn new(interfaces: Vec<String>) -> Self {
        App {
            interfaces,
            selected_iface: None,
            iface_cursor: 0,
            mac_input: String::new(),
            mac_valid: false,
            last_rssi: None,
            smoothed: None,
            auto_channel_enabled: true,
            manage_monitor: false,
            monitor_managed_by_app: false,
            scanning: false,
            total_frames: 0,
            hits: 0,
            start_time: None,
            auto_channel: None,
            channel_note: None,
            error: None,
            rx: None,
            stop_flag: None,
            mode: Mode::Normal,
        }
    }

    fn iface_name(&self) -> Option<&str> {
        self.selected_iface
            .and_then(|i| self.interfaces.get(i))
            .map(|s| s.as_str())
    }

    fn poll(&mut self) {
        if let Some(rx) = &self.rx {
            while let Ok(u) = rx.try_recv() {
                self.total_frames = u.total_frames;
                self.hits = u.hits;
                self.last_rssi = u.last_rssi;
                if let Some(r) = u.last_rssi {
                    let rf = r as f32;
                    self.smoothed = Some(match self.smoothed {
                        Some(p) => p * (1.0 - ALPHA) + rf * ALPHA,
                        None => rf,
                    });
                }
            }
        }
    }

    fn mac_edit_key(&mut self, key: Key) {
        let mut raw: String = self
            .mac_input
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect();
        match key {
            Key::Backspace => {
                raw.pop();
            }
            Key::Char(c) => {
                let ch = c as char;
                if ch.is_ascii_hexdigit() && raw.len() < 12 {
                    raw.push(ch);
                }
            }
            _ => {}
        }
        self.mac_input = format_mac_from_hex(&raw);
        self.mac_valid = parse_mac(&self.mac_input).is_some();
    }

    fn start_scan(&mut self) {
        self.error = None;
        self.total_frames = 0;
        self.hits = 0;
        self.auto_channel = None;
        self.channel_note = None;
        self.smoothed = None;
        self.last_rssi = None;

        let iface = match self.iface_name() {
            Some(i) => i.to_string(),
            None => {
                self.error = Some("Select a network interface first.".into());
                return;
            }
        };
        if !self.mac_valid {
            self.error = Some("Invalid MAC address format.".into());
            return;
        }
        let mac = match parse_mac(&self.mac_input) {
            Some(m) => m,
            None => {
                self.error = Some("Invalid MAC address format.".into());
                return;
            }
        };

        if self.auto_channel_enabled {
            match auto_select_channel(&iface, &mac) {
                Ok(Some(ch)) => {
                    self.auto_channel = Some(ch);
                    self.channel_note = Some(format!("Locked channel {ch} via auto-test"));
                }
                Ok(None) => {
                    self.channel_note =
                        Some("Auto channel: no signal; staying on current channel".into());
                }
                Err(e) => {
                    self.channel_note = Some(format!("Auto channel failed: {e}"));
                }
            }
        } else {
            self.channel_note = Some("Auto channel selection disabled".into());
        }

        if self.manage_monitor {
            if monitor_supported() {
                match enable_monitor_mode(&iface) {
                    Ok(()) => {
                        self.monitor_managed_by_app = true;
                        self.channel_note = Some(match &self.channel_note {
                            Some(n) => format!("{n}; monitor mode enabled"),
                            None => "monitor mode enabled".into(),
                        });
                    }
                    Err(e) => {
                        self.error = Some(format!("Failed to enable monitor mode: {e}"));
                        return;
                    }
                }
            } else {
                self.channel_note = Some("Monitor mode management not available on this OS".into());
            }
        }

        let (tx, rx) = mpsc::channel::<ScanUpdate>();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_clone = stop_flag.clone();
        std::thread::spawn(move || capture_loop(iface, mac, tx, stop_clone));

        self.rx = Some(rx);
        self.stop_flag = Some(stop_flag);
        self.start_time = Some(Instant::now());
        self.scanning = true;
    }

    fn stop_scan(&mut self) {
        if let Some(flag) = &self.stop_flag {
            flag.store(true, Ordering::Relaxed);
        }
        self.scanning = false;
        self.stop_flag = None;
        self.rx = None;
        if self.monitor_managed_by_app {
            if let Some(iface) = self.iface_name().map(|s| s.to_string()) {
                match disable_monitor_mode(&iface) {
                    Ok(()) => {
                        self.channel_note = Some("Monitor mode disabled; interface restored".into())
                    }
                    Err(e) => self.channel_note = Some(format!("Monitor disable failed: {e}")),
                }
            }
            self.monitor_managed_by_app = false;
        }
    }

    fn render(&self) {
        let mut s = Screen::new();
        let mut row = 1usize;

        s.put(row, 3, &format!("{BOLD}{GOLD}PinnacleFinder - MAC Hunter (TUI / Rust){RESET}"));
        row += 2;

        // signal strength
        let rssi = self.smoothed.or(self.last_rssi.map(|r| r as f32));
        let strength = rssi.map(rssi_f32_to_strength).unwrap_or(0.0);
        let color = strength_color(strength);
        s.put(row, 3, &format!("{BOLD}{GOLD}Signal Strength{RESET}"));
        match rssi {
            Some(v) => s.put(row, 21, &format!("{v:6.0} dBm")),
            None => s.put(row, 21, "  -- dBm"),
        }
        let mut bar = String::from("[");
        for i in 0..5 {
            let frac = (i + 1) as f32 / 5.0;
            if strength >= frac {
                let _ = write!(bar, "{color}###{RESET} ");
            } else {
                let _ = write!(bar, "{DIM}...{RESET} ");
            }
        }
        let _ = write!(bar, "] {:3.0}%", strength * 100.0);
        s.put(row, 33, &bar);
        row += 2;

        // interface
        let iface = self.iface_name().unwrap_or("<none selected>");
        s.put(row, 3, &format!("Interface [i]: {iface}"));
        row += 1;

        if self.mode == Mode::IfaceSelect {
            s.put(row, 5, "-- select interface (Up/Down, Enter, Esc) --");
            row += 1;
            for (i, name) in self.interfaces.iter().enumerate() {
                if i == self.iface_cursor {
                    s.put(row, 7, &format!("{REV}> {name}{RESET}"));
                } else {
                    s.put(row, 7, &format!("  {name}"));
                }
                row += 1;
            }
        }

        s.put(
            row,
            3,
            &format!(
                "Auto channel [a]: {}    Manage monitor [o]: {}{}",
                if self.auto_channel_enabled { "ON " } else { "OFF" },
                if self.manage_monitor { "ON " } else { "OFF" },
                if monitor_supported() { "" } else { " (unsupported OS)" },
            ),
        );
        row += 1;

        // MAC input
        let editing = self.mode == Mode::MacEdit;
        let disp = format!("{:<17}", self.mac_input);
        if editing {
            s.put(row, 3, &format!("Target MAC [e]: {UND}{disp}{RESET}  (type hex, Backspace, Enter/Esc)"));
        } else if !self.mac_input.is_empty() && !self.mac_valid {
            s.put(row, 3, &format!("Target MAC [e]: {disp}  {RED}INVALID{RESET}"));
        } else if self.mac_valid {
            s.put(row, 3, &format!("Target MAC [e]: {disp}  {GREEN}ok{RESET}"));
        } else {
            s.put(row, 3, &format!("Target MAC [e]: {disp}"));
        }
        row += 2;

        s.put(row, 3, &format!("{BOLD}[s] {}{RESET}", if self.scanning { "STOP SCAN" } else { "START SCAN" }));
        row += 2;

        if let Some(e) = &self.error {
            s.put(row, 3, &format!("{RED}Error: {e}{RESET}"));
            row += 1;
        }

        let elapsed = self.start_time.map(|t| t.elapsed().as_secs_f32()).unwrap_or(0.0);
        let hit_rate = if elapsed > 0.0 { self.hits as f32 / elapsed } else { 0.0 };
        s.put(row, 3, &format!("{BOLD}{GOLD}Stats{RESET}"));
        row += 1;
        s.put(row, 5, &format!("Frames seen : {}", self.total_frames));
        row += 1;
        s.put(row, 5, &format!("Matches     : {}", self.hits));
        row += 1;
        s.put(row, 5, &format!("Elapsed     : {elapsed:.1} s"));
        row += 1;
        s.put(row, 5, &format!("Hit rate    : {hit_rate:.2} hits/s"));
        row += 1;
        if let Some(ch) = self.auto_channel {
            s.put(row, 5, &format!("Channel     : {ch} (auto)"));
            row += 1;
        }
        if let Some(n) = &self.channel_note {
            s.put(row, 5, &format!("Note        : {n}"));
            row += 1;
        }
        s.put(row, 5, &format!("Interfaces  : {}", self.interfaces.len()));
        row += 2;

        s.put(row, 3, &format!("{DIM}[q] quit  [i] iface  [e] mac  [a] auto  [o] monitor  [s] scan{RESET}"));
        s.flush();
    }
}

pub fn run() -> std::io::Result<()> {
    let interfaces = Device::list()
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.name)
        .collect::<Vec<_>>();
    let mut app = App::new(interfaces);

    let _raw = RawMode::enable();
    print!("\x1b[2J\x1b[?25l"); // clear + hide cursor
    std::io::stdout().flush().ok();

    let mut running = true;
    while running {
        app.poll();
        app.render();
        let key = read_key();

        match app.mode {
            Mode::IfaceSelect => match key {
                Key::Up => {
                    app.iface_cursor = app.iface_cursor.saturating_sub(1);
                }
                Key::Down => {
                    if app.iface_cursor + 1 < app.interfaces.len() {
                        app.iface_cursor += 1;
                    }
                }
                Key::Enter => {
                    if !app.interfaces.is_empty() {
                        app.selected_iface = Some(app.iface_cursor);
                    }
                    app.mode = Mode::Normal;
                }
                Key::Esc => app.mode = Mode::Normal,
                _ => {}
            },
            Mode::MacEdit => match key {
                Key::Enter | Key::Esc => app.mode = Mode::Normal,
                other => app.mac_edit_key(other),
            },
            Mode::Normal => match key {
                Key::Char(b'q') | Key::Char(b'Q') => running = false,
                Key::Char(b'i') | Key::Char(b'I') => {
                    if !app.interfaces.is_empty() {
                        app.iface_cursor = app.selected_iface.unwrap_or(0);
                        app.mode = Mode::IfaceSelect;
                    }
                }
                Key::Char(b'e') | Key::Char(b'E') => app.mode = Mode::MacEdit,
                Key::Char(b'a') | Key::Char(b'A') => {
                    app.auto_channel_enabled = !app.auto_channel_enabled
                }
                Key::Char(b'o') | Key::Char(b'O') => {
                    if monitor_supported() {
                        app.manage_monitor = !app.manage_monitor;
                    }
                }
                Key::Char(b's') | Key::Char(b'S') => {
                    if app.scanning {
                        app.stop_scan();
                    } else {
                        app.start_scan();
                    }
                }
                _ => {}
            },
        }
    }

    if app.scanning {
        app.stop_scan();
    }
    print!("\x1b[2J\x1b[H\x1b[?25h"); // clear + show cursor
    std::io::stdout().flush().ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rssi_strength_endpoints() {
        assert!((rssi_f32_to_strength(-100.0) - 0.0).abs() < 1e-6);
        assert!((rssi_f32_to_strength(-30.0) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn rssi_strength_midpoint_and_clamp() {
        assert!((rssi_f32_to_strength(-65.0) - 0.5).abs() < 1e-5);
        assert!((rssi_f32_to_strength(-120.0) - 0.0).abs() < 1e-6);
        assert!((rssi_f32_to_strength(0.0) - 1.0).abs() < 1e-6);
    }
}
