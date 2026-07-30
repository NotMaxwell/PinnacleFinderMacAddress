//! PinnacleFinder — MAC Hunter (terminal UI).
//!
//! Sniffs 802.11 frames with libpcap, hunts for a target MAC, and shows a live
//! signal-strength meter with auto channel selection and monitor-mode control.
mod capture;
mod mac;
mod radiotap;
mod sysiface;
mod tui;

fn main() {
    if let Err(e) = tui::run() {
        eprintln!("PinnacleFinder TUI error: {e}");
        std::process::exit(1);
    }
}
