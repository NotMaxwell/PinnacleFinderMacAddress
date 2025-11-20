use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use pcap::Capture;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    symbols,
    widgets::{Block, Borders, LineGauge, Paragraph, Sparkline, Wrap},
    Frame, Terminal,
};

use std::env;
use std::error::Error;
use std::io;
use std::str::FromStr;
use std::time::Duration;

const HISTORY_LEN: usize = 120; // ~12 seconds history at 10 Hz

// ------------------------------------------------------------
// MAC TYPE
// ------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Mac([u8; 6]);

impl FromStr for Mac {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err("MAC must have 6 octets".into());
        }
        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16)
                .map_err(|_| format!("Invalid hex in octet {}", i))?;
        }
        Ok(Mac(bytes))
    }
}

impl Mac {
    fn equals_slice(&self, slice: &[u8]) -> bool {
        slice.len() == 6 && slice == self.0
    }
}

// ------------------------------------------------------------
// RADIOTAP PARSING
// ------------------------------------------------------------

fn align_offset(offset: usize, align: usize) -> usize {
    if align <= 1 {
        offset
    } else {
        (offset + (align - 1)) & !(align - 1)
    }
}

/// Extract dBm_Antenna_Signal from radiotap header (bit 5 of present word)
fn parse_radiotap_rssi(rt: &[u8]) -> Option<i8> {
    if rt.len() < 8 {
        return None;
    }

    let it_len = u16::from_le_bytes([rt[2], rt[3]]) as usize;
    if it_len > rt.len() || it_len < 8 {
        return None;
    }

    let present = u32::from_le_bytes([rt[4], rt[5], rt[6], rt[7]]);

    if (present & (1 << 5)) == 0 {
        return None; // no dBm_Antenna_Signal field
    }

    let mut offset = 8usize;

    for bit in 0..=5 {
        if (present & (1 << bit)) == 0 {
            continue;
        }

        match bit {
            // TSFT: 8 bytes, align 8
            0 => {
                offset = align_offset(offset, 8);
                offset += 8;
            }
            // Flags: 1 byte
            1 => {
                offset += 1;
            }
            // Rate: 1 byte
            2 => {
                offset += 1;
            }
            // Channel: 4 bytes, align 2
            3 => {
                offset = align_offset(offset, 2);
                offset += 4;
            }
            // FHSS: 2 bytes
            4 => {
                offset += 2;
            }
            // dBm_Antenna_Signal: 1 byte
            5 => {
                if offset >= it_len {
                    return None;
                }
                return Some(rt[offset] as i8);
            }
            _ => {}
        }
    }

    None
}

// ------------------------------------------------------------
// APP STATE
// ------------------------------------------------------------

struct AppState {
    avg_rssi: f32,
    pkt_count: usize,
    history: Vec<i8>,
}

impl AppState {
    fn new() -> Self {
        Self {
            avg_rssi: -90.0,
            pkt_count: 0,
            history: Vec::with_capacity(HISTORY_LEN),
        }
    }

    fn push_rssi(&mut self, rssi: i8) {
        self.pkt_count += 1;
        self.avg_rssi = rssi as f32;

        if self.history.len() >= HISTORY_LEN {
            self.history.remove(0);
        }
        self.history.push(rssi);
    }
}

// ------------------------------------------------------------
// UI
// ------------------------------------------------------------

fn ui(f: &mut Frame, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(3), // Gauge
                Constraint::Length(3), // Stats
                Constraint::Min(5),    // History
            ]
            .as_ref(),
        )
        .split(f.area()); // <- NOT size(), ratatui 0.29 uses area()

    // Signal gauge
    let gauge_val = ((state.avg_rssi + 90.0) / 60.0)
        .clamp(0.0, 1.0) as f64; // ratio wants f64

    let gauge = LineGauge::default()
        .block(Block::default().borders(Borders::ALL).title("Signal Strength"))
        .ratio(gauge_val)
        .filled_style(Style::default().fg(Color::Green))
        .line_set(symbols::line::THICK);

    f.render_widget(gauge, chunks[0]);

    // Packet counter
    let pkt = Paragraph::new(format!("Packets: {}", state.pkt_count))
        .block(Block::default().borders(Borders::ALL).title("Stats"))
        .wrap(Wrap { trim: true });

    f.render_widget(pkt, chunks[1]);

    // RSSI history sparkline
    let history_data: Vec<u64> = state
        .history
        .iter()
        .map(|v| (*v as i64 + 100) as u64)
        .collect();

    let spark = Sparkline::default()
        .block(Block::default().borders(Borders::ALL).title("RSSI History"))
        .data(&history_data)
        .style(Style::default().fg(Color::Yellow));

    f.render_widget(spark, chunks[2]);
}

// ------------------------------------------------------------
// MAIN
// ------------------------------------------------------------

fn main() -> Result<(), Box<dyn Error>> {
    // Args
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <interface> <target-mac>", args[0]);
        std::process::exit(1);
    }

    let iface = &args[1];
    let target_mac: Mac = args[2].parse().expect("Invalid MAC address");

    // PCAP
    let mut cap = Capture::from_device(iface.as_str())?
        .immediate_mode(true)
        .promisc(true)
        .open()?;

    // TUI setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = AppState::new();

    // Main loop
    loop {
        // Quit on 'q'
        if event::poll(Duration::from_millis(5))? {
            if let Event::Key(k) = event::read()? {
                if k.code == KeyCode::Char('q') {
                    break;
                }
            }
        }

        // Read one packet (non-blocking style)
        if let Ok(packet) = cap.next_packet() {
            let data = packet.data;
            if data.len() < 10 {
                continue;
            }

            // Radiotap header
            let it_len = u16::from_le_bytes([data[2], data[3]]) as usize;
            if it_len >= data.len() || it_len < 8 {
                continue;
            }

            let radiotap = &data[..it_len];
            let frame = &data[it_len..];

            let rssi = match parse_radiotap_rssi(radiotap) {
                Some(v) => v,
                None => continue,
            };

            // 802.11 MAC header
            if frame.len() < 24 {
                continue;
            }

            let addr1 = &frame[4..10];
            let addr2 = &frame[10..16];
            let addr3 = &frame[16..22];

            if target_mac.equals_slice(addr1)
                || target_mac.equals_slice(addr2)
                || target_mac.equals_slice(addr3)
            {
                state.push_rssi(rssi);
            }
        }

        terminal.draw(|f| ui(f, &state))?;
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}
