use iced::widget::{
    button, column, container, pick_list, progress_bar, row, text, text_input,
};
use iced::{time, Element, Length, Subscription, Task};

use pcap::{Capture, Device};

use std::fmt;
use std::sync::{
    mpsc::{self, Receiver, Sender},
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
enum Message {
    IfaceSelected(String),
    MacChanged(String),
    ToggleScan,
    Tick,
}

#[derive(Debug)]
struct App {
    // Interfaces discovered from pcap
    interfaces: Vec<String>,
    selected_iface: Option<String>,

    // Target MAC input
    mac_input: String,
    mac_valid: bool,

    // Scan state
    scanning: bool,
    total_frames: u64,
    hits: u64,
    start_time: Option<Instant>,
    error: Option<String>,

    // Background capture plumbing
    rx: Option<Receiver<ScanUpdate>>,
    stop_flag: Option<Arc<AtomicBool>>,
}

#[derive(Debug, Clone)]
struct ScanUpdate {
    total_frames: u64,
    hits: u64,
}

impl App {
    fn new(interfaces: Vec<String>) -> Self {
        let selected_iface = interfaces.get(0).cloned();

        Self {
            interfaces,
            selected_iface,
            mac_input: String::new(),
            mac_valid: false,
            scanning: false,
            total_frames: 0,
            hits: 0,
            start_time: None,
            error: None,
            rx: None,
            stop_flag: None,
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::IfaceSelected(name) => {
                self.selected_iface = Some(name);
                Task::none()
            }
            Message::MacChanged(s) => {
                self.mac_input = s.clone();
                self.mac_valid = parse_mac(&s).is_some();
                Task::none()
            }
            Message::ToggleScan => {
                if self.scanning {
                    // Stop scanning
                    if let Some(flag) = &self.stop_flag {
                        flag.store(true, Ordering::Relaxed);
                    }
                    self.scanning = false;
                    self.stop_flag = None;
                    // keep rx around; thread will die and channel will close
                    Task::none()
                } else {
                    // Start scanning
                    self.error = None;
                    self.total_frames = 0;
                    self.hits = 0;
                    self.start_time = Some(Instant::now());

                    let iface = match self.selected_iface.clone() {
                        Some(i) => i,
                        None => {
                            self.error =
                                Some("Select a network interface first.".into());
                            return Task::none();
                        }
                    };

                    if !self.mac_valid {
                        self.error = Some(
                            "MAC address is invalid. Use AA:BB:CC:DD:EE:FF.".into(),
                        );
                        return Task::none();
                    }

                    let mac_str = self.mac_input.trim().to_string();
                    let mac_bytes = match parse_mac(&mac_str) {
                        Some(m) => m,
                        None => {
                            self.error =
                                Some("MAC address is invalid. Use AA:BB:CC:DD:EE:FF."
                                    .into());
                            return Task::none();
                        }
                    };

                    let (tx, rx) = mpsc::channel::<ScanUpdate>();
                    let stop_flag = Arc::new(AtomicBool::new(false));
                    let stop_clone = stop_flag.clone();

                    // Spawn capture thread
                    std::thread::spawn(move || {
                        capture_loop(iface, mac_bytes, tx, stop_clone);
                    });

                    self.rx = Some(rx);
                    self.stop_flag = Some(stop_flag);
                    self.scanning = true;

                    Task::none()
                }
            }
            Message::Tick => {
                // Poll channel for new stats
                if let Some(rx) = &self.rx {
                    while let Ok(update) = rx.try_recv() {
                        self.total_frames = update.total_frames;
                        self.hits = update.hits;
                    }
                }
                Task::none()
            }
        }
    }

    pub fn view(&self) -> Element<Message> {
        let title = text("PinnacleFinder MAC Hunter").size(32);

        // Interface dropdown
        let iface_label = text("Network interface (from pcap)").size(18);

        let iface_pick: Element<_> = if self.interfaces.is_empty() {
            text("No interfaces found (pcap::Device::list() returned nothing)")
                .size(16)
                .into()
        } else {
            pick_list(
                self.interfaces.clone(),
                self.selected_iface.clone(),
                Message::IfaceSelected,
            )
            .placeholder("Select NIC")
            .padding(8)
            .width(Length::Fill)
            .into()
        };

        let iface_block = column![iface_label, iface_pick]
            .spacing(4)
            .width(Length::Fill);

        // MAC input
        let mac_label = text("Target MAC address").size(18);

        let mac_field = text_input("AA:BB:CC:DD:EE:FF", &self.mac_input)
            .padding(8)
            .on_input(Message::MacChanged);

        let mac_warning: Element<_> =
            if !self.mac_input.is_empty() && !self.mac_valid {
                text("Invalid MAC format. Use AA:BB:CC:DD:EE:FF.")
                    .size(14)
                    .into()
            } else {
                text("").into()
            };

        let mac_block = column![mac_label, mac_field, mac_warning]
            .spacing(4)
            .width(Length::Fill);

        // Start/Stop button
        let mut scan_button = button(if self.scanning {
            text("Stop scan")
        } else {
            text("Start scan")
        })
        .padding([10, 24]);

        if self.selected_iface.is_some() && self.mac_valid {
            scan_button = scan_button.on_press(Message::ToggleScan);
        }

        // Progress bar: show activity when scanning
        let progress = if self.scanning {
            progress_bar(0.0..=1.0, 0.5)
        } else {
            progress_bar(0.0..=1.0, 0.0)
        };

        // Live stats
        let duration_secs = self
            .start_time
            .map(|t| t.elapsed().as_secs_f32())
            .unwrap_or(0.0);

        let hit_rate = if duration_secs > 0.0 {
            self.hits as f32 / duration_secs
        } else {
            0.0
        };

        let stats_text = format!(
            "Frames seen: {}\nMatches for target MAC: {}\nElapsed: {:.1} s\nHit rate: {:.1} hits/s",
            self.total_frames, self.hits, duration_secs, hit_rate
        );

        let base_status: Element<_> = text(stats_text).size(16).into();

        let status_text: Element<_> = if let Some(err) = &self.error {
            column![text(format!("Error: {err}")).size(16), base_status]
                .spacing(8)
                .into()
        } else {
            base_status
        };

        let status_block = container(status_text)
            .padding(8)
            .width(Length::Fill);

        let content = column![
            title,
            row![iface_block].spacing(10),
            row![mac_block].spacing(10),
            scan_button,
            progress,
            status_block,
        ]
        .spacing(16)
        .padding(16)
        .width(Length::Fill);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        // Tick every 200 ms to pull updates from the capture thread
        time::every(Duration::from_millis(200)).map(|_| Message::Tick)
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

fn capture_loop(
    iface: String,
    mac: [u8; 6],
    tx: Sender<ScanUpdate>,
    stop_flag: Arc<AtomicBool>,
) {
    let target: Vec<u8> = mac.to_vec();

    let mut cap = match Capture::from_device(iface.as_str())
        .and_then(|d| d.promisc(true).timeout(1000).open())
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[capture] Failed to open device: {e}");
            return;
        }
    };

    let mut total_frames: u64 = 0;
    let mut hits: u64 = 0;
    let mut last_send = Instant::now();

    while !stop_flag.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(pkt) => {
                total_frames += 1;

                if pkt.data.len() >= 6 {
                    if pkt.data.windows(6).any(|w| w == target.as_slice()) {
                        hits += 1;
                    }
                }

                // send snapshot every 200ms
                if last_send.elapsed() >= Duration::from_millis(200) {
                    let _ = tx.send(ScanUpdate {
                        total_frames,
                        hits,
                    });
                    last_send = Instant::now();
                }
            }
            Err(_) => {
                // timeout or transient error; just loop
            }
        }
    }

    // final update
    let _ = tx.send(ScanUpdate {
        total_frames,
        hits,
    });
}

// --- Entry point: enumerate NICs, then run iced app ---

fn main() -> iced::Result {
    // Get NIC list from pcap
    let interfaces = Device::list()
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.name)
        .collect::<Vec<_>>();

    iced::application("PinnacleFinder MAC Hunter", App::update, App::view)
        .subscription(App::subscription)
        .run_with(move || (App::new(interfaces), Task::none()))
}
