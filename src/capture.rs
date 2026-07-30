//! libpcap capture: opening handles, the background scan thread, and
//! auto channel selection.
use pcap::{Active, Capture};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use crate::mac::format_mac_bytes;
use crate::radiotap::{extract_80211_src_mac_and_rssi, packet_contains_mac};
use crate::sysiface::{debug_enabled, log_debug, scan_system_channels, set_channel_system};

#[derive(Clone, Debug)]
pub struct ScanUpdate {
    pub total_frames: u64,
    pub hits: u64,
    pub last_rssi: Option<i8>,
}

/// Open a capture handle, trying monitor mode first then falling back to promisc.
pub fn open_capture(iface: &str, timeout_ms: i32) -> Result<Capture<Active>, String> {
    let try_rfmon = Capture::from_device(iface)
        .map_err(|e| format!("from_device({iface}): {e}"))?
        .rfmon(true)
        .promisc(true)
        .timeout(timeout_ms)
        .open();

    match try_rfmon {
        Ok(c) => Ok(c),
        Err(e1) => {
            log_debug(&format!("rfmon open failed on {iface} (will retry promisc): {e1}"));
            Capture::from_device(iface)
                .map_err(|e| format!("from_device({iface}): {e}"))?
                .promisc(true)
                .timeout(timeout_ms)
                .open()
                .map_err(|e2| format!("open({iface}) promisc failed; rfmon error was {e1}: {e2}"))
        }
    }
}

fn channel_sweep_detect(iface: &str, target: &[u8; 6]) -> Option<u8> {
    let candidates: &[u8] = &[1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161];
    let mut best_ch = None;
    let mut best_hits = 0u64;

    for &ch in candidates {
        if let Err(e) = set_channel_system(iface, ch) {
            log_debug(&format!("Channel {ch} set failed: {e}"));
            continue;
        }
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
        log_debug(&format!("Channel {ch} sweep hits: {local_hits}"));
    }

    best_ch
}

/// Lock onto the target's channel via a system scan or a channel sweep.
pub fn auto_select_channel(iface: &str, target: &[u8; 6]) -> Result<Option<u8>, String> {
    let target_s = format_mac_bytes(target).to_lowercase();

    // Fast path: use a system scan to find an exact BSSID match.
    if let Some(rows) = scan_system_channels(iface) {
        log_debug(&format!("system scan found {} entries", rows.len()));
        for (bssid, ch) in &rows {
            if bssid.to_lowercase() == target_s {
                log_debug(&format!("scan matched target on channel {ch}"));
                if let Err(e) = set_channel_system(iface, *ch) {
                    return Err(format!("failed to set channel {ch}: {e}"));
                }
                return Ok(Some(*ch));
            }
        }
    }

    // Fallback: sweep candidate channels with short sniff windows.
    if let Some(ch) = channel_sweep_detect(iface, target) {
        if let Err(e) = set_channel_system(iface, ch) {
            return Err(format!("failed to set channel {ch}: {e}"));
        }
        return Ok(Some(ch));
    }

    Ok(None)
}

/// Capture loop run on a background thread; publishes updates over `tx`.
pub fn capture_loop(
    iface: String,
    mac: [u8; 6],
    tx: mpsc::Sender<ScanUpdate>,
    stop_flag: Arc<AtomicBool>,
) {
    let target = mac;
    let target_slice: &[u8] = &target;
    let target_str = format_mac_bytes(&target);

    let debug_on = debug_enabled();
    if debug_on {
        log_debug(&format!("Starting scan for MAC {target_str} on interface {iface}"));
    }

    let mut cap = match open_capture(&iface, 300) {
        Ok(c) => c,
        Err(e) => {
            log_debug(&format!("Failed to open device: {e}"));
            return;
        }
    };

    let mut total_frames: u64 = 0;
    let mut hits: u64 = 0;
    let mut last_rssi: Option<i8> = None;
    let mut last_seen_mac: Option<[u8; 6]> = None;
    let mut last_send = Instant::now();
    let mut last_debug = Instant::now();
    let mut parse_failures: u64 = 0;
    let mut raw_matches: u64 = 0;
    let mut timeouts: u64 = 0;

    while !stop_flag.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(pkt) => {
                total_frames += 1;

                if let Some((src, rssi)) = extract_80211_src_mac_and_rssi(pkt.data) {
                    last_seen_mac = Some(src);
                    if src == target {
                        last_rssi = Some(rssi);
                        hits += 1;
                    }
                } else {
                    parse_failures += 1;
                    if pkt.data.len() >= 6 && pkt.data.windows(6).any(|w| w == target_slice) {
                        hits += 1;
                        raw_matches += 1;
                    }
                }

                if last_send.elapsed() >= Duration::from_millis(100) {
                    let _ = tx.send(ScanUpdate { total_frames, hits, last_rssi });
                    last_send = Instant::now();
                }

                if debug_on && last_debug.elapsed() >= Duration::from_secs(2) {
                    let last_rssi_display = last_rssi.map(|r| r.to_string()).unwrap_or_else(|| "--".into());
                    let last_seen_display = last_seen_mac
                        .map(|m| format_mac_bytes(&m))
                        .unwrap_or_else(|| "--".into());
                    log_debug(&format!(
                        "Frames: {total_frames}, Hits: {hits}, Parse misses: {parse_failures}, Raw matches: {raw_matches}, Timeouts: {timeouts}, Last RSSI: {last_rssi_display} dBm, Last seen: {last_seen_display}"
                    ));
                    last_debug = Instant::now();
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                timeouts += 1;
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => {
                log_debug(&format!("Packet capture error: {e}"));
            }
        }
    }

    let _ = tx.send(ScanUpdate { total_frames, hits, last_rssi });

    if debug_on {
        log_debug("Capture loop exited after stop flag set");
    }
}
