//! Radiotap + 802.11 frame parsing.

/// Parse Radiotap + 802.11 header. Returns (transmitter MAC, RSSI) if both parse.
pub fn extract_80211_src_mac_and_rssi(data: &[u8]) -> Option<([u8; 6], i8)> {
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

    // Collect present bitmaps (handles extended maps)
    let mut present_maps: Vec<u32> = Vec::new();
    let mut present_offset = 4usize; // first bitmap starts at byte 4
    loop {
        if present_offset + 4 > data.len() {
            return None;
        }
        let word = u32::from_le_bytes([
            data[present_offset],
            data[present_offset + 1],
            data[present_offset + 2],
            data[present_offset + 3],
        ]);
        present_maps.push(word);
        present_offset += 4;
        if (word & (1 << 31)) == 0 {
            break;
        }
    }

    let mut offset = present_offset;
    let mut rssi_opt: Option<i8> = None;

    // Parse radiotap fields according to the radiotap specification
    for (map_idx, present) in present_maps.iter().enumerate() {
        for bit in 0..32 {
            if (present & (1 << bit)) == 0 {
                continue;
            }

            let field_index = map_idx * 32 + bit as usize;

            // Field sizes and alignments according to radiotap spec
            let (size, align) = match field_index {
                0 => (8, 8),  // TSFT: u64 timestamp
                1 => (1, 1),  // Flags: u8
                2 => (1, 1),  // Rate: u8 (500 kbps units)
                3 => (4, 2),  // Channel: u16 frequency, u16 flags
                4 => (2, 2),  // FHSS: u8 hop set, u8 hop pattern
                5 => (1, 1),  // Antenna signal (RSSI): i8 or u8 in dBm
                6 => (1, 1),  // Antenna noise: i8 in dBm
                7 => (2, 2),  // Lock quality: u16
                8 => (2, 2),  // TX power: u16
                9 => (1, 1),  // Antenna: u8
                10 => (1, 1), // DB antenna signal: u8 in dBm
                11 => (1, 1), // DB antenna noise: u8 in dBm
                12 => (2, 2), // RX flags: u16
                13 => (2, 2), // TX flags: u16
                14 => (1, 1), // RTS retries: u8
                15 => (1, 1), // Data retries: u8
                // Unknown or unsupported fields: skip without failing
                _ => {
                    continue;
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
            if field_index == 5 {
                rssi_opt = Some(data[aligned] as i8);
            }

            offset = aligned + size;
        }
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

    // Frame type 1 = Control frame (no usable source MAC)
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
        src.copy_from_slice(&hdr[24..30]); // WDS: source is addr4
    } else if to_ds {
        src.copy_from_slice(&hdr[10..16]); // To DS (STA -> AP): addr2
    } else if from_ds {
        src.copy_from_slice(&hdr[16..22]); // From DS (AP -> STA): addr3
    } else {
        src.copy_from_slice(&hdr[10..16]); // Ad-hoc / mgmt: addr2
    }

    Some((src, rssi))
}

pub fn freq_to_channel(freq: u32) -> Option<u8> {
    // 2.4 GHz: channel = (freq - 2407) / 5
    if (2412..=2484).contains(&freq) {
        return Some(((freq as i32 - 2407) / 5) as u8);
    }
    // 5 GHz common mapping: channel = (freq - 5000) / 5
    if (5000..=6000).contains(&freq) {
        return Some(((freq as i32 - 5000) / 5) as u8);
    }
    None
}

pub fn packet_contains_mac(data: &[u8], target: &[u8; 6]) -> bool {
    if let Some((src, _)) = extract_80211_src_mac_and_rssi(data) {
        if &src == target {
            return true;
        }
    }
    data.windows(6).any(|w| w == target)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Builds a minimal valid radiotap + 802.11 frame.
    fn build_radiotap_80211(
        rssi: i8,
        frame_control: u16,
        addr1: [u8; 6],
        addr2: [u8; 6],
        addr3: [u8; 6],
        addr4: Option<[u8; 6]>,
    ) -> Vec<u8> {
        let radiotap_len: u16 = 9;
        let mut pkt: Vec<u8> = vec![
            0x00, 0x00,
            (radiotap_len & 0xFF) as u8, (radiotap_len >> 8) as u8,
            0x20, 0x00, 0x00, 0x00, // present bitmask: bit 5 (antenna signal)
            rssi as u8,
        ];
        pkt.push((frame_control & 0xFF) as u8);
        pkt.push((frame_control >> 8) as u8);
        pkt.extend_from_slice(&[0x00, 0x00]); // duration
        pkt.extend_from_slice(&addr1);
        pkt.extend_from_slice(&addr2);
        pkt.extend_from_slice(&addr3);
        pkt.extend_from_slice(&[0x00, 0x00]); // seq control
        if let Some(a4) = addr4 {
            pkt.extend_from_slice(&a4);
        }
        pkt
    }

    #[test]
    fn extract_mgmt_no_ds_returns_addr2_as_src() {
        let src_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let pkt = build_radiotap_80211(-60, 0x0000, [0x11; 6], src_mac, [0x22; 6], None);
        assert_eq!(extract_80211_src_mac_and_rssi(&pkt), Some((src_mac, -60i8)));
    }

    #[test]
    fn extract_data_to_ds_returns_addr2_as_src() {
        let src_mac = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01];
        let pkt = build_radiotap_80211(-75, 0x0108, [0x33; 6], src_mac, [0x44; 6], None);
        assert_eq!(extract_80211_src_mac_and_rssi(&pkt), Some((src_mac, -75i8)));
    }

    #[test]
    fn extract_data_from_ds_returns_addr3_as_src() {
        let src_mac = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x02];
        let pkt = build_radiotap_80211(-80, 0x0208, [0x55; 6], [0x66; 6], src_mac, None);
        assert_eq!(extract_80211_src_mac_and_rssi(&pkt), Some((src_mac, -80i8)));
    }

    #[test]
    fn extract_data_wds_returns_addr4_as_src() {
        let src_mac = [0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let pkt = build_radiotap_80211(-50, 0x0308, [0x77; 6], [0x88; 6], [0x99; 6], Some(src_mac));
        assert_eq!(extract_80211_src_mac_and_rssi(&pkt), Some((src_mac, -50i8)));
    }

    #[test]
    fn extract_control_frame_returns_none() {
        let pkt = build_radiotap_80211(-55, 0x0004, [0xAA; 6], [0xBB; 6], [0xCC; 6], None);
        assert_eq!(extract_80211_src_mac_and_rssi(&pkt), None);
    }

    #[test]
    fn extract_too_short_returns_none() {
        assert_eq!(extract_80211_src_mac_and_rssi(&[0u8; 4]), None);
    }

    #[test]
    fn extract_wrong_version_returns_none() {
        let mut pkt = build_radiotap_80211(-60, 0x0000, [0x11; 6], [0xAA; 6], [0x22; 6], None);
        pkt[0] = 1;
        assert_eq!(extract_80211_src_mac_and_rssi(&pkt), None);
    }

    #[test]
    fn extract_rssi_value_preserved() {
        let pkt = build_radiotap_80211(-42, 0x0000, [0x11; 6], [0xAA; 6], [0x22; 6], None);
        let (_, rssi) = extract_80211_src_mac_and_rssi(&pkt).unwrap();
        assert_eq!(rssi, -42i8);
    }

    #[test]
    fn freq_to_channel_2_4ghz() {
        assert_eq!(freq_to_channel(2412), Some(1));
        assert_eq!(freq_to_channel(2437), Some(6));
        assert_eq!(freq_to_channel(2462), Some(11));
    }

    #[test]
    fn freq_to_channel_5ghz() {
        assert_eq!(freq_to_channel(5180), Some(36));
        assert_eq!(freq_to_channel(5200), Some(40));
    }

    #[test]
    fn freq_to_channel_out_of_range() {
        assert_eq!(freq_to_channel(2411), None);
        assert_eq!(freq_to_channel(3000), None);
        assert_eq!(freq_to_channel(6001), None);
    }

    #[test]
    fn packet_contains_mac_via_radiotap_parse() {
        let target = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let pkt = build_radiotap_80211(-60, 0x0000, [0x11; 6], target, [0x22; 6], None);
        assert!(packet_contains_mac(&pkt, &target));
    }

    #[test]
    fn packet_contains_mac_raw_fallback() {
        let target = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02];
        let mut pkt = vec![0xFFu8; 20];
        pkt.extend_from_slice(&target);
        assert!(packet_contains_mac(&pkt, &target));
    }

    #[test]
    fn packet_contains_mac_no_match() {
        let target = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let other = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let pkt = build_radiotap_80211(-60, 0x0000, [0x11; 6], other, [0x22; 6], None);
        assert!(!packet_contains_mac(&pkt, &target));
    }

    #[test]
    fn packet_contains_mac_empty_packet() {
        let target = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert!(!packet_contains_mac(&[], &target));
    }
}
