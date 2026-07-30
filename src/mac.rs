//! MAC address parsing / formatting.
use std::fmt::Write as _;

/// Parse "AA:BB:CC:DD:EE:FF" into 6 bytes.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
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

/// Format MAC bytes as a colon-separated uppercase hex string.
pub fn format_mac_bytes(mac: &[u8; 6]) -> String {
    let mut result = String::new();
    for (i, &byte) in mac.iter().enumerate() {
        if i > 0 {
            result.push(':');
        }
        let _ = write!(result, "{byte:02X}");
    }
    result
}

/// Format raw hex (no separators) into uppercase colon-separated pairs, max 12 hex chars.
pub fn format_mac_from_hex(raw: &str) -> String {
    let mut r = raw
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>();
    if r.len() > 12 {
        r.truncate(12);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mac_valid_uppercase() {
        assert_eq!(parse_mac("AA:BB:CC:DD:EE:FF"), Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
    }

    #[test]
    fn parse_mac_valid_lowercase() {
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff"), Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
    }

    #[test]
    fn parse_mac_all_zeros() {
        assert_eq!(parse_mac("00:00:00:00:00:00"), Some([0; 6]));
    }

    #[test]
    fn parse_mac_too_few_parts() {
        assert_eq!(parse_mac("AA:BB:CC"), None);
    }

    #[test]
    fn parse_mac_too_many_parts() {
        assert_eq!(parse_mac("AA:BB:CC:DD:EE:FF:00"), None);
    }

    #[test]
    fn parse_mac_segment_too_long() {
        assert_eq!(parse_mac("AAA:BB:CC:DD:EE:FF"), None);
    }

    #[test]
    fn parse_mac_segment_too_short() {
        assert_eq!(parse_mac("A:BB:CC:DD:EE:FF"), None);
    }

    #[test]
    fn parse_mac_invalid_hex() {
        assert_eq!(parse_mac("GG:BB:CC:DD:EE:FF"), None);
    }

    #[test]
    fn parse_mac_empty() {
        assert_eq!(parse_mac(""), None);
    }

    #[test]
    fn format_mac_bytes_standard() {
        assert_eq!(format_mac_bytes(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn format_mac_bytes_roundtrip() {
        let mac = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        assert_eq!(parse_mac(&format_mac_bytes(&mac)), Some(mac));
    }

    #[test]
    fn format_mac_from_hex_full() {
        assert_eq!(format_mac_from_hex("AABBCCDDEEFF"), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn format_mac_from_hex_lowercase_input() {
        assert_eq!(format_mac_from_hex("aabbccddeeff"), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn format_mac_from_hex_partial() {
        assert_eq!(format_mac_from_hex("AABB"), "AA:BB");
    }

    #[test]
    fn format_mac_from_hex_empty() {
        assert_eq!(format_mac_from_hex(""), "");
    }

    #[test]
    fn format_mac_from_hex_truncates_at_12() {
        assert_eq!(format_mac_from_hex("AABBCCDDEEFF1122"), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn format_mac_from_hex_strips_non_hex() {
        assert_eq!(format_mac_from_hex("AA:BB:CC:DD:EE:FF"), "AA:BB:CC:DD:EE:FF");
    }
}
