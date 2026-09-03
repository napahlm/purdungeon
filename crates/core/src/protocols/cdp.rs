//! Cisco Discovery Protocol frame recognition.
//!
//! CDP is not an `EtherType` protocol: it rides in IEEE 802.3 frames (a length
//! field instead of an `EtherType`) under an 802.2 LLC/SNAP header. This
//! release only recognises and counts it; its TLVs (device id, port id,
//! platform, addresses) become device evidence in a later release.
//!
//! Layout, from Cisco's "Cisco Discovery Protocol" frame format description
//! and RFC 1042 (SNAP over 802.2); Wireshark's `packet-cdp.c` was consulted
//! read-only to confirm the constants:
//!
//! ```text
//! LLC   DSAP 0xAA  SSAP 0xAA  Control 0x03 (UI)
//! SNAP  OUI 00-00-0C (Cisco)  Protocol id 0x2000
//! CDP   version (1 or 2)  ttl  checksum  TLVs...
//! ```

/// The multicast address CDP is sent to (informational; not enforced).
pub const CDP_GROUP_ADDRESS: [u8; 6] = [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC];

/// True when an 802.3 payload (the bytes right after the length field) is a
/// CDP announcement. The caller must already have checked that the frame's
/// Length/Type field is a length (≤ 1500, IEEE 802.3-2018 §3.2.6).
#[must_use]
pub fn is_cdp(llc_payload: &[u8]) -> bool {
    llc_payload.len() >= 12
        && llc_payload[0..3] == [0xAA, 0xAA, 0x03]
        && llc_payload[3..6] == [0x00, 0x00, 0x0C]
        && llc_payload[6..8] == [0x20, 0x00]
        && matches!(llc_payload[8], 1 | 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CDP_V2: [u8; 12] = [
        0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00, 0x02, 0xB4, 0x00, 0x00,
    ];

    #[test]
    fn cisco_snap_with_version_is_cdp() {
        assert!(is_cdp(&CDP_V2));
    }

    #[test]
    fn other_snap_or_version_is_not_cdp() {
        let mut wrong_oui = CDP_V2;
        wrong_oui[5] = 0x0D;
        assert!(!is_cdp(&wrong_oui));
        let mut version_3 = CDP_V2;
        version_3[8] = 3;
        assert!(!is_cdp(&version_3));
        // Spanning tree: LLC DSAP/SSAP 0x42, no SNAP
        assert!(!is_cdp(&[0x42, 0x42, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    }
}
