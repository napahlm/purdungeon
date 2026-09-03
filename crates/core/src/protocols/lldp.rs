//! LLDP (IEEE 802.1AB) frame recognition.
//!
//! This release only recognises and counts LLDP; the TLVs (chassis id, port
//! id, system name, capabilities) become device evidence in a later release.

/// IEEE 802.1AB-2016 §8.2: LLDPDUs are carried in Ethernet frames with
/// `EtherType` 88-CC.
pub const ETHERTYPE_LLDP: u16 = 0x88CC;

/// IEEE 802.1AB-2016 §7.1, Table 7-1: the nearest-bridge, nearest
/// non-TPMR-bridge and nearest-customer-bridge group addresses. Listed for
/// reference only — some agents use other group addresses, so the ethertype
/// plus the first-TLV check below is what we trust.
pub const LLDP_GROUP_ADDRESSES: [[u8; 6]; 3] = [
    [0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E],
    [0x01, 0x80, 0xC2, 0x00, 0x00, 0x03],
    [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00],
];

/// True for an LLDPDU whose first TLV is a Chassis ID.
///
/// IEEE 802.1AB-2016 §8.4.1: a TLV header is a 7-bit type and a 9-bit length.
/// §8.5.2: the first TLV must be Chassis ID (type 1) carrying at least a
/// subtype byte and one byte of identifier.
#[must_use]
pub fn is_lldp(ether_type: u16, payload: &[u8]) -> bool {
    if ether_type != ETHERTYPE_LLDP || payload.len() < 4 {
        return false;
    }
    let tlv_type = payload[0] >> 1;
    let tlv_len = (usize::from(payload[0] & 1) << 8) | usize::from(payload[1]);
    tlv_type == 1 && tlv_len >= 2 && payload.len() >= 2 + tlv_len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chassis_id_first_tlv_is_lldp() {
        // Chassis ID TLV: type 1, length 7, subtype 4 (MAC), 6-byte id
        let payload = [0x02, 0x07, 0x04, 0, 1, 2, 3, 4, 5, 0x00, 0x00];
        assert!(is_lldp(ETHERTYPE_LLDP, &payload));
    }

    #[test]
    fn wrong_ethertype_or_tlv_is_not_lldp() {
        let payload = [0x02, 0x07, 0x04, 0, 1, 2, 3, 4, 5];
        assert!(!is_lldp(0x0800, &payload));
        // Port ID TLV (type 2) first
        assert!(!is_lldp(ETHERTYPE_LLDP, &[0x04, 0x02, 0x03, 0x01]));
        // Chassis ID claiming more bytes than present
        assert!(!is_lldp(ETHERTYPE_LLDP, &[0x02, 0x20, 0x04, 0x00]));
    }
}
