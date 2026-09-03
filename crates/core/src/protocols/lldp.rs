//! LLDP (IEEE 802.1AB) frame recognition and the TLVs that identify the
//! sender: chassis id, port id, system name and description, capabilities,
//! management address. TLV numbers and layouts follow IEEE 802.1AB-2016 §8.5.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

const TLV_END: u8 = 0;
const TLV_CHASSIS_ID: u8 = 1;
const TLV_PORT_ID: u8 = 2;
// TLV type 3 is the TTL, which says nothing about identity.
const TLV_PORT_DESCRIPTION: u8 = 4;
const TLV_SYSTEM_NAME: u8 = 5;
const TLV_SYSTEM_DESCRIPTION: u8 = 6;
const TLV_SYSTEM_CAPABILITIES: u8 = 7;
const TLV_MANAGEMENT_ADDRESS: u8 = 8;

/// Chassis ID subtype "MAC address" (§8.5.2.2, Table 8-2).
const CHASSIS_SUBTYPE_MAC: u8 = 4;
/// IANA address family numbers used by the management address TLV.
const AF_IPV4: u8 = 1;
const AF_IPV6: u8 = 2;

/// System capability bits (§8.5.8.1, Table 8-4).
const CAPABILITY_NAMES: [(u16, &str); 11] = [
    (0x0001, "other"),
    (0x0002, "repeater"),
    (0x0004, "bridge"),
    (0x0008, "wlan-access-point"),
    (0x0010, "router"),
    (0x0020, "telephone"),
    (0x0040, "docsis"),
    (0x0080, "station-only"),
    (0x0100, "c-vlan"),
    (0x0200, "s-vlan"),
    (0x0400, "two-port-mac-relay"),
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LldpInfo {
    /// Chassis id when it is a MAC address (the usual case for switches).
    pub chassis_mac: Option<[u8; 6]>,
    /// Chassis id as text for the other subtypes.
    pub chassis_id: Option<String>,
    pub port_id: Option<String>,
    pub port_description: Option<String>,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub capabilities_supported: u16,
    pub capabilities_enabled: u16,
    pub management_addresses: Vec<IpAddr>,
}

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

fn text(bytes: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(bytes).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn id_text(subtype: u8, bytes: &[u8]) -> Option<String> {
    match (subtype, bytes.len()) {
        // MAC address subtypes render as colon-separated hex.
        (3 | 4, 6) => Some(
            bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
        ),
        _ => text(bytes),
    }
}

/// Parse the TLVs of an LLDPDU. Stops quietly at a truncated TLV.
#[must_use]
pub fn parse(payload: &[u8]) -> Option<LldpInfo> {
    if !is_lldp(ETHERTYPE_LLDP, payload) {
        return None;
    }
    let mut info = LldpInfo::default();
    let mut pos = 0;
    while pos + 2 <= payload.len() {
        let tlv_type = payload[pos] >> 1;
        let len = (usize::from(payload[pos] & 1) << 8) | usize::from(payload[pos + 1]);
        if tlv_type == TLV_END {
            break;
        }
        let Some(value) = payload.get(pos + 2..pos + 2 + len) else {
            break;
        };
        match tlv_type {
            TLV_CHASSIS_ID if !value.is_empty() => {
                if value[0] == CHASSIS_SUBTYPE_MAC && value.len() == 7 {
                    info.chassis_mac = <[u8; 6]>::try_from(&value[1..]).ok();
                }
                info.chassis_id = id_text(value[0], &value[1..]);
            }
            TLV_PORT_ID if !value.is_empty() => info.port_id = id_text(value[0], &value[1..]),
            TLV_PORT_DESCRIPTION => info.port_description = text(value),
            TLV_SYSTEM_NAME => info.system_name = text(value),
            TLV_SYSTEM_DESCRIPTION => info.system_description = text(value),
            TLV_SYSTEM_CAPABILITIES if value.len() >= 4 => {
                info.capabilities_supported = u16::from_be_bytes([value[0], value[1]]);
                info.capabilities_enabled = u16::from_be_bytes([value[2], value[3]]);
            }
            TLV_MANAGEMENT_ADDRESS if value.len() >= 2 => {
                // address string length counts the subtype byte
                let addr_len = usize::from(value[0]).saturating_sub(1);
                let subtype = value[1];
                if let Some(addr) = value.get(2..2 + addr_len) {
                    let parsed = match (subtype, addr.len()) {
                        (AF_IPV4, 4) => <[u8; 4]>::try_from(addr)
                            .ok()
                            .map(|a| IpAddr::V4(Ipv4Addr::from(a))),
                        (AF_IPV6, 16) => <[u8; 16]>::try_from(addr)
                            .ok()
                            .map(|a| IpAddr::V6(Ipv6Addr::from(a))),
                        _ => None,
                    };
                    if let Some(ip) = parsed {
                        if !info.management_addresses.contains(&ip) {
                            info.management_addresses.push(ip);
                        }
                    }
                }
            }
            _ => {}
        }
        pos += 2 + len;
    }
    Some(info)
}

/// Names of the set capability bits, in bit order.
#[must_use]
pub fn capability_names(bits: u16) -> Vec<&'static str> {
    CAPABILITY_NAMES
        .iter()
        .filter(|(bit, _)| bits & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(kind: u8, value: &[u8]) -> Vec<u8> {
        let len = value.len() as u16;
        let mut out = vec![(kind << 1) | ((len >> 8) as u8 & 1), (len & 0xFF) as u8];
        out.extend_from_slice(value);
        out
    }

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

    #[test]
    fn parses_identity_tlvs() {
        let mut p = tlv(TLV_CHASSIS_ID, &[4, 0x00, 0x80, 0x63, 1, 2, 3]);
        p.extend(tlv(TLV_PORT_ID, b"\x05Gi1/0/5"));
        p.extend(tlv(3, &[0, 120])); // TTL
        p.extend(tlv(TLV_PORT_DESCRIPTION, b"to PLC"));
        p.extend(tlv(TLV_SYSTEM_NAME, b"SW-ENG-01"));
        p.extend(tlv(TLV_SYSTEM_DESCRIPTION, b"Cisco IOS Software, C2960"));
        p.extend(tlv(TLV_SYSTEM_CAPABILITIES, &[0x00, 0x14, 0x00, 0x04]));
        p.extend(tlv(
            TLV_MANAGEMENT_ADDRESS,
            &[5, 1, 10, 0, 0, 2, 2, 0, 0, 0, 1, 0],
        ));
        p.extend(tlv(TLV_END, &[]));
        let info = parse(&p).unwrap();
        assert_eq!(info.chassis_mac, Some([0x00, 0x80, 0x63, 1, 2, 3]));
        assert_eq!(info.chassis_id.as_deref(), Some("00:80:63:01:02:03"));
        assert_eq!(info.port_id.as_deref(), Some("Gi1/0/5"));
        assert_eq!(info.port_description.as_deref(), Some("to PLC"));
        assert_eq!(info.system_name.as_deref(), Some("SW-ENG-01"));
        assert_eq!(
            capability_names(info.capabilities_supported),
            vec!["bridge", "router"]
        );
        assert_eq!(capability_names(info.capabilities_enabled), vec!["bridge"]);
        assert_eq!(
            info.management_addresses,
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))]
        );
    }
}
