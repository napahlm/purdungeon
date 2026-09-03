//! Cisco Discovery Protocol frame recognition and the TLVs that identify
//! the sender: device id, addresses, port id, capabilities, software
//! version, platform.
//!
//! CDP is not an `EtherType` protocol: it rides in IEEE 802.3 frames (a length
//! field instead of an `EtherType`) under an 802.2 LLC/SNAP header.
//!
//! Layout, from Cisco's "Cisco Discovery Protocol" frame format description
//! and RFC 1042 (SNAP over 802.2); Wireshark's `packet-cdp.c` was consulted
//! read-only to confirm the constants:
//!
//! ```text
//! LLC   DSAP 0xAA  SSAP 0xAA  Control 0x03 (UI)
//! SNAP  OUI 00-00-0C (Cisco)  Protocol id 0x2000
//! CDP   version (1 or 2)  ttl  checksum  TLVs (type u16, length u16 incl. header, value)
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The multicast address CDP is sent to (informational; not enforced).
pub const CDP_GROUP_ADDRESS: [u8; 6] = [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC];

const LLC_SNAP_LEN: usize = 8;
const CDP_HEADER_LEN: usize = 4;

const TLV_DEVICE_ID: u16 = 0x0001;
const TLV_ADDRESSES: u16 = 0x0002;
const TLV_PORT_ID: u16 = 0x0003;
const TLV_CAPABILITIES: u16 = 0x0004;
const TLV_SOFTWARE_VERSION: u16 = 0x0005;
const TLV_PLATFORM: u16 = 0x0006;
const TLV_NATIVE_VLAN: u16 = 0x000A;

/// Capability bits of the Capabilities TLV.
const CAPABILITY_NAMES: [(u32, &str); 11] = [
    (0x001, "router"),
    (0x002, "transparent-bridge"),
    (0x004, "source-route-bridge"),
    (0x008, "switch"),
    (0x010, "host"),
    (0x020, "igmp"),
    (0x040, "repeater"),
    (0x080, "voip-phone"),
    (0x100, "remotely-managed"),
    (0x200, "cvta-stp"),
    (0x400, "two-port-mac-relay"),
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CdpInfo {
    pub version: u8,
    pub device_id: Option<String>,
    pub port_id: Option<String>,
    pub platform: Option<String>,
    /// First line of the software version text (Cisco sends several).
    pub software_version: Option<String>,
    pub capabilities: u32,
    pub addresses: Vec<IpAddr>,
    pub native_vlan: Option<u16>,
}

/// True when an 802.3 payload (the bytes right after the length field) is a
/// CDP announcement. The caller must already have checked that the frame's
/// Length/Type field is a length (≤ 1500, IEEE 802.3-2018 §3.2.6).
#[must_use]
pub fn is_cdp(llc_payload: &[u8]) -> bool {
    llc_payload.len() >= LLC_SNAP_LEN + CDP_HEADER_LEN
        && llc_payload[0..3] == [0xAA, 0xAA, 0x03]
        && llc_payload[3..6] == [0x00, 0x00, 0x0C]
        && llc_payload[6..8] == [0x20, 0x00]
        && matches!(llc_payload[8], 1 | 2)
}

fn text(bytes: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(bytes).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Address TLV: a count, then entries of protocol type, protocol length,
/// protocol, address length, address. IPv4 is NLPID 0xCC; IPv6 is the SNAP
/// encoding of ethertype 0x86DD.
fn parse_addresses(value: &[u8]) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let Some(count) = value.get(0..4) else {
        return out;
    };
    let count = u32::from_be_bytes([count[0], count[1], count[2], count[3]]).min(16);
    let mut pos = 4;
    for _ in 0..count {
        let (Some(&ptype), Some(&plen)) = (value.get(pos), value.get(pos + 1)) else {
            break;
        };
        let plen = usize::from(plen);
        let Some(protocol) = value.get(pos + 2..pos + 2 + plen) else {
            break;
        };
        let alen_at = pos + 2 + plen;
        let (Some(&hi), Some(&lo)) = (value.get(alen_at), value.get(alen_at + 1)) else {
            break;
        };
        let alen = usize::from(u16::from_be_bytes([hi, lo]));
        let Some(addr) = value.get(alen_at + 2..alen_at + 2 + alen) else {
            break;
        };
        match (ptype, protocol, alen) {
            (1, [0xCC], 4) => {
                if let Ok(a) = <[u8; 4]>::try_from(addr) {
                    out.push(IpAddr::V4(Ipv4Addr::from(a)));
                }
            }
            (2, [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x86, 0xDD], 16) => {
                if let Ok(a) = <[u8; 16]>::try_from(addr) {
                    out.push(IpAddr::V6(Ipv6Addr::from(a)));
                }
            }
            _ => {}
        }
        pos = alen_at + 2 + alen;
    }
    out
}

/// Parse a CDP announcement. Stops quietly at a truncated TLV.
#[must_use]
pub fn parse(llc_payload: &[u8]) -> Option<CdpInfo> {
    if !is_cdp(llc_payload) {
        return None;
    }
    let mut info = CdpInfo {
        version: llc_payload[LLC_SNAP_LEN],
        ..CdpInfo::default()
    };
    let mut pos = LLC_SNAP_LEN + CDP_HEADER_LEN;
    while pos + 4 <= llc_payload.len() {
        let tlv_type = u16::from_be_bytes([llc_payload[pos], llc_payload[pos + 1]]);
        let len = usize::from(u16::from_be_bytes([
            llc_payload[pos + 2],
            llc_payload[pos + 3],
        ]));
        if len < 4 {
            break;
        }
        let Some(value) = llc_payload.get(pos + 4..pos + len) else {
            break;
        };
        match tlv_type {
            TLV_DEVICE_ID => info.device_id = text(value),
            TLV_ADDRESSES => info.addresses = parse_addresses(value),
            TLV_PORT_ID => info.port_id = text(value),
            TLV_CAPABILITIES if value.len() >= 4 => {
                info.capabilities = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
            }
            TLV_SOFTWARE_VERSION => {
                info.software_version =
                    text(value).and_then(|s| s.lines().next().map(str::to_string));
            }
            TLV_PLATFORM => info.platform = text(value),
            TLV_NATIVE_VLAN if value.len() >= 2 => {
                info.native_vlan = Some(u16::from_be_bytes([value[0], value[1]]));
            }
            _ => {}
        }
        pos += len;
    }
    Some(info)
}

/// Names of the set capability bits, in bit order.
#[must_use]
pub fn capability_names(bits: u32) -> Vec<&'static str> {
    CAPABILITY_NAMES
        .iter()
        .filter(|(bit, _)| bits & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CDP_V2: [u8; 12] = [
        0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00, 0x02, 0xB4, 0x00, 0x00,
    ];

    fn tlv(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut out = kind.to_be_bytes().to_vec();
        out.extend_from_slice(&((value.len() + 4) as u16).to_be_bytes());
        out.extend_from_slice(value);
        out
    }

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

    #[test]
    fn parses_identity_tlvs() {
        let mut p = CDP_V2.to_vec();
        p.extend(tlv(TLV_DEVICE_ID, b"SW-CORE"));
        let mut addresses = 1u32.to_be_bytes().to_vec();
        addresses.extend_from_slice(&[1, 1, 0xCC, 0, 4, 10, 0, 0, 1]);
        p.extend(tlv(TLV_ADDRESSES, &addresses));
        p.extend(tlv(TLV_PORT_ID, b"GigabitEthernet1/0/1"));
        p.extend(tlv(TLV_CAPABILITIES, &[0, 0, 0, 0x29]));
        p.extend(tlv(
            TLV_SOFTWARE_VERSION,
            b"Cisco IOS Software, C2960 Software\nCopyright",
        ));
        p.extend(tlv(TLV_PLATFORM, b"cisco WS-C2960-24TT-L"));
        p.extend(tlv(TLV_NATIVE_VLAN, &[0, 10]));
        let info = parse(&p).unwrap();
        assert_eq!(info.version, 2);
        assert_eq!(info.device_id.as_deref(), Some("SW-CORE"));
        assert_eq!(info.addresses, vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]);
        assert_eq!(info.port_id.as_deref(), Some("GigabitEthernet1/0/1"));
        assert_eq!(
            capability_names(info.capabilities),
            vec!["router", "switch", "igmp"]
        );
        assert_eq!(
            info.software_version.as_deref(),
            Some("Cisco IOS Software, C2960 Software")
        );
        assert_eq!(info.platform.as_deref(), Some("cisco WS-C2960-24TT-L"));
        assert_eq!(info.native_vlan, Some(10));
    }
}
