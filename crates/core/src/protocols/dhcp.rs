//! DHCP (RFC 2131) with the options that identify a client (RFC 2132):
//! host name (12), vendor class (60), parameter request list (55), requested
//! address (50), client identifier (61), domain name (15).
//!
//! The parameter request list is the classic DHCP fingerprint: each client
//! stack asks for its own characteristic set of options in its own order.
//! The small signature table below is ours, built from the widely published
//! values for the common stacks (the technique satori and fingerbank use);
//! it is a guess with a stated confidence, never a fact.

use std::net::Ipv4Addr;

pub const OP_REQUEST: u8 = 1;
pub const OP_REPLY: u8 = 2;

pub const DISCOVER: u8 = 1;
pub const OFFER: u8 = 2;
pub const REQUEST: u8 = 3;
pub const DECLINE: u8 = 4;
pub const ACK: u8 = 5;
pub const NAK: u8 = 6;
pub const RELEASE: u8 = 7;
pub const INFORM: u8 = 8;

const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

#[derive(Debug, Clone)]
pub struct DhcpMessage {
    pub op: u8,
    /// Client hardware address when it is a 6-byte Ethernet MAC.
    pub chaddr: Option<[u8; 6]>,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub message_type: Option<u8>,
    pub hostname: Option<String>,
    pub vendor_class: Option<String>,
    pub client_id: Option<Vec<u8>>,
    pub parameter_request_list: Vec<u8>,
    pub requested_ip: Option<Ipv4Addr>,
    pub domain_name: Option<String>,
}

impl Default for DhcpMessage {
    fn default() -> Self {
        Self {
            op: 0,
            chaddr: None,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            message_type: None,
            hostname: None,
            vendor_class: None,
            client_id: None,
            parameter_request_list: Vec::new(),
            requested_ip: None,
            domain_name: None,
        }
    }
}

fn text(bytes: &[u8]) -> Option<String> {
    let trimmed = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    let s = String::from_utf8_lossy(trimmed).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn ipv4(bytes: &[u8]) -> Option<Ipv4Addr> {
    <[u8; 4]>::try_from(bytes).ok().map(Ipv4Addr::from)
}

/// Parse a BOOTP/DHCP message. `None` unless the fixed header and the DHCP
/// magic cookie are present.
#[must_use]
pub fn parse(bytes: &[u8]) -> Option<DhcpMessage> {
    if bytes.len() < 240 || bytes[236..240] != MAGIC_COOKIE {
        return None;
    }
    let mut msg = DhcpMessage {
        op: bytes[0],
        chaddr: (bytes[1] == 1 && bytes[2] == 6)
            .then(|| <[u8; 6]>::try_from(&bytes[28..34]).ok())
            .flatten(),
        ciaddr: ipv4(&bytes[12..16])?,
        yiaddr: ipv4(&bytes[16..20])?,
        ..DhcpMessage::default()
    };
    let mut pos = 240;
    while pos < bytes.len() {
        let code = bytes[pos];
        match code {
            0 => {
                pos += 1;
                continue;
            }
            255 => break,
            _ => {}
        }
        let len = usize::from(*bytes.get(pos + 1)?);
        let Some(data) = bytes.get(pos + 2..pos + 2 + len) else {
            break; // truncated option: keep what we have
        };
        match code {
            12 => msg.hostname = text(data),
            15 => msg.domain_name = text(data),
            50 => msg.requested_ip = ipv4(data),
            53 => msg.message_type = data.first().copied(),
            55 => msg.parameter_request_list = data.to_vec(),
            60 => msg.vendor_class = text(data),
            61 => msg.client_id = Some(data.to_vec()),
            _ => {}
        }
        pos += 2 + len;
    }
    Some(msg)
}

/// The parameter request list as `1,3,6,…` — the form fingerprint databases
/// use, and what the evidence table stores.
#[must_use]
pub fn fingerprint(parameter_request_list: &[u8]) -> String {
    parameter_request_list
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// A guess at the operating system behind a DHCP client, with confidence.
/// The vendor class is a self-declaration and outranks the option list.
#[must_use]
pub fn os_guess(vendor_class: Option<&str>, fingerprint: &str) -> Option<(&'static str, f64)> {
    if let Some(class) = vendor_class {
        let lower = class.to_ascii_lowercase();
        if lower.starts_with("msft 5.0") {
            return Some(("Windows", 0.7));
        }
        if lower.starts_with("msft 98") {
            return Some(("Windows 98", 0.7));
        }
        if lower.starts_with("msft") {
            return Some(("Windows", 0.6));
        }
        if lower.starts_with("android-dhcp") {
            return Some(("Android", 0.7));
        }
        if lower.starts_with("udhcp") {
            return Some(("Embedded Linux (udhcpc)", 0.6));
        }
        if lower.starts_with("dhcpcd") {
            return Some(("Linux or BSD (dhcpcd)", 0.6));
        }
        if lower.contains("cisco") {
            return Some(("Cisco IOS", 0.6));
        }
    }
    match fingerprint {
        "1,3,6,15,31,33,43,44,46,47,119,121,249,252" => Some(("Windows", 0.5)),
        "1,15,3,6,44,46,47,31,33,249,43" | "1,15,3,6,44,46,47,31,33,121,249,43" => {
            Some(("Windows (XP era)", 0.5))
        }
        "1,28,2,3,15,6,119,12,44,47,26,121,42" => Some(("Linux (dhclient)", 0.5)),
        "1,3,6,15,26,28,51,58,59,43" => Some(("Android", 0.5)),
        "1,121,3,6,15,119,252,95,44,46" => Some(("Apple (macOS or iOS)", 0.5)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discover(options: &[u8]) -> Vec<u8> {
        let mut m = vec![0u8; 240];
        m[0] = OP_REQUEST;
        m[1] = 1;
        m[2] = 6;
        m[28..34].copy_from_slice(&[0x00, 0x0c, 0x29, 1, 2, 3]);
        m[236..240].copy_from_slice(&MAGIC_COOKIE);
        m.extend_from_slice(options);
        m.push(255);
        m
    }

    #[test]
    fn reads_identity_options() {
        let mut options = vec![53, 1, DISCOVER, 12, 8];
        options.extend_from_slice(b"ENG-WS01");
        options.extend_from_slice(&[60, 8]);
        options.extend_from_slice(b"MSFT 5.0");
        options.extend_from_slice(&[55, 4, 1, 3, 6, 15, 0, 0]);
        let msg = parse(&discover(&options)).unwrap();
        assert_eq!(msg.message_type, Some(DISCOVER));
        assert_eq!(msg.chaddr, Some([0x00, 0x0c, 0x29, 1, 2, 3]));
        assert_eq!(msg.hostname.as_deref(), Some("ENG-WS01"));
        assert_eq!(msg.vendor_class.as_deref(), Some("MSFT 5.0"));
        assert_eq!(fingerprint(&msg.parameter_request_list), "1,3,6,15");
        assert_eq!(
            os_guess(msg.vendor_class.as_deref(), ""),
            Some(("Windows", 0.7))
        );
    }

    #[test]
    fn fingerprint_alone_is_a_weaker_guess() {
        assert_eq!(
            os_guess(None, "1,28,2,3,15,6,119,12,44,47,26,121,42"),
            Some(("Linux (dhclient)", 0.5))
        );
        assert_eq!(os_guess(None, "1,2,3"), None);
    }

    #[test]
    fn rejects_non_dhcp_and_survives_truncated_options() {
        assert!(parse(&[0u8; 100]).is_none());
        let mut m = discover(&[12, 20, b'c', b'u', b't']);
        m.pop(); // drop the end marker too
        let msg = parse(&m).unwrap();
        assert_eq!(msg.hostname, None);
    }
}
