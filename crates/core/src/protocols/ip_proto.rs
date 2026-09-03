//! IANA IP protocol numbers and the names the UI shows for them.
//!
//! Numbers and keywords are transcribed from the IANA "Assigned Internet
//! Protocol Numbers" registry
//! (<https://www.iana.org/assignments/protocol-numbers>). Anything not listed
//! is shown as `IP-<number>` so an unusual protocol is still visible rather
//! than folded into "other".

use std::borrow::Cow;

const NAMES: &[(u8, &str)] = &[
    (1, "ICMP"),
    (2, "IGMP"),
    (4, "IPIP"),
    (6, "TCP"),
    (17, "UDP"),
    (41, "IPv6"),
    (47, "GRE"),
    (50, "ESP"),
    (51, "AH"),
    (58, "ICMPv6"),
    (88, "EIGRP"),
    (89, "OSPF"),
    (103, "PIM"),
    (112, "VRRP"),
    (115, "L2TP"),
    (132, "SCTP"),
    (136, "UDP-Lite"),
];

/// Display name for an IP protocol number.
#[must_use]
pub fn name(number: u8) -> Cow<'static, str> {
    NAMES.iter().find(|(n, _)| *n == number).map_or_else(
        || Cow::Owned(format!("IP-{number}")),
        |(_, s)| Cow::Borrowed(*s),
    )
}

/// Inverse of [`name`]: the protocol number a stored display name refers to.
#[must_use]
pub fn number(name: &str) -> Option<u8> {
    if let Some((n, _)) = NAMES.iter().find(|(_, s)| *s == name) {
        return Some(*n);
    }
    name.strip_prefix("IP-")?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_numbers_round_trip() {
        for (n, s) in NAMES {
            assert_eq!(name(*n), *s);
            assert_eq!(number(s), Some(*n));
        }
    }

    #[test]
    fn unknown_numbers_round_trip_through_generic_name() {
        assert_eq!(name(200), "IP-200");
        assert_eq!(number("IP-200"), Some(200));
        assert_eq!(number("nonsense"), None);
    }
}
