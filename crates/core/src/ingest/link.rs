//! Link-type normalisation: every capture link type we read ends up as an
//! etherparse lax slice plus whatever MAC addresses its link header carried.
//! Only Ethernet carries both MACs; Linux cooked headers carry the sender's;
//! raw-IP and loopback captures carry none.

use etherparse::err::ip::LaxHeaderSliceError;
use etherparse::err::linux_sll::HeaderSliceError as SllError;
use etherparse::{EtherType, LaxSlicedPacket, LinkSlice, LinuxSllProtocolType, LinuxSllSlice};
use pcap_parser::Linktype;

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Macs {
    pub src: Option<[u8; 6]>,
    pub dst: Option<[u8; 6]>,
}

// The decoded variant is large because it holds every parsed layer; boxing it
// would cost an allocation per packet on the hot path for nothing.
#[allow(clippy::large_enum_variant)]
pub(crate) enum LinkDecode<'a> {
    Ok {
        parsed: LaxSlicedPacket<'a>,
        macs: Macs,
    },
    UnsupportedLinkType,
    /// The link header itself did not fit in the captured bytes.
    TooShort,
    /// The link header was present but not decodable.
    Malformed,
}

/// Link types this reader decodes. Values from tcpdump.org/linktypes.html,
/// via pcap-parser's `Linktype` constants.
pub(crate) fn decode(linktype: Linktype, data: &[u8]) -> LinkDecode<'_> {
    match linktype {
        Linktype::ETHERNET => ethernet(data),
        Linktype::LINUX_SLL => linux_sll(data),
        Linktype::LINUX_SLL2 => linux_sll2(data),
        Linktype::RAW | Linktype::IPV4 | Linktype::IPV6 => raw_ip(data),
        // NULL (BSD loopback) / LOOP (OpenBSD loopback): a 4-byte address
        // family word (host order for NULL, network order for LOOP) precedes
        // the IP header. The IP version nibble says the same thing, so the
        // word is skipped.
        Linktype::NULL | Linktype::LOOP => {
            if data.len() < 4 {
                LinkDecode::TooShort
            } else {
                raw_ip(&data[4..])
            }
        }
        _ => LinkDecode::UnsupportedLinkType,
    }
}

fn ethernet(data: &[u8]) -> LinkDecode<'_> {
    // Lax parsing tolerates snaplen truncation: headers still decode and the
    // payload is whatever was captured, instead of dropping the packet.
    match LaxSlicedPacket::from_ethernet(data) {
        Ok(parsed) => {
            let macs = match &parsed.link {
                Some(LinkSlice::Ethernet2(eth)) => Macs {
                    src: Some(eth.source()),
                    dst: Some(eth.destination()),
                },
                _ => Macs::default(),
            };
            LinkDecode::Ok { parsed, macs }
        }
        Err(_) => LinkDecode::TooShort,
    }
}

/// `LINKTYPE_LINUX_SLL` (113): the 16-byte "cooked" header `tcpdump -i any`
/// writes. Only the sender address is present.
fn linux_sll(data: &[u8]) -> LinkDecode<'_> {
    match LinuxSllSlice::from_slice(data) {
        Ok(sll) => {
            let ether_type = match sll.protocol_type() {
                LinuxSllProtocolType::EtherType(et) => et,
                _ => EtherType(0),
            };
            let src = (sll.sender_address_valid_length() == 6)
                .then(|| sll.sender_address().try_into().ok())
                .flatten();
            LinkDecode::Ok {
                parsed: LaxSlicedPacket::from_ether_type(ether_type, sll.payload_slice()),
                macs: Macs { src, dst: None },
            }
        }
        Err(SllError::Len(_)) => LinkDecode::TooShort,
        Err(SllError::Content(_)) => LinkDecode::Malformed,
    }
}

/// `LINKTYPE_LINUX_SLL2` (276), the newer cooked header
/// (<https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html>):
///
/// ```text
/// 0   protocol type (big-endian u16)
/// 2   reserved
/// 4   interface index (big-endian u32)
/// 8   ARPHRD type (big-endian u16)
/// 10  packet type
/// 11  link-layer address length
/// 12  link-layer address (8 bytes, zero padded)
/// 20  payload
/// ```
fn linux_sll2(data: &[u8]) -> LinkDecode<'_> {
    const HEADER_LEN: usize = 20;
    if data.len() < HEADER_LEN {
        return LinkDecode::TooShort;
    }
    let protocol = u16::from_be_bytes([data[0], data[1]]);
    let hardware_type = u16::from_be_bytes([data[8], data[9]]);
    let address_len = data[11];
    // ARPHRD_ETHER = 1 with a 6-byte address is the only case that is a MAC.
    let src = (hardware_type == 1 && address_len == 6)
        .then(|| data[12..18].try_into().ok())
        .flatten();
    LinkDecode::Ok {
        parsed: LaxSlicedPacket::from_ether_type(EtherType(protocol), &data[HEADER_LEN..]),
        macs: Macs { src, dst: None },
    }
}

fn raw_ip(data: &[u8]) -> LinkDecode<'_> {
    match LaxSlicedPacket::from_ip(data) {
        Ok(parsed) => LinkDecode::Ok {
            parsed,
            macs: Macs::default(),
        },
        Err(LaxHeaderSliceError::Len(_)) => LinkDecode::TooShort,
        Err(LaxHeaderSliceError::Content(_)) => LinkDecode::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sll2_header_yields_sender_mac_and_ethertype() {
        let mut frame = vec![0x08, 0x00, 0, 0, 0, 0, 0, 2, 0, 1, 0, 6];
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0, 0]);
        // Minimal IPv4 header (20 bytes) with protocol 1, 10.0.0.1 -> 10.0.0.2
        frame.extend_from_slice(&[
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ]);
        let LinkDecode::Ok { parsed, macs } = decode(Linktype::LINUX_SLL2, &frame) else {
            panic!("SLL2 frame should decode");
        };
        assert_eq!(macs.src, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert_eq!(macs.dst, None);
        assert!(matches!(parsed.net, Some(etherparse::LaxNetSlice::Ipv4(_))));
    }

    #[test]
    fn unknown_link_types_are_reported_not_guessed() {
        assert!(matches!(
            decode(Linktype(105), &[0u8; 64]),
            LinkDecode::UnsupportedLinkType
        ));
    }

    #[test]
    fn short_link_headers_are_too_short() {
        assert!(matches!(
            decode(Linktype::ETHERNET, &[0u8; 10]),
            LinkDecode::TooShort
        ));
        assert!(matches!(
            decode(Linktype::LINUX_SLL2, &[0u8; 10]),
            LinkDecode::TooShort
        ));
        assert!(matches!(
            decode(Linktype::NULL, &[0u8; 3]),
            LinkDecode::TooShort
        ));
    }
}
