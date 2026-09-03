//! Frame classification: turns an etherparse lax slice into the one fact the
//! ingest sink needs — an IP packet with hosts and a flow, a link-layer
//! announcement worth counting, or something we count but do not read.
//!
//! Everything here reads etherparse's parsed structures; nothing indexes raw
//! frame offsets, so VLAN tags and cooked headers can never shift a check.

use std::net::IpAddr;

use etherparse::err::packet::SliceError;
use etherparse::{
    LaxLinkExtSlice, LaxNetSlice, LaxSlicedPacket, LinkSlice, LinuxSllProtocolType, TransportSlice,
};

use crate::ingest::link::Macs;
use crate::protocols::arp;
use crate::protocols::cdp::{self, CdpInfo};
use crate::protocols::lldp::{self, LldpInfo};

/// IEEE 802.1AE (`MACsec`) ethertype; a protected payload is opaque to us.
const ETHERTYPE_MACSEC: u16 = 0x88E5;

/// IEEE 802.3-2018 §3.2.6: a Length/Type value of 1500 or less is a length,
/// and the payload then starts with an IEEE 802.2 LLC header.
const MAX_802_3_LENGTH: u16 = 1500;

pub(crate) enum Transport<'a> {
    Tcp {
        src_port: u16,
        dst_port: u16,
        payload: &'a [u8],
    },
    Udp {
        src_port: u16,
        dst_port: u16,
        payload: &'a [u8],
    },
    /// ICMP (v4 and v6), IGMP and every other IP protocol: a port-less flow.
    Portless,
}

pub(crate) struct IpFrame<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// IANA protocol number of the innermost IP payload.
    pub ip_proto: u8,
    pub transport: Transport<'a>,
}

pub(crate) enum Frame<'a> {
    Ip(IpFrame<'a>),
    /// A non-first IP fragment: hosts are known, the transport is not.
    Fragment {
        src: IpAddr,
        dst: IpAddr,
    },
    /// ARP; `None` when the hardware/protocol pair is not Ethernet/IPv4.
    Arp(Option<arp::ArpInfo>),
    Lldp(LldpInfo),
    Cdp(CdpInfo),
    /// An Ethernet payload we do not read: other ethertypes (PROFINET RT,
    /// `EtherCAT`, …) and non-CDP 802.3/LLC frames (spanning tree, …).
    OtherEthertype,
    /// A header was cut by the capture's snapshot length. Hosts are present
    /// when the IP header survived the cut.
    Truncated {
        hosts: Option<(IpAddr, IpAddr)>,
    },
    /// A header that could not be decoded for any other reason.
    Malformed {
        hosts: Option<(IpAddr, IpAddr)>,
    },
}

pub(crate) struct Classified<'a> {
    pub macs: Macs,
    /// 802.1Q VLAN id of the outermost tag, if the frame was tagged.
    pub vlan: Option<u16>,
    pub frame: Frame<'a>,
}

/// `cut_by_snaplen` — the record's captured length is below its wire length,
/// which decides whether a missing header is truncation or corruption.
pub(crate) fn classify<'a>(
    parsed: &LaxSlicedPacket<'a>,
    macs: Macs,
    cut_by_snaplen: bool,
) -> Classified<'a> {
    let vlan = parsed.link_exts.iter().find_map(|ext| match ext {
        LaxLinkExtSlice::Vlan(tag) => Some(tag.vlan_identifier().value()),
        LaxLinkExtSlice::Macsec(_) => None,
    });
    Classified {
        macs,
        vlan,
        frame: classify_frame(parsed, cut_by_snaplen),
    }
}

fn classify_frame<'a>(parsed: &LaxSlicedPacket<'a>, cut_by_snaplen: bool) -> Frame<'a> {
    if let Some((err, _layer)) = &parsed.stop_err {
        let hosts = net_addrs(parsed.net.as_ref());
        return if cut_by_snaplen && matches!(err, SliceError::Len(_)) {
            Frame::Truncated { hosts }
        } else {
            Frame::Malformed { hosts }
        };
    }
    match &parsed.net {
        Some(LaxNetSlice::Ipv4(v4)) => {
            let header = v4.header();
            let (src, dst) = (
                IpAddr::V4(header.source_addr()),
                IpAddr::V4(header.destination_addr()),
            );
            if v4.is_payload_fragmented() {
                return Frame::Fragment { src, dst };
            }
            Frame::Ip(IpFrame {
                src,
                dst,
                ip_proto: v4.payload().ip_number.0,
                transport: transport(parsed.transport.as_ref()),
            })
        }
        Some(LaxNetSlice::Ipv6(v6)) => {
            let header = v6.header();
            let (src, dst) = (
                IpAddr::V6(header.source_addr()),
                IpAddr::V6(header.destination_addr()),
            );
            if v6.is_payload_fragmented() {
                return Frame::Fragment { src, dst };
            }
            Frame::Ip(IpFrame {
                src,
                dst,
                ip_proto: v6.payload().ip_number.0,
                transport: transport(parsed.transport.as_ref()),
            })
        }
        Some(LaxNetSlice::Arp(packet)) => Frame::Arp(arp::from_slice(packet)),
        None => classify_non_ip(parsed),
    }
}

fn net_addrs(net: Option<&LaxNetSlice<'_>>) -> Option<(IpAddr, IpAddr)> {
    match net {
        Some(LaxNetSlice::Ipv4(v4)) => {
            let h = v4.header();
            Some((
                IpAddr::V4(h.source_addr()),
                IpAddr::V4(h.destination_addr()),
            ))
        }
        Some(LaxNetSlice::Ipv6(v6)) => {
            let h = v6.header();
            Some((
                IpAddr::V6(h.source_addr()),
                IpAddr::V6(h.destination_addr()),
            ))
        }
        _ => None,
    }
}

fn transport<'a>(slice: Option<&TransportSlice<'a>>) -> Transport<'a> {
    match slice {
        Some(TransportSlice::Tcp(tcp)) => Transport::Tcp {
            src_port: tcp.source_port(),
            dst_port: tcp.destination_port(),
            payload: tcp.payload(),
        },
        Some(TransportSlice::Udp(udp)) => Transport::Udp {
            src_port: udp.source_port(),
            dst_port: udp.destination_port(),
            payload: udp.payload(),
        },
        _ => Transport::Portless,
    }
}

fn sll_ether_type(protocol: LinuxSllProtocolType) -> u16 {
    match protocol {
        LinuxSllProtocolType::EtherType(et) => et.0,
        _ => 0,
    }
}

/// The innermost ethertype and payload of a frame that carried no IP packet.
fn ether_payload<'a>(parsed: &LaxSlicedPacket<'a>) -> Option<(u16, &'a [u8])> {
    if let Some(ext) = parsed.link_exts.last() {
        return match ext {
            LaxLinkExtSlice::Vlan(tag) => Some((tag.ether_type().0, tag.payload_slice())),
            LaxLinkExtSlice::Macsec(_) => Some((ETHERTYPE_MACSEC, &[])),
        };
    }
    match &parsed.link {
        Some(LinkSlice::Ethernet2(eth)) => Some((eth.ether_type().0, eth.payload_slice())),
        Some(LinkSlice::EtherPayload(p)) => Some((p.ether_type.0, p.payload)),
        Some(LinkSlice::LinuxSll(sll)) => {
            Some((sll_ether_type(sll.protocol_type()), sll.payload_slice()))
        }
        Some(LinkSlice::LinuxSllPayload(p)) => Some((sll_ether_type(p.protocol_type), p.payload)),
        None => None,
    }
}

fn classify_non_ip<'a>(parsed: &LaxSlicedPacket<'a>) -> Frame<'a> {
    let Some((ether_type, payload)) = ether_payload(parsed) else {
        return Frame::Malformed { hosts: None };
    };
    if ether_type == lldp::ETHERTYPE_LLDP {
        return match lldp::parse(payload) {
            Some(info) => Frame::Lldp(info),
            None => Frame::Malformed { hosts: None },
        };
    }
    if ether_type <= MAX_802_3_LENGTH && cdp::is_cdp(payload) {
        return match cdp::parse(payload) {
            Some(info) => Frame::Cdp(info),
            None => Frame::Malformed { hosts: None },
        };
    }
    Frame::OtherEthertype
}
