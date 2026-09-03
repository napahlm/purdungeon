//! ARP (RFC 826): which devices an ARP packet vouches for.
//!
//! ARP is the cheapest asset source there is — every IPv4 device on a segment
//! announces its own address/MAC pair whether or not it ever sends IP traffic
//! the capture point can see.

use std::net::Ipv4Addr;

use etherparse::{ArpHardwareId, ArpOperation, ArpPacketSlice, EtherType};

/// The address pairs carried by an Ethernet/IPv4 ARP packet.
#[derive(Debug, Clone, Copy)]
pub struct ArpInfo {
    pub is_reply: bool,
    pub sender: (Ipv4Addr, [u8; 6]),
    pub target: (Ipv4Addr, [u8; 6]),
}

/// `None` unless the packet maps 6-byte Ethernet addresses to 4-byte IPv4
/// addresses (hardware type 1, protocol type 0x0800 — RFC 826). Other
/// combinations exist (token ring, IPX) but never on the networks we care
/// about, and reading them as Ethernet/IPv4 would invent hosts.
#[must_use]
pub fn from_slice(arp: &ArpPacketSlice<'_>) -> Option<ArpInfo> {
    if arp.hw_addr_type() != ArpHardwareId::ETHERNET
        || arp.proto_addr_type() != EtherType::IPV4
        || arp.hw_addr_size() != 6
        || arp.proto_addr_size() != 4
    {
        return None;
    }
    let mac = |b: &[u8]| -> Option<[u8; 6]> { b.try_into().ok() };
    let ip = |b: &[u8]| -> Option<Ipv4Addr> { <[u8; 4]>::try_from(b).ok().map(Ipv4Addr::from) };
    Some(ArpInfo {
        is_reply: arp.operation() == ArpOperation::REPLY,
        sender: (ip(arp.sender_protocol_addr())?, mac(arp.sender_hw_addr())?),
        target: (ip(arp.target_protocol_addr())?, mac(arp.target_hw_addr())?),
    })
}

/// The hosts this packet is evidence for.
///
/// The sender is always real — it is announcing itself — except for an ARP
/// probe, which uses 0.0.0.0 while the sender is still deciding on an
/// address (RFC 5227 §2.1.1). The target of a *request* is a question, not a
/// device, and must not become an asset; the target of a *reply* is the
/// requester, which is real. A gratuitous ARP (sender == target, RFC 5227 §3)
/// contributes its sender once.
#[must_use]
pub fn hosts_from(info: &ArpInfo) -> Vec<(Ipv4Addr, [u8; 6])> {
    let mut hosts = Vec::with_capacity(2);
    if is_asset(info.sender) {
        hosts.push(info.sender);
    }
    if info.is_reply && is_asset(info.target) && info.target.0 != info.sender.0 {
        hosts.push(info.target);
    }
    hosts
}

fn is_asset((ip, mac): (Ipv4Addr, [u8; 6])) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && mac != [0; 6]
        && mac != [0xff; 6]
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC_A: [u8; 6] = [0x00, 0x1b, 0x1b, 1, 2, 3];
    const MAC_B: [u8; 6] = [0x00, 0x0c, 0x29, 4, 5, 6];

    fn info(is_reply: bool, sender: (Ipv4Addr, [u8; 6]), target: (Ipv4Addr, [u8; 6])) -> ArpInfo {
        ArpInfo {
            is_reply,
            sender,
            target,
        }
    }

    #[test]
    fn request_vouches_for_sender_only() {
        let hosts = hosts_from(&info(
            false,
            (Ipv4Addr::new(10, 0, 0, 1), MAC_A),
            (Ipv4Addr::new(10, 0, 0, 200), [0; 6]),
        ));
        assert_eq!(hosts, vec![(Ipv4Addr::new(10, 0, 0, 1), MAC_A)]);
    }

    #[test]
    fn reply_vouches_for_both_ends() {
        let hosts = hosts_from(&info(
            true,
            (Ipv4Addr::new(10, 0, 0, 200), MAC_B),
            (Ipv4Addr::new(10, 0, 0, 1), MAC_A),
        ));
        assert_eq!(hosts.len(), 2);
    }

    #[test]
    fn probe_and_gratuitous_arp() {
        let probe = info(
            false,
            (Ipv4Addr::UNSPECIFIED, MAC_A),
            (Ipv4Addr::new(10, 0, 0, 1), [0; 6]),
        );
        assert!(hosts_from(&probe).is_empty());
        let gratuitous = info(
            true,
            (Ipv4Addr::new(10, 0, 0, 1), MAC_A),
            (Ipv4Addr::new(10, 0, 0, 1), MAC_A),
        );
        assert_eq!(hosts_from(&gratuitous).len(), 1);
    }
}
