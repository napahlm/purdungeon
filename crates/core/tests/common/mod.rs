//! Shared builders for the integration tests: synthetic frames, legacy pcap
//! and pcapng writers, and the import harness. Every test that imports a
//! capture ends with [`assert_reconciles`].
#![allow(dead_code)]

pub mod identity;

use std::path::Path;
use std::sync::atomic::AtomicU64;

use etherparse::{IpNumber, PacketBuilder, VlanId};
use purdungeon_core::types::ImportResult;
use purdungeon_core::{CoreError, Session};

pub const SCADA_MAC: [u8; 6] = [0x00, 0x0c, 0x29, 0x11, 0x22, 0x33];
// 00:1b:1b is a Siemens prefix in the bundled OUI table
pub const PLC_MAC: [u8; 6] = [0x00, 0x1b, 0x1b, 0x44, 0x55, 0x66];
pub const HMI_MAC: [u8; 6] = [0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc];
pub const SWITCH_MAC: [u8; 6] = [0x00, 0x80, 0x63, 0x01, 0x02, 0x03];
pub const BROADCAST_MAC: [u8; 6] = [0xff; 6];
pub const SCADA_IP: [u8; 4] = [192, 168, 10, 100];
pub const PLC_A_IP: [u8; 4] = [192, 168, 10, 1];
pub const PLC_B_IP: [u8; 4] = [192, 168, 10, 2];
pub const PLC_C_IP: [u8; 4] = [192, 168, 10, 3];
pub const HMI_IP: [u8; 4] = [192, 168, 10, 50];
pub const PLC_D_IP: [u8; 4] = [192, 168, 10, 4];
pub const BASE_TS: f64 = 1_700_000_000.0;

// ── Payload and packet builders ─────────────────────────────────────────────

pub fn mbap(tid: u16, unit: u8, pdu: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&tid.to_be_bytes());
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&((pdu.len() as u16 + 1).to_be_bytes()));
    buf.push(unit);
    buf.extend_from_slice(pdu);
    buf
}

/// Read Holding Registers request for 10 registers at address 0.
pub fn read_request(tid: u16) -> Vec<u8> {
    mbap(tid, 1, &[0x03, 0x00, 0x00, 0x00, 0x0A])
}

/// Read Holding Registers response with 10 zero registers.
pub fn read_response(tid: u16) -> Vec<u8> {
    let mut body = vec![0x03, 0x14];
    body.extend_from_slice(&[0u8; 20]);
    mbap(tid, 1, &body)
}

pub fn tcp_packet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
        .ipv4(src_ip, dst_ip, 64)
        .tcp(src_port, dst_port, 1000, 64240);
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).unwrap();
    out
}

pub fn vlan_tcp_packet(
    vlan: u16,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
        .single_vlan(VlanId::try_new(vlan).unwrap())
        .ipv4(src_ip, dst_ip, 64)
        .tcp(src_port, dst_port, 1000, 64240);
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).unwrap();
    out
}

pub fn qinq_tcp_packet(
    outer: u16,
    inner: u16,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
        .double_vlan(
            VlanId::try_new(outer).unwrap(),
            VlanId::try_new(inner).unwrap(),
        )
        .ipv4(src_ip, dst_ip, 64)
        .tcp(src_port, dst_port, 1000, 64240);
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).unwrap();
    out
}

pub fn udp_packet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
        .ipv4(src_ip, dst_ip, 64)
        .udp(src_port, dst_port);
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).unwrap();
    out
}

pub fn tcp6_packet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
        .ipv6(src_ip, dst_ip, 64)
        .tcp(src_port, dst_port, 1000, 64240);
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).unwrap();
    out
}

pub fn udp6_packet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
        .ipv6(src_ip, dst_ip, 64)
        .udp(src_port, dst_port);
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).unwrap();
    out
}

pub fn icmpv6_echo(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    reply: bool,
) -> Vec<u8> {
    let ip = PacketBuilder::ethernet2(src_mac, dst_mac).ipv6(src_ip, dst_ip, 64);
    let builder = if reply {
        ip.icmpv6_echo_reply(1, 1)
    } else {
        ip.icmpv6_echo_request(1, 1)
    };
    let mut out = Vec::with_capacity(builder.size(8));
    builder.write(&mut out, &[0u8; 8]).unwrap();
    out
}

/// An IPv4 packet carrying an arbitrary protocol number (IGMP, VRRP, GRE…).
pub fn ip_proto_packet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    protocol: IpNumber,
    payload: &[u8],
) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(src_mac, dst_mac).ipv4(src_ip, dst_ip, 64);
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, protocol, payload).unwrap();
    out
}

/// A non-first IPv4 fragment (offset 100 × 8 bytes) of a UDP datagram.
pub fn ipv4_fragment(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
) -> Vec<u8> {
    let payload = [0xABu8; 32];
    let mut header =
        etherparse::Ipv4Header::new(payload.len() as u16, 64, IpNumber::UDP, src_ip, dst_ip)
            .unwrap();
    header.fragment_offset = etherparse::IpFragOffset::try_new(100).unwrap();
    header.more_fragments = false;
    let mut out = Vec::new();
    out.extend_from_slice(&dst_mac);
    out.extend_from_slice(&src_mac);
    out.extend_from_slice(&[0x08, 0x00]);
    header.write(&mut out).unwrap();
    out.extend_from_slice(&payload);
    out
}

/// IPv4 + TCP with no link header, for raw-IP and cooked link types.
pub fn bare_ipv4_tcp(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let builder = PacketBuilder::ipv4(src_ip, dst_ip, 64).tcp(src_port, dst_port, 1000, 64240);
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).unwrap();
    out
}

pub fn bare_ipv6_udp(
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let builder = PacketBuilder::ipv6(src_ip, dst_ip, 64).udp(src_port, dst_port);
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).unwrap();
    out
}

fn ethernet_header(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    vlan: Option<u16>,
    ether_type: u16,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(18);
    out.extend_from_slice(&dst_mac);
    out.extend_from_slice(&src_mac);
    if let Some(id) = vlan {
        out.extend_from_slice(&[0x81, 0x00]);
        out.extend_from_slice(&(id & 0x0FFF).to_be_bytes());
    }
    out.extend_from_slice(&ether_type.to_be_bytes());
    out
}

/// A raw Ethernet/IPv4 ARP frame (RFC 826), optionally 802.1Q tagged.
/// Requests go to the broadcast MAC; replies go to the target MAC.
pub fn arp_frame(
    is_reply: bool,
    sender: ([u8; 4], [u8; 6]),
    target: ([u8; 4], [u8; 6]),
    vlan: Option<u16>,
) -> Vec<u8> {
    let dst_mac = if is_reply { target.1 } else { BROADCAST_MAC };
    let mut out = ethernet_header(sender.1, dst_mac, vlan, 0x0806);
    out.extend_from_slice(&[0x00, 0x01]); // hardware: Ethernet
    out.extend_from_slice(&[0x08, 0x00]); // protocol: IPv4
    out.extend_from_slice(&[6, 4]);
    out.extend_from_slice(&if is_reply { [0x00, 0x02] } else { [0x00, 0x01] });
    out.extend_from_slice(&sender.1);
    out.extend_from_slice(&sender.0);
    out.extend_from_slice(&target.1);
    out.extend_from_slice(&target.0);
    // Ethernet minimum frame padding, as a switch would add.
    while out.len() < 60 {
        out.push(0);
    }
    out
}

/// An LLDP announcement: Chassis ID (MAC), Port ID, TTL, End.
pub fn lldp_frame(src_mac: [u8; 6]) -> Vec<u8> {
    let mut out = ethernet_header(src_mac, [0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E], None, 0x88CC);
    out.extend_from_slice(&[0x02, 0x07, 0x04]); // Chassis ID, len 7, subtype MAC
    out.extend_from_slice(&src_mac);
    out.extend_from_slice(&[0x04, 0x04, 0x05, b'g', b'i', b'1']); // Port ID, interface name
    out.extend_from_slice(&[0x06, 0x02, 0x00, 0x78]); // TTL 120
    out.extend_from_slice(&[0x00, 0x00]); // End of LLDPDU
    out
}

/// A CDP v2 announcement in an 802.3 frame under LLC/SNAP.
pub fn cdp_frame(src_mac: [u8; 6]) -> Vec<u8> {
    let mut body = vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00];
    body.extend_from_slice(&[0x02, 0xB4, 0x00, 0x00]); // version 2, ttl 180, checksum
    body.extend_from_slice(&[0x00, 0x01, 0x00, 0x0A, b'S', b'W', b'1', b'2', b'3', b'4']); // Device ID
    let mut out = Vec::new();
    out.extend_from_slice(&[0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC]);
    out.extend_from_slice(&src_mac);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// A spanning-tree BPDU: 802.3 frame, LLC DSAP/SSAP 0x42, no SNAP.
pub fn stp_frame(src_mac: [u8; 6]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x01, 0x80, 0xC2, 0x00, 0x00, 0x00]);
    out.extend_from_slice(&src_mac);
    out.extend_from_slice(&38u16.to_be_bytes());
    out.extend_from_slice(&[0x42, 0x42, 0x03]);
    out.extend_from_slice(&[0u8; 35]);
    out
}

/// An Ethernet II frame with an arbitrary ethertype and payload.
pub fn ethertype_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    ether_type: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = ethernet_header(src_mac, dst_mac, None, ether_type);
    out.extend_from_slice(payload);
    out
}

/// `LINKTYPE_LINUX_SLL`: 16-byte cooked header before an IP packet.
pub fn sll_frame(src_mac: [u8; 6], ether_type: u16, ip_packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_be_bytes()); // packet type: to us
    out.extend_from_slice(&1u16.to_be_bytes()); // ARPHRD_ETHER
    out.extend_from_slice(&6u16.to_be_bytes()); // address length
    out.extend_from_slice(&src_mac);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&ether_type.to_be_bytes());
    out.extend_from_slice(ip_packet);
    out
}

/// `LINKTYPE_LINUX_SLL2`: 20-byte cooked header before an IP packet.
pub fn sll2_frame(src_mac: [u8; 6], ether_type: u16, ip_packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&ether_type.to_be_bytes());
    out.extend_from_slice(&[0, 0]); // reserved
    out.extend_from_slice(&2u32.to_be_bytes()); // interface index
    out.extend_from_slice(&1u16.to_be_bytes()); // ARPHRD_ETHER
    out.push(0); // packet type
    out.push(6); // address length
    out.extend_from_slice(&src_mac);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(ip_packet);
    out
}

/// `LINKTYPE_NULL`: 4-byte address family (`AF_INET` = 2, host order) then IP.
pub fn null_frame(ip_packet: &[u8]) -> Vec<u8> {
    let mut out = 2u32.to_le_bytes().to_vec();
    out.extend_from_slice(ip_packet);
    out
}

// ── Capture file writers ────────────────────────────────────────────────────

pub const MAGIC_MICROS: u32 = 0xa1b2_c3d4;
pub const MAGIC_NANOS: u32 = 0xa1b2_3c4d;

/// Minimal legacy pcap writer: global header + per-packet records. The magic
/// selects micro- vs nanosecond sub-second fields; `snaplen` truncates the
/// stored bytes while keeping the original length in the record header.
pub fn write_pcap_ex(
    packets: &[(f64, Vec<u8>)],
    magic: u32,
    linktype: u32,
    snaplen: Option<usize>,
) -> Vec<u8> {
    let subsec_scale = if magic == MAGIC_NANOS {
        1_000_000_000.0
    } else {
        1_000_000.0
    };
    let mut buf = Vec::new();
    buf.extend_from_slice(&magic.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes()); // major
    buf.extend_from_slice(&4u16.to_le_bytes()); // minor
    buf.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    buf.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    buf.extend_from_slice(&(snaplen.unwrap_or(65535) as u32).to_le_bytes());
    buf.extend_from_slice(&linktype.to_le_bytes());
    for (ts, data) in packets {
        let secs = ts.trunc() as u32;
        let subsec = (ts.fract() * subsec_scale) as u32;
        let incl = snaplen.map_or(data.len(), |s| s.min(data.len()));
        buf.extend_from_slice(&secs.to_le_bytes());
        buf.extend_from_slice(&subsec.to_le_bytes());
        buf.extend_from_slice(&(incl as u32).to_le_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes()); // orig_len
        buf.extend_from_slice(&data[..incl]);
    }
    buf
}

pub fn write_pcap(packets: &[(f64, Vec<u8>)]) -> Vec<u8> {
    write_pcap_ex(packets, MAGIC_MICROS, 1, None)
}

pub fn write_pcap_linktype(packets: &[(f64, Vec<u8>)], linktype: u32) -> Vec<u8> {
    write_pcap_ex(packets, MAGIC_MICROS, linktype, None)
}

// ── Minimal pcapng writer: SHB + IDB + EPB/SPB blocks ───────────────────────

pub fn png_block(block_type: u32, body: &[u8]) -> Vec<u8> {
    let padded = body.len().div_ceil(4) * 4;
    let total = (12 + padded) as u32;
    let mut b = Vec::new();
    b.extend_from_slice(&block_type.to_le_bytes());
    b.extend_from_slice(&total.to_le_bytes());
    b.extend_from_slice(body);
    b.resize(8 + padded, 0);
    b.extend_from_slice(&total.to_le_bytes());
    b
}

pub fn png_shb() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x1A2B_3C4D_u32.to_le_bytes()); // byte-order magic
    body.extend_from_slice(&1u16.to_le_bytes()); // major
    body.extend_from_slice(&0u16.to_le_bytes()); // minor
    body.extend_from_slice(&(-1i64).to_le_bytes()); // section length: unknown
    png_block(0x0A0D_0D0A, &body)
}

pub fn png_idb(linktype: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&linktype.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // reserved
    body.extend_from_slice(&0u32.to_le_bytes()); // snaplen: unlimited
    png_block(0x0000_0001, &body)
}

/// Enhanced Packet Block with a microsecond timestamp (the IDB above carries
/// no `if_tsresol` option, so 1 µs is the default).
pub fn png_epb_on(if_id: u32, ts_micros: u64, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&if_id.to_le_bytes());
    body.extend_from_slice(&((ts_micros >> 32) as u32).to_le_bytes());
    body.extend_from_slice(&((ts_micros & 0xFFFF_FFFF) as u32).to_le_bytes());
    body.extend_from_slice(&(data.len() as u32).to_le_bytes()); // caplen
    body.extend_from_slice(&(data.len() as u32).to_le_bytes()); // origlen
    body.extend_from_slice(data);
    png_block(0x0000_0006, &body)
}

pub fn png_epb(ts_micros: u64, data: &[u8]) -> Vec<u8> {
    png_epb_on(0, ts_micros, data)
}

pub fn png_spb(data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(data.len() as u32).to_le_bytes()); // origlen
    body.extend_from_slice(data);
    png_block(0x0000_0003, &body)
}

// ── Scenario captures ───────────────────────────────────────────────────────

/// SCADA polls three PLCs once a second for ten rounds; writes a coil on
/// PLC A every third round.
pub fn polling_capture() -> Vec<(f64, Vec<u8>)> {
    let mut packets = Vec::new();
    let mut ts = BASE_TS;
    let mut tid: u16 = 1;
    for round in 0..10 {
        for (i, plc_ip) in [PLC_A_IP, PLC_B_IP, PLC_C_IP].iter().enumerate() {
            let port = 49000 + i as u16;
            packets.push((
                ts,
                tcp_packet(
                    SCADA_MAC,
                    PLC_MAC,
                    SCADA_IP,
                    *plc_ip,
                    port,
                    502,
                    &read_request(tid),
                ),
            ));
            packets.push((
                ts + 0.01,
                tcp_packet(
                    PLC_MAC,
                    SCADA_MAC,
                    *plc_ip,
                    SCADA_IP,
                    502,
                    port,
                    &read_response(tid),
                ),
            ));
            tid = tid.wrapping_add(1);
        }
        if round % 3 == 0 {
            // Write single coil to PLC A
            let req = mbap(tid, 1, &[0x05, 0x00, 0x10, 0xFF, 0x00]);
            packets.push((
                ts + 0.02,
                tcp_packet(SCADA_MAC, PLC_MAC, SCADA_IP, PLC_A_IP, 49000, 502, &req),
            ));
            tid = tid.wrapping_add(1);
        }
        ts += 1.0;
    }
    packets
}

/// A second capture: the SCADA keeps polling PLC A (an overlapping flow that
/// must fuse) and a new HMI appears polling a new PLC D.
pub fn follow_up_capture() -> Vec<(f64, Vec<u8>)> {
    let mut packets = Vec::new();
    let mut ts = BASE_TS + 100.0;
    let mut tid: u16 = 1;
    for _ in 0..5 {
        packets.push((
            ts,
            tcp_packet(
                SCADA_MAC,
                PLC_MAC,
                SCADA_IP,
                PLC_A_IP,
                49000,
                502,
                &read_request(tid),
            ),
        ));
        packets.push((
            ts + 0.01,
            tcp_packet(
                HMI_MAC,
                PLC_MAC,
                HMI_IP,
                PLC_D_IP,
                50000,
                502,
                &read_request(tid),
            ),
        ));
        tid = tid.wrapping_add(1);
        ts += 1.0;
    }
    packets
}

pub const V6_LINK_LOCAL_A: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
pub const V6_LINK_LOCAL_B: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
pub const V6_ALL_NODES: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
pub const V6_ULA_HMI: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];
pub const V6_ULA_PLC: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20];
pub const V6_MDNS: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb];

/// A deterministic capture that touches every decode path: untagged and
/// VLAN-tagged Modbus, ARP in all its shapes, IPv6 unicast and multicast,
/// `ICMPv6`, port-less IP protocols, a fragment, LLDP, CDP, spanning tree,
/// `EtherCAT`, and one frame without a timestamp. Backs the synthetic golden.
// A flat list of frames reads best as one list; splitting it would hide the
// order the golden depends on.
#[allow(clippy::too_many_lines)]
pub fn mixed_capture() -> Vec<(f64, Vec<u8>)> {
    let t = BASE_TS;
    let siemens_a = [0x00, 0x1b, 0x1b, 0x0a, 0x00, 0x01];
    let mut p: Vec<(f64, Vec<u8>)> = Vec::new();
    // Modbus polling, untagged
    for i in 0..3u16 {
        let ts = t + f64::from(i);
        p.push((
            ts,
            tcp_packet(
                SCADA_MAC,
                PLC_MAC,
                SCADA_IP,
                PLC_A_IP,
                49000,
                502,
                &read_request(i),
            ),
        ));
        p.push((
            ts + 0.01,
            tcp_packet(
                PLC_MAC,
                SCADA_MAC,
                PLC_A_IP,
                SCADA_IP,
                502,
                49000,
                &read_response(i),
            ),
        ));
    }
    // The same SCADA polls PLC B on VLAN 20
    p.push((
        t + 0.5,
        vlan_tcp_packet(
            20,
            SCADA_MAC,
            PLC_MAC,
            SCADA_IP,
            PLC_B_IP,
            49001,
            502,
            &read_request(9),
        ),
    ));
    p.push((
        t + 0.51,
        vlan_tcp_packet(
            20,
            PLC_MAC,
            SCADA_MAC,
            PLC_B_IP,
            SCADA_IP,
            502,
            49001,
            &read_response(9),
        ),
    ));
    // ARP on VLAN 10: a Siemens device asks for the gateway, the gateway answers
    let gw = ([10, 0, 10, 254], SWITCH_MAC);
    p.push((
        t + 1.1,
        arp_frame(
            false,
            ([10, 0, 10, 1], siemens_a),
            ([10, 0, 10, 254], [0; 6]),
            Some(10),
        ),
    ));
    p.push((
        t + 1.11,
        arp_frame(true, gw, ([10, 0, 10, 1], siemens_a), Some(10)),
    ));
    // Gratuitous ARP and an ARP probe (no host from the probe)
    p.push((
        t + 1.2,
        arp_frame(
            false,
            ([10, 0, 10, 7], HMI_MAC),
            ([10, 0, 10, 7], [0; 6]),
            None,
        ),
    ));
    p.push((
        t + 1.3,
        arp_frame(
            false,
            ([0, 0, 0, 0], [0x00, 0x0c, 0x29, 0x77, 0x77, 0x77]),
            ([10, 0, 10, 8], [0; 6]),
            None,
        ),
    ));
    // IPv6: mDNS to multicast, Modbus over IPv6 ULA, neighbour ping
    p.push((
        t + 2.0,
        udp6_packet(
            HMI_MAC,
            [0x33, 0x33, 0, 0, 0, 0xfb],
            V6_LINK_LOCAL_A,
            V6_MDNS,
            5353,
            5353,
            &[0u8; 12],
        ),
    ));
    p.push((
        t + 2.1,
        tcp6_packet(
            HMI_MAC,
            PLC_MAC,
            V6_ULA_HMI,
            V6_ULA_PLC,
            51000,
            502,
            &read_request(1),
        ),
    ));
    p.push((
        t + 2.11,
        tcp6_packet(
            PLC_MAC,
            HMI_MAC,
            V6_ULA_PLC,
            V6_ULA_HMI,
            502,
            51000,
            &read_response(1),
        ),
    ));
    p.push((
        t + 2.2,
        icmpv6_echo(HMI_MAC, PLC_MAC, V6_LINK_LOCAL_A, V6_LINK_LOCAL_B, false),
    ));
    p.push((
        t + 2.21,
        icmpv6_echo(PLC_MAC, HMI_MAC, V6_LINK_LOCAL_B, V6_LINK_LOCAL_A, true),
    ));
    // Port-less IPv4 protocols
    p.push((
        t + 3.0,
        ip_proto_packet(
            SCADA_MAC,
            [0x01, 0x00, 0x5e, 0, 0, 0x16],
            SCADA_IP,
            [224, 0, 0, 22],
            IpNumber::IGMP,
            &[0x22, 0, 0, 0, 0, 0, 0, 0],
        ),
    ));
    p.push((
        t + 3.1,
        ip_proto_packet(
            SWITCH_MAC,
            [0x01, 0x00, 0x5e, 0, 0, 0x12],
            [192, 168, 10, 254],
            [224, 0, 0, 18],
            IpNumber::VRRP,
            &[0u8; 8],
        ),
    ));
    // A fragment between two otherwise silent hosts
    p.push((
        t + 3.2,
        ipv4_fragment(HMI_MAC, PLC_MAC, [192, 168, 10, 5], [192, 168, 10, 6]),
    ));
    // Link-layer announcements and frames we do not read
    p.push((t + 4.0, lldp_frame(SWITCH_MAC)));
    p.push((t + 4.1, cdp_frame(SWITCH_MAC)));
    p.push((t + 4.2, stp_frame(SWITCH_MAC)));
    p.push((
        t + 4.3,
        ethertype_frame(PLC_MAC, BROADCAST_MAC, 0x88A4, &[0u8; 40]),
    ));
    // A record without a timestamp
    p.push((
        0.0,
        tcp_packet(
            SCADA_MAC,
            PLC_MAC,
            SCADA_IP,
            PLC_A_IP,
            49000,
            502,
            &read_request(99),
        ),
    ));
    p
}

// ── Harness ─────────────────────────────────────────────────────────────────

/// Write capture bytes to a temp file, import them, and clean the file up.
pub fn import_bytes(tag: &str, bytes: &[u8]) -> Result<(Session, ImportResult), CoreError> {
    let path =
        std::env::temp_dir().join(format!("purdungeon-test-{tag}-{}.pcap", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    let result = import_file(&path);
    std::fs::remove_file(&path).ok();
    result
}

pub fn import_file(path: &Path) -> Result<(Session, ImportResult), CoreError> {
    let progress = AtomicU64::new(0);
    Session::import(path, &progress, &|_| {})
}

pub fn append_bytes(session: &Session, tag: &str, bytes: &[u8]) -> Result<ImportResult, CoreError> {
    let path = std::env::temp_dir().join(format!(
        "purdungeon-test-{tag}-append-{}.pcap",
        std::process::id()
    ));
    std::fs::write(&path, bytes).unwrap();
    let progress = AtomicU64::new(0);
    let result = session.add_capture(&path, &progress, &|_| {});
    std::fs::remove_file(&path).ok();
    result
}

/// The accounting invariant every import must satisfy: nothing read from
/// the file is unaccounted for.
pub fn assert_reconciles(result: &ImportResult) {
    assert_eq!(
        result.frames_read,
        result.packet_count + result.skipped.total(),
        "frames read must equal decoded + skipped: {result:?}"
    );
    assert_eq!(
        result.packet_count,
        result.decoded.total(),
        "packet count must equal the decoded breakdown: {result:?}"
    );
}
