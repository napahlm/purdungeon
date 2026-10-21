//! One line per packet for the capture tab, and the decoded view of a
//! packet the user clicks. Both read the frame once through the same
//! decoders the ingester uses, so the Protocol column and the topology never
//! disagree about what a packet was.

use std::net::IpAddr;

use etherparse::{LinkSlice, TransportSlice};

use crate::analysis::ports::protocol_for_port;
use crate::ingest::frame::{self, Frame, Transport};
use crate::ingest::identity::{self, UdpFacts, PORT_DHCP_CLIENT, PORT_DHCP_SERVER};
use crate::ingest::ingester::format_mac;
use crate::ingest::link::{self, LinkDecode};
use crate::ingest::Linktype;
use crate::live::types::{DetailSection, PacketDetail, PacketRow};
use crate::protocols::{arp, dhcp, ip_proto, modbus};

/// What both the row and the detail need.
struct Decoded {
    src: String,
    dst: String,
    protocol: String,
    app_protocol: Option<String>,
    info: String,
    sections: Vec<DetailSection>,
}

impl Decoded {
    fn bare(protocol: &str, info: String) -> Self {
        Self {
            src: String::new(),
            dst: String::new(),
            protocol: protocol.into(),
            app_protocol: None,
            info,
            sections: Vec::new(),
        }
    }
}

/// The packet list row for one frame.
#[must_use]
pub fn summarize(
    no: u64,
    timestamp: f64,
    linktype: Linktype,
    data: &[u8],
    orig_len: u32,
    spool_offset: u64,
) -> PacketRow {
    let decoded = decode(linktype, data, orig_len, false);
    PacketRow {
        no,
        timestamp,
        src: decoded.src,
        dst: decoded.dst,
        protocol: decoded.protocol,
        app_protocol: decoded.app_protocol,
        length: orig_len.max(data.len() as u32),
        info: decoded.info,
        spool_offset,
    }
}

/// Everything the decoders read from one frame, as labelled sections.
#[must_use]
pub fn detail(
    no: u64,
    timestamp: f64,
    linktype: Linktype,
    data: &[u8],
    orig_len: u32,
) -> PacketDetail {
    let mut decoded = decode(linktype, data, orig_len, true);
    let length = orig_len.max(data.len() as u32);
    let mut frame_rows = vec![
        ("Frame".into(), no.to_string()),
        ("Wire length".into(), format!("{length} bytes")),
        ("Captured".into(), format!("{} bytes", data.len())),
        ("Link type".into(), linktype.to_string()),
    ];
    if decoded.sections.is_empty() && !decoded.info.is_empty() {
        frame_rows.push(("Note".into(), decoded.info.clone()));
    }
    decoded.sections.insert(
        0,
        DetailSection {
            title: "Frame".into(),
            rows: frame_rows,
        },
    );
    PacketDetail {
        no,
        timestamp,
        length,
        captured: data.len() as u32,
        protocol: decoded.protocol,
        info: decoded.info,
        sections: decoded.sections,
    }
}

/// The Protocol column for an application tag the port table or a parser
/// produced: `modbus` reads best as it is written, everything else as the
/// acronym it is.
fn display_protocol(tag: &str) -> String {
    if tag == "modbus" {
        "Modbus".into()
    } else {
        tag.to_ascii_uppercase()
    }
}

fn decode(linktype: Linktype, data: &[u8], orig_len: u32, with_sections: bool) -> Decoded {
    let cut_by_snaplen = (data.len() as u32) < orig_len;
    let (parsed, macs) = match link::decode(linktype, data) {
        LinkDecode::Ok { parsed, macs } => (parsed, macs),
        LinkDecode::UnsupportedLinkType => {
            return Decoded::bare(
                "Unsupported",
                format!("link type {linktype} is not decoded"),
            );
        }
        LinkDecode::TooShort if cut_by_snaplen => {
            return Decoded::bare("Truncated", "link header cut by the snapshot length".into());
        }
        LinkDecode::TooShort | LinkDecode::Malformed => {
            return Decoded::bare("Malformed", "link header could not be decoded".into());
        }
    };
    let classified = frame::classify(&parsed, macs, cut_by_snaplen);
    let src_mac = format_mac(macs.src.as_ref());
    let dst_mac = format_mac(macs.dst.as_ref());

    let mut out = match &classified.frame {
        Frame::Ip(ip) => ip_packet(ip, &parsed, with_sections),
        Frame::Fragment { src, dst } => Decoded {
            src: src.to_string(),
            dst: dst.to_string(),
            protocol: ip_version(*src).into(),
            app_protocol: None,
            info: "fragment (not the first)".into(),
            sections: Vec::new(),
        },
        Frame::Arp(info) => arp_packet(info.as_ref(), &src_mac, &dst_mac, with_sections),
        Frame::Lldp(info) => lldp_packet(info, with_sections),
        Frame::Cdp(info) => cdp_packet(info, with_sections),
        Frame::OtherEthertype => {
            let (ether_type, _) = frame::ether_payload(&parsed).unwrap_or((0, &[]));
            Decoded::bare(
                ethertype_name(ether_type),
                format!("ethertype 0x{ether_type:04x}"),
            )
        }
        Frame::Truncated { hosts } => with_hosts(
            Decoded::bare(
                "Truncated",
                "a header was cut by the snapshot length".into(),
            ),
            *hosts,
        ),
        Frame::Malformed { hosts } => with_hosts(
            Decoded::bare("Malformed", "a header could not be decoded".into()),
            *hosts,
        ),
    };

    // Frames without an IP layer are addressed by MAC.
    if out.src.is_empty() {
        out.src.clone_from(&src_mac);
    }
    if out.dst.is_empty() {
        out.dst.clone_from(&dst_mac);
    }
    if let Some(vlan) = classified.vlan {
        out.info = format!("{} (VLAN {vlan})", out.info);
    }
    if with_sections {
        if let Some(section) = link_section(&parsed, src_mac, dst_mac, classified.vlan) {
            out.sections.insert(0, section);
        }
    }
    out
}

fn link_section(
    parsed: &etherparse::LaxSlicedPacket<'_>,
    src_mac: String,
    dst_mac: String,
    vlan: Option<u16>,
) -> Option<DetailSection> {
    let mut rows = Vec::new();
    match &parsed.link {
        Some(LinkSlice::Ethernet2(eth)) => {
            rows.push(("Source MAC".into(), src_mac));
            rows.push(("Destination MAC".into(), dst_mac));
            rows.push(("Ethertype".into(), format!("0x{:04x}", eth.ether_type().0)));
        }
        Some(LinkSlice::LinuxSll(_)) => {
            rows.push(("Sender MAC".into(), src_mac));
            rows.push(("Header".into(), "Linux cooked capture".into()));
        }
        _ => {}
    }
    if let Some(vlan) = vlan {
        rows.push(("VLAN".into(), vlan.to_string()));
    }
    (!rows.is_empty()).then_some(DetailSection {
        title: "Link".into(),
        rows,
    })
}

fn lldp_packet(info: &crate::protocols::lldp::LldpInfo, with_sections: bool) -> Decoded {
    let name = info
        .system_name
        .clone()
        .or_else(|| info.chassis_id.clone())
        .unwrap_or_else(|| "unnamed".into());
    let mut d = Decoded::bare(
        "LLDP",
        match &info.port_id {
            Some(port) => format!("{name} port {port}"),
            None => name,
        },
    );
    if with_sections {
        let mut rows = vec![
            (
                "Chassis id".into(),
                info.chassis_id.clone().unwrap_or_default(),
            ),
            ("Port id".into(), info.port_id.clone().unwrap_or_default()),
            (
                "Port description".into(),
                info.port_description.clone().unwrap_or_default(),
            ),
            (
                "System name".into(),
                info.system_name.clone().unwrap_or_default(),
            ),
            (
                "System description".into(),
                info.system_description.clone().unwrap_or_default(),
            ),
            (
                "Capabilities".into(),
                crate::protocols::lldp::capability_names(info.capabilities_enabled).join(", "),
            ),
        ];
        rows.push((
            "Management addresses".into(),
            join_addresses(&info.management_addresses),
        ));
        d.sections.push(DetailSection {
            title: "LLDP".into(),
            rows: non_empty(rows),
        });
    }
    d
}

fn cdp_packet(info: &crate::protocols::cdp::CdpInfo, with_sections: bool) -> Decoded {
    let name = info.device_id.clone().unwrap_or_else(|| "unnamed".into());
    let mut d = Decoded::bare(
        "CDP",
        match &info.port_id {
            Some(port) => format!("{name} port {port}"),
            None => name,
        },
    );
    if with_sections {
        let rows = vec![
            (
                "Device id".into(),
                info.device_id.clone().unwrap_or_default(),
            ),
            ("Port id".into(), info.port_id.clone().unwrap_or_default()),
            ("Platform".into(), info.platform.clone().unwrap_or_default()),
            (
                "Software".into(),
                info.software_version.clone().unwrap_or_default(),
            ),
            (
                "Capabilities".into(),
                crate::protocols::cdp::capability_names(info.capabilities).join(", "),
            ),
            ("Addresses".into(), join_addresses(&info.addresses)),
            (
                "Native VLAN".into(),
                info.native_vlan.map(|v| v.to_string()).unwrap_or_default(),
            ),
        ];
        d.sections.push(DetailSection {
            title: "CDP".into(),
            rows: non_empty(rows),
        });
    }
    d
}

fn with_hosts(mut decoded: Decoded, hosts: Option<(IpAddr, IpAddr)>) -> Decoded {
    if let Some((src, dst)) = hosts {
        decoded.src = src.to_string();
        decoded.dst = dst.to_string();
    }
    decoded
}

fn ip_version(addr: IpAddr) -> &'static str {
    match addr {
        IpAddr::V4(_) => "IPv4",
        IpAddr::V6(_) => "IPv6",
    }
}

fn join_addresses(addresses: &[IpAddr]) -> String {
    addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn non_empty(rows: Vec<(String, String)>) -> Vec<(String, String)> {
    rows.into_iter().filter(|(_, v)| !v.is_empty()).collect()
}

fn ethertype_name(ether_type: u16) -> &'static str {
    match ether_type {
        0..=1500 => "LLC",
        0x8892 => "PROFINET",
        0x88a4 => "EtherCAT",
        0x88f7 => "PTP",
        0x8847 | 0x8848 => "MPLS",
        0x88e5 => "MACsec",
        0x88ab => "POWERLINK",
        0x8902 => "CFM",
        0x9000 => "Loopback",
        _ => "Other",
    }
}

fn arp_packet(
    info: Option<&arp::ArpInfo>,
    src_mac: &str,
    dst_mac: &str,
    with_sections: bool,
) -> Decoded {
    let Some(info) = info else {
        return Decoded::bare("ARP", "not an Ethernet/IPv4 ARP".into());
    };
    let (sender_ip, sender_mac) = info.sender;
    let (target_ip, target_mac) = info.target;
    let text = if info.is_reply {
        format!("{sender_ip} is at {}", format_mac(Some(&sender_mac)))
    } else if sender_ip == target_ip {
        format!("Gratuitous ARP for {sender_ip}")
    } else {
        format!("Who has {target_ip}? Tell {sender_ip}")
    };
    let mut d = Decoded::bare("ARP", text);
    d.src = src_mac.into();
    d.dst = dst_mac.into();
    if with_sections {
        d.sections.push(DetailSection {
            title: "ARP".into(),
            rows: vec![
                (
                    "Operation".into(),
                    if info.is_reply { "reply" } else { "request" }.into(),
                ),
                ("Sender IP".into(), sender_ip.to_string()),
                ("Sender MAC".into(), format_mac(Some(&sender_mac))),
                ("Target IP".into(), target_ip.to_string()),
                ("Target MAC".into(), format_mac(Some(&target_mac))),
            ],
        });
    }
    d
}

fn ip_packet(
    ip: &frame::IpFrame<'_>,
    parsed: &etherparse::LaxSlicedPacket<'_>,
    with_sections: bool,
) -> Decoded {
    let mut d = Decoded {
        src: ip.src.to_string(),
        dst: ip.dst.to_string(),
        protocol: ip_proto::name(ip.ip_proto).into_owned(),
        app_protocol: None,
        info: String::new(),
        sections: Vec::new(),
    };
    if with_sections {
        d.sections.push(ip_section(ip, parsed));
    }
    match ip.transport {
        Transport::Tcp {
            src_port,
            dst_port,
            payload,
        } => tcp(&mut d, parsed, src_port, dst_port, payload, with_sections),
        Transport::Udp {
            src_port,
            dst_port,
            payload,
        } => udp(&mut d, src_port, dst_port, payload, with_sections),
        Transport::Portless => portless(&mut d, parsed),
    }
    d
}

fn ip_section(ip: &frame::IpFrame<'_>, parsed: &etherparse::LaxSlicedPacket<'_>) -> DetailSection {
    let mut rows = vec![
        ("Source".into(), ip.src.to_string()),
        ("Destination".into(), ip.dst.to_string()),
        (
            "Protocol".into(),
            format!("{} ({})", ip_proto::name(ip.ip_proto), ip.ip_proto),
        ),
    ];
    match &parsed.net {
        Some(etherparse::LaxNetSlice::Ipv4(v4)) => {
            let h = v4.header();
            rows.push(("TTL".into(), h.ttl().to_string()));
            rows.push(("Identification".into(), h.identification().to_string()));
            rows.push(("Total length".into(), h.total_len().to_string()));
        }
        Some(etherparse::LaxNetSlice::Ipv6(v6)) => {
            let h = v6.header();
            rows.push(("Hop limit".into(), h.hop_limit().to_string()));
            rows.push(("Payload length".into(), h.payload_length().to_string()));
        }
        _ => {}
    }
    DetailSection {
        title: ip_version(ip.src).into(),
        rows,
    }
}

/// The application tag for a flow, server side first.
fn port_tag(src_port: u16, dst_port: u16) -> Option<&'static str> {
    protocol_for_port(dst_port).or_else(|| protocol_for_port(src_port))
}

fn tcp(
    d: &mut Decoded,
    parsed: &etherparse::LaxSlicedPacket<'_>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    with_sections: bool,
) {
    let flags = match &parsed.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            let mut names = Vec::new();
            for (set, name) in [
                (tcp.syn(), "SYN"),
                (tcp.ack(), "ACK"),
                (tcp.fin(), "FIN"),
                (tcp.rst(), "RST"),
                (tcp.psh(), "PSH"),
                (tcp.urg(), "URG"),
            ] {
                if set {
                    names.push(name);
                }
            }
            if with_sections {
                d.sections.push(DetailSection {
                    title: "TCP".into(),
                    rows: vec![
                        ("Source port".into(), src_port.to_string()),
                        ("Destination port".into(), dst_port.to_string()),
                        ("Flags".into(), names.join(", ")),
                        ("Sequence".into(), tcp.sequence_number().to_string()),
                        (
                            "Acknowledgment".into(),
                            tcp.acknowledgment_number().to_string(),
                        ),
                        ("Payload".into(), format!("{} bytes", payload.len())),
                    ],
                });
            }
            names.join(", ")
        }
        _ => String::new(),
    };
    d.info = format!("{src_port} -> {dst_port} [{flags}] len {}", payload.len());

    let is_request = dst_port == modbus::MODBUS_PORT;
    if modbus::is_modbus_tcp(src_port, dst_port, payload) {
        let frames = modbus::parse_frames(payload, is_request);
        if !frames.is_empty() {
            d.protocol = "Modbus".into();
            d.app_protocol = Some("modbus".into());
            d.info = frames
                .iter()
                .map(|f| modbus_line(f, is_request))
                .collect::<Vec<_>>()
                .join("; ");
            if with_sections {
                for (i, f) in frames.iter().enumerate() {
                    d.sections
                        .push(modbus_section(f, is_request, i + 1, frames.len()));
                }
            }
            return;
        }
    }
    if let Some(tag) = port_tag(src_port, dst_port) {
        d.protocol = display_protocol(tag);
        d.app_protocol = Some(tag.into());
    }
}

fn modbus_exception_name(code: u8) -> &'static str {
    match code {
        0x01 => "Illegal Function",
        0x02 => "Illegal Data Address",
        0x03 => "Illegal Data Value",
        0x04 => "Server Device Failure",
        0x05 => "Acknowledge",
        0x06 => "Server Device Busy",
        0x08 => "Memory Parity Error",
        0x0A => "Gateway Path Unavailable",
        0x0B => "Gateway Target Device Failed To Respond",
        _ => "Unknown Exception",
    }
}

fn register_range(f: &modbus::ModbusFrame) -> Option<String> {
    let start = f.start_address?;
    Some(match f.quantity {
        Some(n) if n > 1 => format!("{start}..{}", u32::from(start) + u32::from(n) - 1),
        _ => start.to_string(),
    })
}

fn modbus_line(f: &modbus::ModbusFrame, is_request: bool) -> String {
    let name = modbus::function_name(f.function_code);
    if f.is_exception {
        let code = f.exception_code.unwrap_or(0);
        return format!(
            "Exception: {name}, unit {}, {} (0x{code:02x})",
            f.unit_id,
            modbus_exception_name(code)
        );
    }
    let kind = if is_request { "Query" } else { "Response" };
    match register_range(f) {
        Some(range) => format!("{kind}: {name}, unit {}, {range}", f.unit_id),
        None => format!("{kind}: {name}, unit {}", f.unit_id),
    }
}

fn modbus_section(
    f: &modbus::ModbusFrame,
    is_request: bool,
    index: usize,
    total: usize,
) -> DetailSection {
    let mut rows = vec![
        (
            "Direction".into(),
            if is_request { "query" } else { "response" }.into(),
        ),
        ("Transaction".into(), f.transaction_id.to_string()),
        ("Unit".into(), f.unit_id.to_string()),
        (
            "Function".into(),
            format!(
                "{} (0x{:02x})",
                modbus::function_name(f.function_code),
                f.function_code
            ),
        ),
    ];
    if let Some(start) = f.start_address {
        rows.push(("Start address".into(), start.to_string()));
    }
    if let Some(n) = f.quantity {
        rows.push(("Quantity".into(), n.to_string()));
    }
    rows.push((
        "Writes".into(),
        if f.is_write { "yes" } else { "no" }.into(),
    ));
    if f.is_exception {
        let code = f.exception_code.unwrap_or(0);
        rows.push((
            "Exception".into(),
            format!("{} (0x{code:02x})", modbus_exception_name(code)),
        ));
    }
    DetailSection {
        title: if total > 1 {
            format!("Modbus PDU {index} of {total}")
        } else {
            "Modbus".into()
        },
        rows,
    }
}

fn dhcp_message_name(message_type: Option<u8>) -> &'static str {
    match message_type {
        Some(dhcp::DISCOVER) => "Discover",
        Some(dhcp::OFFER) => "Offer",
        Some(dhcp::REQUEST) => "Request",
        Some(dhcp::DECLINE) => "Decline",
        Some(dhcp::ACK) => "ACK",
        Some(dhcp::NAK) => "NAK",
        Some(dhcp::RELEASE) => "Release",
        Some(dhcp::INFORM) => "Inform",
        _ => "message",
    }
}

fn udp(d: &mut Decoded, src_port: u16, dst_port: u16, payload: &[u8], with_sections: bool) {
    d.info = format!("{src_port} -> {dst_port} len {}", payload.len());
    if with_sections {
        d.sections.push(DetailSection {
            title: "UDP".into(),
            rows: vec![
                ("Source port".into(), src_port.to_string()),
                ("Destination port".into(), dst_port.to_string()),
                ("Payload".into(), format!("{} bytes", payload.len())),
            ],
        });
    }
    if let Some(tag) = port_tag(src_port, dst_port) {
        d.protocol = display_protocol(tag);
        d.app_protocol = Some(tag.into());
    }

    let dhcp_ports = [PORT_DHCP_SERVER, PORT_DHCP_CLIENT];
    if dhcp_ports.contains(&src_port) && dhcp_ports.contains(&dst_port) {
        if let Some(msg) = dhcp::parse(payload) {
            let kind = dhcp_message_name(msg.message_type);
            d.info = match msg.chaddr {
                Some(mac) => format!("DHCP {kind} from {}", format_mac(Some(&mac))),
                None => format!("DHCP {kind}"),
            };
            if with_sections {
                let rows = vec![
                    ("Message".into(), kind.into()),
                    ("Client MAC".into(), format_mac(msg.chaddr.as_ref())),
                    ("Client IP".into(), msg.ciaddr.to_string()),
                    ("Your IP".into(), msg.yiaddr.to_string()),
                    ("Hostname".into(), msg.hostname.clone().unwrap_or_default()),
                    (
                        "Vendor class".into(),
                        msg.vendor_class.clone().unwrap_or_default(),
                    ),
                    ("Domain".into(), msg.domain_name.clone().unwrap_or_default()),
                ];
                d.sections.push(DetailSection {
                    title: "DHCP".into(),
                    rows: non_empty(rows),
                });
            }
        }
        return;
    }

    if let Some(UdpFacts::Sender { source, facts }) =
        identity::inspect_udp(src_port, dst_port, payload)
    {
        d.protocol = source.to_ascii_uppercase();
        let names: Vec<&str> = facts
            .iter()
            .filter(|f| f.kind == "hostname")
            .map(|f| f.value.as_str())
            .collect();
        if !names.is_empty() {
            d.info = format!("{} announces {}", d.protocol, names.join(", "));
        }
        if with_sections {
            d.sections.push(DetailSection {
                title: "Identity".into(),
                rows: facts
                    .iter()
                    .map(|f| (f.kind.to_string(), f.value.clone()))
                    .collect(),
            });
        }
    }
}

fn icmp_name(v6: bool, type_u8: u8) -> String {
    let name = if v6 {
        match type_u8 {
            1 => "destination unreachable",
            2 => "packet too big",
            3 => "time exceeded",
            4 => "parameter problem",
            128 => "echo request",
            129 => "echo reply",
            130 => "multicast listener query",
            131 | 143 => "multicast listener report",
            133 => "router solicitation",
            134 => "router advertisement",
            135 => "neighbor solicitation",
            136 => "neighbor advertisement",
            137 => "redirect",
            _ => "",
        }
    } else {
        match type_u8 {
            0 => "echo reply",
            3 => "destination unreachable",
            5 => "redirect",
            8 => "echo request",
            11 => "time exceeded",
            12 => "parameter problem",
            13 => "timestamp request",
            14 => "timestamp reply",
            _ => "",
        }
    };
    if name.is_empty() {
        format!("type {type_u8}")
    } else {
        name.into()
    }
}

fn portless(d: &mut Decoded, parsed: &etherparse::LaxSlicedPacket<'_>) {
    d.info = match &parsed.transport {
        Some(TransportSlice::Icmpv4(icmp)) => icmp_name(false, icmp.type_u8()),
        Some(TransportSlice::Icmpv6(icmp)) => icmp_name(true, icmp.type_u8()),
        _ => String::new(),
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    const SCADA: [u8; 6] = [0x00, 0x0c, 0x29, 0x11, 0x22, 0x33];
    const PLC: [u8; 6] = [0x00, 0x1b, 0x1b, 0x44, 0x55, 0x66];

    fn tcp_frame(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        PacketBuilder::ethernet2(SCADA, PLC)
            .ipv4([192, 168, 10, 100], [192, 168, 10, 1], 64)
            .tcp(src_port, dst_port, 1, 1024)
            .psh()
            .ack(7)
            .write(&mut out, payload)
            .unwrap();
        out
    }

    fn row(data: &[u8]) -> PacketRow {
        summarize(1, 1.0, Linktype::ETHERNET, data, data.len() as u32, 24)
    }

    #[test]
    fn modbus_query_names_function_unit_and_registers() {
        // MBAP: tid 7, proto 0, len 6, unit 1; PDU: read holding 100..109
        let frame = tcp_frame(49000, 502, &[0, 7, 0, 0, 0, 6, 1, 0x03, 0, 100, 0, 10]);
        let row = row(&frame);
        assert_eq!(row.protocol, "Modbus");
        assert_eq!(row.app_protocol.as_deref(), Some("modbus"));
        assert_eq!(row.info, "Query: Read Holding Registers, unit 1, 100..109");
        assert_eq!(
            (row.src.as_str(), row.dst.as_str()),
            ("192.168.10.100", "192.168.10.1")
        );
        assert_eq!(row.length, frame.len() as u32);
    }

    #[test]
    fn modbus_exception_is_named_with_its_code() {
        let frame = tcp_frame(502, 49000, &[0, 7, 0, 0, 0, 3, 1, 0x83, 0x02]);
        let row = row(&frame);
        assert_eq!(row.protocol, "Modbus");
        assert_eq!(
            row.info,
            "Exception: Read Holding Registers, unit 1, Illegal Data Address (0x02)"
        );
    }

    #[test]
    fn plain_tcp_shows_ports_flags_and_port_name() {
        let http = row(&tcp_frame(51000, 8080, b"GET / HTTP/1.0\r\n"));
        assert_eq!(http.protocol, "HTTP");
        assert_eq!(http.app_protocol.as_deref(), Some("http"));
        assert_eq!(http.info, "51000 -> 8080 [ACK, PSH] len 16");
        let bare = row(&tcp_frame(51000, 9999, b""));
        assert_eq!(bare.protocol, "TCP");
        assert!(bare.app_protocol.is_none());
    }

    #[test]
    fn arp_request_asks_the_question() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xff; 6]);
        frame.extend_from_slice(&SCADA);
        frame.extend_from_slice(&[0x08, 0x06]);
        frame.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
        frame.extend_from_slice(&SCADA);
        frame.extend_from_slice(&[192, 168, 10, 100]);
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&[192, 168, 10, 1]);
        let row = row(&frame);
        assert_eq!(row.protocol, "ARP");
        assert_eq!(row.info, "Who has 192.168.10.1? Tell 192.168.10.100");
        assert_eq!(row.src, "00:0c:29:11:22:33");
        assert_eq!(row.dst, "ff:ff:ff:ff:ff:ff");
        let d = detail(1, 1.0, Linktype::ETHERNET, &frame, frame.len() as u32);
        assert!(d.sections.iter().any(|s| s.title == "ARP"));
        assert!(d.sections.iter().any(|s| s.title == "Link"));
    }

    #[test]
    fn icmp_and_unsupported_link_types_are_named() {
        let mut out = Vec::new();
        PacketBuilder::ethernet2(SCADA, PLC)
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .icmpv4_echo_request(1, 2)
            .write(&mut out, &[])
            .unwrap();
        let ping = row(&out);
        assert_eq!(ping.protocol, "ICMP");
        assert_eq!(ping.info, "echo request");

        let wifi = summarize(1, 1.0, Linktype(105), &[0u8; 40], 40, 24);
        assert_eq!(wifi.protocol, "Unsupported");
        assert!(wifi.info.contains("105") || wifi.info.contains("IEEE802_11"));
    }

    #[test]
    fn detail_leads_with_the_frame_section() {
        let frame = tcp_frame(49000, 502, &[0, 7, 0, 0, 0, 6, 1, 0x03, 0, 0, 0, 2]);
        let d = detail(9, 1.5, Linktype::ETHERNET, &frame, frame.len() as u32 + 10);
        assert_eq!(d.sections[0].title, "Frame");
        assert_eq!(d.length, frame.len() as u32 + 10);
        let titles: Vec<&str> = d.sections.iter().map(|s| s.title.as_str()).collect();
        assert_eq!(titles, ["Frame", "Link", "IPv4", "TCP", "Modbus"]);
        assert_eq!(d.info, "Query: Read Holding Registers, unit 1, 0..1");
    }
}
