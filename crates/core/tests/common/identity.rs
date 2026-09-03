//! Builders for the identity protocols: DHCP, `NetBIOS` name service, mDNS,
//! LLMNR, SNMP responses, and full LLDP/CDP announcements — plus the
//! scenario capture that exercises them all.

use super::*;

pub const WS_MAC: [u8; 6] = [0x00, 0x50, 0x56, 0x01, 0x02, 0x03];
pub const WS_IP: [u8; 4] = [192, 168, 10, 77];
pub const DHCP_SERVER_IP: [u8; 4] = [192, 168, 10, 254];
pub const PRINTER_MAC: [u8; 6] = [0x00, 0x0c, 0x29, 0x90, 0x90, 0x90];
pub const PRINTER_IP: [u8; 4] = [192, 168, 10, 90];
pub const CORE_SWITCH_IP: [u8; 4] = [192, 168, 10, 2];
/// A switch that only ever speaks CDP: no IP traffic in the capture at all.
pub const SILENT_SWITCH_MAC: [u8; 6] = [0x00, 0x1e, 0x14, 0xaa, 0xbb, 0xcc];
pub const ROUTER_MAC: [u8; 6] = [0x00, 0x1e, 0x14, 0x00, 0x00, 0x01];
pub const MOVED_IP: [u8; 4] = [192, 168, 10, 60];
pub const MOVED_MAC: [u8; 6] = [0x00, 0x0c, 0x29, 0x60, 0x60, 0x60];

// ── DNS wire format ─────────────────────────────────────────────────────────

pub fn dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

pub fn dns_record(name: &str, rtype: u16, rdata: &[u8]) -> Vec<u8> {
    let mut out = dns_name(name);
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // class IN
    out.extend_from_slice(&120u32.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
    out
}

pub fn dns_message(
    flags: u16,
    questions: &[Vec<u8>],
    answers: &[Vec<u8>],
    additional: &[Vec<u8>],
) -> Vec<u8> {
    let mut out = vec![0x12, 0x34];
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&(questions.len() as u16).to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&(additional.len() as u16).to_be_bytes());
    for section in [questions, answers, additional] {
        for item in section {
            out.extend_from_slice(item);
        }
    }
    out
}

// ── DHCP ────────────────────────────────────────────────────────────────────

pub fn dhcp_message(
    op: u8,
    message_type: u8,
    chaddr: [u8; 6],
    client_addr: [u8; 4],
    your_addr: [u8; 4],
    options: &[(u8, Vec<u8>)],
) -> Vec<u8> {
    let mut m = vec![0u8; 240];
    m[0] = op;
    m[1] = 1;
    m[2] = 6;
    m[12..16].copy_from_slice(&client_addr);
    m[16..20].copy_from_slice(&your_addr);
    m[28..34].copy_from_slice(&chaddr);
    m[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    m.extend_from_slice(&[53, 1, message_type]);
    for (code, data) in options {
        m.push(*code);
        m.push(data.len() as u8);
        m.extend_from_slice(data);
    }
    m.push(255);
    m
}

/// A Windows-looking DHCP Discover: hostname, `MSFT 5.0`, the classic
/// parameter request list. Sent from 0.0.0.0 to the broadcast address.
pub fn dhcp_discover_frame(mac: [u8; 6], hostname: &str) -> Vec<u8> {
    let payload = dhcp_message(
        1,
        1,
        mac,
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        &[
            (12, hostname.as_bytes().to_vec()),
            (60, b"MSFT 5.0".to_vec()),
            (
                55,
                vec![1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252],
            ),
        ],
    );
    udp_packet(
        mac,
        BROADCAST_MAC,
        [0, 0, 0, 0],
        [255, 255, 255, 255],
        68,
        67,
        &payload,
    )
}

/// The server's ACK granting `yiaddr` to `mac`, with a domain name.
pub fn dhcp_ack_frame(server_mac: [u8; 6], mac: [u8; 6], yiaddr: [u8; 4], domain: &str) -> Vec<u8> {
    let payload = dhcp_message(
        2,
        5,
        mac,
        [0, 0, 0, 0],
        yiaddr,
        &[
            (54, DHCP_SERVER_IP.to_vec()),
            (15, domain.as_bytes().to_vec()),
        ],
    );
    udp_packet(server_mac, mac, DHCP_SERVER_IP, yiaddr, 67, 68, &payload)
}

// ── NetBIOS, mDNS, LLMNR ────────────────────────────────────────────────────

/// A `NetBIOS` name registration request broadcast from `ip`.
pub fn nbns_registration_frame(
    mac: [u8; 6],
    ip: [u8; 4],
    name: &str,
    suffix: u8,
    group: bool,
) -> Vec<u8> {
    let encoded = purdungeon_core::protocols::nbns::encode_name(name, suffix);
    let qname = dns_name(&encoded);
    let mut question = qname.clone();
    question.extend_from_slice(&[0, 0x20, 0, 1]);
    let mut rdata = vec![if group { 0x80 } else { 0x00 }, 0x00];
    rdata.extend_from_slice(&ip);
    let additional = dns_record(&encoded, 0x20, &rdata);
    let payload = dns_message(0x2910, &[question], &[], &[additional]);
    udp_packet(
        mac,
        BROADCAST_MAC,
        ip,
        [192, 168, 10, 255],
        137,
        137,
        &payload,
    )
}

/// An mDNS response announcing a host, one service instance and its TXT model.
pub fn mdns_response_frame(
    mac: [u8; 6],
    ip: [u8; 4],
    hostname: &str,
    service: &str,
    model: &str,
) -> Vec<u8> {
    let host_fqdn = format!("{hostname}.local");
    let service_fqdn = format!("{service}.local");
    let instance = format!("{hostname}.{service_fqdn}");
    let mut srv = vec![0, 0, 0, 0, 0x02, 0x77];
    srv.extend(dns_name(&host_fqdn));
    let mut txt = vec![(6 + model.len()) as u8];
    txt.extend_from_slice(b"model=");
    txt.extend_from_slice(model.as_bytes());
    let answers = [
        dns_record(&host_fqdn, 1, &ip),
        dns_record(&service_fqdn, 12, &dns_name(&instance)),
        dns_record(&instance, 33, &srv),
        dns_record(&instance, 16, &txt),
    ];
    let payload = dns_message(0x8400, &[], &answers, &[]);
    udp_packet(
        mac,
        [0x01, 0x00, 0x5e, 0, 0, 0xfb],
        ip,
        [224, 0, 0, 251],
        5353,
        5353,
        &payload,
    )
}

/// An LLMNR response from `ip` answering for its own name.
pub fn llmnr_response_frame(
    mac: [u8; 6],
    ip: [u8; 4],
    hostname: &str,
    querier_ip: [u8; 4],
) -> Vec<u8> {
    let mut question = dns_name(hostname);
    question.extend_from_slice(&[0, 1, 0, 1]);
    let answers = [dns_record(hostname, 1, &ip)];
    let payload = dns_message(0x8000, &[question], &answers, &[]);
    udp_packet(mac, SCADA_MAC, ip, querier_ip, 5355, 51234, &payload)
}

// ── SNMP ────────────────────────────────────────────────────────────────────

fn ber(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 128 {
        out.push(content.len() as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(content);
    out
}

fn ber_int(v: u8) -> Vec<u8> {
    ber(0x02, &[v])
}

fn ber_oid(arcs: &[u32]) -> Vec<u8> {
    let mut body = vec![(40 * arcs[0] + arcs[1]) as u8];
    for arc in &arcs[2..] {
        let mut chunks = vec![(*arc & 0x7F) as u8];
        let mut rest = *arc >> 7;
        while rest > 0 {
            chunks.push((rest & 0x7F) as u8 | 0x80);
            rest >>= 7;
        }
        chunks.reverse();
        body.extend(chunks);
    }
    ber(0x06, &body)
}

fn varbind(name: &[u32], value: Vec<u8>) -> Vec<u8> {
    let mut body = ber_oid(name);
    body.extend(value);
    ber(0x30, &body)
}

/// A v2c `GetResponse` carrying `sysDescr`, `sysObjectID` and `sysName`.
pub fn snmp_response_frame(
    mac: [u8; 6],
    ip: [u8; 4],
    descr: &str,
    object_id: &[u32],
    name: &str,
    manager_ip: [u8; 4],
) -> Vec<u8> {
    let mut list = varbind(&[1, 3, 6, 1, 2, 1, 1, 1, 0], ber(0x04, descr.as_bytes()));
    list.extend(varbind(&[1, 3, 6, 1, 2, 1, 1, 2, 0], ber_oid(object_id)));
    list.extend(varbind(
        &[1, 3, 6, 1, 2, 1, 1, 5, 0],
        ber(0x04, name.as_bytes()),
    ));
    let mut pdu = ber_int(1);
    pdu.extend(ber_int(0));
    pdu.extend(ber_int(0));
    pdu.extend(ber(0x30, &list));
    let mut msg = ber_int(1);
    msg.extend(ber(0x04, b"public"));
    msg.extend(ber(0xA2, &pdu));
    let payload = ber(0x30, &msg);
    udp_packet(mac, SCADA_MAC, ip, manager_ip, 161, 50000, &payload)
}

// ── LLDP / CDP with real TLVs ───────────────────────────────────────────────

fn lldp_tlv(kind: u8, value: &[u8]) -> Vec<u8> {
    let len = value.len() as u16;
    let mut out = vec![(kind << 1) | ((len >> 8) as u8 & 1), (len & 0xFF) as u8];
    out.extend_from_slice(value);
    out
}

/// A full LLDP announcement: chassis id (MAC), port id, TTL, port description,
/// system name and description, capabilities, optional management address.
pub fn lldp_announcement(
    src_mac: [u8; 6],
    system_name: &str,
    description: &str,
    capabilities_enabled: u16,
    port: &str,
    management: Option<[u8; 4]>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E]);
    out.extend_from_slice(&src_mac);
    out.extend_from_slice(&[0x88, 0xCC]);
    let mut chassis = vec![4];
    chassis.extend_from_slice(&src_mac);
    out.extend(lldp_tlv(1, &chassis));
    let mut port_id = vec![5];
    port_id.extend_from_slice(port.as_bytes());
    out.extend(lldp_tlv(2, &port_id));
    out.extend(lldp_tlv(3, &[0, 120]));
    out.extend(lldp_tlv(4, b"uplink"));
    out.extend(lldp_tlv(5, system_name.as_bytes()));
    out.extend(lldp_tlv(6, description.as_bytes()));
    let mut caps = capabilities_enabled.to_be_bytes().to_vec();
    caps.extend_from_slice(&capabilities_enabled.to_be_bytes());
    out.extend(lldp_tlv(7, &caps));
    if let Some(ip) = management {
        let mut mgmt = vec![5, 1];
        mgmt.extend_from_slice(&ip);
        mgmt.extend_from_slice(&[2, 0, 0, 0, 1, 0]);
        out.extend(lldp_tlv(8, &mgmt));
    }
    out.extend(lldp_tlv(0, &[]));
    out
}

fn cdp_tlv(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut out = kind.to_be_bytes().to_vec();
    out.extend_from_slice(&((value.len() + 4) as u16).to_be_bytes());
    out.extend_from_slice(value);
    out
}

/// A full CDP v2 announcement in an 802.3 frame.
pub fn cdp_announcement(
    src_mac: [u8; 6],
    device_id: &str,
    platform: &str,
    software: &str,
    capabilities: u32,
    port: &str,
    address: Option<[u8; 4]>,
) -> Vec<u8> {
    let mut body = vec![
        0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00, 0x02, 0xB4, 0x00, 0x00,
    ];
    body.extend(cdp_tlv(0x0001, device_id.as_bytes()));
    if let Some(ip) = address {
        let mut addresses = 1u32.to_be_bytes().to_vec();
        addresses.extend_from_slice(&[1, 1, 0xCC, 0, 4]);
        addresses.extend_from_slice(&ip);
        body.extend(cdp_tlv(0x0002, &addresses));
    }
    body.extend(cdp_tlv(0x0003, port.as_bytes()));
    body.extend(cdp_tlv(0x0004, &capabilities.to_be_bytes()));
    body.extend(cdp_tlv(0x0005, software.as_bytes()));
    body.extend(cdp_tlv(0x0006, platform.as_bytes()));
    let mut out = Vec::new();
    out.extend_from_slice(&[0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC]);
    out.extend_from_slice(&src_mac);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

// ── Scenario ────────────────────────────────────────────────────────────────

/// Everything a chatty segment gives away: a Windows workstation getting an
/// address and registering its name, a printer announcing itself over mDNS,
/// a core switch answering SNMP and sending LLDP with a management address,
/// a second switch that only ever sends CDP, a Siemens controller that
/// announces itself over LLDP and answers Modbus, and a host whose ARP reply
/// corrects the MAC its first frame suggested.
// A flat list of frames reads best as one list; splitting it would hide the
// order the golden depends on.
#[allow(clippy::too_many_lines)]
pub fn identity_capture() -> Vec<(f64, Vec<u8>)> {
    let t = BASE_TS;
    // Workstation: DHCP exchange, then NetBIOS and LLMNR, then an ARP reply
    let mut p: Vec<(f64, Vec<u8>)> = vec![(t, dhcp_discover_frame(WS_MAC, "ENG-WS01"))];
    p.push((
        t + 0.5,
        dhcp_ack_frame(ROUTER_MAC, WS_MAC, WS_IP, "plant.local"),
    ));
    p.push((
        t + 1.0,
        nbns_registration_frame(WS_MAC, WS_IP, "ENG-WS01", 0x00, false),
    ));
    p.push((
        t + 1.1,
        nbns_registration_frame(WS_MAC, WS_IP, "PLANT", 0x00, true),
    ));
    p.push((
        t + 1.5,
        llmnr_response_frame(WS_MAC, WS_IP, "ENG-WS01", SCADA_IP),
    ));
    p.push((
        t + 1.6,
        arp_frame(true, (WS_IP, WS_MAC), (SCADA_IP, SCADA_MAC), None),
    ));
    p.push((
        t + 1.7,
        tcp_packet(
            WS_MAC,
            PLC_MAC,
            WS_IP,
            PLC_A_IP,
            52000,
            80,
            b"GET / HTTP/1.0\r\n\r\n",
        ),
    ));
    // Printer over mDNS
    p.push((
        t + 2.0,
        mdns_response_frame(
            PRINTER_MAC,
            PRINTER_IP,
            "printer",
            "_ipp._tcp",
            "Deskjet 2700",
        ),
    ));
    // Core switch: SNMP answer to the SCADA, LLDP with management address
    p.push((
        t + 3.0,
        snmp_response_frame(
            SWITCH_MAC,
            CORE_SWITCH_IP,
            "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M)",
            &[1, 3, 6, 1, 4, 1, 9, 1, 716],
            "SW-CORE",
            SCADA_IP,
        ),
    ));
    p.push((
        t + 3.5,
        lldp_announcement(
            SWITCH_MAC,
            "SW-CORE",
            "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M)",
            0x0004,
            "Gi1/0/5",
            Some(CORE_SWITCH_IP),
        ),
    ));
    // A switch that only speaks CDP
    p.push((
        t + 4.0,
        cdp_announcement(
            SILENT_SWITCH_MAC,
            "SW-ACCESS-2",
            "cisco WS-C2960-24TT-L",
            "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M)",
            0x28,
            "GigabitEthernet1/0/12",
            None,
        ),
    ));
    // Siemens controller: LLDP (station + bridge) and Modbus traffic
    p.push((
        t + 5.0,
        lldp_announcement(
            PLC_MAC,
            "plc-line1",
            "Siemens, SIMATIC S7, CPU 1516-3 PN/DP, 6ES7 516-3AN01-0AB0, HW: 5, FW: V2.8",
            0x0084,
            "port-001",
            Some(PLC_A_IP),
        ),
    ));
    p.push((
        t + 5.1,
        tcp_packet(
            SCADA_MAC,
            PLC_MAC,
            SCADA_IP,
            PLC_A_IP,
            49000,
            502,
            &read_request(1),
        ),
    ));
    p.push((
        t + 5.11,
        tcp_packet(
            PLC_MAC,
            SCADA_MAC,
            PLC_A_IP,
            SCADA_IP,
            502,
            49000,
            &read_response(1),
        ),
    ));
    // A host first seen behind the router, then answering ARP itself
    p.push((
        t + 6.0,
        tcp_packet(
            ROUTER_MAC,
            SCADA_MAC,
            MOVED_IP,
            SCADA_IP,
            40000,
            80,
            b"GET / HTTP/1.0\r\n\r\n",
        ),
    ));
    p.push((
        t + 6.5,
        arp_frame(true, (MOVED_IP, MOVED_MAC), (SCADA_IP, SCADA_MAC), None),
    ));
    p
}
