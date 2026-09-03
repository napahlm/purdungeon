//! End-to-end tests of the headless core: build small captures with real
//! Modbus TCP exchanges (and every other kind of frame the reader handles),
//! import them, and check discovery results and frame accounting.

mod common;

use std::sync::atomic::AtomicU64;

use common::*;
use etherparse::IpNumber;
use purdungeon_core::Session;

#[test]
fn import_discovers_roles_and_modbus_activity() {
    let pcap = write_pcap(&polling_capture());
    let dir = std::env::temp_dir();
    let path = dir.join(format!("purdungeon-test-{}.pcap", std::process::id()));
    std::fs::write(&path, &pcap).unwrap();

    let progress = AtomicU64::new(0);
    let stages = std::sync::Mutex::new(Vec::new());
    let (session, result) = Session::import(&path, &progress, &|stage| {
        stages.lock().unwrap().push(stage);
    })
    .unwrap();
    std::fs::remove_file(&path).ok();
    assert_reconciles(&result);

    // Four hosts (scada + 3 plcs), all packets read
    assert_eq!(result.host_count, 4);
    assert!(result.packet_count >= 60);
    assert_eq!(result.decoded.ipv4, result.packet_count);
    assert_eq!(result.skipped.total(), 0);

    // All import stages fired, in order
    let stages = stages.lock().unwrap();
    assert_eq!(stages.len(), 5);

    let hosts = session.hosts().unwrap();
    let scada = hosts
        .iter()
        .find(|h| h.ip_address == "192.168.10.100")
        .unwrap();
    let plc_a = hosts
        .iter()
        .find(|h| h.ip_address == "192.168.10.1")
        .unwrap();

    // Polls 3 devices → scada at level 2; answers on 502 → plc at level 1
    assert_eq!(scada.role, "scada", "evidence: {:?}", scada.role_evidence);
    assert_eq!(scada.purdue_level, Some(2));
    assert_eq!(plc_a.role, "plc", "evidence: {:?}", plc_a.role_evidence);
    assert_eq!(plc_a.purdue_level, Some(1));
    assert_eq!(plc_a.vendor.as_deref(), Some("Siemens"));
    assert!(scada.protocols.contains("modbus"));
    assert_eq!(plc_a.link_protocols, "");

    // Modbus flows got tagged even though connection rows opened untagged
    let connections = session.connections().unwrap();
    assert!(
        connections
            .iter()
            .any(|c| c.app_protocol.as_deref() == Some("modbus")),
        "no modbus-tagged connections"
    );
    assert!(connections.iter().all(|c| c.vlan_id.is_none()));

    // Findings: the coil writes and the cleartext note should both surface
    let findings = session.findings().unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.kind == "write" && f.host_ids.contains(&plc_a.id)),
        "write finding missing: {findings:?}"
    );
    assert!(findings.iter().any(|f| f.kind == "cleartext"));
}

#[test]
fn add_capture_merges_hosts_and_fuses_flows() {
    let (session, first) = import_bytes("stitch-a", &write_pcap(&polling_capture())).unwrap();
    assert_reconciles(&first);
    let connections_before = session.connections().unwrap().len();

    // Override PLC A's role; the override must survive re-analysis on append.
    let plc_a_id = session
        .hosts()
        .unwrap()
        .into_iter()
        .find(|h| h.ip_address == "192.168.10.1")
        .unwrap()
        .id;
    session
        .set_role_override(plc_a_id, Some("historian"))
        .unwrap();

    // Append a second capture that overlaps one flow and adds an HMI + PLC D.
    let second = append_bytes(&session, "stitch-b", &write_pcap(&follow_up_capture())).unwrap();
    assert_reconciles(&second);

    let hosts = session.hosts().unwrap();
    assert!(
        hosts.iter().any(|h| h.ip_address == "192.168.10.50"),
        "new HMI host missing after append"
    );
    assert!(
        hosts.iter().any(|h| h.ip_address == "192.168.10.4"),
        "new PLC D host missing after append"
    );
    assert_eq!(
        hosts.len(),
        6,
        "expected union of hosts across both captures"
    );

    // The overlapping SCADA→PLC A flow fused: exactly one new flow row was
    // added (HMI→PLC D), not a duplicate of the existing one.
    let connections_after = session.connections().unwrap();
    assert_eq!(
        connections_after.len(),
        connections_before + 1,
        "overlapping flow should fuse, only the HMI→PLC D flow is new"
    );

    // Re-analysis ran over the merged set but left the user override intact.
    let plc_a = hosts.iter().find(|h| h.id == plc_a_id).unwrap();
    assert_eq!(
        plc_a.role_override.as_deref(),
        Some("historian"),
        "user role override must survive an append"
    );

    // Findings were regenerated, not duplicated.
    let findings = session.findings().unwrap();
    let cleartext = findings.iter().filter(|f| f.kind == "cleartext").count();
    assert_eq!(cleartext, 1, "findings should be regenerated, not stacked");
}

#[test]
fn nanosecond_pcap_matches_microsecond_twin() {
    let packets = polling_capture();
    let (_s_us, us) = import_bytes("us", &write_pcap_ex(&packets, MAGIC_MICROS, 1, None)).unwrap();
    let (_s_ns, ns) = import_bytes("ns", &write_pcap_ex(&packets, MAGIC_NANOS, 1, None)).unwrap();
    assert_eq!(us.packet_count, ns.packet_count);
    assert!(
        (us.time_range.0 - ns.time_range.0).abs() < 1e-3
            && (us.time_range.1 - ns.time_range.1).abs() < 1e-3,
        "nanosecond timestamps must decode to the same instants: {:?} vs {:?}",
        us.time_range,
        ns.time_range
    );
}

#[test]
fn snaplen_truncated_capture_counts_wire_bytes() {
    let packets = polling_capture();
    let wire_bytes: i64 = packets.iter().map(|(_, d)| d.len() as i64).sum();
    // Snaplen 60 keeps Ethernet+IP+TCP headers but cuts every Modbus payload.
    let (session, result) =
        import_bytes("snap", &write_pcap_ex(&packets, MAGIC_MICROS, 1, Some(60))).unwrap();
    assert_reconciles(&result);
    assert_eq!(
        result.packet_count,
        packets.len(),
        "truncated payloads must still import as packets"
    );
    assert_eq!(
        result.skipped.truncated, 0,
        "a cut payload is not a cut header"
    );
    let stored: i64 = session
        .connections()
        .unwrap()
        .iter()
        .map(|c| c.byte_count)
        .sum();
    assert_eq!(
        stored, wire_bytes,
        "byte counts must reflect wire length, not snaplen"
    );
}

#[test]
fn snaplen_cutting_headers_is_counted_as_truncated() {
    let packets = polling_capture();
    // 20 bytes: Ethernet plus six bytes of IP header — no addresses survive.
    let (session, result) = import_bytes(
        "snap20",
        &write_pcap_ex(&packets, MAGIC_MICROS, 1, Some(20)),
    )
    .unwrap();
    assert_reconciles(&result);
    assert_eq!(result.packet_count, 0);
    assert_eq!(result.skipped.truncated, packets.len());
    assert_eq!(session.hosts().unwrap().len(), 0);

    // 40 bytes: the IP header is whole, the TCP header is cut — hosts are
    // known, the flow is not.
    let (session, result) = import_bytes(
        "snap40",
        &write_pcap_ex(&packets, MAGIC_MICROS, 1, Some(40)),
    )
    .unwrap();
    assert_reconciles(&result);
    assert_eq!(result.packet_count, 0);
    assert_eq!(result.skipped.truncated, packets.len());
    assert_eq!(session.hosts().unwrap().len(), 4);
    assert!(session.connections().unwrap().is_empty());
}

#[test]
fn pcapng_multi_section_resets_interfaces_and_skips_spbs() {
    let pkt = |sp: u16| {
        tcp_packet(
            SCADA_MAC,
            PLC_MAC,
            SCADA_IP,
            PLC_A_IP,
            sp,
            502,
            &read_request(1),
        )
    };
    let t0: u64 = 1_700_000_000_000_000; // µs
    let mut file = Vec::new();
    // Section 1: two packets
    file.extend(png_shb());
    file.extend(png_idb(1));
    file.extend(png_epb(t0, &pkt(49000)));
    file.extend(png_epb(t0 + 1_000_000, &pkt(49000)));
    // A Simple Packet Block carries no timestamp — skipped, not imported at 1970
    file.extend(png_spb(&pkt(49001)));
    // Section 2 (mergecap-style): interface table starts over
    file.extend(png_shb());
    file.extend(png_idb(1));
    file.extend(png_epb(t0 + 2_000_000, &pkt(49002)));

    let (_session, result) = import_bytes("ng-multi", &file).unwrap();
    assert_reconciles(&result);
    assert_eq!(result.packet_count, 3);
    assert_eq!(
        result.skipped.no_timestamp, 1,
        "the SPB should be counted as lacking a timestamp"
    );
    assert!(
        (result.time_range.0 - 1_700_000_000.0).abs() < 1e-3
            && (result.time_range.1 - 1_700_000_002.0).abs() < 1e-3,
        "second-section timestamps must decode with its own interface table: {:?}",
        result.time_range
    );
}

#[test]
fn pcapng_unknown_interface_id_is_malformed() {
    let pkt = tcp_packet(
        SCADA_MAC,
        PLC_MAC,
        SCADA_IP,
        PLC_A_IP,
        49000,
        502,
        &read_request(1),
    );
    let t0: u64 = 1_700_000_000_000_000;
    let mut file = Vec::new();
    file.extend(png_shb());
    file.extend(png_idb(1));
    file.extend(png_epb_on(0, t0, &pkt));
    file.extend(png_epb_on(7, t0 + 1, &pkt));
    let (_session, result) = import_bytes("ng-badif", &file).unwrap();
    assert_reconciles(&result);
    assert_eq!(result.packet_count, 1);
    assert_eq!(result.skipped.malformed, 1);
}

#[test]
fn unsupported_link_type_is_per_packet_in_pcapng_and_an_error_when_alone() {
    let pkt = tcp_packet(
        SCADA_MAC,
        PLC_MAC,
        SCADA_IP,
        PLC_A_IP,
        49000,
        502,
        &read_request(1),
    );
    let t0: u64 = 1_700_000_000_000_000;
    // Interface 0 is 802.11 (105), interface 1 is Ethernet.
    let mut file = Vec::new();
    file.extend(png_shb());
    file.extend(png_idb(105));
    file.extend(png_idb(1));
    file.extend(png_epb_on(0, t0, &[0u8; 64]));
    file.extend(png_epb_on(1, t0 + 1, &pkt));
    file.extend(png_epb_on(0, t0 + 2, &[0u8; 64]));
    let (_session, result) = import_bytes("ng-mixed-lt", &file).unwrap();
    assert_reconciles(&result);
    assert_eq!(result.packet_count, 1);
    assert_eq!(result.skipped.unsupported_link_type, 2);

    // Only unreadable interfaces: a clear error naming the link type.
    let mut only = Vec::new();
    only.extend(png_shb());
    only.extend(png_idb(105));
    only.extend(png_epb_on(0, t0, &[0u8; 64]));
    let Err(err) = import_bytes("ng-only-lt", &only) else {
        panic!("an all-802.11 pcapng must not import silently");
    };
    let err = err.to_string();
    assert!(
        err.contains("link type"),
        "error should name the link type: {err}"
    );

    let legacy = write_pcap_linktype(&[(BASE_TS, vec![0u8; 64])], 105);
    let Err(err) = import_bytes("legacy-lt", &legacy) else {
        panic!("an 802.11 legacy pcap must not import silently");
    };
    let err = err.to_string();
    assert!(
        err.contains("link type"),
        "error should name the link type: {err}"
    );
}

#[test]
fn linux_cooked_captures_import_with_sender_macs_only() {
    let ip = |sp: u16| bare_ipv4_tcp(SCADA_IP, PLC_A_IP, sp, 502, &read_request(1));
    let v1 = vec![
        (BASE_TS, sll_frame(SCADA_MAC, 0x0800, &ip(49000))),
        (BASE_TS + 1.0, sll_frame(SCADA_MAC, 0x0800, &ip(49000))),
    ];
    let (session, result) = import_bytes("sll", &write_pcap_linktype(&v1, 113)).unwrap();
    assert_reconciles(&result);
    assert_eq!(result.decoded.ipv4, 2);
    let hosts = session.hosts().unwrap();
    let scada = hosts
        .iter()
        .find(|h| h.ip_address == "192.168.10.100")
        .unwrap();
    let plc = hosts
        .iter()
        .find(|h| h.ip_address == "192.168.10.1")
        .unwrap();
    assert_eq!(scada.mac_address, "00:0c:29:11:22:33");
    assert_eq!(
        plc.mac_address, "",
        "a cooked header carries no destination MAC"
    );
    assert_eq!(plc.vendor, None);

    let v2 = vec![(BASE_TS, sll2_frame(PLC_MAC, 0x0800, &ip(49001)))];
    let (session, result) = import_bytes("sll2", &write_pcap_linktype(&v2, 276)).unwrap();
    assert_reconciles(&result);
    assert_eq!(result.decoded.ipv4, 1);
    let hosts = session.hosts().unwrap();
    let scada = hosts
        .iter()
        .find(|h| h.ip_address == "192.168.10.100")
        .unwrap();
    assert_eq!(scada.mac_address, "00:1b:1b:44:55:66");
}

#[test]
fn raw_ip_and_loopback_captures_import() {
    let v4 = bare_ipv4_tcp(SCADA_IP, PLC_A_IP, 49000, 502, &read_request(1));
    let v6 = bare_ipv6_udp(V6_ULA_HMI, V6_ULA_PLC, 5000, 5001, &[0u8; 4]);
    for (tag, linktype, frame) in [
        ("raw", 101, v4.clone()),
        ("ipv4", 228, v4.clone()),
        ("ipv6", 229, v6),
        ("null", 0, null_frame(&v4)),
        ("loop", 108, null_frame(&v4)),
    ] {
        let (session, result) =
            import_bytes(tag, &write_pcap_linktype(&[(BASE_TS, frame)], linktype)).unwrap();
        assert_reconciles(&result);
        assert_eq!(result.packet_count, 1, "{tag}: the packet should decode");
        assert!(
            session
                .hosts()
                .unwrap()
                .iter()
                .all(|h| h.mac_address.is_empty()),
            "{tag}: raw-IP link types carry no MAC"
        );
    }
}

#[test]
fn vlan_tagged_arp_populates_a_subnet_without_ip_traffic() {
    let siemens = [0x00, 0x1b, 0x1b, 0x0a, 0x00, 0x01];
    let gateway = ([10, 0, 10, 254], SWITCH_MAC);
    let mut packets = Vec::new();
    for i in 1..=6u8 {
        let mac = if i == 1 {
            siemens
        } else {
            [0x00, 0x0c, 0x29, 0x10, 0x00, i]
        };
        packets.push((
            BASE_TS + f64::from(i),
            arp_frame(
                false,
                ([10, 0, 10, i], mac),
                ([10, 0, 10, 254], [0; 6]),
                Some(10),
            ),
        ));
    }
    packets.push((
        BASE_TS + 7.0,
        arp_frame(true, gateway, ([10, 0, 10, 1], siemens), Some(10)),
    ));
    packets.push((
        BASE_TS + 8.0,
        arp_frame(
            true,
            gateway,
            ([10, 0, 10, 2], [0x00, 0x0c, 0x29, 0x10, 0x00, 2]),
            Some(10),
        ),
    ));

    let (session, result) = import_bytes("arp-subnet", &write_pcap(&packets)).unwrap();
    assert_reconciles(&result);
    assert_eq!(result.decoded.arp, 8);
    assert_eq!(
        result.skipped.total(),
        0,
        "tagged ARP must not land in a skip bucket"
    );
    assert_eq!(result.host_count, 7);
    assert_eq!(result.connection_count, 0);

    let hosts = session.hosts().unwrap();
    let dev1 = hosts.iter().find(|h| h.ip_address == "10.0.10.1").unwrap();
    assert_eq!(dev1.mac_address, "00:1b:1b:0a:00:01");
    assert_eq!(dev1.vendor.as_deref(), Some("Siemens"));
    assert_eq!(dev1.link_protocols, "arp");
    assert_eq!(dev1.role, "field-device");
    assert!(
        dev1.role_evidence
            .as_deref()
            .unwrap_or("")
            .contains("seen only in ARP"),
        "evidence should say the device was only seen in ARP: {:?}",
        dev1.role_evidence
    );
    let dev3 = hosts.iter().find(|h| h.ip_address == "10.0.10.3").unwrap();
    assert_eq!(dev3.role, "unknown");
    assert!(
        dev3.role_confidence.abs() < 1e-9,
        "unknown must carry no confidence"
    );
    assert_eq!(
        dev3.role_evidence.as_deref(),
        Some("seen only in ARP; no IP traffic")
    );
    assert!(hosts.iter().any(|h| h.ip_address == "10.0.10.254"));
}

#[test]
fn arp_edge_cases_only_vouch_for_real_senders() {
    let packets = vec![
        // Gratuitous ARP: the sender announces its own address
        (
            BASE_TS,
            arp_frame(
                false,
                ([10, 0, 0, 7], HMI_MAC),
                ([10, 0, 0, 7], [0; 6]),
                None,
            ),
        ),
        // ARP probe from 0.0.0.0: no host yet
        (
            BASE_TS + 1.0,
            arp_frame(
                false,
                ([0, 0, 0, 0], SCADA_MAC),
                ([10, 0, 0, 8], [0; 6]),
                None,
            ),
        ),
        // A request's target is a question, not a device
        (
            BASE_TS + 2.0,
            arp_frame(
                false,
                ([10, 0, 0, 9], PLC_MAC),
                ([10, 0, 0, 200], [0; 6]),
                None,
            ),
        ),
    ];
    let (session, result) = import_bytes("arp-edge", &write_pcap(&packets)).unwrap();
    assert_reconciles(&result);
    assert_eq!(result.decoded.arp, 3);
    let ips: Vec<String> = session
        .hosts()
        .unwrap()
        .into_iter()
        .map(|h| h.ip_address)
        .collect();
    assert_eq!(ips.len(), 2, "hosts: {ips:?}");
    assert!(ips.contains(&"10.0.0.7".to_string()));
    assert!(ips.contains(&"10.0.0.9".to_string()));
}

#[test]
fn ipv6_flows_become_assets() {
    let packets = vec![
        (
            BASE_TS,
            udp6_packet(
                HMI_MAC,
                [0x33, 0x33, 0, 0, 0, 1],
                V6_LINK_LOCAL_A,
                V6_ALL_NODES,
                5353,
                5353,
                &[0u8; 8],
            ),
        ),
        (
            BASE_TS + 1.0,
            tcp6_packet(
                HMI_MAC,
                PLC_MAC,
                V6_ULA_HMI,
                V6_ULA_PLC,
                51000,
                502,
                &read_request(1),
            ),
        ),
        (
            BASE_TS + 1.01,
            tcp6_packet(
                PLC_MAC,
                HMI_MAC,
                V6_ULA_PLC,
                V6_ULA_HMI,
                502,
                51000,
                &read_response(1),
            ),
        ),
        (
            BASE_TS + 2.0,
            tcp6_packet(
                HMI_MAC,
                PLC_MAC,
                V6_ULA_HMI,
                V6_ULA_PLC,
                51000,
                502,
                &read_request(2),
            ),
        ),
    ];
    let (session, result) = import_bytes("v6", &write_pcap(&packets)).unwrap();
    assert_reconciles(&result);
    assert_eq!(result.decoded.ipv6, 4);
    assert_eq!(result.decoded.ipv4, 0);

    let hosts = session.hosts().unwrap();
    assert_eq!(hosts.len(), 4);
    let by_ip = |ip: &str| {
        hosts
            .iter()
            .find(|h| h.ip_address == ip)
            .unwrap_or_else(|| {
                panic!(
                    "{ip} missing; addresses must be RFC 5952 compressed: {:?}",
                    hosts.iter().map(|h| &h.ip_address).collect::<Vec<_>>()
                )
            })
    };
    assert_eq!(by_ip("ff02::1").role, "broadcast");
    let plc = by_ip("fd00::20");
    assert_eq!(plc.role, "plc", "evidence: {:?}", plc.role_evidence);
    assert!(!plc.is_external);
    assert!(!by_ip("fe80::1").is_external);
    assert!(session
        .connections()
        .unwrap()
        .iter()
        .any(|c| c.app_protocol.as_deref() == Some("modbus")));
}

#[test]
fn icmpv6_and_other_ip_protocols_are_portless_flows() {
    let packets = vec![
        (
            BASE_TS,
            icmpv6_echo(HMI_MAC, PLC_MAC, V6_LINK_LOCAL_A, V6_LINK_LOCAL_B, false),
        ),
        (
            BASE_TS + 0.01,
            icmpv6_echo(PLC_MAC, HMI_MAC, V6_LINK_LOCAL_B, V6_LINK_LOCAL_A, true),
        ),
        // IGMPv3 membership report: an 8-byte header etherparse insists on
        (
            BASE_TS + 1.0,
            ip_proto_packet(
                SCADA_MAC,
                [0x01, 0x00, 0x5e, 0, 0, 0x16],
                SCADA_IP,
                [224, 0, 0, 22],
                IpNumber::IGMP,
                &[0x22, 0, 0, 0, 0, 0, 0, 0],
            ),
        ),
        (
            BASE_TS + 2.0,
            ip_proto_packet(
                SWITCH_MAC,
                [0x01, 0x00, 0x5e, 0, 0, 0x12],
                [192, 168, 10, 254],
                [224, 0, 0, 18],
                IpNumber::VRRP,
                &[0u8; 8],
            ),
        ),
        (
            BASE_TS + 3.0,
            ip_proto_packet(
                SCADA_MAC,
                PLC_MAC,
                SCADA_IP,
                PLC_A_IP,
                IpNumber::GRE,
                &[0u8; 8],
            ),
        ),
    ];
    let (session, result) = import_bytes("portless", &write_pcap(&packets)).unwrap();
    assert_reconciles(&result);
    assert_eq!(result.packet_count, 5);
    let connections = session.connections().unwrap();
    let mut names: Vec<&str> = connections.iter().map(|c| c.protocol.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["GRE", "ICMPv6", "ICMPv6", "IGMP", "VRRP"]);
    assert!(connections
        .iter()
        .all(|c| c.src_port == 0 && c.dst_port == 0));
}

#[test]
fn ip_fragments_record_hosts_but_no_flow() {
    let packets = vec![(
        BASE_TS,
        ipv4_fragment(HMI_MAC, PLC_MAC, [192, 168, 10, 5], [192, 168, 10, 6]),
    )];
    let (session, result) = import_bytes("frag", &write_pcap(&packets)).unwrap();
    assert_reconciles(&result);
    assert_eq!(result.skipped.fragment, 1);
    assert_eq!(session.hosts().unwrap().len(), 2);
    assert!(session.connections().unwrap().is_empty());
}

#[test]
fn lldp_and_cdp_are_counted_but_not_yet_assets() {
    let packets = vec![
        (BASE_TS, lldp_frame(SWITCH_MAC)),
        (BASE_TS + 30.0, cdp_frame(SWITCH_MAC)),
    ];
    let (session, result) = import_bytes("lldp-cdp", &write_pcap(&packets)).unwrap();
    assert_reconciles(&result);
    assert_eq!(result.decoded.lldp, 1);
    assert_eq!(result.decoded.cdp, 1);
    assert_eq!(result.packet_count, 2);
    assert_eq!(result.host_count, 0);
    assert!((result.time_range.1 - result.time_range.0 - 30.0).abs() < 1e-3);
    assert_eq!(session.time_range().unwrap(), result.time_range);
}

#[test]
fn unreadable_ethernet_payloads_are_counted_by_kind() {
    let packets = vec![
        (BASE_TS, stp_frame(SWITCH_MAC)),
        (
            BASE_TS + 1.0,
            ethertype_frame(PLC_MAC, BROADCAST_MAC, 0x88A4, &[0u8; 40]),
        ),
        (
            BASE_TS + 2.0,
            ethertype_frame(PLC_MAC, BROADCAST_MAC, 0x8892, &[0u8; 40]),
        ),
        // 0x88CC that is not an LLDPDU
        (
            BASE_TS + 3.0,
            ethertype_frame(SWITCH_MAC, BROADCAST_MAC, 0x88CC, &[0xff, 0xff, 0, 0]),
        ),
    ];
    let (_session, result) = import_bytes("other-eth", &write_pcap(&packets)).unwrap();
    assert_reconciles(&result);
    assert_eq!(result.skipped.other_ethertype, 3);
    assert_eq!(result.skipped.malformed, 1);
    assert_eq!(result.packet_count, 0);
}

#[test]
fn truncated_file_tail_imports_what_it_can() {
    let packets = polling_capture();
    let bytes = write_pcap(&packets);
    let cut = &bytes[..bytes.len() - 10];
    let (_session, result) = import_bytes("cut-tail", cut).unwrap();
    assert_reconciles(&result);
    assert_eq!(result.packet_count, packets.len() - 1);
    assert_eq!(result.skipped.malformed, 1);
    assert_eq!(result.frames_read, packets.len());
}

#[test]
fn zero_timestamp_frames_are_counted_not_dated() {
    let mut packets = polling_capture();
    packets.push((
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
    let (session, result) = import_bytes("zero-ts", &write_pcap(&packets)).unwrap();
    assert_reconciles(&result);
    assert_eq!(result.skipped.no_timestamp, 1);
    assert!(
        result.time_range.0 >= BASE_TS,
        "1970 must not appear: {:?}",
        result.time_range
    );
    assert!(session.time_range().unwrap().0 >= BASE_TS);
}

#[test]
fn append_with_ipv6_hosts_present_and_arp_for_a_known_host() {
    let first = vec![
        (
            BASE_TS,
            tcp6_packet(
                HMI_MAC,
                PLC_MAC,
                V6_ULA_HMI,
                V6_ULA_PLC,
                51000,
                502,
                &read_request(1),
            ),
        ),
        (
            BASE_TS + 0.01,
            tcp6_packet(
                PLC_MAC,
                HMI_MAC,
                V6_ULA_PLC,
                V6_ULA_HMI,
                502,
                51000,
                &read_response(1),
            ),
        ),
        (
            BASE_TS + 1.0,
            tcp_packet(
                SCADA_MAC,
                PLC_MAC,
                SCADA_IP,
                PLC_A_IP,
                49000,
                502,
                &read_request(2),
            ),
        ),
    ];
    let (session, r1) = import_bytes("v6-append-a", &write_pcap(&first)).unwrap();
    assert_reconciles(&r1);
    let connections_before = session.connections().unwrap().len();

    let second = vec![
        // Same IPv6 flow again: must fuse, not duplicate
        (
            BASE_TS + 10.0,
            tcp6_packet(
                HMI_MAC,
                PLC_MAC,
                V6_ULA_HMI,
                V6_ULA_PLC,
                51000,
                502,
                &read_request(3),
            ),
        ),
        // The SCADA now also shows up in ARP
        (
            BASE_TS + 11.0,
            arp_frame(false, (SCADA_IP, SCADA_MAC), (PLC_A_IP, [0; 6]), None),
        ),
    ];
    let r2 = append_bytes(&session, "v6-append-b", &write_pcap(&second)).unwrap();
    assert_reconciles(&r2);
    assert_eq!(r2.decoded.ipv6, 1);
    assert_eq!(r2.decoded.arp, 1);

    let hosts = session.hosts().unwrap();
    assert_eq!(
        hosts.len(),
        4,
        "no host may be duplicated on append: {hosts:?}"
    );
    assert_eq!(session.connections().unwrap().len(), connections_before);
    let scada = hosts
        .iter()
        .find(|h| h.ip_address == "192.168.10.100")
        .unwrap();
    assert_eq!(
        scada.link_protocols, "arp",
        "link-layer sightings must union on append"
    );
}

#[test]
fn vlan_ids_are_recorded_on_conversations() {
    let packets = vec![
        (
            BASE_TS,
            vlan_tcp_packet(
                20,
                SCADA_MAC,
                PLC_MAC,
                SCADA_IP,
                PLC_A_IP,
                49000,
                502,
                &read_request(1),
            ),
        ),
        (
            BASE_TS + 1.0,
            tcp_packet(
                SCADA_MAC,
                PLC_MAC,
                SCADA_IP,
                PLC_B_IP,
                49001,
                502,
                &read_request(2),
            ),
        ),
        (
            BASE_TS + 2.0,
            qinq_tcp_packet(
                100,
                200,
                SCADA_MAC,
                PLC_MAC,
                SCADA_IP,
                PLC_C_IP,
                49002,
                502,
                &read_request(3),
            ),
        ),
    ];
    let (session, result) = import_bytes("vlan", &write_pcap(&packets)).unwrap();
    assert_reconciles(&result);
    assert_eq!(result.packet_count, 3);
    let connections = session.connections().unwrap();
    let vlan_of = |port: u16| {
        connections
            .iter()
            .find(|c| c.src_port == port)
            .unwrap()
            .vlan_id
    };
    assert_eq!(vlan_of(49000), Some(20));
    assert_eq!(vlan_of(49001), None);
    assert_eq!(vlan_of(49002), Some(100), "QinQ records the outer tag");

    let scada_id = session
        .hosts()
        .unwrap()
        .iter()
        .find(|h| h.ip_address == "192.168.10.100")
        .unwrap()
        .id;
    let detail = session.host_detail(scada_id).unwrap();
    assert_eq!(detail.vlans, vec![20, 100]);
}

#[test]
fn identical_imports_produce_identical_findings() {
    let bytes = write_pcap(&polling_capture());
    let (session_a, _) = import_bytes("det-a", &bytes).unwrap();
    let (session_b, _) = import_bytes("det-b", &bytes).unwrap();
    let signature = |s: &Session| -> Vec<(String, String, String, String)> {
        s.findings()
            .unwrap()
            .into_iter()
            .map(|f| (f.kind, f.severity, f.title, f.detail))
            .collect()
    };
    assert_eq!(
        signature(&session_a),
        signature(&session_b),
        "the same capture must always produce the same findings, in the same order"
    );
}
