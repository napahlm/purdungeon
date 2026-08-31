//! End-to-end test of the headless core: build a small legacy pcap with real
//! Modbus TCP exchanges, import it, and check discovery results.

use std::sync::atomic::AtomicU64;

use purdungeon_core::Session;

const SCADA_MAC: [u8; 6] = [0x00, 0x0c, 0x29, 0x11, 0x22, 0x33];
// 00:1b:1b is a Siemens prefix in the bundled OUI table
const PLC_MAC: [u8; 6] = [0x00, 0x1b, 0x1b, 0x44, 0x55, 0x66];
const SCADA_IP: [u8; 4] = [192, 168, 10, 100];
const PLC_A_IP: [u8; 4] = [192, 168, 10, 1];
const PLC_B_IP: [u8; 4] = [192, 168, 10, 2];
const PLC_C_IP: [u8; 4] = [192, 168, 10, 3];

fn mbap(tid: u16, unit: u8, pdu: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&tid.to_be_bytes());
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&((pdu.len() as u16 + 1).to_be_bytes()));
    buf.push(unit);
    buf.extend_from_slice(pdu);
    buf
}

fn tcp_packet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let builder = etherparse::PacketBuilder::ethernet2(src_mac, dst_mac)
        .ipv4(src_ip, dst_ip, 64)
        .tcp(src_port, dst_port, 1000, 64240);
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).unwrap();
    out
}

const MAGIC_MICROS: u32 = 0xa1b2_c3d4;
const MAGIC_NANOS: u32 = 0xa1b2_3c4d;

/// Minimal legacy pcap writer: global header + per-packet records. The magic
/// selects micro- vs nanosecond sub-second fields; `snaplen` truncates the
/// stored bytes while keeping the original length in the record header.
fn write_pcap_ex(
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

fn write_pcap(packets: &[(f64, Vec<u8>)]) -> Vec<u8> {
    write_pcap_ex(packets, MAGIC_MICROS, 1, None)
}

// ── Minimal pcapng writer: SHB + IDB + EPB/SPB blocks ───────────────────────

fn png_block(block_type: u32, body: &[u8]) -> Vec<u8> {
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

fn png_shb() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x1A2B_3C4D_u32.to_le_bytes()); // byte-order magic
    body.extend_from_slice(&1u16.to_le_bytes()); // major
    body.extend_from_slice(&0u16.to_le_bytes()); // minor
    body.extend_from_slice(&(-1i64).to_le_bytes()); // section length: unknown
    png_block(0x0A0D_0D0A, &body)
}

fn png_idb(linktype: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&linktype.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // reserved
    body.extend_from_slice(&0u32.to_le_bytes()); // snaplen: unlimited
    png_block(0x0000_0001, &body)
}

/// Enhanced Packet Block on interface 0 with a microsecond timestamp
/// (the IDB above carries no `if_tsresol` option, so 1 µs is the default).
fn png_epb(ts_micros: u64, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_le_bytes()); // if_id
    body.extend_from_slice(&((ts_micros >> 32) as u32).to_le_bytes());
    body.extend_from_slice(&((ts_micros & 0xFFFF_FFFF) as u32).to_le_bytes());
    body.extend_from_slice(&(data.len() as u32).to_le_bytes()); // caplen
    body.extend_from_slice(&(data.len() as u32).to_le_bytes()); // origlen
    body.extend_from_slice(data);
    png_block(0x0000_0006, &body)
}

fn png_spb(data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(data.len() as u32).to_le_bytes()); // origlen
    body.extend_from_slice(data);
    png_block(0x0000_0003, &body)
}

/// A second capture: the SCADA keeps polling PLC A (an overlapping flow that
/// must fuse) and a new HMI appears polling a new PLC D.
const HMI_MAC: [u8; 6] = [0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc];
const HMI_IP: [u8; 4] = [192, 168, 10, 50];
const PLC_D_IP: [u8; 4] = [192, 168, 10, 4];

fn follow_up_capture() -> Vec<(f64, Vec<u8>)> {
    let mut packets = Vec::new();
    let mut ts = 1_700_000_100.0;
    let mut tid: u16 = 1;
    for _ in 0..5 {
        // SCADA → PLC A on the same flow tuple as the first capture (port 49000)
        let req = mbap(tid, 1, &[0x03, 0x00, 0x00, 0x00, 0x0A]);
        packets.push((
            ts,
            tcp_packet(SCADA_MAC, PLC_MAC, SCADA_IP, PLC_A_IP, 49000, 502, &req),
        ));
        // New HMI → new PLC D
        let req2 = mbap(tid, 1, &[0x03, 0x00, 0x00, 0x00, 0x0A]);
        packets.push((
            ts + 0.01,
            tcp_packet(HMI_MAC, PLC_MAC, HMI_IP, PLC_D_IP, 50000, 502, &req2),
        ));
        tid = tid.wrapping_add(1);
        ts += 1.0;
    }
    packets
}

fn polling_capture() -> Vec<(f64, Vec<u8>)> {
    let mut packets = Vec::new();
    let mut ts = 1_700_000_000.0;
    let mut tid: u16 = 1;

    // SCADA polls three PLCs once a second; writes a coil on PLC A sometimes
    for round in 0..10 {
        for (i, plc_ip) in [PLC_A_IP, PLC_B_IP, PLC_C_IP].iter().enumerate() {
            let port = 49000 + i as u16;
            // Read holding registers request
            let req = mbap(tid, 1, &[0x03, 0x00, 0x00, 0x00, 0x0A]);
            packets.push((
                ts,
                tcp_packet(SCADA_MAC, PLC_MAC, SCADA_IP, *plc_ip, port, 502, &req),
            ));
            // Response with 10 registers
            let mut body = vec![0x03, 0x14];
            body.extend_from_slice(&[0u8; 20]);
            let resp = mbap(tid, 1, &body);
            packets.push((
                ts + 0.01,
                tcp_packet(PLC_MAC, SCADA_MAC, *plc_ip, SCADA_IP, 502, port, &resp),
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

/// Write capture bytes to a temp file, import them, and clean the file up.
fn import_bytes(
    tag: &str,
    bytes: &[u8],
) -> Result<(Session, purdungeon_core::types::ImportResult), purdungeon_core::CoreError> {
    let path =
        std::env::temp_dir().join(format!("purdungeon-test-{tag}-{}.pcap", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    let progress = AtomicU64::new(0);
    let result = Session::import(&path, &progress, &|_| {});
    std::fs::remove_file(&path).ok();
    result
}

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

    // Four hosts (scada + 3 plcs), all packets read
    assert_eq!(result.host_count, 4);
    assert!(result.packet_count >= 60);

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

    // Modbus flows got tagged even though connection rows opened untagged
    let connections = session.connections().unwrap();
    assert!(
        connections
            .iter()
            .any(|c| c.app_protocol.as_deref() == Some("modbus")),
        "no modbus-tagged connections"
    );

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
    let dir = std::env::temp_dir();
    let pid = std::process::id();

    let pcap_a = write_pcap(&polling_capture());
    let path_a = dir.join(format!("purdungeon-stitch-a-{pid}.pcap"));
    std::fs::write(&path_a, &pcap_a).unwrap();

    let progress = AtomicU64::new(0);
    let (session, _first) = Session::import(&path_a, &progress, &|_| {}).unwrap();

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
    let pcap_b = write_pcap(&follow_up_capture());
    let path_b = dir.join(format!("purdungeon-stitch-b-{pid}.pcap"));
    std::fs::write(&path_b, &pcap_b).unwrap();
    let progress_b = AtomicU64::new(0);
    session.add_capture(&path_b, &progress_b, &|_| {}).unwrap();

    std::fs::remove_file(&path_a).ok();
    std::fs::remove_file(&path_b).ok();

    let hosts = session.hosts().unwrap();
    // Original four plus the new HMI and PLC D
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
    assert_eq!(
        result.packet_count,
        packets.len(),
        "truncated packets must still import"
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
fn non_ethernet_linktype_is_a_clear_error() {
    // Linktype 113 = LINUX_SLL (cooked capture)
    let Err(err) = import_bytes(
        "sll",
        &write_pcap_ex(&polling_capture(), MAGIC_MICROS, 113, None),
    ) else {
        panic!("non-Ethernet capture must not import silently");
    };
    let msg = err.to_string();
    assert!(
        msg.contains("link type"),
        "error should name the link type: {msg}"
    );
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
            &mbap(1, 1, &[0x03, 0x00, 0x00, 0x00, 0x0A]),
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
    assert_eq!(result.packet_count, 3);
    assert_eq!(
        result.skipped.other, 1,
        "the SPB should be counted as skipped"
    );
    assert!(
        (result.time_range.0 - 1_700_000_000.0).abs() < 1e-3
            && (result.time_range.1 - 1_700_000_002.0).abs() < 1e-3,
        "second-section timestamps must decode with its own interface table: {:?}",
        result.time_range
    );
}

#[test]
fn skipped_counters_report_ipv6_and_arp() {
    let mut packets = polling_capture();
    let ts = 1_700_000_050.0;

    // One IPv6 UDP packet
    let builder = etherparse::PacketBuilder::ethernet2(SCADA_MAC, PLC_MAC)
        .ipv6([1u8; 16], [2u8; 16], 64)
        .udp(1234, 5678);
    let mut v6 = Vec::with_capacity(builder.size(4));
    builder.write(&mut v6, &[0u8; 4]).unwrap();
    packets.push((ts, v6));

    // One ARP request (ethertype 0x0806, body content irrelevant)
    let mut arp = Vec::new();
    arp.extend_from_slice(&[0xff; 6]); // dst: broadcast
    arp.extend_from_slice(&SCADA_MAC);
    arp.extend_from_slice(&[0x08, 0x06]);
    arp.extend_from_slice(&[0u8; 28]);
    packets.push((ts + 0.5, arp));

    let ipv4_count = packets.len() - 2;
    let (_session, result) = import_bytes("skips", &write_pcap(&packets)).unwrap();
    assert_eq!(result.packet_count, ipv4_count);
    assert_eq!(result.skipped.ipv6, 1);
    assert_eq!(result.skipped.arp, 1);
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
