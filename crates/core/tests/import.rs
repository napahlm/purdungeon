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

/// Minimal legacy pcap writer: global header + per-packet records.
fn write_pcap(packets: &[(f64, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes()); // magic
    buf.extend_from_slice(&2u16.to_le_bytes()); // major
    buf.extend_from_slice(&4u16.to_le_bytes()); // minor
    buf.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    buf.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    buf.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    buf.extend_from_slice(&1u32.to_le_bytes()); // linktype: ethernet
    for (ts, data) in packets {
        let secs = ts.trunc() as u32;
        let micros = (ts.fract() * 1_000_000.0) as u32;
        buf.extend_from_slice(&secs.to_le_bytes());
        buf.extend_from_slice(&micros.to_le_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(data);
    }
    buf
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
    let scada = hosts.iter().find(|h| h.ip_address == "192.168.10.100").unwrap();
    let plc_a = hosts.iter().find(|h| h.ip_address == "192.168.10.1").unwrap();

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
        connections.iter().any(|c| c.app_protocol.as_deref() == Some("modbus")),
        "no modbus-tagged connections"
    );

    // Findings: the coil writes and the cleartext note should both surface
    let findings = session.findings().unwrap();
    assert!(
        findings.iter().any(|f| f.kind == "write" && f.host_ids.contains(&plc_a.id)),
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
    session.set_role_override(plc_a_id, Some("historian")).unwrap();

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
    assert_eq!(hosts.len(), 6, "expected union of hosts across both captures");

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
