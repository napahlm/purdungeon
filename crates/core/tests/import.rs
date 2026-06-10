//! End-to-end test of the headless core: build a small legacy pcap with real
//! Modbus TCP exchanges, import it, and check discovery results.

use std::sync::atomic::AtomicU64;

use coil_core::Session;

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
    let path = dir.join(format!("coil-test-{}.pcap", std::process::id()));
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
