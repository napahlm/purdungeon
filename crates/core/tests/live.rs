//! Live ingest: frames arriving in batches through `LiveWriter` must leave
//! the session exactly as one import of the same frames would, and repeated
//! checkpoints must never count anything twice.

mod common;

use common::identity::{dhcp_ack_frame, dhcp_discover_frame, ROUTER_MAC, WS_IP, WS_MAC};
use common::*;
use purdungeon_core::ingest::Linktype;
use purdungeon_core::live::{LiveWriter, OwnedFrame, LIVE_GRACE_SECS};
use purdungeon_core::types::ImportResult;
use purdungeon_core::Session;

/// libpcap hands over seconds and microseconds, the same resolution a pcap
/// file stores, so a stream quantises its timestamps the way a file does.
fn micros(ts: f64) -> f64 {
    let subsec = (ts.fract() * 1_000_000.0) as u32;
    ts.trunc() + f64::from(subsec) / 1_000_000.0
}

fn owned(frames: &[(f64, Vec<u8>)]) -> Vec<OwnedFrame> {
    frames
        .iter()
        .map(|(ts, data)| OwnedFrame {
            timestamp: micros(*ts),
            orig_len: data.len() as u32,
            data: data.clone(),
        })
        .collect()
}

/// Stream `frames` through a fresh live session in batches of `chunk`.
fn stream(frames: &[(f64, Vec<u8>)], chunk: usize, grace: f64) -> (Session, ImportResult) {
    let session = Session::empty().unwrap();
    let mut writer: LiveWriter = session.live_writer(grace).unwrap();
    for batch in owned(frames).chunks(chunk) {
        writer.commit_batch(Linktype::ETHERNET, batch).unwrap();
    }
    let result = writer.finish().unwrap();
    assert_reconciles(&result);
    (session, result)
}

#[test]
fn empty_session_answers_every_query() {
    let session = Session::empty().unwrap();
    assert!(session.hosts().unwrap().is_empty());
    assert!(session.connections().unwrap().is_empty());
    assert!(session.findings().unwrap().is_empty());
    assert_eq!(session.time_range().unwrap(), (0.0, 0.0));
    assert!(session.traffic_histogram(120).unwrap().is_empty());
}

/// Every decode path in small batches, attribution deferred to the end as a
/// file import defers it: the result must be the file import's, field for
/// field. (A finite grace window can legitimately differ when an exchange
/// straddles a batch; that is `grace_window_keeps_dhcp_client_whole`.)
#[test]
fn streaming_with_deferred_attribution_equals_one_shot() {
    let frames = mixed_capture();
    let (file_session, file_result) = import_bytes("live-oneshot", &write_pcap(&frames)).unwrap();
    let (live_session, live_result) = stream(&frames, 7, f64::INFINITY);

    assert_eq!(live_result.frames_read, file_result.frames_read);
    assert_eq!(live_result.packet_count, file_result.packet_count);
    assert_eq!(live_result.host_count, file_result.host_count);
    assert_eq!(live_result.connection_count, file_result.connection_count);
    assert_eq!(live_result.time_range, file_result.time_range);
    assert_eq!(
        format!("{:?}", live_result.skipped),
        format!("{:?}", file_result.skipped)
    );
    assert_eq!(
        session_fingerprint(&live_session),
        session_fingerprint(&file_session)
    );
}

/// Two batches with a checkpoint between them must add up to one import:
/// flow counts, host ranges and evidence counts are deltas that restart.
#[test]
fn checkpoints_never_double_count() {
    let frames = polling_capture();
    let (file_session, _) = import_bytes("live-double", &write_pcap(&frames)).unwrap();
    let half = frames.len() / 2;
    let (live_session, _) = stream(&frames, half, 0.0);
    assert_eq!(
        session_fingerprint(&live_session),
        session_fingerprint(&file_session)
    );
}

/// A DHCP client is first seen by MAC alone (the Discover), and named by IP
/// only when the server answers. With a grace window the two land on one
/// host even when a batch boundary falls between them; without it, the
/// Discover would have become a MAC-only asset of its own.
#[test]
fn grace_window_keeps_dhcp_client_whole() {
    let discover = vec![(BASE_TS, dhcp_discover_frame(WS_MAC, "ENG-WS-01"))];
    let ack = vec![(
        BASE_TS + 1.5,
        dhcp_ack_frame(ROUTER_MAC, WS_MAC, WS_IP, "plant.example"),
    )];
    let ws_mac = "00:50:56:01:02:03";

    let hosts_with = |grace: f64| {
        let session = Session::empty().unwrap();
        let mut writer = session.live_writer(grace).unwrap();
        writer
            .commit_batch(Linktype::ETHERNET, &owned(&discover))
            .unwrap();
        writer
            .commit_batch(Linktype::ETHERNET, &owned(&ack))
            .unwrap();
        writer.finish().unwrap();
        let hosts: Vec<_> = session
            .hosts()
            .unwrap()
            .into_iter()
            // The Discover goes out from 0.0.0.0, which is a pseudo-host
            // row of its own (the UI never shows it); the device is the rest.
            .filter(|h| h.mac_address == ws_mac && h.ip_address.as_deref() != Some("0.0.0.0"))
            .collect();
        (session, hosts)
    };

    let (session, hosts) = hosts_with(LIVE_GRACE_SECS);
    assert_eq!(hosts.len(), 1, "one device: {hosts:?}");
    let ws = &hosts[0];
    assert_eq!(ws.ip_address.as_deref(), Some("192.168.10.77"));
    assert_eq!(ws.hostname.as_deref(), Some("ENG-WS-01"));
    let detail = session.host_detail(ws.id).unwrap();
    assert!(detail
        .evidence
        .iter()
        .any(|e| e.kind == "hostname" && e.value == "ENG-WS-01" && e.source_protocol == "dhcp"));

    // The control: attributing at once splits the device, which is the
    // reason the window exists.
    let (_, hosts) = hosts_with(0.0);
    assert_eq!(hosts.len(), 2, "split into MAC-only and IP: {hosts:?}");
    assert!(hosts.iter().any(|h| h.ip_address.is_none()));
}

/// The analysis is a whole-dataset pass; it runs when a batch brought
/// something it reads (a host, a flow, evidence, a Modbus event) and is
/// skipped for a batch that only added packets to known flows.
#[test]
fn analysis_runs_when_dirty_and_is_skipped_when_idle() {
    let session = Session::empty().unwrap();
    let mut writer = session.live_writer(LIVE_GRACE_SECS).unwrap();
    let web = |ts: f64| {
        (
            ts,
            tcp_packet(
                HMI_MAC,
                SCADA_MAC,
                HMI_IP,
                SCADA_IP,
                51000,
                8080,
                b"GET / HTTP/1.0",
            ),
        )
    };

    let first = writer
        .commit_batch(Linktype::ETHERNET, &owned(&[web(BASE_TS)]))
        .unwrap();
    assert!(first.checkpoint.changed());
    assert!(first.analysed, "the first batch derives roles: {first:?}");
    assert_eq!(first.counts.host_count, 2);

    let again = writer
        .commit_batch(Linktype::ETHERNET, &owned(&[web(BASE_TS + 1.0)]))
        .unwrap();
    assert!(!again.checkpoint.changed());
    assert!(!again.analysed, "nothing new to derive: {again:?}");
    assert_eq!(again.checkpoint.packets, 1);
    assert_eq!(again.counts.packet_count, 2);

    let result = writer.finish().unwrap();
    assert_reconciles(&result);
    let flows = session.connections().unwrap();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].packet_count, 2);
    assert_eq!(flows[0].app_protocol.as_deref(), Some("http"));
}
