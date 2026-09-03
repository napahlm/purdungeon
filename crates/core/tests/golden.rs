//! Golden-file tests: import a fixed capture, summarise what the core made of
//! it, and compare against a committed JSON snapshot. A change in the
//! snapshot is a change in behaviour that a reviewer must see.
//!
//! Regenerate with `UPDATE_GOLDEN=1 cargo test -p purdungeon-core --test golden`
//! (`just golden-update`), then commit the diff under `tests/golden/`.

mod common;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use purdungeon_core::types::{ImportResult, LinkLayerCounts, SkippedPackets};
use purdungeon_core::Session;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn tests_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")
}

// ── Summary ─────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct Summary {
    fixture: String,
    frames_read: usize,
    packet_count: usize,
    decoded: LinkLayerCounts,
    skipped: SkippedPackets,
    host_count: usize,
    connection_count: usize,
    time_range: (f64, f64),
    /// Sorted by address (IPv4 before IPv6).
    hosts: Vec<HostLine>,
    /// IP protocol name → number of conversations.
    transports: BTreeMap<String, usize>,
    /// Application protocol (or "unnamed") → number of conversations.
    app_protocols: BTreeMap<String, usize>,
    /// Distinct VLAN ids seen on conversations.
    vlans: Vec<i64>,
}

#[derive(Serialize)]
struct HostLine {
    ip: String,
    mac: String,
    vendor: Option<String>,
    link_protocols: String,
}

fn summarize(fixture: &str, session: &Session, result: &ImportResult) -> Summary {
    let mut hosts: Vec<(IpAddr, HostLine)> = session
        .hosts()
        .unwrap()
        .into_iter()
        .map(|h| {
            let addr: IpAddr = h
                .ip_address
                .parse()
                .unwrap_or_else(|_| panic!("stored address is not an IP: {}", h.ip_address));
            (
                addr,
                HostLine {
                    ip: h.ip_address,
                    mac: h.mac_address,
                    vendor: h.vendor,
                    link_protocols: h.link_protocols,
                },
            )
        })
        .collect();
    hosts.sort_by_key(|(addr, _)| *addr);

    let connections = session.connections().unwrap();
    let mut transports = BTreeMap::new();
    let mut app_protocols = BTreeMap::new();
    let mut vlans: Vec<i64> = Vec::new();
    for c in &connections {
        *transports.entry(c.protocol.clone()).or_insert(0) += 1;
        *app_protocols
            .entry(c.app_protocol.clone().unwrap_or_else(|| "unnamed".into()))
            .or_insert(0) += 1;
        if let Some(v) = c.vlan_id {
            if !vlans.contains(&v) {
                vlans.push(v);
            }
        }
    }
    vlans.sort_unstable();

    Summary {
        fixture: fixture.to_string(),
        frames_read: result.frames_read,
        packet_count: result.packet_count,
        decoded: result.decoded,
        skipped: result.skipped,
        host_count: result.host_count,
        connection_count: result.connection_count,
        time_range: result.time_range,
        hosts: hosts.into_iter().map(|(_, line)| line).collect(),
        transports,
        app_protocols,
        vlans,
    }
}

// ── Comparison ──────────────────────────────────────────────────────────────

fn check_golden(name: &str, summary: &Summary) {
    let path = tests_dir().join("golden").join(format!("{name}.json"));
    let actual = serde_json::to_string_pretty(summary).unwrap() + "\n";
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, &actual).unwrap();
        eprintln!("updated {}", path.display());
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| {
            panic!(
                "missing golden {}; run `just golden-update`",
                path.display()
            )
        })
        .replace("\r\n", "\n");
    if expected != actual {
        let mut report = String::new();
        for (i, (e, a)) in expected.lines().zip(actual.lines()).enumerate() {
            if e != a {
                let _ = writeln!(report, "line {}:\n  expected: {e}\n  actual:   {a}", i + 1);
                break;
            }
        }
        if report.is_empty() {
            report.push_str("the files differ in length\n");
        }
        panic!(
            "golden {name} differs:\n{report}If the change is intended, run `just golden-update` and commit tests/golden/{name}.json"
        );
    }
}

fn sha256_file(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    Sha256::digest(&bytes)
        .iter()
        .fold(String::new(), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        })
}

fn assert_hash(path: &Path, expected: &str) {
    let actual = sha256_file(path);
    assert_eq!(
        actual,
        expected,
        "{} does not match its manifest sha256 — was it modified or line-ending converted?",
        path.display()
    );
}

fn import_and_check(name: &str, path: &Path) {
    let (session, result) =
        common::import_file(path).unwrap_or_else(|e| panic!("import {}: {e}", path.display()));
    common::assert_reconciles(&result);
    check_golden(name, &summarize(name, &session, &result));
}

// ── Fixtures (committed) ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct FixtureManifest {
    fixture: Vec<FixtureEntry>,
}

#[derive(Deserialize)]
struct FixtureEntry {
    name: String,
    file: String,
    sha256: String,
}

fn fixture_manifest() -> FixtureManifest {
    let path = tests_dir().join("fixtures").join("MANIFEST.toml");
    toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn run_fixture(name: &str) {
    let manifest = fixture_manifest();
    let entry = manifest
        .fixture
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("fixture {name} is not in MANIFEST.toml"));
    let path = tests_dir().join("fixtures").join(&entry.file);
    assert_hash(&path, &entry.sha256);
    import_and_check(name, &path);
}

#[test]
fn golden_icsnpp_modbus() {
    run_fixture("icsnpp-modbus");
}

#[test]
fn golden_icsnpp_s7comm_plus() {
    run_fixture("icsnpp-s7comm-plus");
}

#[test]
fn golden_icsnpp_profinet_mixed() {
    run_fixture("icsnpp-profinet-mixed");
}

#[test]
fn golden_synthetic_mixed() {
    let bytes = common::write_pcap(&common::mixed_capture());
    let (session, result) = common::import_bytes("golden-mixed", &bytes).unwrap();
    common::assert_reconciles(&result);
    check_golden(
        "synthetic-mixed",
        &summarize("synthetic-mixed", &session, &result),
    );
}

// ── Corpus (fetch-only) ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CorpusManifest {
    capture: Vec<CorpusEntry>,
}

#[derive(Deserialize)]
struct CorpusEntry {
    name: String,
    file: String,
    sha256: String,
}

/// Large public captures are not committed; `just fetch-corpus` downloads
/// them. Ignored by default because importing hundreds of megabytes in a
/// debug build takes minutes — run with `just golden-corpus`.
#[test]
#[ignore = "needs the fetched corpus; run `just golden-corpus`"]
fn golden_corpus() {
    let dir = tests_dir().join("corpus");
    let manifest: CorpusManifest =
        toml::from_str(&std::fs::read_to_string(dir.join("manifest.toml")).unwrap()).unwrap();
    let mut ran = 0;
    for entry in &manifest.capture {
        let path = dir.join(&entry.file);
        if !path.exists() {
            eprintln!(
                "skipping {}: not fetched (run `just fetch-corpus`)",
                entry.name
            );
            continue;
        }
        assert_hash(&path, &entry.sha256);
        import_and_check(&format!("corpus-{}", entry.name), &path);
        ran += 1;
    }
    assert!(
        ran > 0,
        "no corpus captures were present; run `just fetch-corpus`"
    );
}
