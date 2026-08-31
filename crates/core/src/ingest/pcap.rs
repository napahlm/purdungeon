use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use rusqlite::params;

use crate::oui;
use crate::protocols::modbus;
use crate::store::{queries, schema};
use crate::types::{ImportResult, SkippedPackets};
use crate::CoreError;

/// The reader buffer must hold one complete block — a full-snaplen (65535 B)
/// packet plus block framing — or parsing aborts with a buffer-too-small
/// error. 1 MB also leaves room for jumbo frames.
const READER_BUFFER_SIZE: usize = 1 << 20;

/// Parse a capture into a fresh session, clearing any existing data first.
pub fn parse_pcap(
    path: &Path,
    conn: &mut rusqlite::Connection,
    progress: &AtomicU64,
) -> Result<ImportResult, CoreError> {
    ingest(path, conn, progress, false)
}

/// Parse a capture into the *existing* session, merging its hosts and flows
/// with what is already there. Flows seen in more than one file fuse into a
/// single conversation row rather than duplicating.
pub fn append_pcap(
    path: &Path,
    conn: &mut rusqlite::Connection,
    progress: &AtomicU64,
) -> Result<ImportResult, CoreError> {
    ingest(path, conn, progress, true)
}

/// Directional flow identity: (src ip, dst ip, src port, dst port, protocol).
type FlowKey = (u32, u32, u16, u16, u8);

/// IP protocol numbers used as the last element of a `FlowKey`. The DB stores
/// the display name; these keep the hot-path key free of strings.
fn protocol_code(protocol: &str) -> u8 {
    match protocol {
        "TCP" => 6,
        "UDP" => 17,
        "ICMP" => 1,
        _ => 0,
    }
}

/// Per-host aggregate accumulated in memory during a parse and flushed to the
/// DB once at the end, instead of issuing an UPDATE per packet.
struct HostAgg {
    id: i64,
    first_seen: f64,
    last_seen: f64,
}

/// Per-flow aggregate, same idea. `packets`/`bytes` count only this parse —
/// the flush adds them to whatever the row already holds, so appends compose.
struct FlowAgg {
    id: i64,
    packets: i64,
    bytes: i64,
    first_seen: f64,
    last_seen: f64,
    tagged: bool,
    late_tag: Option<&'static str>,
}

#[derive(Default)]
struct IngestState {
    hosts: HashMap<u32, HostAgg>,
    flows: HashMap<FlowKey, FlowAgg>,
    packet_count: usize,
    skipped: SkippedPackets,
    /// First link type other than Ethernet seen, for the error message when a
    /// capture yields nothing readable.
    unsupported_linktype: Option<String>,
    min_ts: f64,
    max_ts: f64,
}

impl IngestState {
    fn new() -> Self {
        Self {
            min_ts: f64::MAX,
            max_ts: f64::MIN,
            ..Self::default()
        }
    }
}

fn unsupported_linktype_error(linktype: &str) -> CoreError {
    CoreError::Parse(format!(
        "this capture uses link type {linktype}; purdungeon reads Ethernet \
         captures — convert it with Wireshark or editcap, or re-capture on an \
         Ethernet interface"
    ))
}

fn ingest(
    path: &Path,
    conn: &mut rusqlite::Connection,
    progress: &AtomicU64,
    append: bool,
) -> Result<ImportResult, CoreError> {
    // Stream from the file rather than reading it whole into memory, so several
    // large captures don't multiply RAM. Peek the magic to pick the reader,
    // then rewind.
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut magic = [0u8; 4];
    if reader.read_exact(&mut magic).is_err() {
        return Err(CoreError::Parse("file too small".into()));
    }
    reader.seek(SeekFrom::Start(0))?;
    let is_pcapng = u32::from_le_bytes(magic) == 0x0A0D_0D0A;

    // One transaction covers everything, the destructive prep included, so a
    // failed parse leaves the previous session exactly as it was — dropping
    // the transaction rolls back.
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)?;

    // A fresh import wipes prior data; an append keeps it and adds to it.
    if !append {
        schema::clear_data(&tx)?;
    }
    schema::drop_packet_indexes(&tx)?;

    let mut state = IngestState::new();
    // On append, seed the caches from existing rows so the same host or flow
    // resolves to its existing id instead of being inserted again.
    if append {
        preload_caches(&tx, &mut state)?;
    }

    if is_pcapng {
        parse_pcapng_data(reader, &tx, &mut state, progress)?;
    } else {
        parse_legacy_data(reader, &tx, &mut state, progress)?;
    }

    // A capture that only contained unreadable link types should say so
    // rather than silently import as empty.
    if state.packet_count == 0 {
        if let Some(linktype) = &state.unsupported_linktype {
            return Err(unsupported_linktype_error(linktype));
        }
    }

    flush_aggregates(&tx, &state)?;

    // Recreate indexes after all data is inserted
    schema::create_packet_indexes(&tx)?;
    tx.commit()?;

    if state.min_ts > state.max_ts {
        state.min_ts = 0.0;
        state.max_ts = 0.0;
    }

    Ok(ImportResult {
        host_count: state.hosts.len(),
        connection_count: state.flows.len(),
        packet_count: state.packet_count,
        skipped: state.skipped,
        time_range: (state.min_ts, state.max_ts),
    })
}

/// Rebuild the host and flow caches from the session so an append reuses
/// existing ids. Aggregates start empty — the flush only adds what this
/// parse contributes on top of the stored rows.
fn preload_caches(conn: &rusqlite::Connection, state: &mut IngestState) -> Result<(), CoreError> {
    let mut stmt = conn.prepare("SELECT ip_address, id FROM hosts")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (ip, id) = row?;
        let Ok(addr) = ip.parse::<Ipv4Addr>() else {
            continue;
        };
        state.hosts.insert(
            u32::from(addr),
            HostAgg {
                id,
                first_seen: f64::MAX,
                last_seen: f64::MIN,
            },
        );
    }

    let mut stmt = conn.prepare(
        "SELECT c.id, hs.ip_address, c.src_port, ds.ip_address, c.dst_port, c.protocol, c.app_protocol
         FROM connections c
         JOIN hosts hs ON hs.id = c.src_host_id
         JOIN hosts ds ON ds.id = c.dst_host_id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, u16>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, u16>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, Option<String>>(6)?,
        ))
    })?;
    for row in rows {
        let (id, src_ip, src_port, dst_ip, dst_port, protocol, app_protocol) = row?;
        let (Ok(src), Ok(dst)) = (src_ip.parse::<Ipv4Addr>(), dst_ip.parse::<Ipv4Addr>()) else {
            continue;
        };
        let key = (
            u32::from(src),
            u32::from(dst),
            src_port,
            dst_port,
            protocol_code(&protocol),
        );
        state.flows.insert(
            key,
            FlowAgg {
                id,
                packets: 0,
                bytes: 0,
                first_seen: f64::MAX,
                last_seen: f64::MIN,
                tagged: app_protocol.is_some(),
                late_tag: None,
            },
        );
    }
    Ok(())
}

/// Write the accumulated per-host and per-flow aggregates in one pass.
/// Untouched entries (preloaded on append but not seen in this file) are
/// skipped so an append only writes what changed.
fn flush_aggregates(conn: &rusqlite::Connection, state: &IngestState) -> Result<(), CoreError> {
    let mut host_stmt = conn.prepare_cached(
        "UPDATE hosts SET
            first_seen = MIN(first_seen, ?1),
            last_seen = MAX(last_seen, ?2)
         WHERE id = ?3",
    )?;
    for agg in state.hosts.values() {
        if agg.first_seen <= agg.last_seen {
            host_stmt.execute(params![agg.first_seen, agg.last_seen, agg.id])?;
        }
    }

    let mut flow_stmt = conn.prepare_cached(
        "UPDATE connections SET
            packet_count = packet_count + ?1,
            byte_count = byte_count + ?2,
            first_seen = MIN(first_seen, ?3),
            last_seen = MAX(last_seen, ?4)
         WHERE id = ?5",
    )?;
    let mut tag_stmt =
        conn.prepare_cached("UPDATE connections SET app_protocol = ?1 WHERE id = ?2")?;
    for agg in state.flows.values() {
        if agg.packets > 0 {
            flow_stmt.execute(params![
                agg.packets,
                agg.bytes,
                agg.first_seen,
                agg.last_seen,
                agg.id
            ])?;
        }
        if let Some(tag) = agg.late_tag {
            tag_stmt.execute(params![tag, agg.id])?;
        }
    }
    Ok(())
}

/// Per-interface decoding parameters from an Interface Description Block.
struct IfaceInfo {
    ts_offset: u64,
    resolution: u64,
    linktype: Linktype,
}

fn parse_pcapng_data<R: Read>(
    source: R,
    conn: &rusqlite::Connection,
    state: &mut IngestState,
    progress: &AtomicU64,
) -> Result<(), CoreError> {
    let mut reader = PcapNGReader::new(READER_BUFFER_SIZE, source)
        .map_err(|e| CoreError::Parse(format!("pcapng reader: {e}")))?;

    let mut if_info: Vec<IfaceInfo> = Vec::new();

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    // Interface ids are scoped to their section, so a new
                    // section (mergecap output, rotated captures) starts a
                    // fresh interface table.
                    PcapBlockOwned::NG(Block::SectionHeader(_)) => {
                        if_info.clear();
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                        if_info.push(IfaceInfo {
                            ts_offset: idb.if_tsoffset as u64,
                            resolution: idb.ts_resolution().unwrap_or(1_000_000),
                            linktype: idb.linktype,
                        });
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                        let info = if_info.get(epb.if_id as usize);
                        let linktype = info.map_or(Linktype::ETHERNET, |i| i.linktype);
                        if linktype == Linktype::ETHERNET {
                            let (ts_offset, resolution) =
                                info.map_or((0, 1_000_000), |i| (i.ts_offset, i.resolution));
                            let ts = epb.decode_ts_f64(ts_offset, resolution);
                            let orig_len = epb.origlen.max(epb.caplen);
                            // EPB data is padded to a 32-bit boundary; the
                            // real capture length is caplen.
                            let data = epb.data.get(..epb.caplen as usize).unwrap_or(epb.data);
                            process_packet(data, orig_len, ts, conn, state)?;
                        } else {
                            state.skipped.other += 1;
                            state
                                .unsupported_linktype
                                .get_or_insert_with(|| linktype.to_string());
                        }
                    }
                    // Simple Packet Blocks carry no timestamp; inventing one
                    // would poison first/last-seen, so they are skipped and
                    // counted instead.
                    PcapBlockOwned::NG(Block::SimplePacket(_)) => {
                        state.skipped.other += 1;
                    }
                    _ => {}
                }
                reader.consume(offset);
                progress.fetch_add(offset as u64, Ordering::Relaxed);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader
                    .refill()
                    .map_err(|e| CoreError::Parse(format!("refill: {e}")))?;
            }
            Err(e) => return Err(CoreError::Parse(format!("pcapng: {e}"))),
        }
    }
    Ok(())
}

fn parse_legacy_data<R: Read>(
    source: R,
    conn: &rusqlite::Connection,
    state: &mut IngestState,
    progress: &AtomicU64,
) -> Result<(), CoreError> {
    let mut reader = LegacyPcapReader::new(READER_BUFFER_SIZE, source)
        .map_err(|e| CoreError::Parse(format!("pcap reader: {e}")))?;

    // tcpdump's nanosecond variant (magic 0xa1b23c4d) stores nanoseconds in
    // the sub-second field; everything else stores microseconds.
    let mut ts_divisor = 1_000_000.0;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(header) => {
                        if header.network != Linktype::ETHERNET {
                            return Err(unsupported_linktype_error(&header.network.to_string()));
                        }
                        if header.is_nanosecond_precision() {
                            ts_divisor = 1_000_000_000.0;
                        }
                    }
                    PcapBlockOwned::Legacy(packet) => {
                        let ts = f64::from(packet.ts_sec) + f64::from(packet.ts_usec) / ts_divisor;
                        let orig_len = packet.origlen.max(packet.caplen);
                        process_packet(packet.data, orig_len, ts, conn, state)?;
                    }
                    PcapBlockOwned::NG(_) => {}
                }
                reader.consume(offset);
                progress.fetch_add(offset as u64, Ordering::Relaxed);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader
                    .refill()
                    .map_err(|e| CoreError::Parse(format!("refill: {e}")))?;
            }
            Err(e) => return Err(CoreError::Parse(format!("pcap: {e}"))),
        }
    }
    Ok(())
}

/// Decode one Ethernet frame and fold it into the session. `orig_len` is the
/// packet's length on the wire — captures taken with a snaplen truncate
/// `data`, and byte counts must reflect the wire, not the truncation.
fn process_packet(
    data: &[u8],
    orig_len: u32,
    timestamp: f64,
    conn: &rusqlite::Connection,
    state: &mut IngestState,
) -> Result<(), CoreError> {
    if data.len() < 14 {
        state.skipped.other += 1;
        return Ok(());
    }
    // Lax parsing tolerates snaplen truncation: headers still decode and the
    // payload is whatever was captured, instead of dropping the packet.
    let Ok(parsed) = etherparse::LaxSlicedPacket::from_ethernet(data) else {
        state.skipped.other += 1;
        return Ok(());
    };

    let (src_ip, dst_ip) = match &parsed.net {
        Some(etherparse::LaxNetSlice::Ipv4(ipv4)) => {
            let h = ipv4.header();
            (u32::from(h.source_addr()), u32::from(h.destination_addr()))
        }
        Some(etherparse::LaxNetSlice::Ipv6(_)) => {
            state.skipped.ipv6 += 1;
            return Ok(());
        }
        None => {
            // 0x0806 is the ARP ethertype — worth its own count because
            // ARP-only devices are invisible to an IPv4-based inventory.
            if data[12..14] == [0x08, 0x06] {
                state.skipped.arp += 1;
            } else {
                state.skipped.other += 1;
            }
            return Ok(());
        }
    };

    let (src_port, dst_port, protocol, payload): (u16, u16, &str, &[u8]) = match &parsed.transport {
        Some(etherparse::TransportSlice::Tcp(tcp)) => (
            tcp.source_port(),
            tcp.destination_port(),
            "TCP",
            tcp.payload(),
        ),
        Some(etherparse::TransportSlice::Udp(udp)) => (
            udp.source_port(),
            udp.destination_port(),
            "UDP",
            udp.payload(),
        ),
        Some(etherparse::TransportSlice::Icmpv4(_)) => (0, 0, "ICMP", &[] as &[u8]),
        _ => {
            state.skipped.other += 1;
            return Ok(());
        }
    };

    let is_modbus_request = dst_port == modbus::MODBUS_PORT;
    let modbus_frames = if protocol == "TCP" && modbus::is_modbus_tcp(src_port, dst_port, payload) {
        modbus::parse_frames(payload, is_modbus_request)
    } else {
        Vec::new()
    };
    let app_protocol = if modbus_frames.is_empty() {
        None
    } else {
        Some("modbus")
    };

    if timestamp > 0.0 {
        if timestamp < state.min_ts {
            state.min_ts = timestamp;
        }
        if timestamp > state.max_ts {
            state.max_ts = timestamp;
        }
    }

    // Hosts and flows accumulate in memory; only first sight touches the DB.
    let src_host_id = upsert_host(conn, state, src_ip, &data[6..12], timestamp)?;
    let dst_host_id = upsert_host(conn, state, dst_ip, &data[0..6], timestamp)?;

    let flow_key = (src_ip, dst_ip, src_port, dst_port, protocol_code(protocol));
    let conn_id = upsert_connection(
        conn,
        state,
        flow_key,
        (src_host_id, dst_host_id, src_port, dst_port),
        protocol,
        app_protocol,
        i64::from(orig_len),
        timestamp,
    )?;

    insert_modbus_events(
        conn,
        conn_id,
        src_host_id,
        dst_host_id,
        timestamp,
        is_modbus_request,
        &modbus_frames,
    )?;

    conn.prepare_cached(
        "INSERT INTO packets (connection_id, timestamp, length) VALUES (?1, ?2, ?3)",
    )?
    .execute(params![conn_id, timestamp, i64::from(orig_len)])?;

    state.packet_count += 1;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn upsert_connection(
    conn: &rusqlite::Connection,
    state: &mut IngestState,
    flow_key: FlowKey,
    (src_host_id, dst_host_id, src_port, dst_port): (i64, i64, u16, u16),
    protocol: &str,
    app_protocol: Option<&'static str>,
    packet_len: i64,
    timestamp: f64,
) -> Result<i64, CoreError> {
    if let Some(agg) = state.flows.get_mut(&flow_key) {
        agg.packets += 1;
        agg.bytes += packet_len;
        agg.first_seen = agg.first_seen.min(timestamp);
        agg.last_seen = agg.last_seen.max(timestamp);
        // A TCP flow opens with an empty SYN, so the app protocol is only
        // recognizable once payload arrives — tag the flow late.
        if !agg.tagged {
            if let Some(tag) = app_protocol {
                agg.late_tag = Some(tag);
                agg.tagged = true;
            }
        }
        return Ok(agg.id);
    }

    // Counts start at zero: the flush adds this parse's aggregate on top.
    conn.prepare_cached(
        "INSERT INTO connections
            (src_host_id, dst_host_id, src_port, dst_port, protocol, app_protocol,
             packet_count, byte_count, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, ?7, ?7)",
    )?
    .execute(params![
        src_host_id,
        dst_host_id,
        src_port,
        dst_port,
        protocol,
        app_protocol,
        timestamp,
    ])?;
    let id = conn.last_insert_rowid();
    state.flows.insert(
        flow_key,
        FlowAgg {
            id,
            packets: 1,
            bytes: packet_len,
            first_seen: timestamp,
            last_seen: timestamp,
            tagged: app_protocol.is_some(),
            late_tag: None,
        },
    );
    Ok(id)
}

fn insert_modbus_events(
    conn: &rusqlite::Connection,
    conn_id: i64,
    src_host_id: i64,
    dst_host_id: i64,
    timestamp: f64,
    is_request: bool,
    frames: &[modbus::ModbusFrame],
) -> Result<(), CoreError> {
    for frame in frames {
        conn.prepare_cached(
            "INSERT INTO modbus_events
                (connection_id, src_host_id, dst_host_id, timestamp, is_request,
                 transaction_id, unit_id, function_code, is_exception, exception_code,
                 start_address, quantity, is_write)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        )?
        .execute(params![
            conn_id,
            src_host_id,
            dst_host_id,
            timestamp,
            i64::from(is_request),
            i64::from(frame.transaction_id),
            i64::from(frame.unit_id),
            i64::from(frame.function_code),
            i64::from(frame.is_exception),
            frame.exception_code.map(i64::from),
            frame.start_address.map(i64::from),
            frame.quantity.map(i64::from),
            i64::from(frame.is_write),
        ])?;
    }
    Ok(())
}

/// Return the host's id, inserting it on first sight. The MAC string, vendor
/// lookup, and IP formatting only happen on that first sight — never in the
/// per-packet hot path.
fn upsert_host(
    conn: &rusqlite::Connection,
    state: &mut IngestState,
    ip: u32,
    mac_bytes: &[u8],
    timestamp: f64,
) -> Result<i64, CoreError> {
    if let Some(agg) = state.hosts.get_mut(&ip) {
        agg.first_seen = agg.first_seen.min(timestamp);
        agg.last_seen = agg.last_seen.max(timestamp);
        return Ok(agg.id);
    }
    let ip_str = Ipv4Addr::from(ip).to_string();
    let mac = format_mac(mac_bytes);
    let vendor = oui::lookup_vendor(mac_bytes);
    let id = queries::insert_host(conn, &mac, &ip_str, vendor, timestamp)?;
    state.hosts.insert(
        ip,
        HostAgg {
            id,
            first_seen: timestamp,
            last_seen: timestamp,
        },
    );
    Ok(id)
}

fn format_mac(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        let _ = write!(out, "{b:02x}");
    }
    out
}
