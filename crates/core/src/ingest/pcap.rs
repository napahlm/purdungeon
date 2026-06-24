use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use rusqlite::params;

use crate::types::ImportResult;
use crate::store::{queries, schema};
use crate::oui;
use crate::protocols::modbus;
use crate::CoreError;

/// Parse a capture into a fresh session, clearing any existing data first.
pub fn parse_pcap(
    path: &Path,
    conn: &rusqlite::Connection,
    progress: &AtomicU64,
) -> Result<ImportResult, CoreError> {
    ingest(path, conn, progress, false)
}

/// Parse a capture into the *existing* session, merging its hosts and flows
/// with what is already there. Flows seen in more than one file fuse into a
/// single conversation row rather than duplicating.
pub fn append_pcap(
    path: &Path,
    conn: &rusqlite::Connection,
    progress: &AtomicU64,
) -> Result<ImportResult, CoreError> {
    ingest(path, conn, progress, true)
}

fn ingest(
    path: &Path,
    conn: &rusqlite::Connection,
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

    // A fresh import wipes prior data; an append keeps it and adds to it.
    if !append {
        schema::clear_data(conn)?;
    }
    schema::drop_packet_indexes(conn)?;

    // Single transaction for the entire ingest
    conn.execute_batch("BEGIN EXCLUSIVE")?;

    let mut host_map: HashMap<String, i64> = HashMap::new();
    let mut conn_map: HashMap<String, (i64, bool)> = HashMap::new();
    // On append, seed the caches from existing rows so the same host or flow
    // resolves to its existing id instead of being inserted again.
    if append {
        if let Err(e) = preload_caches(conn, &mut host_map, &mut conn_map) {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(e);
        }
    }
    let mut packet_count: usize = 0;
    let mut min_ts: f64 = f64::MAX;
    let mut max_ts: f64 = f64::MIN;

    let result = if is_pcapng {
        parse_pcapng_data(
            reader, conn, &mut host_map, &mut conn_map,
            &mut packet_count, &mut min_ts, &mut max_ts, progress,
        )
    } else {
        parse_legacy_data(
            reader, conn, &mut host_map, &mut conn_map,
            &mut packet_count, &mut min_ts, &mut max_ts, progress,
        )
    };

    if let Err(e) = result {
        let _ = conn.execute_batch("ROLLBACK");
        return Err(e);
    }

    // Recreate indexes after all data is inserted
    schema::create_packet_indexes(conn)?;

    conn.execute_batch("COMMIT")?;

    if packet_count == 0 {
        min_ts = 0.0;
        max_ts = 0.0;
    }

    Ok(ImportResult {
        host_count: host_map.len(),
        connection_count: conn_map.len(),
        packet_count,
        time_range: (min_ts, max_ts),
    })
}

/// Rebuild the host and connection caches from the session so an append reuses
/// existing ids. `host_map` keys on IP; `conn_map` keys on the same flow key
/// the parser builds (`src:port-dst:port-proto`).
fn preload_caches(
    conn: &rusqlite::Connection,
    host_map: &mut HashMap<String, i64>,
    conn_map: &mut HashMap<String, (i64, bool)>,
) -> Result<(), CoreError> {
    let mut stmt = conn.prepare("SELECT ip_address, id FROM hosts")?;
    let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?;
    for row in rows {
        let (ip, id) = row?;
        host_map.insert(ip, id);
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
        let flow_key = format!("{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}");
        conn_map.insert(flow_key, (id, app_protocol.is_some()));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn parse_pcapng_data<R: Read>(
    source: R,
    conn: &rusqlite::Connection,
    host_map: &mut HashMap<String, i64>,
    conn_map: &mut HashMap<String, (i64, bool)>,
    packet_count: &mut usize,
    min_ts: &mut f64,
    max_ts: &mut f64,
    progress: &AtomicU64,
) -> Result<(), CoreError> {
    let mut reader = PcapNGReader::new(65536, source)
        .map_err(|e| CoreError::Parse(format!("pcapng reader: {e}")))?;

    let mut if_info: Vec<(u64, u64)> = Vec::new();

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                        let resolution = idb.ts_resolution().unwrap_or(1_000_000);
                        let ts_offset = idb.if_tsoffset as u64;
                        if_info.push((ts_offset, resolution));
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                        let (ts_offset, resolution) = if_info
                            .get(epb.if_id as usize)
                            .copied()
                            .unwrap_or((0, 1_000_000));
                        let ts = epb.decode_ts_f64(ts_offset, resolution);
                        process_packet(
                            epb.data, ts, conn, host_map, conn_map,
                            packet_count, min_ts, max_ts,
                        )?;
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(spb)) => {
                        process_packet(
                            spb.data, 0.0, conn, host_map, conn_map,
                            packet_count, min_ts, max_ts,
                        )?;
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

#[allow(clippy::too_many_arguments)]
fn parse_legacy_data<R: Read>(
    source: R,
    conn: &rusqlite::Connection,
    host_map: &mut HashMap<String, i64>,
    conn_map: &mut HashMap<String, (i64, bool)>,
    packet_count: &mut usize,
    min_ts: &mut f64,
    max_ts: &mut f64,
    progress: &AtomicU64,
) -> Result<(), CoreError> {
    let mut reader = LegacyPcapReader::new(65536, source)
        .map_err(|e| CoreError::Parse(format!("pcap reader: {e}")))?;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                if let PcapBlockOwned::Legacy(packet) = block {
                    let ts = f64::from(packet.ts_sec) + f64::from(packet.ts_usec) / 1_000_000.0;
                    process_packet(
                        packet.data, ts, conn, host_map, conn_map,
                        packet_count, min_ts, max_ts,
                    )?;
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

#[allow(clippy::too_many_arguments)]
fn process_packet(
    data: &[u8],
    timestamp: f64,
    conn: &rusqlite::Connection,
    host_map: &mut HashMap<String, i64>,
    conn_map: &mut HashMap<String, (i64, bool)>,
    packet_count: &mut usize,
    min_ts: &mut f64,
    max_ts: &mut f64,
) -> Result<(), CoreError> {
    let Ok(parsed) = etherparse::SlicedPacket::from_ethernet(data) else {
        return Ok(());
    };

    let (src_mac, dst_mac) = if data.len() >= 14 {
        (format_mac(&data[6..12]), format_mac(&data[0..6]))
    } else {
        return Ok(());
    };

    let (src_ip, dst_ip) = match &parsed.net {
        Some(etherparse::NetSlice::Ipv4(ipv4)) => {
            let h = ipv4.header();
            (
                format!("{}", h.source_addr()),
                format!("{}", h.destination_addr()),
            )
        }
        _ => return Ok(()),
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
        _ => return Ok(()),
    };

    let modbus_frames = if protocol == "TCP" && modbus::is_modbus_tcp(src_port, dst_port, payload) {
        modbus::parse_frames(payload, dst_port == modbus::MODBUS_PORT)
    } else {
        Vec::new()
    };
    let app_protocol = if modbus_frames.is_empty() {
        None
    } else {
        Some("modbus".to_string())
    };

    if timestamp > 0.0 {
        if timestamp < *min_ts {
            *min_ts = timestamp;
        }
        if timestamp > *max_ts {
            *max_ts = timestamp;
        }
    }

    // Upsert hosts — in-memory cache avoids repeated DB calls
    let src_host_id = upsert_host(conn, host_map, &src_ip, &src_mac, timestamp)?;
    let dst_host_id = upsert_host(conn, host_map, &dst_ip, &dst_mac, timestamp)?;

    // Upsert connection — in-memory cache for the common case
    let flow_key = format!("{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}");
    let conn_id = upsert_connection(
        conn,
        conn_map,
        flow_key,
        (src_host_id, dst_host_id, src_port, dst_port),
        protocol,
        app_protocol.as_deref(),
        data.len() as i64,
        timestamp,
    )?;

    insert_modbus_events(
        conn,
        conn_id,
        src_host_id,
        dst_host_id,
        timestamp,
        dst_port == modbus::MODBUS_PORT,
        &modbus_frames,
    )?;

    // Insert packet using cached prepared statement
    conn.prepare_cached(
        "INSERT INTO packets (connection_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?
    .execute(params![conn_id, timestamp, &src_ip, &dst_ip, src_port, dst_port, protocol, data.len() as i64])?;

    *packet_count += 1;
    Ok(())
}

fn upsert_connection(
    conn: &rusqlite::Connection,
    conn_map: &mut HashMap<String, (i64, bool)>,
    flow_key: String,
    (src_host_id, dst_host_id, src_port, dst_port): (i64, i64, u16, u16),
    protocol: &str,
    app_protocol: Option<&str>,
    packet_len: i64,
    timestamp: f64,
) -> Result<i64, CoreError> {
    if let Some(entry) = conn_map.get_mut(&flow_key) {
        let (id, tagged) = *entry;
        conn.prepare_cached(
            "UPDATE connections SET
                packet_count = packet_count + 1,
                byte_count = byte_count + ?1,
                first_seen = MIN(first_seen, ?2),
                last_seen = MAX(last_seen, ?2)
             WHERE id = ?3",
        )?
        .execute(params![packet_len, timestamp, id])?;
        // A TCP flow opens with an empty SYN, so the app protocol is only
        // recognizable once payload arrives — tag the flow late.
        if !tagged && app_protocol.is_some() {
            conn.prepare_cached("UPDATE connections SET app_protocol = ?1 WHERE id = ?2")?
                .execute(params![app_protocol, id])?;
            entry.1 = true;
        }
        return Ok(id);
    }

    conn.prepare_cached(
        "INSERT INTO connections
            (src_host_id, dst_host_id, src_port, dst_port, protocol, app_protocol,
             packet_count, byte_count, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8, ?8)",
    )?
    .execute(params![
        src_host_id, dst_host_id, src_port, dst_port,
        protocol, app_protocol,
        packet_len, timestamp,
    ])?;
    let id = conn.last_insert_rowid();
    conn_map.insert(flow_key, (id, app_protocol.is_some()));
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

fn upsert_host(
    conn: &rusqlite::Connection,
    host_map: &mut HashMap<String, i64>,
    ip: &str,
    mac: &str,
    timestamp: f64,
) -> Result<i64, CoreError> {
    if let Some(&id) = host_map.get(ip) {
        conn.prepare_cached(
            "UPDATE hosts SET
                first_seen = MIN(first_seen, ?1),
                last_seen = MAX(last_seen, ?1)
             WHERE id = ?2",
        )?
        .execute(params![timestamp, id])?;
        return Ok(id);
    }
    let id = queries::upsert_host_returning_id(conn, mac, ip, timestamp)?;
    if let Some(vendor) = oui::lookup_vendor(mac) {
        conn.prepare_cached("UPDATE hosts SET vendor = ?1 WHERE id = ?2 AND vendor IS NULL")?
            .execute(params![vendor, id])?;
    }
    host_map.insert(ip.to_string(), id);
    Ok(id)
}

fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
