use rusqlite::{params, Connection};

use crate::commands::query::{Connection as NetConnection, Host, HostConnection, HostDetail, Packet};
use crate::CoilSnifferError;

// ── Bulk-import helper: upsert host and return correct id ────────────────────

pub fn upsert_host_returning_id(
    conn: &Connection,
    mac: &str,
    ip: &str,
    timestamp: f64,
) -> Result<i64, CoilSnifferError> {
    conn.execute(
        "INSERT INTO hosts (mac_address, ip_address, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?3)
         ON CONFLICT(ip_address) DO UPDATE SET
            last_seen = MAX(last_seen, ?3),
            mac_address = CASE WHEN mac_address = '' THEN ?1 ELSE mac_address END",
        params![mac, ip, timestamp],
    )?;
    // last_insert_rowid() returns 0 on conflict-update, so always SELECT
    let id: i64 = conn.query_row(
        "SELECT id FROM hosts WHERE ip_address = ?1",
        params![ip],
        |row| row.get(0),
    )?;
    Ok(id)
}

pub fn get_all_hosts(conn: &Connection) -> Result<Vec<Host>, CoilSnifferError> {
    let mut stmt = conn.prepare(
        "SELECT id, mac_address, ip_address, device_type, first_seen, last_seen FROM hosts",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(Host {
            id: row.get(0)?,
            mac_address: row.get(1)?,
            ip_address: row.get(2)?,
            device_type: row.get(3)?,
            first_seen: row.get(4)?,
            last_seen: row.get(5)?,
        })
    })?;
    let mut hosts = Vec::new();
    for row in rows {
        hosts.push(row?);
    }
    Ok(hosts)
}

pub fn get_all_connections(conn: &Connection) -> Result<Vec<NetConnection>, CoilSnifferError> {
    let mut stmt = conn.prepare(
        "SELECT id, src_host_id, dst_host_id, src_port, dst_port, protocol,
                app_protocol, packet_count, byte_count, first_seen, last_seen
         FROM connections",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(NetConnection {
            id: row.get(0)?,
            src_host_id: row.get(1)?,
            dst_host_id: row.get(2)?,
            src_port: row.get(3)?,
            dst_port: row.get(4)?,
            protocol: row.get(5)?,
            app_protocol: row.get(6)?,
            packet_count: row.get(7)?,
            byte_count: row.get(8)?,
            first_seen: row.get(9)?,
            last_seen: row.get(10)?,
        })
    })?;
    let mut connections = Vec::new();
    for row in rows {
        connections.push(row?);
    }
    Ok(connections)
}

pub fn get_time_range(conn: &Connection) -> Result<(f64, f64), CoilSnifferError> {
    let mut stmt = conn
        .prepare("SELECT COALESCE(MIN(timestamp), 0), COALESCE(MAX(timestamp), 0) FROM packets")?;
    let range = stmt.query_row([], |row| Ok((row.get(0)?, row.get(1)?)))?;
    Ok(range)
}

pub fn save_node_position(
    conn: &Connection,
    host_id: i64,
    x: f64,
    y: f64,
) -> Result<(), CoilSnifferError> {
    conn.execute(
        "INSERT INTO node_positions (host_id, x, y) VALUES (?1, ?2, ?3)
         ON CONFLICT(host_id) DO UPDATE SET x = ?2, y = ?3",
        params![host_id, x, y],
    )?;
    Ok(())
}

pub fn get_host_detail(conn: &Connection, host_id: i64) -> Result<HostDetail, CoilSnifferError> {
    let host = conn.query_row(
        "SELECT id, mac_address, ip_address, device_type, first_seen, last_seen
         FROM hosts WHERE id = ?1",
        params![host_id],
        |row| {
            Ok(Host {
                id: row.get(0)?,
                mac_address: row.get(1)?,
                ip_address: row.get(2)?,
                device_type: row.get(3)?,
                first_seen: row.get(4)?,
                last_seen: row.get(5)?,
            })
        },
    )?;

    let mut stmt = conn.prepare(
        "SELECT c.id, h.ip_address, h.mac_address,
                CASE WHEN c.src_host_id = ?1 THEN 'outbound' ELSE 'inbound' END,
                c.src_port, c.dst_port, c.protocol, c.app_protocol,
                c.packet_count, c.byte_count, c.first_seen, c.last_seen
         FROM connections c
         JOIN hosts h ON h.id = CASE WHEN c.src_host_id = ?1 THEN c.dst_host_id ELSE c.src_host_id END
         WHERE c.src_host_id = ?1 OR c.dst_host_id = ?1
         ORDER BY c.packet_count DESC",
    )?;
    let connections: Vec<HostConnection> = stmt
        .query_map(params![host_id], |row| {
            Ok(HostConnection {
                connection_id: row.get(0)?,
                peer_ip: row.get(1)?,
                peer_mac: row.get(2)?,
                direction: row.get(3)?,
                src_port: row.get(4)?,
                dst_port: row.get(5)?,
                protocol: row.get(6)?,
                app_protocol: row.get(7)?,
                packet_count: row.get(8)?,
                byte_count: row.get(9)?,
                first_seen: row.get(10)?,
                last_seen: row.get(11)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let (total_packets, total_bytes) = conn.query_row(
        "SELECT COALESCE(SUM(packet_count), 0), COALESCE(SUM(byte_count), 0)
         FROM connections WHERE src_host_id = ?1 OR dst_host_id = ?1",
        params![host_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    Ok(HostDetail {
        host,
        connections,
        total_packets,
        total_bytes,
    })
}

pub fn get_connection_packets(
    conn: &Connection,
    connection_id: i64,
    limit: i64,
) -> Result<Vec<Packet>, CoilSnifferError> {
    let mut stmt = conn.prepare(
        "SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length
         FROM packets
         WHERE connection_id = ?1
         ORDER BY timestamp ASC
         LIMIT ?2",
    )?;
    let packets: Vec<Packet> = stmt
        .query_map(params![connection_id, limit], |row| {
            Ok(Packet {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                src_ip: row.get(2)?,
                dst_ip: row.get(3)?,
                src_port: row.get(4)?,
                dst_port: row.get(5)?,
                protocol: row.get(6)?,
                length: row.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(packets)
}
