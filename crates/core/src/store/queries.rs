use rusqlite::{params, Connection};

use crate::types::{Connection as NetConnection, Host, HostConnection, HostDetail, Packet};
use crate::CoreError;

// ── Bulk-import helper: upsert host and return correct id ────────────────────

pub fn upsert_host_returning_id(
    conn: &Connection,
    mac: &str,
    ip: &str,
    timestamp: f64,
) -> Result<i64, CoreError> {
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

const HOST_COLUMNS: &str = "id, mac_address, ip_address, hostname, vendor, role,
    role_confidence, role_evidence, purdue_level, role_override, level_override,
    protocols, is_external, first_seen, last_seen";

fn host_from_row(row: &rusqlite::Row) -> Result<Host, rusqlite::Error> {
    Ok(Host {
        id: row.get(0)?,
        mac_address: row.get(1)?,
        ip_address: row.get(2)?,
        hostname: row.get(3)?,
        vendor: row.get(4)?,
        role: row.get(5)?,
        role_confidence: row.get(6)?,
        role_evidence: row.get(7)?,
        purdue_level: row.get(8)?,
        role_override: row.get(9)?,
        level_override: row.get(10)?,
        protocols: row.get(11)?,
        is_external: row.get::<_, i64>(12)? != 0,
        first_seen: row.get(13)?,
        last_seen: row.get(14)?,
    })
}

pub fn get_all_hosts(conn: &Connection) -> Result<Vec<Host>, CoreError> {
    let mut stmt = conn.prepare(&format!("SELECT {HOST_COLUMNS} FROM hosts"))?;
    let rows = stmt.query_map([], host_from_row)?;
    let mut hosts = Vec::new();
    for row in rows {
        hosts.push(row?);
    }
    Ok(hosts)
}

pub fn get_findings(conn: &Connection) -> Result<Vec<crate::types::Finding>, CoreError> {
    let mut stmt = conn.prepare(
        "SELECT id, kind, severity, title, detail, host_ids, connection_ids
         FROM findings
         ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, id",
    )?;
    let parse_ids = |s: String| -> Vec<i64> {
        s.split(',').filter_map(|p| p.parse().ok()).collect()
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
        ))
    })?;
    let mut findings = Vec::new();
    for row in rows {
        let (id, kind, severity, title, detail, host_ids, connection_ids) = row?;
        findings.push(crate::types::Finding {
            id,
            kind,
            severity,
            title,
            detail,
            host_ids: parse_ids(host_ids),
            connection_ids: parse_ids(connection_ids),
        });
    }
    Ok(findings)
}

pub fn set_role_override(
    conn: &Connection,
    host_id: i64,
    role: Option<&str>,
) -> Result<(), CoreError> {
    conn.execute(
        "UPDATE hosts SET role_override = ?1 WHERE id = ?2",
        params![role, host_id],
    )?;
    Ok(())
}

pub fn set_level_override(
    conn: &Connection,
    host_id: i64,
    level: Option<i64>,
) -> Result<(), CoreError> {
    conn.execute(
        "UPDATE hosts SET level_override = ?1 WHERE id = ?2",
        params![level, host_id],
    )?;
    Ok(())
}

pub fn get_all_connections(conn: &Connection) -> Result<Vec<NetConnection>, CoreError> {
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

pub fn get_time_range(conn: &Connection) -> Result<(f64, f64), CoreError> {
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
) -> Result<(), CoreError> {
    conn.execute(
        "INSERT INTO node_positions (host_id, x, y) VALUES (?1, ?2, ?3)
         ON CONFLICT(host_id) DO UPDATE SET x = ?2, y = ?3",
        params![host_id, x, y],
    )?;
    Ok(())
}

pub fn get_node_positions(conn: &Connection) -> Result<Vec<(i64, f64, f64)>, CoreError> {
    let mut stmt = conn.prepare("SELECT host_id, x, y FROM node_positions")?;
    let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
    let mut positions = Vec::new();
    for row in rows {
        positions.push(row?);
    }
    Ok(positions)
}

pub fn get_host_detail(conn: &Connection, host_id: i64) -> Result<HostDetail, CoreError> {
    let host = conn.query_row(
        &format!("SELECT {HOST_COLUMNS} FROM hosts WHERE id = ?1"),
        params![host_id],
        host_from_row,
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
) -> Result<Vec<Packet>, CoreError> {
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
