//! Findings: the short "what to look at" list a consultant scans first.
//! Generated once per import, after roles and levels are inferred.

use std::collections::HashMap;

use rusqlite::{params, Connection};

use crate::analysis::ports;
use crate::protocols::modbus::function_name;
use crate::CoreError;

struct HostInfo {
    ip: String,
    role: String,
    level: Option<i64>,
    is_external: bool,
}

struct FindingRow {
    kind: &'static str,
    severity: &'static str, // "high" | "medium" | "info"
    title: String,
    detail: String,
    host_ids: Vec<i64>,
    connection_ids: Vec<i64>,
}

pub fn generate(conn: &Connection) -> Result<(), CoreError> {
    let hosts = load_hosts(conn)?;
    let mut findings: Vec<FindingRow> = Vec::new();

    cross_zone_conduits(conn, &hosts, &mut findings)?;
    writes_to_controllers(conn, &hosts, &mut findings)?;
    external_on_ot(conn, &hosts, &mut findings)?;
    scan_like_behavior(conn, &hosts, &mut findings)?;
    rejected_requests(conn, &hosts, &mut findings)?;
    cleartext_control(conn, &mut findings)?;

    let mut insert = conn.prepare(
        "INSERT INTO findings (kind, severity, title, detail, host_ids, connection_ids)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for f in findings {
        insert.execute(params![
            f.kind,
            f.severity,
            f.title,
            f.detail,
            join_ids(&f.host_ids),
            join_ids(&f.connection_ids),
        ])?;
    }
    Ok(())
}

fn join_ids(ids: &[i64]) -> String {
    ids.iter().map(i64::to_string).collect::<Vec<_>>().join(",")
}

fn load_hosts(conn: &Connection) -> Result<HashMap<i64, HostInfo>, CoreError> {
    let mut stmt =
        conn.prepare("SELECT id, ip_address, role, purdue_level, is_external FROM hosts")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            HostInfo {
                ip: row.get(1)?,
                role: row.get(2)?,
                level: row.get(3)?,
                is_external: row.get::<_, i64>(4)? != 0,
            },
        ))
    })?;
    let mut map = HashMap::new();
    for row in rows {
        let (id, info) = row?;
        map.insert(id, info);
    }
    Ok(map)
}

fn describe(info: &HostInfo) -> String {
    match info.level {
        Some(level) => format!("{} ({}, L{level})", info.ip, info.role),
        None => format!("{} ({})", info.ip, info.role),
    }
}

#[derive(Default)]
struct PairFlow {
    packets: i64,
    protocols: Vec<String>,
    connection_ids: Vec<i64>,
}

/// Conversations grouped by unordered host pair.
fn pair_flows(conn: &Connection) -> Result<HashMap<(i64, i64), PairFlow>, CoreError> {
    let mut stmt = conn.prepare(
        "SELECT id, src_host_id, dst_host_id, packet_count, COALESCE(app_protocol, LOWER(protocol))
         FROM connections",
    )?;
    let rows: Vec<(i64, i64, i64, i64, String)> = stmt
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut pairs: HashMap<(i64, i64), PairFlow> = HashMap::new();
    for (id, src, dst, packets, proto) in rows {
        let key = if src < dst { (src, dst) } else { (dst, src) };
        let entry = pairs.entry(key).or_default();
        entry.packets += packets;
        if !entry.protocols.contains(&proto) {
            entry.protocols.push(proto);
        }
        entry.connection_ids.push(id);
    }
    Ok(pairs)
}

fn cross_zone_conduits(
    conn: &Connection,
    hosts: &HashMap<i64, HostInfo>,
    findings: &mut Vec<FindingRow>,
) -> Result<(), CoreError> {
    for ((a, b), flow) in pair_flows(conn)? {
        let (Some(ha), Some(hb)) = (hosts.get(&a), hosts.get(&b)) else { continue };
        let (Some(la), Some(lb)) = (ha.level, hb.level) else { continue };
        if la == lb {
            continue;
        }
        let (lo, hi) = if la < lb { (la, lb) } else { (lb, la) };
        let skips = hi - lo >= 2;
        let crosses_boundary = lo <= 2 && hi >= 3;
        if !skips && !crosses_boundary {
            continue;
        }
        let severity = if skips { "high" } else { "medium" };
        let title = if skips {
            format!("Level {hi} host talks directly to a level {lo} device")
        } else {
            "Conversation crosses the control/IT boundary".to_string()
        };
        findings.push(FindingRow {
            kind: "cross-zone",
            severity,
            title,
            detail: format!(
                "{} ↔ {} — {}, {} packets",
                describe(ha),
                describe(hb),
                flow.protocols.join(", "),
                flow.packets
            ),
            host_ids: vec![a, b],
            connection_ids: flow.connection_ids,
        });
    }
    Ok(())
}

fn writes_to_controllers(
    conn: &Connection,
    hosts: &HashMap<i64, HostInfo>,
    findings: &mut Vec<FindingRow>,
) -> Result<(), CoreError> {
    let mut stmt = conn.prepare(
        "SELECT src_host_id, dst_host_id, COUNT(*),
                GROUP_CONCAT(DISTINCT function_code), GROUP_CONCAT(DISTINCT connection_id)
         FROM modbus_events
         WHERE is_request = 1 AND is_write = 1
         GROUP BY src_host_id, dst_host_id",
    )?;
    let rows: Vec<(i64, i64, i64, String, String)> = stmt
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    for (writer_id, target_id, writes, codes, conn_ids) in rows {
        let (Some(writer), Some(target)) = (hosts.get(&writer_id), hosts.get(&target_id)) else {
            continue;
        };
        // Writing is what masters and engineering stations do; everyone else
        // writing to a controller deserves a closer look.
        let expected = matches!(writer.role.as_str(), "scada" | "engineering-workstation" | "hmi");
        let severity = if writer.is_external {
            "high"
        } else if expected {
            "info"
        } else {
            "medium"
        };
        let fn_names: Vec<&str> = codes
            .split(',')
            .filter_map(|c| c.parse::<u8>().ok())
            .map(function_name)
            .collect();
        findings.push(FindingRow {
            kind: "write",
            severity,
            title: format!(
                "{} writes to {}",
                if expected { &writer.role } else { "Unexpected source" },
                target.ip
            ),
            detail: format!(
                "{} sent {} write request{} to {} — {}",
                describe(writer),
                writes,
                if writes == 1 { "" } else { "s" },
                describe(target),
                fn_names.join(", ")
            ),
            host_ids: vec![writer_id, target_id],
            connection_ids: conn_ids.split(',').filter_map(|s| s.parse().ok()).collect(),
        });
    }
    Ok(())
}

fn external_on_ot(
    conn: &Connection,
    hosts: &HashMap<i64, HostInfo>,
    findings: &mut Vec<FindingRow>,
) -> Result<(), CoreError> {
    for ((a, b), flow) in pair_flows(conn)? {
        let (Some(ha), Some(hb)) = (hosts.get(&a), hosts.get(&b)) else { continue };
        let (ext, ot, ext_id, ot_id) = if ha.is_external {
            (ha, hb, a, b)
        } else if hb.is_external {
            (hb, ha, b, a)
        } else {
            continue;
        };
        let Some(ot_level) = ot.level else { continue };
        if ot_level > 2 || ot.is_external {
            continue;
        }
        findings.push(FindingRow {
            kind: "external",
            severity: if ot_level <= 1 { "high" } else { "medium" },
            title: format!("External address reaches a level {ot_level} device"),
            detail: format!(
                "{} ↔ {} — {}, {} packets",
                describe(ext),
                describe(ot),
                flow.protocols.join(", "),
                flow.packets
            ),
            host_ids: vec![ext_id, ot_id],
            connection_ids: flow.connection_ids,
        });
    }
    Ok(())
}

fn scan_like_behavior(
    conn: &Connection,
    hosts: &HashMap<i64, HostInfo>,
    findings: &mut Vec<FindingRow>,
) -> Result<(), CoreError> {
    // Many distinct ports on one target host smells like a port scan
    let mut stmt = conn.prepare(
        "SELECT src_host_id, dst_host_id, COUNT(DISTINCT dst_port), GROUP_CONCAT(DISTINCT id)
         FROM connections
         GROUP BY src_host_id, dst_host_id
         HAVING COUNT(DISTINCT dst_port) >= 10",
    )?;
    let rows: Vec<(i64, i64, i64, String)> = stmt
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (src, dst, port_count, conn_ids) in rows {
        let (Some(hs), Some(hd)) = (hosts.get(&src), hosts.get(&dst)) else { continue };
        findings.push(FindingRow {
            kind: "scan",
            severity: "high",
            title: format!("{} probes {} ports on {}", hs.ip, port_count, hd.ip),
            detail: format!(
                "{} contacted {} distinct ports on {} — looks like a port scan",
                describe(hs),
                port_count,
                describe(hd)
            ),
            host_ids: vec![src, dst],
            connection_ids: conn_ids.split(',').filter_map(|s| s.parse().ok()).collect(),
        });
    }

    // Touching very many peers is worth a look too
    let mut stmt = conn.prepare(
        "SELECT src_host_id, COUNT(DISTINCT dst_host_id) FROM connections
         GROUP BY src_host_id HAVING COUNT(DISTINCT dst_host_id) >= 20",
    )?;
    let rows: Vec<(i64, i64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    for (src, peer_count) in rows {
        let Some(hs) = hosts.get(&src) else { continue };
        // Pollers legitimately talk to many devices
        if hs.role == "scada" {
            continue;
        }
        findings.push(FindingRow {
            kind: "scan",
            severity: "medium",
            title: format!("{} contacts {peer_count} different hosts", hs.ip),
            detail: format!(
                "{} initiated conversations with {peer_count} hosts — wide reach for a {}",
                describe(hs),
                hs.role
            ),
            host_ids: vec![src],
            connection_ids: Vec::new(),
        });
    }
    Ok(())
}

fn rejected_requests(
    conn: &Connection,
    hosts: &HashMap<i64, HostInfo>,
    findings: &mut Vec<FindingRow>,
) -> Result<(), CoreError> {
    let mut stmt = conn.prepare(
        "SELECT src_host_id, SUM(is_exception), COUNT(*)
         FROM modbus_events WHERE is_request = 0
         GROUP BY src_host_id
         HAVING SUM(is_exception) >= 5",
    )?;
    let rows: Vec<(i64, i64, i64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    for (host_id, exceptions, responses) in rows {
        let Some(h) = hosts.get(&host_id) else { continue };
        if exceptions * 20 < responses {
            continue; // under 5% — noise
        }
        findings.push(FindingRow {
            kind: "exceptions",
            severity: "medium",
            title: format!("{} rejects many requests", h.ip),
            detail: format!(
                "{} answered {exceptions} of {responses} responses with Modbus exceptions — \
                 someone may be asking for things it refuses to do",
                describe(h)
            ),
            host_ids: vec![host_id],
            connection_ids: Vec::new(),
        });
    }
    Ok(())
}

fn cleartext_control(conn: &Connection, findings: &mut Vec<FindingRow>) -> Result<(), CoreError> {
    let mut stmt = conn.prepare(
        "SELECT app_protocol, COUNT(*) FROM connections
         WHERE app_protocol IS NOT NULL GROUP BY app_protocol",
    )?;
    let rows: Vec<(String, i64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut ot_protocols: Vec<String> = Vec::new();
    let mut flow_count = 0;
    for (proto, count) in rows {
        if ports::is_ot_protocol(&proto) {
            ot_protocols.push(proto);
            flow_count += count;
        }
    }
    if flow_count == 0 {
        return Ok(());
    }
    findings.push(FindingRow {
        kind: "cleartext",
        severity: "info",
        title: "Control traffic is unauthenticated cleartext".to_string(),
        detail: format!(
            "{} {} conversation{} ({}) carry no authentication or encryption — normal for these \
             protocols, which is exactly why network segmentation matters",
            flow_count,
            if ot_protocols.len() == 1 { "control" } else { "OT" },
            if flow_count == 1 { "" } else { "s" },
            ot_protocols.join(", ")
        ),
        host_ids: Vec::new(),
        connection_ids: Vec::new(),
    });
    Ok(())
}
