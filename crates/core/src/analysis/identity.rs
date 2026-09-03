//! Resolve the identity columns on `hosts` from the evidence table: the best
//! hostname, and the best MAC. Frames seen beyond a router only carry the
//! router's MAC, so ARP, DHCP and LLDP/CDP — which name a device's own —
//! outrank them by confidence.

use std::collections::HashMap;

use rusqlite::{params, Connection};

use crate::oui;
use crate::CoreError;

/// The highest-confidence value of `kind` per host (ties: most often seen,
/// then most recently seen).
fn best_by_host(conn: &Connection, kind: &str) -> Result<HashMap<i64, String>, CoreError> {
    let mut stmt = conn.prepare(
        "SELECT host_id, value FROM evidence WHERE kind = ?1
         ORDER BY host_id, confidence DESC, count DESC, last_seen DESC",
    )?;
    let rows = stmt.query_map(params![kind], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut best = HashMap::new();
    for row in rows {
        let (host_id, value) = row?;
        best.entry(host_id).or_insert(value);
    }
    Ok(best)
}

pub fn resolve(conn: &Connection) -> Result<(), CoreError> {
    let hostnames = best_by_host(conn, "hostname")?;
    let mut update = conn.prepare("UPDATE hosts SET hostname = ?1 WHERE id = ?2")?;
    for (host_id, name) in &hostnames {
        update.execute(params![name, host_id])?;
    }

    // Only hosts known by IP carry MAC evidence; a MAC-only host *is* its MAC.
    let macs = best_by_host(conn, "mac")?;
    let mut update = conn.prepare(
        "UPDATE hosts SET mac_address = ?1, vendor = ?2
         WHERE id = ?3 AND ip_address IS NOT NULL AND mac_address != ?1",
    )?;
    for (host_id, mac) in &macs {
        let vendor = parse_mac(mac).and_then(|bytes| oui::lookup_vendor(&bytes));
        update.execute(params![mac, vendor, host_id])?;
    }
    Ok(())
}

fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = text.split(':');
    for slot in &mut out {
        *slot = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}
