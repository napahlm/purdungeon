//! Port-based application protocol classification for flows that were not
//! identified by deep parsing. A port match is a guess, but a useful one —
//! the UI treats these the same as parsed protocols for coloring/filtering.

use rusqlite::{params, Connection};

use crate::CoreError;

/// Well-known ports worth naming on an OT network. OT protocols first.
const PORT_PROTOCOLS: &[(u16, &str)] = &[
    (102, "s7comm"),
    (502, "modbus"),
    (1089, "ff-annunc"),
    (1911, "fox"),
    (2222, "enip-io"),
    (2404, "iec104"),
    (4840, "opcua"),
    (9600, "fins"),
    (20000, "dnp3"),
    (44818, "enip"),
    (47808, "bacnet"),
    (20, "ftp"),
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "dns"),
    (67, "dhcp"),
    (68, "dhcp"),
    (69, "tftp"),
    (80, "http"),
    (88, "kerberos"),
    (123, "ntp"),
    (135, "msrpc"),
    (137, "netbios"),
    (138, "netbios"),
    (139, "netbios"),
    (161, "snmp"),
    (162, "snmp"),
    (389, "ldap"),
    (443, "https"),
    (445, "smb"),
    (1433, "mssql"),
    (1521, "oracle"),
    (3306, "mysql"),
    (3389, "rdp"),
    (5432, "postgres"),
    (5900, "vnc"),
    (8080, "http"),
];

#[must_use]
pub fn protocol_for_port(port: u16) -> Option<&'static str> {
    PORT_PROTOCOLS
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, name)| *name)
}

/// Ports that indicate an OT/ICS protocol server.
#[must_use]
pub fn is_ot_protocol(name: &str) -> bool {
    matches!(
        name,
        "modbus" | "s7comm" | "iec104" | "opcua" | "dnp3" | "enip" | "enip-io" | "bacnet" | "fins" | "fox" | "ff-annunc"
    )
}

/// Name untagged flows by their best-known port (server side wins).
pub fn classify_connections(conn: &Connection) -> Result<(), CoreError> {
    let mut stmt = conn.prepare(
        "SELECT id, src_port, dst_port FROM connections WHERE app_protocol IS NULL",
    )?;
    let rows: Vec<(i64, u16, u16)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<Vec<_>, _>>()?;

    let mut update = conn.prepare("UPDATE connections SET app_protocol = ?1 WHERE id = ?2")?;
    for (id, src_port, dst_port) in rows {
        let name = protocol_for_port(dst_port).or_else(|| protocol_for_port(src_port));
        if let Some(name) = name {
            update.execute(params![name, id])?;
        }
    }
    Ok(())
}
