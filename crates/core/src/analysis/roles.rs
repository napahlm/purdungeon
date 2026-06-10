//! Role and Purdue level inference.
//!
//! Every inference is a best guess with a confidence and a one-line piece of
//! evidence; the user can override both role and level from the UI without
//! losing the original inference.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use rusqlite::{params, Connection};

use super::ports;
use crate::CoreError;

/// Vendors whose devices on the wire are usually controllers or field gear.
const OT_DEVICE_VENDORS: &[&str] = &[
    "Siemens", "Rockwell", "ABB", "Schneider", "Wago", "Beckhoff", "Phoenix Contact",
    "Omron", "Mitsubishi", "Honeywell", "Emerson", "Yokogawa", "GE Automation",
    "B&R Automation", "Bosch Rexroth", "Fanuc", "Yaskawa", "KUKA", "Festo", "Pilz",
    "Eaton", "Danfoss", "SEL", "Red Lion", "Turck", "IFM Electronic", "Pepperl+Fuchs",
    "Balluff", "SICK", "Keyence", "Endress+Hauser", "Weidmuller", "Lenze", "Parker",
];

/// Vendors that ship switches, routers, and industrial gateways.
const NETWORK_VENDORS: &[&str] = &[
    "Cisco", "Moxa", "Hirschmann", "Ruggedcom", "Westermo", "Belden", "NetModule",
    "Lantronix", "Digi International", "HMS Industrial", "Hilscher", "ProSoft",
];

#[derive(Debug, Default)]
pub struct HostProfile {
    pub mb_requests_sent: i64,
    pub mb_writes_sent: i64,
    pub mb_servers_polled: i64,
    pub mb_responses_sent: i64,
    pub mb_unit_ids_served: i64,
    pub protocols_served: HashSet<String>,
    pub protocols_used: HashSet<String>,
    pub peers_contacted: i64,
    pub ports_contacted: i64,
    pub vendor: Option<String>,
    pub ip: String,
}

fn matches_vendor(vendor: Option<&str>, list: &[&str]) -> bool {
    vendor.is_some_and(|v| list.iter().any(|known| v.contains(known)))
}

fn is_multicast_or_broadcast(ip: &str) -> bool {
    let Some(first) = ip.split('.').next().and_then(|o| o.parse::<u8>().ok()) else {
        return false;
    };
    (224..=239).contains(&first) || ip == "255.255.255.255" || ip.ends_with(".255")
}

fn is_private(ip: &str) -> bool {
    let octets: Vec<u8> = ip.split('.').filter_map(|o| o.parse().ok()).collect();
    if octets.len() != 4 {
        return true; // don't flag unparseable addresses
    }
    match octets[0] {
        10 | 127 => true,
        172 => (16..=31).contains(&octets[1]),
        192 => octets[1] == 168,
        169 => octets[1] == 254,
        _ => false,
    }
}

/// Store the comma-joined set of application protocols each host touches.
pub fn collect_host_protocols(conn: &Connection) -> Result<(), CoreError> {
    let mut stmt = conn.prepare(
        "SELECT host_id, GROUP_CONCAT(DISTINCT app_protocol) FROM (
            SELECT src_host_id AS host_id, app_protocol FROM connections WHERE app_protocol IS NOT NULL
            UNION
            SELECT dst_host_id AS host_id, app_protocol FROM connections WHERE app_protocol IS NOT NULL
         ) GROUP BY host_id",
    )?;
    let rows: Vec<(i64, String)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;

    let mut update = conn.prepare("UPDATE hosts SET protocols = ?1 WHERE id = ?2")?;
    for (host_id, protocols) in rows {
        update.execute(params![protocols, host_id])?;
    }
    Ok(())
}

pub fn build_profiles(conn: &Connection) -> Result<HashMap<i64, HostProfile>, CoreError> {
    let mut profiles: HashMap<i64, HostProfile> = HashMap::new();

    // Seed every host so unknowns still get a row
    let mut stmt = conn.prepare("SELECT id, ip_address, vendor FROM hosts")?;
    let hosts: Vec<(i64, String, Option<String>)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    for (id, ip, vendor) in hosts {
        let p = profiles.entry(id).or_default();
        p.ip = ip;
        p.vendor = vendor;
    }

    // Modbus client activity
    let mut stmt = conn.prepare(
        "SELECT src_host_id, COUNT(*), SUM(is_write), COUNT(DISTINCT dst_host_id)
         FROM modbus_events WHERE is_request = 1 GROUP BY src_host_id",
    )?;
    let rows: Vec<(i64, i64, i64, i64)> = stmt
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (id, requests, writes, servers) in rows {
        let p = profiles.entry(id).or_default();
        p.mb_requests_sent = requests;
        p.mb_writes_sent = writes;
        p.mb_servers_polled = servers;
    }

    // Modbus server activity
    let mut stmt = conn.prepare(
        "SELECT src_host_id, COUNT(*), COUNT(DISTINCT unit_id)
         FROM modbus_events WHERE is_request = 0 GROUP BY src_host_id",
    )?;
    let rows: Vec<(i64, i64, i64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    for (id, responses, unit_ids) in rows {
        let p = profiles.entry(id).or_default();
        p.mb_responses_sent = responses;
        p.mb_unit_ids_served = unit_ids;
    }

    // Which side of each named flow is the server (the side on the known port)
    let mut stmt = conn.prepare(
        "SELECT src_host_id, dst_host_id, src_port, dst_port, app_protocol
         FROM connections WHERE app_protocol IS NOT NULL",
    )?;
    let rows: Vec<(i64, i64, u16, u16, String)> = stmt
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (src_id, dst_id, src_port, dst_port, proto) in rows {
        if ports::protocol_for_port(dst_port) == Some(proto.as_str()) {
            profiles.entry(dst_id).or_default().protocols_served.insert(proto.clone());
            profiles.entry(src_id).or_default().protocols_used.insert(proto);
        } else if ports::protocol_for_port(src_port) == Some(proto.as_str()) {
            profiles.entry(src_id).or_default().protocols_served.insert(proto.clone());
            profiles.entry(dst_id).or_default().protocols_used.insert(proto);
        }
    }

    // Fan-out, for scan-like behavior and master detection
    let mut stmt = conn.prepare(
        "SELECT src_host_id, COUNT(DISTINCT dst_host_id), COUNT(DISTINCT dst_port)
         FROM connections GROUP BY src_host_id",
    )?;
    let rows: Vec<(i64, i64, i64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    for (id, peers, ports_contacted) in rows {
        let p = profiles.entry(id).or_default();
        p.peers_contacted = peers;
        p.ports_contacted = ports_contacted;
    }

    Ok(profiles)
}

struct Inference {
    role: &'static str,
    confidence: f64,
    level: Option<i64>,
    evidence: String,
}

fn infer(profile: &HostProfile) -> Inference {
    let vendor = profile.vendor.as_deref();
    let ot_vendor = matches_vendor(vendor, OT_DEVICE_VENDORS);
    let net_vendor = matches_vendor(vendor, NETWORK_VENDORS);

    if is_multicast_or_broadcast(&profile.ip) {
        return Inference {
            role: "broadcast",
            confidence: 1.0,
            level: None,
            evidence: "broadcast or multicast address".into(),
        };
    }
    if !is_private(&profile.ip) {
        return Inference {
            role: "external",
            confidence: 0.9,
            level: Some(5),
            evidence: "address outside private ranges".into(),
        };
    }

    let ot_served: Vec<&str> = profile
        .protocols_served
        .iter()
        .map(String::as_str)
        .filter(|p| ports::is_ot_protocol(p))
        .collect();
    let mb_server = profile.mb_responses_sent > 0 || profile.protocols_served.contains("modbus");
    let mb_client = profile.mb_requests_sent > 0;
    let it_served = profile.protocols_served.iter().any(|p| !ports::is_ot_protocol(p));

    // Answers control-protocol requests → controller or field device
    if (mb_server || !ot_served.is_empty()) && !mb_client {
        let proto_list = if ot_served.is_empty() {
            "modbus".to_string()
        } else {
            ot_served.join(", ")
        };
        let mut evidence = format!("answers {proto_list} requests");
        if profile.mb_unit_ids_served > 1 {
            let _ = write!(evidence, " for {} unit ids", profile.mb_unit_ids_served);
        }
        let confidence = if ot_vendor {
            let _ = write!(evidence, "; {} hardware", vendor.unwrap_or_default());
            0.85
        } else {
            0.6
        };
        return Inference { role: "plc", confidence, level: Some(1), evidence };
    }

    // Speaks control protocols as a client → master of some kind
    if mb_client {
        if mb_server {
            return Inference {
                role: "plc",
                confidence: 0.5,
                level: Some(1),
                evidence: "both answers and issues modbus requests (gateway or chained controller)".into(),
            };
        }
        if profile.mb_servers_polled >= 3 {
            return Inference {
                role: "scada",
                confidence: 0.75,
                level: Some(2),
                evidence: format!("polls {} modbus devices", profile.mb_servers_polled),
            };
        }
        if profile.mb_writes_sent > 0 && profile.mb_writes_sent * 2 >= profile.mb_requests_sent {
            return Inference {
                role: "engineering-workstation",
                confidence: 0.5,
                level: Some(3),
                evidence: format!(
                    "mostly writes to controllers ({} of {} requests)",
                    profile.mb_writes_sent, profile.mb_requests_sent
                ),
            };
        }
        return Inference {
            role: "hmi",
            confidence: 0.55,
            level: Some(2),
            evidence: format!(
                "reads from {} modbus device{}",
                profile.mb_servers_polled,
                if profile.mb_servers_polled == 1 { "" } else { "s" }
            ),
        };
    }

    infer_without_control_traffic(profile, vendor, ot_vendor, net_vendor, it_served)
}

/// Classification for hosts that show no control-protocol traffic at all.
fn infer_without_control_traffic(
    profile: &HostProfile,
    vendor: Option<&str>,
    ot_vendor: bool,
    net_vendor: bool,
    it_served: bool,
) -> Inference {
    if net_vendor {
        return Inference {
            role: "network-gear",
            confidence: 0.6,
            level: Some(3),
            evidence: format!("{} hardware, no control traffic", vendor.unwrap_or_default()),
        };
    }
    let db_served = ["mssql", "oracle", "mysql", "postgres"]
        .iter()
        .any(|p| profile.protocols_served.contains(*p));
    if db_served {
        return Inference {
            role: "historian",
            confidence: 0.5,
            level: Some(3),
            evidence: "serves a database on an OT segment".into(),
        };
    }
    if profile.protocols_served.contains("dns") || profile.protocols_served.contains("dhcp") {
        return Inference {
            role: "network-gear",
            confidence: 0.45,
            level: Some(3),
            evidence: "provides network services (dns/dhcp)".into(),
        };
    }
    if it_served {
        let served: Vec<&str> = profile.protocols_served.iter().map(String::as_str).collect();
        return Inference {
            role: "server",
            confidence: 0.4,
            level: Some(4),
            evidence: format!("serves {}", served.join(", ")),
        };
    }
    if !profile.protocols_used.is_empty() {
        if ot_vendor {
            return Inference {
                role: "field-device",
                confidence: 0.4,
                level: Some(1),
                evidence: format!("{} hardware, only initiates traffic", vendor.unwrap_or_default()),
            };
        }
        return Inference {
            role: "workstation",
            confidence: 0.35,
            level: Some(4),
            evidence: "only initiates IT-protocol traffic".into(),
        };
    }
    if ot_vendor {
        return Inference {
            role: "field-device",
            confidence: 0.4,
            level: Some(1),
            evidence: format!("{} hardware", vendor.unwrap_or_default()),
        };
    }

    Inference {
        role: "unknown",
        confidence: 0.0,
        level: None,
        evidence: "not enough traffic to classify".into(),
    }
}

pub fn infer_and_store(
    conn: &Connection,
    profiles: &HashMap<i64, HostProfile>,
) -> Result<(), CoreError> {
    let mut update = conn.prepare(
        "UPDATE hosts SET role = ?1, role_confidence = ?2, role_evidence = ?3,
                          purdue_level = ?4, is_external = ?5
         WHERE id = ?6",
    )?;
    for (host_id, profile) in profiles {
        let inference = infer(profile);
        update.execute(params![
            inference.role,
            inference.confidence,
            inference.evidence,
            inference.level,
            i64::from(inference.role == "external"),
            host_id,
        ])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modbus_responder_is_a_plc() {
        let profile = HostProfile {
            ip: "192.168.1.10".into(),
            mb_responses_sent: 500,
            vendor: Some("Siemens".into()),
            ..Default::default()
        };
        let inf = infer(&profile);
        assert_eq!(inf.role, "plc");
        assert_eq!(inf.level, Some(1));
        assert!(inf.confidence > 0.8);
    }

    #[test]
    fn wide_poller_is_scada() {
        let profile = HostProfile {
            ip: "192.168.1.100".into(),
            mb_requests_sent: 10_000,
            mb_servers_polled: 8,
            ..Default::default()
        };
        let inf = infer(&profile);
        assert_eq!(inf.role, "scada");
        assert_eq!(inf.level, Some(2));
    }

    #[test]
    fn public_address_is_external() {
        let profile = HostProfile {
            ip: "8.8.8.8".into(),
            ..Default::default()
        };
        let inf = infer(&profile);
        assert_eq!(inf.role, "external");
        assert_eq!(inf.level, Some(5));
    }

    #[test]
    fn multicast_is_not_an_asset() {
        let profile = HostProfile {
            ip: "239.255.255.250".into(),
            ..Default::default()
        };
        assert_eq!(infer(&profile).role, "broadcast");
    }

    #[test]
    fn writer_is_engineering_workstation() {
        let profile = HostProfile {
            ip: "10.0.0.5".into(),
            mb_requests_sent: 10,
            mb_writes_sent: 9,
            mb_servers_polled: 1,
            ..Default::default()
        };
        let inf = infer(&profile);
        assert_eq!(inf.role, "engineering-workstation");
        assert_eq!(inf.level, Some(3));
    }
}
