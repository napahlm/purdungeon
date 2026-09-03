//! Role and Purdue level inference.
//!
//! Every inference is a best guess with a confidence and a one-line piece of
//! evidence; the user can override both role and level from the UI without
//! losing the original inference.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};

use rusqlite::{params, Connection};

use super::ports;
use crate::CoreError;

/// Vendors whose devices on the wire are usually controllers or field gear.
const OT_DEVICE_VENDORS: &[&str] = &[
    "Siemens",
    "Rockwell",
    "ABB",
    "Schneider",
    "Wago",
    "Beckhoff",
    "Phoenix Contact",
    "Omron",
    "Mitsubishi",
    "Honeywell",
    "Emerson",
    "Yokogawa",
    "GE Automation",
    "B&R Automation",
    "Bosch Rexroth",
    "Fanuc",
    "Yaskawa",
    "KUKA",
    "Festo",
    "Pilz",
    "Eaton",
    "Danfoss",
    "SEL",
    "Red Lion",
    "Turck",
    "IFM Electronic",
    "Pepperl+Fuchs",
    "Balluff",
    "SICK",
    "Keyence",
    "Endress+Hauser",
    "Weidmuller",
    "Lenze",
    "Parker",
];

/// Vendors that ship switches, routers, and industrial gateways.
const NETWORK_VENDORS: &[&str] = &[
    "Cisco",
    "Moxa",
    "Hirschmann",
    "Ruggedcom",
    "Westermo",
    "Belden",
    "NetModule",
    "Lantronix",
    "Digi International",
    "HMS Industrial",
    "Hilscher",
    "ProSoft",
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
    /// Comma-joined link-layer protocols the host was seen in (`arp`, …).
    pub link_protocols: String,
    /// Conversations the host takes part in, in either direction.
    pub flow_count: i64,
}

fn matches_vendor(vendor: Option<&str>, list: &[&str]) -> bool {
    vendor.is_some_and(|v| list.iter().any(|known| v.contains(known)))
}

/// Addresses that are unambiguously not hosts: IPv4 multicast (224/4) and
/// limited broadcast, IPv6 multicast (`ff00::/8`). An `x.x.x.255` suffix is
/// NOT enough — in a /23 or larger subnet that is a legitimate host address,
/// and misclassifying it would hide a real device.
fn is_multicast_or_broadcast(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_multicast() || v4.is_broadcast(),
        Ok(IpAddr::V6(v6)) => v6.is_multicast(),
        Err(_) => false,
    }
}

fn is_private_v4(v4: Ipv4Addr) -> bool {
    v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
}

/// Addresses that belong on a private network: RFC 1918, loopback and
/// link-local for IPv4; unique-local (`fc00::/7`), link-local (`fe80::/10`)
/// and loopback for IPv6, with IPv4-mapped addresses judged by the IPv4 inside.
/// Unparseable addresses are not flagged.
fn is_private(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => is_private_v4(v4),
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => is_private_v4(v4),
            None => {
                v6.is_unique_local()
                    || v6.is_unicast_link_local()
                    || v6.is_loopback()
                    || v6.is_unspecified()
            }
        },
        Err(_) => true,
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
    let mut stmt = conn.prepare("SELECT id, ip_address, vendor, link_protocols FROM hosts")?;
    let hosts: Vec<(i64, String, Option<String>, String)> = stmt
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (id, ip, vendor, link_protocols) in hosts {
        let p = profiles.entry(id).or_default();
        p.ip = ip;
        p.vendor = vendor;
        p.link_protocols = link_protocols;
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
            profiles
                .entry(dst_id)
                .or_default()
                .protocols_served
                .insert(proto.clone());
            profiles
                .entry(src_id)
                .or_default()
                .protocols_used
                .insert(proto);
        } else if ports::protocol_for_port(src_port) == Some(proto.as_str()) {
            profiles
                .entry(src_id)
                .or_default()
                .protocols_served
                .insert(proto.clone());
            profiles
                .entry(dst_id)
                .or_default()
                .protocols_used
                .insert(proto);
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

    load_flow_counts(conn, &mut profiles)?;

    Ok(profiles)
}

/// How many conversations each host takes part in at all, so a host known
/// only from ARP can say so in its evidence.
fn load_flow_counts(
    conn: &Connection,
    profiles: &mut HashMap<i64, HostProfile>,
) -> Result<(), CoreError> {
    let mut stmt = conn.prepare(
        "SELECT host_id, COUNT(*) FROM (
            SELECT src_host_id AS host_id FROM connections
            UNION ALL
            SELECT dst_host_id AS host_id FROM connections
         ) GROUP BY host_id",
    )?;
    let rows: Vec<(i64, i64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    for (id, flows) in rows {
        profiles.entry(id).or_default().flow_count = flows;
    }
    Ok(())
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
    let it_served = profile
        .protocols_served
        .iter()
        .any(|p| !ports::is_ot_protocol(p));

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
        return Inference {
            role: "plc",
            confidence,
            level: Some(1),
            evidence,
        };
    }

    // Speaks control protocols as a client → master of some kind
    if mb_client {
        if mb_server {
            return Inference {
                role: "plc",
                confidence: 0.5,
                level: Some(1),
                evidence: "both answers and issues modbus requests (gateway or chained controller)"
                    .into(),
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
                if profile.mb_servers_polled == 1 {
                    ""
                } else {
                    "s"
                }
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
            evidence: format!(
                "{} hardware, no control traffic",
                vendor.unwrap_or_default()
            ),
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
        let served: Vec<&str> = profile
            .protocols_served
            .iter()
            .map(String::as_str)
            .collect();
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
                evidence: format!(
                    "{} hardware, only initiates traffic",
                    vendor.unwrap_or_default()
                ),
            };
        }
        return Inference {
            role: "workstation",
            confidence: 0.35,
            level: Some(4),
            evidence: "only initiates IT-protocol traffic".into(),
        };
    }
    // Seen only in link-layer announcements (ARP) with no IP conversation at
    // all: say so, because "not enough traffic" would suggest the capture
    // simply missed it.
    let link_only = profile.flow_count == 0 && !profile.link_protocols.is_empty();
    let link_list = || profile.link_protocols.to_uppercase().replace(',', ", ");
    if ot_vendor {
        let evidence = if link_only {
            format!(
                "{} hardware, seen only in {}",
                vendor.unwrap_or_default(),
                link_list()
            )
        } else {
            format!("{} hardware", vendor.unwrap_or_default())
        };
        return Inference {
            role: "field-device",
            confidence: 0.4,
            level: Some(1),
            evidence,
        };
    }

    Inference {
        role: "unknown",
        confidence: 0.0,
        level: None,
        evidence: if link_only {
            format!("seen only in {}; no IP traffic", link_list())
        } else {
            "not enough traffic to classify".into()
        },
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

#[cfg(test)]
mod address_tests {
    use super::{is_multicast_or_broadcast, is_private};

    #[test]
    fn ipv6_private_ranges() {
        assert!(is_private("fe80::1"));
        assert!(is_private("fd12:3456::1"));
        assert!(is_private("::1"));
        assert!(is_private("::ffff:10.0.0.1"));
        assert!(!is_private("2001:db8::1"));
        assert!(!is_private("::ffff:8.8.8.8"));
    }

    #[test]
    fn multicast_in_both_families_is_not_an_asset() {
        assert!(is_multicast_or_broadcast("ff02::1"));
        assert!(is_multicast_or_broadcast("ff02::fb"));
        assert!(!is_multicast_or_broadcast("fe80::1"));
        assert!(is_multicast_or_broadcast("239.255.255.250"));
        assert!(is_multicast_or_broadcast("255.255.255.255"));
        assert!(!is_multicast_or_broadcast("192.168.1.255"));
    }
}
