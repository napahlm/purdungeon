//! Identity facts from the protocols that hand them out for free: DHCP,
//! `NetBIOS` name service, mDNS, LLMNR, SNMP responses, LLDP and CDP. Every
//! function here is pure — bytes in, facts out — and the ingest sink decides
//! which device the facts belong to.
//!
//! Confidence is how far the value can be trusted to describe the device it
//! is attached to: a self-declared name is high, a guessed operating system
//! is low.

use std::net::{IpAddr, Ipv4Addr};

use crate::ingest::evidence::{kind, push_unique, Fact};
use crate::protocols::cdp::{self, CdpInfo};
use crate::protocols::dhcp;
use crate::protocols::dns::{self, RData};
use crate::protocols::lldp::{self, LldpInfo};
use crate::protocols::{nbns, snmp};

pub const PORT_DHCP_SERVER: u16 = 67;
pub const PORT_DHCP_CLIENT: u16 = 68;
pub const PORT_NBNS: u16 = 137;
pub const PORT_SNMP: u16 = 161;
pub const PORT_MDNS: u16 = 5353;
pub const PORT_LLMNR: u16 = 5355;

/// Facts about a DHCP client, which the packet's addresses do not name: a
/// client asking for an address sends from 0.0.0.0, and the ACK that grants
/// one comes from the server.
pub(crate) struct DhcpFacts {
    pub client_mac: [u8; 6],
    /// The client's address when the exchange names it (ciaddr on a renewal
    /// or inform, yiaddr on an ACK); `None` while it is still being decided.
    pub client_ip: Option<Ipv4Addr>,
    pub facts: Vec<Fact>,
}

pub(crate) enum UdpFacts {
    /// Facts about the packet's sender.
    Sender {
        source: &'static str,
        facts: Vec<Fact>,
    },
    Dhcp(DhcpFacts),
}

/// Facts announced over a link-layer protocol, to be attributed by MAC.
pub(crate) struct L2Facts {
    pub source: &'static str,
    pub facts: Vec<Fact>,
    /// Management addresses the announcement names — the surest way to tie
    /// it to an IP host.
    pub management: Vec<IpAddr>,
}

pub(crate) fn inspect_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Option<UdpFacts> {
    if payload.is_empty() {
        return None;
    }
    let dhcp_ports = [PORT_DHCP_SERVER, PORT_DHCP_CLIENT];
    if dhcp_ports.contains(&src_port) && dhcp_ports.contains(&dst_port) {
        return dhcp_facts(payload).map(UdpFacts::Dhcp);
    }
    if src_port == PORT_NBNS || dst_port == PORT_NBNS {
        return sender("nbns", nbns_facts(payload));
    }
    if src_port == PORT_MDNS {
        return sender("mdns", dns_facts(payload, true));
    }
    if src_port == PORT_LLMNR {
        return sender("llmnr", dns_facts(payload, false));
    }
    if src_port == PORT_SNMP {
        return sender("snmp", snmp_facts(payload));
    }
    None
}

fn sender(source: &'static str, facts: Vec<Fact>) -> Option<UdpFacts> {
    if facts.is_empty() {
        None
    } else {
        Some(UdpFacts::Sender { source, facts })
    }
}

fn dhcp_facts(payload: &[u8]) -> Option<DhcpFacts> {
    let msg = dhcp::parse(payload)?;
    let client_mac = msg.chaddr?;
    let is_ack = msg.op == dhcp::OP_REPLY && msg.message_type == Some(dhcp::ACK);
    // Offers and NAKs promise nothing about the client; only the ACK binds
    // an address to it.
    if msg.op == dhcp::OP_REPLY && !is_ack {
        return None;
    }
    let mut facts = Vec::new();
    if let Some(name) = &msg.hostname {
        facts.push(Fact::new(kind::HOSTNAME, name, 0.9));
    }
    if let Some(class) = &msg.vendor_class {
        facts.push(Fact::new(kind::VENDOR_CLASS, class, 0.9));
    }
    let fingerprint = dhcp::fingerprint(&msg.parameter_request_list);
    if !fingerprint.is_empty() {
        facts.push(Fact::new(kind::DHCP_FINGERPRINT, &fingerprint, 0.9));
    }
    if let Some((os, confidence)) = dhcp::os_guess(msg.vendor_class.as_deref(), &fingerprint) {
        facts.push(Fact::new(kind::OS, os, confidence));
    }
    if let Some(domain) = &msg.domain_name {
        facts.push(Fact::new(kind::DOMAIN, domain, 0.7));
    }
    let nonzero = |ip: Ipv4Addr| (!ip.is_unspecified()).then_some(ip);
    let client_ip = if is_ack {
        nonzero(msg.yiaddr).or_else(|| nonzero(msg.ciaddr))
    } else {
        nonzero(msg.ciaddr)
    };
    Some(DhcpFacts {
        client_mac,
        client_ip,
        facts,
    })
}

fn nbns_facts(payload: &[u8]) -> Vec<Fact> {
    let Some(msg) = nbns::parse(payload) else {
        return Vec::new();
    };
    let mut facts = Vec::new();
    let host_suffix = |s: u8| matches!(s, nbns::SUFFIX_WORKSTATION | nbns::SUFFIX_SERVER);
    let group_suffix = |s: u8| {
        matches!(
            s,
            nbns::SUFFIX_WORKSTATION
                | nbns::SUFFIX_BROWSER_ELECTION
                | nbns::SUFFIX_DOMAIN_CONTROLLERS
                | nbns::SUFFIX_DOMAIN_MASTER
        )
    };
    for (name, confidence) in msg
        .claimed
        .iter()
        .map(|n| (n, 0.9))
        .chain(msg.answered.iter().map(|n| (n, 0.85)))
    {
        match name.is_group {
            Some(true) if group_suffix(name.suffix) => {
                push_unique(&mut facts, Fact::new(kind::DOMAIN, &name.name, 0.7));
            }
            Some(true) => {}
            _ if host_suffix(name.suffix) => {
                push_unique(
                    &mut facts,
                    Fact::new(kind::HOSTNAME, &name.name, confidence),
                );
            }
            _ => {}
        }
    }
    facts
}

/// Drop the `.local` (mDNS) suffix and any trailing dot.
fn bare_name(name: &str) -> Option<String> {
    let trimmed = name.trim_end_matches('.');
    let bare = trimmed
        .strip_suffix(".local")
        .or_else(|| trimmed.strip_suffix(".LOCAL"))
        .unwrap_or(trimmed);
    if bare.is_empty() {
        None
    } else {
        Some(bare.to_string())
    }
}

/// Names and services from an mDNS or LLMNR response. Only responses carry
/// facts about the sender — a query is about someone else.
fn dns_facts(payload: &[u8], with_services: bool) -> Vec<Fact> {
    let Some(msg) = dns::parse(payload) else {
        return Vec::new();
    };
    if !msg.is_response {
        return Vec::new();
    }
    let mut facts = Vec::new();
    for record in msg.answers.iter().chain(msg.additional.iter()) {
        match &record.data {
            RData::A(_) | RData::Aaaa(_) => {
                if let Some(name) = bare_name(&record.name) {
                    push_unique(&mut facts, Fact::new(kind::HOSTNAME, name, 0.8));
                }
            }
            RData::Srv { target, .. } if with_services => {
                if let Some(name) = bare_name(target) {
                    push_unique(&mut facts, Fact::new(kind::HOSTNAME, name, 0.7));
                }
            }
            RData::Ptr(target) if with_services => {
                // Service enumeration answers name the type; an instance
                // record's owner *is* the type (RFC 6763 §4.1).
                let owner = record.name.trim_end_matches('.');
                let service = if owner.eq_ignore_ascii_case("_services._dns-sd._udp.local") {
                    bare_name(target)
                } else if owner.ends_with("._tcp.local") || owner.ends_with("._udp.local") {
                    bare_name(owner)
                } else {
                    None
                };
                if let Some(service) = service {
                    push_unique(&mut facts, Fact::new(kind::SERVICE, service, 0.8));
                }
            }
            RData::Txt(items) if with_services => {
                for item in items {
                    if let Some(model) = item.strip_prefix("model=") {
                        if !model.is_empty() {
                            push_unique(&mut facts, Fact::new(kind::MODEL, model, 0.8));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    facts
}

fn snmp_facts(payload: &[u8]) -> Vec<Fact> {
    let Some(system) = snmp::parse_response(payload) else {
        return Vec::new();
    };
    let mut facts = Vec::new();
    if let Some(descr) = system.descr {
        facts.push(Fact::new(kind::DESCRIPTION, descr, 0.9));
    }
    if let Some(name) = system.name {
        facts.push(Fact::new(kind::HOSTNAME, name, 0.9));
    }
    if let Some(oid) = system.object_id {
        if let Some(vendor) = snmp::enterprise_vendor(&oid) {
            facts.push(Fact::new(kind::VENDOR, vendor, 0.8));
        }
        facts.push(Fact::new(kind::SYS_OBJECT_ID, oid, 0.9));
    }
    if let Some(location) = system.location {
        facts.push(Fact::new(kind::LOCATION, location, 0.8));
    }
    if let Some(contact) = system.contact {
        facts.push(Fact::new(kind::CONTACT, contact, 0.8));
    }
    facts
}

pub(crate) fn lldp_facts(info: &LldpInfo) -> L2Facts {
    let mut facts = Vec::new();
    if let Some(name) = &info.system_name {
        facts.push(Fact::new(kind::HOSTNAME, name, 0.9));
    }
    if let Some(descr) = &info.system_description {
        facts.push(Fact::new(kind::DESCRIPTION, descr, 0.85));
    }
    let capabilities = lldp::capability_names(info.capabilities_enabled);
    if !capabilities.is_empty() {
        facts.push(Fact::new(kind::CAPABILITIES, capabilities.join(", "), 0.9));
    }
    if let Some(port) = &info.port_id {
        let value = match &info.port_description {
            Some(description) => format!("{port} ({description})"),
            None => port.clone(),
        };
        facts.push(Fact::new(kind::PORT, value, 0.9));
    }
    for address in &info.management_addresses {
        facts.push(Fact::new(
            kind::MANAGEMENT_ADDRESS,
            address.to_string(),
            0.9,
        ));
    }
    L2Facts {
        source: "lldp",
        facts,
        management: info.management_addresses.clone(),
    }
}

pub(crate) fn cdp_facts(info: &CdpInfo) -> L2Facts {
    let mut facts = Vec::new();
    if let Some(name) = &info.device_id {
        facts.push(Fact::new(kind::HOSTNAME, name, 0.9));
    }
    if let Some(platform) = &info.platform {
        facts.push(Fact::new(kind::MODEL, platform, 0.9));
    }
    if let Some(software) = &info.software_version {
        facts.push(Fact::new(kind::DESCRIPTION, software, 0.85));
    }
    let capabilities = cdp::capability_names(info.capabilities);
    if !capabilities.is_empty() {
        facts.push(Fact::new(kind::CAPABILITIES, capabilities.join(", "), 0.9));
    }
    if let Some(port) = &info.port_id {
        facts.push(Fact::new(kind::PORT, port, 0.9));
    }
    for address in &info.addresses {
        facts.push(Fact::new(
            kind::MANAGEMENT_ADDRESS,
            address.to_string(),
            0.9,
        ));
    }
    L2Facts {
        source: "cdp",
        facts,
        management: info.addresses.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_names_drop_the_mdns_suffix() {
        assert_eq!(bare_name("printer.local."), Some("printer".into()));
        assert_eq!(bare_name("ENG-WS01"), Some("ENG-WS01".into()));
        assert_eq!(bare_name("."), None);
    }
}
