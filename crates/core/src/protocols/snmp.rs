//! SNMP v1/v2c responses: the MIB-II system group (RFC 3418) is the closest
//! thing to a device introducing itself — description, name, object id
//! (which names the vendor), location, contact. The BER decoding is done by
//! the `snmp-parser` crate (MIT/Apache-2.0); this module only picks fields.

use snmp_parser::{
    parse_snmp_generic_message, ObjectSyntax, PduType, SnmpGenericMessage, SnmpPdu, VarBindValue,
};

pub const SYS_DESCR: &str = "1.3.6.1.2.1.1.1.0";
pub const SYS_OBJECT_ID: &str = "1.3.6.1.2.1.1.2.0";
pub const SYS_CONTACT: &str = "1.3.6.1.2.1.1.4.0";
pub const SYS_NAME: &str = "1.3.6.1.2.1.1.5.0";
pub const SYS_LOCATION: &str = "1.3.6.1.2.1.1.6.0";

/// The prefix every vendor-specific object id starts with: iso.org.dod.
/// internet.private.enterprise.
const ENTERPRISE_PREFIX: &str = "1.3.6.1.4.1.";

/// A small table of IANA Private Enterprise Numbers
/// (<https://www.iana.org/assignments/enterprise-numbers>) for vendors that
/// matter on an OT network. Only entries checked against the registry are
/// listed; an unknown number yields no vendor rather than a wrong one.
const ENTERPRISES: &[(u32, &str)] = &[
    (9, "Cisco Systems"),
    (11, "Hewlett-Packard"),
    (43, "3Com"),
    (171, "D-Link"),
    (248, "Hirschmann"),
    (311, "Microsoft"),
    (674, "Dell"),
    (1991, "Brocade"),
    (2011, "Huawei"),
    (2636, "Juniper Networks"),
    (3833, "Schneider Electric"),
    (4329, "Siemens"),
    (4526, "Netgear"),
    (6889, "Avaya"),
    (8691, "Moxa"),
    (14823, "Aruba Networks"),
    (25506, "H3C"),
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnmpSystem {
    pub descr: Option<String>,
    pub object_id: Option<String>,
    pub name: Option<String>,
    pub location: Option<String>,
    pub contact: Option<String>,
}

impl SnmpSystem {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.descr.is_none()
            && self.object_id.is_none()
            && self.name.is_none()
            && self.location.is_none()
            && self.contact.is_none()
    }
}

fn text(bytes: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(bytes).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// System-group values from a v1/v2c Response PDU; `None` for anything else
/// or when no system-group variable was answered.
#[must_use]
pub fn parse_response(bytes: &[u8]) -> Option<SnmpSystem> {
    let (_, message) = parse_snmp_generic_message(bytes).ok()?;
    let message = match message {
        SnmpGenericMessage::V1(m) | SnmpGenericMessage::V2(m) => m,
        SnmpGenericMessage::V3(_) => return None,
    };
    let SnmpPdu::Generic(pdu) = &message.pdu else {
        return None;
    };
    if pdu.pdu_type.0 != PduType::Response.0 {
        return None;
    }
    let mut system = SnmpSystem::default();
    for var in &pdu.var {
        let VarBindValue::Value(value) = &var.val else {
            continue;
        };
        let as_text = match value {
            ObjectSyntax::String(bytes) => text(bytes),
            _ => None,
        };
        match var.oid.to_id_string().as_str() {
            SYS_DESCR => system.descr = as_text,
            SYS_NAME => system.name = as_text,
            SYS_LOCATION => system.location = as_text,
            SYS_CONTACT => system.contact = as_text,
            SYS_OBJECT_ID => {
                if let ObjectSyntax::Object(oid) = value {
                    system.object_id = Some(oid.to_id_string());
                }
            }
            _ => {}
        }
    }
    if system.is_empty() {
        None
    } else {
        Some(system)
    }
}

/// The vendor a sysObjectID belongs to, when its enterprise number is known.
#[must_use]
pub fn enterprise_vendor(object_id: &str) -> Option<&'static str> {
    let rest = object_id.strip_prefix(ENTERPRISE_PREFIX)?;
    let number: u32 = rest.split('.').next()?.parse().ok()?;
    ENTERPRISES
        .iter()
        .find(|(n, _)| *n == number)
        .map(|(_, vendor)| *vendor)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── A tiny BER encoder, enough for one SNMP response ────────────────────
    fn ber(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 128 {
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        out.extend_from_slice(content);
        out
    }
    fn int(v: i64) -> Vec<u8> {
        let bytes = v.to_be_bytes();
        let start = bytes.iter().position(|b| *b != 0).unwrap_or(7);
        ber(0x02, &bytes[start..])
    }
    fn octets(s: &[u8]) -> Vec<u8> {
        ber(0x04, s)
    }
    fn oid(arcs: &[u32]) -> Vec<u8> {
        let mut body = vec![(40 * arcs[0] + arcs[1]) as u8];
        for arc in &arcs[2..] {
            let mut chunks = vec![(*arc & 0x7F) as u8];
            let mut rest = *arc >> 7;
            while rest > 0 {
                chunks.push((rest & 0x7F) as u8 | 0x80);
                rest >>= 7;
            }
            chunks.reverse();
            body.extend(chunks);
        }
        ber(0x06, &body)
    }
    fn varbind(name: &[u32], value: Vec<u8>) -> Vec<u8> {
        let mut body = oid(name);
        body.extend(value);
        ber(0x30, &body)
    }

    pub fn response(varbinds: &[Vec<u8>]) -> Vec<u8> {
        let mut list = Vec::new();
        for v in varbinds {
            list.extend_from_slice(v);
        }
        let mut pdu = int(1);
        pdu.extend(int(0));
        pdu.extend(int(0));
        pdu.extend(ber(0x30, &list));
        let mut msg = int(1); // v2c
        msg.extend(octets(b"public"));
        msg.extend(ber(0xA2, &pdu));
        ber(0x30, &msg)
    }

    #[test]
    fn reads_the_system_group() {
        let bytes = response(&[
            varbind(
                &[1, 3, 6, 1, 2, 1, 1, 1, 0],
                octets(b"Cisco IOS Software, C2960"),
            ),
            varbind(
                &[1, 3, 6, 1, 2, 1, 1, 2, 0],
                oid(&[1, 3, 6, 1, 4, 1, 9, 1, 716]),
            ),
            varbind(&[1, 3, 6, 1, 2, 1, 1, 5, 0], octets(b"SW-CORE")),
        ]);
        let system = parse_response(&bytes).unwrap();
        assert_eq!(system.descr.as_deref(), Some("Cisco IOS Software, C2960"));
        assert_eq!(system.object_id.as_deref(), Some("1.3.6.1.4.1.9.1.716"));
        assert_eq!(system.name.as_deref(), Some("SW-CORE"));
        assert_eq!(
            enterprise_vendor("1.3.6.1.4.1.9.1.716"),
            Some("Cisco Systems")
        );
        assert_eq!(enterprise_vendor("1.3.6.1.4.1.999999.1"), None);
    }

    #[test]
    fn ignores_requests_and_garbage() {
        assert!(parse_response(&[0x30, 0x03, 0x02, 0x01, 0x01]).is_none());
        assert!(parse_response(b"not snmp at all").is_none());
    }
}
