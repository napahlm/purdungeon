//! `NetBIOS` Name Service (RFC 1001/1002) on UDP 137: the names Windows
//! machines register and answer for. The packet layout is DNS with a
//! "first-level encoded" name — 16 name bytes spread over 32 characters
//! `A`–`P` (RFC 1001 §14.1) — where byte 16 is the name's suffix (service
//! type) and the rest is space-padded.

use crate::protocols::dns::{self, RData};

pub const OPCODE_QUERY: u8 = 0;
pub const OPCODE_REGISTRATION: u8 = 5;
pub const OPCODE_RELEASE: u8 = 6;
pub const OPCODE_REFRESH: u8 = 8;
pub const OPCODE_REFRESH_ALT: u8 = 9;
pub const OPCODE_MULTIHOMED: u8 = 15;

/// NB resource record type (RFC 1002 §4.2.1.3).
pub const TYPE_NB: u16 = 0x20;

/// Well-known name suffixes (Microsoft KB 163409).
pub const SUFFIX_WORKSTATION: u8 = 0x00;
pub const SUFFIX_MESSENGER: u8 = 0x03;
pub const SUFFIX_SERVER: u8 = 0x20;
pub const SUFFIX_DOMAIN_MASTER: u8 = 0x1B;
pub const SUFFIX_DOMAIN_CONTROLLERS: u8 = 0x1C;
pub const SUFFIX_BROWSER_ELECTION: u8 = 0x1E;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NbName {
    pub name: String,
    pub suffix: u8,
    /// Group (workgroup/domain) rather than unique (host) name, when the
    /// record's `NB_FLAGS` were present to say so.
    pub is_group: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct NbnsMessage {
    pub is_response: bool,
    pub opcode: u8,
    /// Names the sender registers or refreshes — its own names.
    pub claimed: Vec<NbName>,
    /// Names the sender answers positive queries for — also its own.
    pub answered: Vec<NbName>,
}

/// Decode a first-level encoded label into `(name, suffix)`.
#[must_use]
pub fn decode_name(label: &str) -> Option<(String, u8)> {
    let encoded = label.as_bytes();
    if encoded.len() != 32 {
        return None;
    }
    let mut raw = [0u8; 16];
    for (i, slot) in raw.iter_mut().enumerate() {
        let hi = encoded[2 * i].checked_sub(b'A')?;
        let lo = encoded[2 * i + 1].checked_sub(b'A')?;
        if hi > 15 || lo > 15 {
            return None;
        }
        *slot = (hi << 4) | lo;
    }
    let name = String::from_utf8_lossy(&raw[..15]).trim_end().to_string();
    Some((name, raw[15]))
}

fn group_flag(data: &RData) -> Option<bool> {
    // NB rdata: NB_FLAGS (G bit is the top bit) followed by the address.
    match data {
        RData::Other(raw) => raw.first().map(|b| b & 0x80 != 0),
        _ => None,
    }
}

fn decode_first_label(name: &str) -> Option<(String, u8)> {
    decode_name(name.split('.').next()?)
}

#[must_use]
pub fn parse(bytes: &[u8]) -> Option<NbnsMessage> {
    let msg = dns::parse(bytes)?;
    let mut out = NbnsMessage {
        is_response: msg.is_response,
        opcode: msg.opcode,
        ..NbnsMessage::default()
    };
    let is_claim = matches!(
        msg.opcode,
        OPCODE_REGISTRATION | OPCODE_REFRESH | OPCODE_REFRESH_ALT | OPCODE_MULTIHOMED
    );
    if !msg.is_response && is_claim {
        // The question carries the claimed name; the additional NB record
        // says whether it is a group name.
        let flag = msg
            .additional
            .iter()
            .find(|r| r.rtype == TYPE_NB)
            .and_then(|r| group_flag(&r.data));
        for q in &msg.questions {
            if let Some((name, suffix)) = decode_first_label(&q.name) {
                out.claimed.push(NbName {
                    name,
                    suffix,
                    is_group: flag,
                });
            }
        }
    }
    if msg.is_response && msg.opcode == OPCODE_QUERY {
        for r in msg.answers.iter().filter(|r| r.rtype == TYPE_NB) {
            if let Some((name, suffix)) = decode_first_label(&r.name) {
                out.answered.push(NbName {
                    name,
                    suffix,
                    is_group: group_flag(&r.data),
                });
            }
        }
    }
    Some(out)
}

/// First-level encode a name and suffix (test builders and symmetry).
#[must_use]
pub fn encode_name(name: &str, suffix: u8) -> String {
    let mut raw = [b' '; 16];
    for (slot, b) in raw.iter_mut().zip(name.bytes().take(15)) {
        *slot = b.to_ascii_uppercase();
    }
    raw[15] = suffix;
    let mut out = String::with_capacity(32);
    for b in raw {
        out.push(char::from(b'A' + (b >> 4)));
        out.push(char::from(b'A' + (b & 0x0F)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_encoding_round_trips() {
        let encoded = encode_name("ENG-WS01", SUFFIX_WORKSTATION);
        assert_eq!(encoded.len(), 32);
        assert_eq!(decode_name(&encoded), Some(("ENG-WS01".into(), 0x00)));
        assert_eq!(decode_name("too short"), None);
    }

    #[test]
    fn registration_claims_the_question_name() {
        let mut m = vec![0, 1, 0x29, 0x10, 0, 1, 0, 0, 0, 0, 0, 1];
        let label = encode_name("ENG-WS01", SUFFIX_SERVER);
        let mut qname = vec![32];
        qname.extend_from_slice(label.as_bytes());
        qname.push(0);
        m.extend_from_slice(&qname);
        m.extend_from_slice(&[0, 0x20, 0, 1]);
        // additional NB record: pointer to the question name, unique (G=0), 10.0.0.5
        m.extend_from_slice(&[
            0xC0, 0x0C, 0, 0x20, 0, 1, 0, 0, 0, 60, 0, 6, 0x00, 0x00, 10, 0, 0, 5,
        ]);
        let msg = parse(&m).unwrap();
        assert_eq!(msg.opcode, OPCODE_REGISTRATION);
        assert_eq!(
            msg.claimed,
            vec![NbName {
                name: "ENG-WS01".into(),
                suffix: SUFFIX_SERVER,
                is_group: Some(false)
            }]
        );
    }
}
