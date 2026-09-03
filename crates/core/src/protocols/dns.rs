//! Minimal DNS wire-format reader (RFC 1035 §4.1) for the identity chatter
//! that rides on it: mDNS (RFC 6762), LLMNR (RFC 4795) and the `NetBIOS` name
//! service (RFC 1002, which borrows the layout). It reads only what device
//! identity needs — names and A/AAAA/PTR/SRV/TXT records — and keeps the raw
//! bytes of anything else so callers can decode protocol-specific records.
//!
//! A truncated message yields the records that were complete; nothing here
//! can panic on hostile input, and name compression is hop-limited.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;

/// Records per section and name length are capped so a hostile packet cannot
/// make us allocate without bound.
const MAX_RECORDS: usize = 64;
const MAX_NAME_LEN: usize = 255;
const MAX_POINTER_HOPS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ptr(String),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Txt(Vec<String>),
    /// Any other type, or a typed record whose rdata did not decode.
    Other(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub data: RData,
}

#[derive(Debug, Clone)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, Default)]
pub struct DnsMessage {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
}

fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]))
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *bytes.get(at)?,
        *bytes.get(at + 1)?,
        *bytes.get(at + 2)?,
        *bytes.get(at + 3)?,
    ]))
}

/// Parse a message. `None` only when the 12-byte header is missing.
#[must_use]
pub fn parse(bytes: &[u8]) -> Option<DnsMessage> {
    if bytes.len() < 12 {
        return None;
    }
    let flags = be16(bytes, 2)?;
    let mut msg = DnsMessage {
        id: be16(bytes, 0)?,
        is_response: flags & 0x8000 != 0,
        opcode: ((flags >> 11) & 0x0F) as u8,
        ..DnsMessage::default()
    };
    let counts = [
        usize::from(be16(bytes, 4)?),
        usize::from(be16(bytes, 6)?),
        usize::from(be16(bytes, 8)?),
        usize::from(be16(bytes, 10)?),
    ];

    let mut cursor = 12;
    for _ in 0..counts[0].min(MAX_RECORDS) {
        let Some((name, next)) = read_name(bytes, cursor) else {
            return Some(msg);
        };
        let (Some(qtype), Some(qclass)) = (be16(bytes, next), be16(bytes, next + 2)) else {
            return Some(msg);
        };
        msg.questions.push(Question {
            name,
            qtype,
            qclass,
        });
        cursor = next + 4;
    }

    let mut sections: [Vec<Record>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    'sections: for (section, count) in sections.iter_mut().zip(counts[1..].iter()) {
        for _ in 0..(*count).min(MAX_RECORDS) {
            let Some((record, next)) = read_record(bytes, cursor) else {
                break 'sections; // truncated: keep what was complete
            };
            section.push(record);
            cursor = next;
        }
    }
    let [answers, authority, additional] = sections;
    msg.answers = answers;
    msg.authority = authority;
    msg.additional = additional;
    Some(msg)
}

/// Read a possibly-compressed name starting at `start`. Returns the dotted
/// name and the offset just past it in the *uncompressed* stream.
fn read_name(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut resume: Option<usize> = None;
    let mut hops = 0;
    let mut total = 0;
    loop {
        let len = usize::from(*bytes.get(pos)?);
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer (RFC 1035 §4.1.4).
            let target = ((len & 0x3F) << 8) | usize::from(*bytes.get(pos + 1)?);
            if resume.is_none() {
                resume = Some(pos + 2);
            }
            hops += 1;
            if hops > MAX_POINTER_HOPS || target >= bytes.len() {
                return None;
            }
            pos = target;
            continue;
        }
        if len & 0xC0 != 0 {
            return None; // reserved label types
        }
        let label = bytes.get(pos + 1..pos + 1 + len)?;
        total += len + 1;
        if total > MAX_NAME_LEN {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += 1 + len;
    }
    Some((labels.join("."), resume.unwrap_or(pos)))
}

fn read_record(bytes: &[u8], start: usize) -> Option<(Record, usize)> {
    let (name, at) = read_name(bytes, start)?;
    let rtype = be16(bytes, at)?;
    let rclass = be16(bytes, at + 2)?;
    let ttl = be32(bytes, at + 4)?;
    let rdlength = usize::from(be16(bytes, at + 8)?);
    let rdata_at = at + 10;
    let rdata = bytes.get(rdata_at..rdata_at + rdlength)?;
    let data =
        decode_rdata(bytes, rdata_at, rtype, rdata).unwrap_or_else(|| RData::Other(rdata.to_vec()));
    Some((
        Record {
            name,
            rtype,
            rclass,
            ttl,
            data,
        },
        rdata_at + rdlength,
    ))
}

fn decode_rdata(bytes: &[u8], rdata_at: usize, rtype: u16, rdata: &[u8]) -> Option<RData> {
    match rtype {
        TYPE_A => <[u8; 4]>::try_from(rdata)
            .ok()
            .map(|a| RData::A(Ipv4Addr::from(a))),
        TYPE_AAAA => <[u8; 16]>::try_from(rdata)
            .ok()
            .map(|a| RData::Aaaa(Ipv6Addr::from(a))),
        TYPE_PTR => read_name(bytes, rdata_at).map(|(n, _)| RData::Ptr(n)),
        TYPE_SRV => {
            let (target, _) = read_name(bytes, rdata_at + 6)?;
            Some(RData::Srv {
                priority: be16(rdata, 0)?,
                weight: be16(rdata, 2)?,
                port: be16(rdata, 4)?,
                target,
            })
        }
        TYPE_TXT => {
            let mut items = Vec::new();
            let mut pos = 0;
            while pos < rdata.len() {
                let len = usize::from(rdata[pos]);
                let item = rdata.get(pos + 1..pos + 1 + len)?;
                items.push(String::from_utf8_lossy(item).into_owned());
                pos += 1 + len;
            }
            Some(RData::Txt(items))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(labels: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for label in labels {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    #[test]
    fn response_with_a_ptr_srv_txt_and_compression() {
        let mut m = vec![0x12, 0x34, 0x84, 0x00, 0, 0, 0, 3, 0, 0, 0, 1];
        // Answer 1: printer.local A 10.0.0.9 (owner at offset 12)
        m.extend(name(&["printer", "local"]));
        m.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 10, 0, 0, 9]);
        // Answer 2: _ipp._tcp.local PTR Printer._ipp._tcp.local (owner literal, target pointer)
        m.extend(name(&["_ipp", "_tcp", "local"]));
        m.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0, 120, 0, 10]);
        m.push(7);
        m.extend_from_slice(b"Printer");
        m.extend_from_slice(&[0xC0, 0x29]); // pointer to _ipp._tcp.local at offset 41
                                            // Answer 3: Printer._ipp._tcp.local (pointer to offset 68) SRV 0 0 631
                                            // printer.local (pointer to offset 12)
        m.extend_from_slice(&[0xC0, 0x44]);
        m.extend_from_slice(&[
            0, 33, 0, 1, 0, 0, 0, 120, 0, 8, 0, 0, 0, 0, 0x02, 0x77, 0xC0, 0x0C,
        ]);
        // Additional: TXT model=Deskjet on the same instance name
        m.extend_from_slice(&[0xC0, 0x44, 0, 16, 0, 1, 0, 0, 0, 120, 0, 14, 13]);
        m.extend_from_slice(b"model=Deskjet");

        let msg = parse(&m).unwrap();
        assert!(msg.is_response);
        assert_eq!(msg.answers.len(), 3);
        assert_eq!(msg.answers[0].name, "printer.local");
        assert_eq!(msg.answers[0].data, RData::A(Ipv4Addr::new(10, 0, 0, 9)));
        assert_eq!(
            msg.answers[1].data,
            RData::Ptr("Printer._ipp._tcp.local".into())
        );
        assert_eq!(msg.answers[2].name, "Printer._ipp._tcp.local");
        assert!(
            matches!(&msg.answers[2].data, RData::Srv { port: 631, target, .. } if target == "printer.local")
        );
        assert_eq!(
            msg.additional[0].data,
            RData::Txt(vec!["model=Deskjet".into()])
        );
    }

    #[test]
    fn pointer_loops_and_truncation_are_survivable() {
        let mut looped = vec![0, 1, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        looped.extend_from_slice(&[0xC0, 0x0C]); // points at itself
        let msg = parse(&looped).unwrap();
        assert!(msg.answers.is_empty());

        let mut cut = vec![0, 1, 0x84, 0, 0, 0, 0, 2, 0, 0, 0, 0];
        cut.extend(name(&["host", "local"]));
        cut.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 10, 0, 0, 1]);
        cut.extend_from_slice(&[4, b'o', b't', b'h']); // second record cut mid-label
        let msg = parse(&cut).unwrap();
        assert_eq!(msg.answers.len(), 1);
        assert!(parse(&[0u8; 5]).is_none());
    }
}
