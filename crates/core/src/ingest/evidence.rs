//! Evidence: one row per (device, kind, value, source) fact, accumulated in
//! memory during a parse and written once at the end — the same discipline
//! as hosts and flows. Role inference and the panels read these rows; no
//! later stage looks at packets.

use std::collections::HashMap;

use rusqlite::params;

use crate::CoreError;

/// Evidence kinds. Values are free text; the kind says how to read them.
pub mod kind {
    pub const HOSTNAME: &str = "hostname";
    pub const MAC: &str = "mac";
    pub const OS: &str = "os";
    pub const VENDOR: &str = "vendor";
    pub const VENDOR_CLASS: &str = "vendor-class";
    pub const DHCP_FINGERPRINT: &str = "dhcp-fingerprint";
    pub const DOMAIN: &str = "domain";
    pub const DESCRIPTION: &str = "description";
    pub const MODEL: &str = "model";
    pub const SYS_OBJECT_ID: &str = "sysobjectid";
    pub const CAPABILITIES: &str = "capabilities";
    pub const PORT: &str = "port";
    pub const SERVICE: &str = "service";
    pub const MANAGEMENT_ADDRESS: &str = "management-address";
    pub const LOCATION: &str = "location";
    pub const CONTACT: &str = "contact";
}

/// One thing a protocol said about a device, with how far to trust it.
#[derive(Debug, Clone, PartialEq)]
pub struct Fact {
    pub kind: &'static str,
    pub value: String,
    pub confidence: f64,
}

impl Fact {
    pub fn new(kind: &'static str, value: impl Into<String>, confidence: f64) -> Self {
        Self {
            kind,
            value: value.into(),
            confidence,
        }
    }
}

/// Push a fact unless the same kind and value is already in the list, so
/// one packet that repeats a name (A and AAAA records, say) counts once.
pub fn push_unique(facts: &mut Vec<Fact>, fact: Fact) {
    if !facts
        .iter()
        .any(|f| f.kind == fact.kind && f.value == fact.value)
    {
        facts.push(fact);
    }
}

struct Agg {
    first_seen: f64,
    last_seen: f64,
    count: i64,
    confidence: f64,
}

type Key = (i64, &'static str, String, &'static str);

#[derive(Default)]
pub(crate) struct EvidenceSink {
    rows: HashMap<Key, Agg>,
}

impl EvidenceSink {
    pub fn record(&mut self, host_id: i64, source: &'static str, fact: Fact, timestamp: f64) {
        let key = (host_id, fact.kind, fact.value, source);
        match self.rows.get_mut(&key) {
            Some(agg) => {
                agg.first_seen = agg.first_seen.min(timestamp);
                agg.last_seen = agg.last_seen.max(timestamp);
                agg.count += 1;
                agg.confidence = agg.confidence.max(fact.confidence);
            }
            None => {
                self.rows.insert(
                    key,
                    Agg {
                        first_seen: timestamp,
                        last_seen: timestamp,
                        count: 1,
                        confidence: fact.confidence,
                    },
                );
            }
        }
    }

    pub fn record_all(
        &mut self,
        host_id: i64,
        source: &'static str,
        facts: Vec<Fact>,
        timestamp: f64,
    ) {
        for fact in facts {
            self.record(host_id, source, fact, timestamp);
        }
    }

    /// Write every accumulated row, merging into rows an earlier capture
    /// already stored. Rows are written in key order so ids are stable.
    pub fn flush(&self, conn: &rusqlite::Connection) -> Result<(), CoreError> {
        let mut keys: Vec<&Key> = self.rows.keys().collect();
        keys.sort();
        let mut stmt = conn.prepare_cached(
            "INSERT INTO evidence
                (host_id, kind, value, source_protocol, first_seen, last_seen, confidence, count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(host_id, kind, value, source_protocol) DO UPDATE SET
                first_seen = MIN(first_seen, excluded.first_seen),
                last_seen = MAX(last_seen, excluded.last_seen),
                confidence = MAX(confidence, excluded.confidence),
                count = count + excluded.count",
        )?;
        for key in keys {
            let agg = &self.rows[key];
            stmt.execute(params![
                key.0,
                key.1,
                key.2,
                key.3,
                agg.first_seen,
                agg.last_seen,
                agg.confidence,
                agg.count
            ])?;
        }
        Ok(())
    }
}
