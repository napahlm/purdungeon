//! The packet list's backing store: the most recent rows of a capture, in a
//! bounded ring so a day-long capture costs a fixed amount of memory. The
//! spool on disk keeps every frame; the ring only keeps what the list can
//! usefully scroll through.

use std::collections::VecDeque;

use crate::live::types::{PacketPage, PacketRow};

/// Rows kept by default: at a few hundred bytes each, under 100 MB.
pub const DEFAULT_RING_CAPACITY: usize = 200_000;

pub struct PacketRing {
    rows: VecDeque<PacketRow>,
    capacity: usize,
}

impl PacketRing {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            rows: VecDeque::with_capacity(capacity.min(DEFAULT_RING_CAPACITY)),
            capacity: capacity.max(1),
        }
    }

    pub fn push(&mut self, row: PacketRow) {
        if self.rows.len() == self.capacity {
            self.rows.pop_front();
        }
        self.rows.push_back(row);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The oldest frame number still held (the next one to be pushed when
    /// the ring is empty, so a UI can always anchor on it).
    #[must_use]
    pub fn first_no(&self) -> u64 {
        self.rows.front().map_or(1, |row| row.no)
    }

    #[must_use]
    pub fn get(&self, no: u64) -> Option<&PacketRow> {
        let first = self.rows.front()?.no;
        if no < first {
            return None;
        }
        let index = usize::try_from(no - first).ok()?;
        self.rows.get(index).filter(|row| row.no == no)
    }

    /// `limit` rows starting `offset` rows into the ones that match `query`
    /// (a case-insensitive substring of source, destination, protocol or
    /// info; empty matches everything).
    #[must_use]
    pub fn page(&self, offset: usize, limit: usize, query: Option<&str>) -> PacketPage {
        let query = query.map(str::trim).filter(|q| !q.is_empty());
        let (total, rows) = match query {
            None => (
                self.rows.len(),
                self.rows.iter().skip(offset).take(limit).cloned().collect(),
            ),
            Some(q) => {
                let needle = q.to_lowercase();
                let mut total = 0;
                let mut rows = Vec::new();
                for row in &self.rows {
                    if !matches(row, &needle) {
                        continue;
                    }
                    if total >= offset && rows.len() < limit {
                        rows.push(row.clone());
                    }
                    total += 1;
                }
                (total, rows)
            }
        };
        PacketPage {
            total,
            first_no: self.first_no(),
            offset,
            rows,
        }
    }
}

fn matches(row: &PacketRow, needle: &str) -> bool {
    row.src.to_lowercase().contains(needle)
        || row.dst.to_lowercase().contains(needle)
        || row.protocol.to_lowercase().contains(needle)
        || row.info.to_lowercase().contains(needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(no: u64, protocol: &str, info: &str) -> PacketRow {
        PacketRow {
            no,
            timestamp: no as f64,
            src: format!("10.0.0.{}", no % 3),
            dst: "10.0.0.9".into(),
            protocol: protocol.into(),
            app_protocol: None,
            length: 64,
            info: info.into(),
            spool_offset: no * 100,
        }
    }

    #[test]
    fn eviction_keeps_numbers_monotonic_and_lookups_exact() {
        let mut ring = PacketRing::new(3);
        for no in 1..=5 {
            ring.push(row(no, "TCP", ""));
        }
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.first_no(), 3);
        assert!(ring.get(2).is_none());
        assert_eq!(ring.get(3).map(|r| r.no), Some(3));
        assert_eq!(ring.get(5).map(|r| r.spool_offset), Some(500));
        assert!(ring.get(6).is_none());
    }

    #[test]
    fn pages_filter_case_insensitively_and_count_matches_not_rows() {
        let mut ring = PacketRing::new(10);
        ring.push(row(1, "Modbus", "Query: Read Coils"));
        ring.push(row(2, "TCP", "49000 -> 502 [ACK]"));
        ring.push(row(3, "Modbus", "Response: Read Coils"));
        ring.push(row(4, "ARP", "Who has 10.0.0.1?"));

        let page = ring.page(0, 10, Some("modbus"));
        assert_eq!(page.total, 2);
        assert_eq!(page.rows.iter().map(|r| r.no).collect::<Vec<_>>(), [1, 3]);

        let page = ring.page(1, 1, Some("MODBUS"));
        assert_eq!((page.total, page.offset), (2, 1));
        assert_eq!(page.rows.iter().map(|r| r.no).collect::<Vec<_>>(), [3]);

        let page = ring.page(0, 10, Some("who has"));
        assert_eq!(page.rows.iter().map(|r| r.no).collect::<Vec<_>>(), [4]);

        let page = ring.page(9, 5, None);
        assert_eq!(page.total, 4);
        assert!(page.rows.is_empty());
        assert_eq!(page.first_no, 1);

        let page = ring.page(0, 10, Some("  "));
        assert_eq!(page.total, 4);
    }

    #[test]
    fn empty_ring_anchors_on_frame_one() {
        let ring = PacketRing::new(5);
        assert!(ring.is_empty());
        assert_eq!(ring.first_no(), 1);
        assert_eq!(ring.page(0, 10, None).total, 0);
    }
}
