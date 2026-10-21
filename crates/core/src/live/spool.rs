//! The capture spool: every frame a live capture reads, appended to a legacy
//! pcap file as it arrives. "Save as pcap" copies the spool; the packet
//! list reads single records back from it by offset, so the frames the UI
//! shows are never held in memory twice.
//!
//! Legacy pcap (magic `0xa1b2c3d4`, microsecond timestamps) rather than
//! pcapng: one link type per file is exactly what one interface gives, the
//! format is 24 bytes of header plus 16 per record, and everything from
//! Wireshark to this crate's own reader opens it.

use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::ingest::Linktype;
use crate::CoreError;

const MAGIC_MICROS: u32 = 0xa1b2_c3d4;
const GLOBAL_HEADER_LEN: u64 = 24;
const RECORD_HEADER_LEN: usize = 16;

/// Appends records to a spool file. Records reach the disk on
/// [`flush`](Self::flush); a caller publishes a record's offset only after
/// that, so any offset a reader holds is readable.
pub struct SpoolWriter {
    file: BufWriter<File>,
    /// Where the next record's header will start.
    offset: u64,
}

impl SpoolWriter {
    /// Create (or truncate) the spool at `path` with its global header.
    pub fn create(path: &Path, linktype: Linktype, snaplen: u32) -> Result<Self, CoreError> {
        let mut file = BufWriter::new(File::create(path)?);
        file.write_all(&MAGIC_MICROS.to_le_bytes())?;
        file.write_all(&2u16.to_le_bytes())?; // major version
        file.write_all(&4u16.to_le_bytes())?; // minor version
        file.write_all(&0i32.to_le_bytes())?; // thiszone
        file.write_all(&0u32.to_le_bytes())?; // sigfigs
        file.write_all(&snaplen.to_le_bytes())?;
        file.write_all(&(linktype.0 as u32).to_le_bytes())?;
        Ok(Self {
            file,
            offset: GLOBAL_HEADER_LEN,
        })
    }

    /// Append one record and return the offset its header starts at.
    pub fn write(
        &mut self,
        seconds: u32,
        micros: u32,
        orig_len: u32,
        data: &[u8],
    ) -> Result<u64, CoreError> {
        let at = self.offset;
        self.file.write_all(&seconds.to_le_bytes())?;
        self.file.write_all(&micros.to_le_bytes())?;
        self.file.write_all(&(data.len() as u32).to_le_bytes())?;
        self.file
            .write_all(&orig_len.max(data.len() as u32).to_le_bytes())?;
        self.file.write_all(data)?;
        self.offset += (RECORD_HEADER_LEN + data.len()) as u64;
        Ok(at)
    }

    pub fn flush(&mut self) -> Result<(), CoreError> {
        self.file.flush()?;
        Ok(())
    }

    /// Bytes written so far, header included.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.offset
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.offset == GLOBAL_HEADER_LEN
    }
}

/// One record read back from a spool.
#[derive(Debug, Clone, PartialEq)]
pub struct SpoolRecord {
    /// Epoch seconds, at the microsecond resolution the file stores.
    pub timestamp: f64,
    pub orig_len: u32,
    pub data: Vec<u8>,
}

/// Read the record whose header starts at `offset` (as returned by
/// [`SpoolWriter::write`]).
pub fn read_record(path: &Path, offset: u64) -> Result<SpoolRecord, CoreError> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut header = [0u8; RECORD_HEADER_LEN];
    file.read_exact(&mut header)?;
    let word =
        |i: usize| u32::from_le_bytes([header[i], header[i + 1], header[i + 2], header[i + 3]]);
    let (seconds, micros, caplen, orig_len) = (word(0), word(4), word(8), word(12));
    let mut data = vec![0u8; caplen as usize];
    file.read_exact(&mut data)?;
    Ok(SpoolRecord {
        timestamp: f64::from(seconds) + f64::from(micros) / 1_000_000.0,
        orig_len,
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip_by_offset() {
        let path =
            std::env::temp_dir().join(format!("purdungeon-spool-{}.pcap", std::process::id()));
        let mut spool = SpoolWriter::create(&path, Linktype::ETHERNET, 65535).unwrap();
        assert!(spool.is_empty());
        let first = spool.write(1_700_000_000, 250_000, 60, &[1, 2, 3]).unwrap();
        let second = spool.write(1_700_000_001, 0, 4, &[9, 8, 7, 6]).unwrap();
        spool.flush().unwrap();
        assert_eq!(first, GLOBAL_HEADER_LEN);
        assert_eq!(second, GLOBAL_HEADER_LEN + 16 + 3);
        assert_eq!(spool.len(), second + 16 + 4);

        let record = read_record(&path, second).unwrap();
        assert_eq!(record.data, vec![9, 8, 7, 6]);
        assert_eq!(record.orig_len, 4);
        assert!((record.timestamp - 1_700_000_001.0).abs() < 1e-9);
        let record = read_record(&path, first).unwrap();
        assert_eq!(record.data, vec![1, 2, 3]);
        assert_eq!(record.orig_len, 60);
        assert!((record.timestamp - 1_700_000_000.25).abs() < 1e-9);
        std::fs::remove_file(&path).ok();
    }
}
