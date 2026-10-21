//! Capture files: stream a pcap/pcapng file record by record into the
//! [`Ingester`]. The whole file is one exclusive transaction with the packet
//! indexes dropped for the duration, which is what makes a 200 MB import
//! fast; a failed parse rolls back and leaves the session as it was.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;

use crate::ingest::Ingester;
use crate::store::schema;
use crate::types::ImportResult;
use crate::CoreError;

/// The reader buffer must hold one complete block - a full-snaplen (65535 B)
/// packet plus block framing - or parsing aborts with a buffer-too-small
/// error. 1 MB also leaves room for jumbo frames.
const READER_BUFFER_SIZE: usize = 1 << 20;

/// Parse a capture into a fresh session, clearing any existing data first.
pub fn parse_pcap(
    path: &Path,
    conn: &mut rusqlite::Connection,
    progress: &AtomicU64,
) -> Result<ImportResult, CoreError> {
    ingest(path, conn, progress, false)
}

/// Parse a capture into the *existing* session, merging its hosts and flows
/// with what is already there. Flows seen in more than one file fuse into a
/// single conversation row rather than duplicating.
pub fn append_pcap(
    path: &Path,
    conn: &mut rusqlite::Connection,
    progress: &AtomicU64,
) -> Result<ImportResult, CoreError> {
    ingest(path, conn, progress, true)
}

fn ingest(
    path: &Path,
    conn: &mut rusqlite::Connection,
    progress: &AtomicU64,
    append: bool,
) -> Result<ImportResult, CoreError> {
    // Stream from the file rather than reading it whole into memory, so several
    // large captures don't multiply RAM. Peek the magic to pick the reader,
    // then rewind.
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut magic = [0u8; 4];
    if reader.read_exact(&mut magic).is_err() {
        return Err(CoreError::Parse("file too small".into()));
    }
    reader.seek(SeekFrom::Start(0))?;
    let is_pcapng = u32::from_le_bytes(magic) == 0x0A0D_0D0A;

    // One transaction covers everything, the destructive prep included, so a
    // failed parse leaves the previous session exactly as it was - dropping
    // the transaction rolls back.
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)?;

    // A fresh import wipes prior data; an append keeps it and adds to it.
    if !append {
        schema::clear_data(&tx)?;
    }
    schema::drop_packet_indexes(&tx)?;

    let mut ingester = Ingester::begin(&tx, append)?;
    if is_pcapng {
        parse_pcapng_data(reader, &tx, &mut ingester, progress)?;
    } else {
        parse_legacy_data(reader, &tx, &mut ingester, progress)?;
    }
    if let Some(error) = ingester.unsupported_only() {
        return Err(error);
    }

    // The file has been read to its end, so every pending fact is attributed.
    ingester.checkpoint(&tx, 0.0)?;

    // Recreate indexes after all data is inserted
    schema::create_packet_indexes(&tx)?;
    tx.commit()?;

    Ok(ingester.result())
}

/// Per-interface decoding parameters from an Interface Description Block.
struct IfaceInfo {
    ts_offset: u64,
    resolution: u64,
    linktype: Linktype,
}

fn parse_pcapng_data<R: Read>(
    source: R,
    conn: &rusqlite::Connection,
    ingester: &mut Ingester,
    progress: &AtomicU64,
) -> Result<(), CoreError> {
    let mut reader = PcapNGReader::new(READER_BUFFER_SIZE, source)
        .map_err(|e| CoreError::Parse(format!("pcapng reader: {e}")))?;

    let mut if_info: Vec<IfaceInfo> = Vec::new();

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    // Interface ids are scoped to their section, so a new
                    // section (mergecap output, rotated captures) starts a
                    // fresh interface table.
                    PcapBlockOwned::NG(Block::SectionHeader(_)) => {
                        if_info.clear();
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                        if_info.push(IfaceInfo {
                            ts_offset: idb.if_tsoffset as u64,
                            resolution: idb.ts_resolution().unwrap_or(1_000_000),
                            linktype: idb.linktype,
                        });
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                        // A packet on an interface this section never
                        // described has no link type or clock to decode with.
                        if let Some(info) = if_info.get(epb.if_id as usize) {
                            let ts = epb.decode_ts_f64(info.ts_offset, info.resolution);
                            let orig_len = epb.origlen.max(epb.caplen);
                            // EPB data is padded to a 32-bit boundary; the
                            // real capture length is caplen.
                            let data = epb.data.get(..epb.caplen as usize).unwrap_or(epb.data);
                            ingester.push_frame(conn, info.linktype, data, orig_len, ts)?;
                        } else {
                            ingester.count_malformed_record();
                        }
                    }
                    // Simple Packet Blocks carry no timestamp; inventing one
                    // would poison first/last-seen, so they are skipped and
                    // counted instead.
                    PcapBlockOwned::NG(Block::SimplePacket(_)) => {
                        ingester.count_untimed_record();
                    }
                    _ => {}
                }
                reader.consume(offset);
                progress.fetch_add(offset as u64, Ordering::Relaxed);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader
                    .refill()
                    .map_err(|e| CoreError::Parse(format!("refill: {e}")))?;
            }
            // The file ends in the middle of a block: the capture tool was
            // killed mid-write. Keep what was read and count the stub.
            Err(PcapError::UnexpectedEof) => {
                ingester.count_malformed_record();
                break;
            }
            Err(e) => return Err(CoreError::Parse(format!("pcapng: {e}"))),
        }
    }
    Ok(())
}

fn parse_legacy_data<R: Read>(
    source: R,
    conn: &rusqlite::Connection,
    ingester: &mut Ingester,
    progress: &AtomicU64,
) -> Result<(), CoreError> {
    let mut reader = LegacyPcapReader::new(READER_BUFFER_SIZE, source)
        .map_err(|e| CoreError::Parse(format!("pcap reader: {e}")))?;

    // tcpdump's nanosecond variant (magic 0xa1b23c4d) stores nanoseconds in
    // the sub-second field; everything else stores microseconds.
    let mut ts_divisor = 1_000_000.0;
    let mut linktype = Linktype::ETHERNET;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(header) => {
                        // The upper half of the link-type word carries the
                        // FCS length and a flag bit (draft-ietf-opsawg-pcap
                        // §4); only the low 16 bits name the link type.
                        linktype = Linktype(header.network.0 & 0xFFFF);
                        if header.is_nanosecond_precision() {
                            ts_divisor = 1_000_000_000.0;
                        }
                    }
                    PcapBlockOwned::Legacy(packet) => {
                        let ts = f64::from(packet.ts_sec) + f64::from(packet.ts_usec) / ts_divisor;
                        let orig_len = packet.origlen.max(packet.caplen);
                        ingester.push_frame(conn, linktype, packet.data, orig_len, ts)?;
                    }
                    PcapBlockOwned::NG(_) => {}
                }
                reader.consume(offset);
                progress.fetch_add(offset as u64, Ordering::Relaxed);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader
                    .refill()
                    .map_err(|e| CoreError::Parse(format!("refill: {e}")))?;
            }
            Err(PcapError::UnexpectedEof) => {
                ingester.count_malformed_record();
                break;
            }
            Err(e) => return Err(CoreError::Parse(format!("pcap: {e}"))),
        }
    }
    Ok(())
}
