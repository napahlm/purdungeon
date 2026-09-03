//! Capture ingest: stream a pcap/pcapng file, decode every frame, and fold
//! hosts, flows, packets and identity evidence into the session database.
//! Nothing is dropped silently — every record ends up in `ImportResult`
//! either as decoded or as a counted reason for skipping, and the two always
//! add up to the frames read.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use rusqlite::params;

use crate::ingest::evidence::{kind, EvidenceSink, Fact};
use crate::ingest::frame::{self, Frame, IpFrame, Transport};
use crate::ingest::identity::{self, DhcpFacts, L2Facts, UdpFacts};
use crate::ingest::link::{self, LinkDecode, Macs};
use crate::oui;
use crate::protocols::{arp, ip_proto, modbus};
use crate::store::{queries, schema};
use crate::types::{ImportResult, LinkLayerCounts, SkippedPackets};
use crate::CoreError;

/// The reader buffer must hold one complete block — a full-snaplen (65535 B)
/// packet plus block framing — or parsing aborts with a buffer-too-small
/// error. 1 MB also leaves room for jumbo frames.
const READER_BUFFER_SIZE: usize = 1 << 20;

/// Link-layer protocols a host has been seen in, kept as bit flags on the
/// host cache and stored comma-joined in `hosts.link_protocols`.
pub const LINK_ARP: u8 = 1;
pub const LINK_LLDP: u8 = 2;
pub const LINK_CDP: u8 = 4;
const LINK_NAMES: [(u8, &str); 3] = [(LINK_ARP, "arp"), (LINK_LLDP, "lldp"), (LINK_CDP, "cdp")];

fn link_names(flags: u8) -> String {
    LINK_NAMES
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join(",")
}

fn link_flags(names: &str) -> u8 {
    names.split(',').fold(0, |acc, n| {
        acc | LINK_NAMES
            .iter()
            .find(|(_, name)| *name == n)
            .map_or(0, |(bit, _)| *bit)
    })
}

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

/// Directional flow identity: (src ip, dst ip, src port, dst port, IANA ip
/// protocol number). Port-less protocols use 0/0.
type FlowKey = (IpAddr, IpAddr, u16, u16, u8);

/// Facts waiting for the host they belong to, each with when it was seen.
type PendingFacts = Vec<(Fact, f64)>;
type PendingAnnouncements = Vec<(L2Facts, f64)>;

/// Broadcast, multicast and unspecified addresses are not devices; their
/// MACs are group addresses or a client's before it has an address.
fn is_pseudo_host(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast(),
        IpAddr::V6(v6) => v6.is_unspecified() || v6.is_multicast(),
    }
}

/// Where a MAC address for a host was learned, and how much that is worth.
/// A frame's source MAC is the last hop's — a router's for anything beyond
/// the local segment — whereas ARP, DHCP and LLDP/CDP name the device's own.
#[derive(Clone, Copy)]
enum MacSource {
    Frame,
    Arp,
    Dhcp,
    Announcement(&'static str),
}

impl MacSource {
    fn name(self) -> &'static str {
        match self {
            Self::Frame => "ethernet",
            Self::Arp => "arp",
            Self::Dhcp => "dhcp",
            Self::Announcement(source) => source,
        }
    }

    fn confidence(self) -> f64 {
        match self {
            Self::Frame => 0.5,
            Self::Arp => 0.95,
            Self::Dhcp | Self::Announcement(_) => 0.9,
        }
    }
}

/// Per-host aggregate accumulated in memory during a parse and flushed to the
/// DB once at the end, instead of issuing an UPDATE per packet.
struct HostAgg {
    id: i64,
    first_seen: f64,
    last_seen: f64,
    /// Link-layer protocols this parse saw the host in.
    link_seen: u8,
    /// What the stored row already lists, so the flush only writes changes.
    link_stored: u8,
    /// The last MAC a frame carried for this host, so the hot path only
    /// records evidence when it changes.
    last_frame_mac: Option<[u8; 6]>,
}

impl HostAgg {
    fn new(id: i64, timestamp: f64, link: u8) -> Self {
        Self {
            id,
            first_seen: timestamp,
            last_seen: timestamp,
            link_seen: link,
            link_stored: 0,
            last_frame_mac: None,
        }
    }

    fn touch(&mut self, timestamp: f64, link: u8) {
        self.first_seen = self.first_seen.min(timestamp);
        self.last_seen = self.last_seen.max(timestamp);
        self.link_seen |= link;
    }
}

/// Per-flow aggregate, same idea. `packets`/`bytes` count only this parse —
/// the flush adds them to whatever the row already holds, so appends compose.
struct FlowAgg {
    id: i64,
    packets: i64,
    bytes: i64,
    first_seen: f64,
    last_seen: f64,
    tagged: bool,
    late_tag: Option<&'static str>,
}

#[derive(Default)]
struct IngestState {
    hosts: HashMap<IpAddr, HostAgg>,
    /// Devices known only by MAC: seen in LLDP, CDP or DHCP but never in IP
    /// traffic the capture point could see.
    mac_hosts: HashMap<[u8; 6], HostAgg>,
    /// MAC → hosts that ARP, DHCP or an announcement say own it.
    mac_index: HashMap<[u8; 6], Vec<i64>>,
    /// MAC → hosts whose frames carried it (possibly a router's MAC).
    frame_mac_index: HashMap<[u8; 6], Vec<i64>>,
    flows: HashMap<FlowKey, FlowAgg>,
    evidence: EvidenceSink,
    /// DHCP client facts waiting for the exchange to name the client.
    dhcp_pending: HashMap<[u8; 6], PendingFacts>,
    /// LLDP/CDP announcements by sender MAC, attributed once every host is
    /// known so a device is not split into a MAC-only asset and an IP one.
    l2_pending: HashMap<[u8; 6], PendingAnnouncements>,
    /// Every record read from the file, whatever became of it.
    frames_read: usize,
    /// Frames that became rows in `packets`.
    packet_count: usize,
    decoded: LinkLayerCounts,
    skipped: SkippedPackets,
    /// First unreadable link type seen, for the error message when a capture
    /// yields nothing at all.
    unsupported_linktype: Option<String>,
    min_ts: f64,
    max_ts: f64,
}

impl IngestState {
    fn new() -> Self {
        Self {
            min_ts: f64::MAX,
            max_ts: f64::MIN,
            ..Self::default()
        }
    }
}

fn unsupported_linktype_error(linktype: &str) -> CoreError {
    CoreError::Parse(format!(
        "this capture uses link type {linktype}; purdungeon reads Ethernet, \
         Linux cooked (tcpdump -i any), raw IP and loopback captures — convert \
         it with Wireshark or editcap, or re-capture on an Ethernet interface"
    ))
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
    // failed parse leaves the previous session exactly as it was — dropping
    // the transaction rolls back.
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)?;

    // A fresh import wipes prior data; an append keeps it and adds to it.
    if !append {
        schema::clear_data(&tx)?;
    }
    schema::drop_packet_indexes(&tx)?;

    let mut state = IngestState::new();
    // On append, seed the caches from existing rows so the same host or flow
    // resolves to its existing id instead of being inserted again.
    if append {
        preload_caches(&tx, &mut state)?;
    }

    if is_pcapng {
        parse_pcapng_data(reader, &tx, &mut state, progress)?;
    } else {
        parse_legacy_data(reader, &tx, &mut state, progress)?;
    }

    debug_assert_eq!(
        state.frames_read,
        state.packet_count + state.skipped.total(),
        "frame accounting must reconcile"
    );
    debug_assert_eq!(state.packet_count, state.decoded.total());

    // A capture whose every frame sits on a link type we cannot read should
    // say so rather than import as empty.
    if state.packet_count == 0
        && state.frames_read > 0
        && state.skipped.unsupported_link_type == state.frames_read
    {
        if let Some(linktype) = &state.unsupported_linktype {
            return Err(unsupported_linktype_error(linktype));
        }
    }

    resolve_pending(&tx, &mut state)?;
    flush_aggregates(&tx, &state)?;
    state.evidence.flush(&tx)?;

    // Recreate indexes after all data is inserted
    schema::create_packet_indexes(&tx)?;
    tx.commit()?;

    if state.min_ts > state.max_ts {
        state.min_ts = 0.0;
        state.max_ts = 0.0;
    }

    Ok(ImportResult {
        frames_read: state.frames_read,
        packet_count: state.packet_count,
        decoded: state.decoded,
        skipped: state.skipped,
        host_count: state.hosts.len() + state.mac_hosts.len(),
        connection_count: state.flows.len(),
        time_range: (state.min_ts, state.max_ts),
    })
}

/// Addresses are only ever written by `IpAddr::to_string`, so a stored row
/// that fails to parse means the session is corrupt — better to say so than
/// to skip it and hit the UNIQUE constraint on the next insert.
fn parse_stored_ip(text: &str) -> Result<IpAddr, CoreError> {
    text.parse().map_err(|_| {
        CoreError::Internal(format!("stored host address {text:?} is not an IP address"))
    })
}

fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = text.split(':');
    for slot in &mut out {
        *slot = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// Rebuild the host and flow caches from the session so an append reuses
/// existing ids. Aggregates start empty — the flush only adds what this
/// parse contributes on top of the stored rows.
fn preload_caches(conn: &rusqlite::Connection, state: &mut IngestState) -> Result<(), CoreError> {
    let mut stmt = conn.prepare("SELECT id, ip_address, mac_address, link_protocols FROM hosts")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    for row in rows {
        let (id, ip, mac, links) = row?;
        let mut agg = HostAgg::new(id, f64::MAX, 0);
        agg.last_seen = f64::MIN;
        agg.link_stored = link_flags(&links);
        if let Some(ip) = ip {
            let ip = parse_stored_ip(&ip)?;
            if let Some(mac) = parse_mac(&mac).filter(|_| !is_pseudo_host(ip)) {
                agg.last_frame_mac = Some(mac);
                state.frame_mac_index.entry(mac).or_default().push(id);
            }
            state.hosts.insert(ip, agg);
        } else {
            let mac = parse_mac(&mac).ok_or_else(|| {
                CoreError::Internal(format!("stored MAC-only host {mac:?} has no valid MAC"))
            })?;
            state.mac_hosts.insert(mac, agg);
        }
    }

    let mut stmt = conn.prepare(
        "SELECT c.id, hs.ip_address, c.src_port, ds.ip_address, c.dst_port, c.protocol, c.app_protocol
         FROM connections c
         JOIN hosts hs ON hs.id = c.src_host_id
         JOIN hosts ds ON ds.id = c.dst_host_id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, u16>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, u16>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, Option<String>>(6)?,
        ))
    })?;
    for row in rows {
        let (id, src_ip, src_port, dst_ip, dst_port, protocol, app_protocol) = row?;
        let ip_proto = ip_proto::number(&protocol).ok_or_else(|| {
            CoreError::Internal(format!(
                "stored protocol {protocol:?} has no IP protocol number"
            ))
        })?;
        let key = (
            parse_stored_ip(&src_ip)?,
            parse_stored_ip(&dst_ip)?,
            src_port,
            dst_port,
            ip_proto,
        );
        state.flows.insert(
            key,
            FlowAgg {
                id,
                packets: 0,
                bytes: 0,
                first_seen: f64::MAX,
                last_seen: f64::MIN,
                tagged: app_protocol.is_some(),
                late_tag: None,
            },
        );
    }
    Ok(())
}

/// Write the accumulated per-host and per-flow aggregates in one pass.
/// Untouched entries (preloaded on append but not seen in this file) are
/// skipped so an append only writes what changed.
fn flush_aggregates(conn: &rusqlite::Connection, state: &IngestState) -> Result<(), CoreError> {
    let mut host_stmt = conn.prepare_cached(
        "UPDATE hosts SET
            first_seen = MIN(first_seen, ?1),
            last_seen = MAX(last_seen, ?2)
         WHERE id = ?3",
    )?;
    let mut link_stmt =
        conn.prepare_cached("UPDATE hosts SET link_protocols = ?1 WHERE id = ?2")?;
    for agg in state.hosts.values().chain(state.mac_hosts.values()) {
        if agg.first_seen <= agg.last_seen {
            host_stmt.execute(params![agg.first_seen, agg.last_seen, agg.id])?;
        }
        let links = agg.link_seen | agg.link_stored;
        if links != agg.link_stored {
            link_stmt.execute(params![link_names(links), agg.id])?;
        }
    }

    let mut flow_stmt = conn.prepare_cached(
        "UPDATE connections SET
            packet_count = packet_count + ?1,
            byte_count = byte_count + ?2,
            first_seen = MIN(first_seen, ?3),
            last_seen = MAX(last_seen, ?4)
         WHERE id = ?5",
    )?;
    let mut tag_stmt =
        conn.prepare_cached("UPDATE connections SET app_protocol = ?1 WHERE id = ?2")?;
    for agg in state.flows.values() {
        if agg.packets > 0 {
            flow_stmt.execute(params![
                agg.packets,
                agg.bytes,
                agg.first_seen,
                agg.last_seen,
                agg.id
            ])?;
        }
        if let Some(tag) = agg.late_tag {
            tag_stmt.execute(params![tag, agg.id])?;
        }
    }
    Ok(())
}

/// Attribute the facts that could not be placed while parsing: DHCP client
/// facts whose exchange never named an address, and LLDP/CDP announcements,
/// which are keyed by MAC. Done last so every IP host is already known and a
/// device is not split into a MAC-only asset and an IP one.
fn resolve_pending(conn: &rusqlite::Connection, state: &mut IngestState) -> Result<(), CoreError> {
    let mut dhcp: Vec<([u8; 6], PendingFacts)> = state.dhcp_pending.drain().collect();
    dhcp.sort_by_key(|(mac, _)| *mac);
    for (mac, facts) in dhcp {
        let first_ts = facts.iter().map(|(_, ts)| *ts).fold(f64::MAX, f64::min);
        let id = host_for_mac(conn, state, mac, 0, first_ts)?;
        for (fact, ts) in facts {
            state.evidence.record(id, "dhcp", fact, ts);
        }
    }

    let mut announcements: Vec<([u8; 6], PendingAnnouncements)> =
        state.l2_pending.drain().collect();
    announcements.sort_by_key(|(mac, _)| *mac);
    for (mac, items) in announcements {
        for (l2, ts) in items {
            let link = if l2.source == "lldp" {
                LINK_LLDP
            } else {
                LINK_CDP
            };
            let id = match l2.management.first() {
                Some(address) => upsert_host(
                    conn,
                    state,
                    *address,
                    Some(&mac),
                    MacSource::Announcement(l2.source),
                    link,
                    ts,
                )?,
                None => host_for_mac(conn, state, mac, link, ts)?,
            };
            state.evidence.record_all(id, l2.source, l2.facts, ts);
        }
    }
    Ok(())
}

/// The host a MAC belongs to: the one ARP/DHCP/announcements say owns it,
/// else the only host whose frames carried it, else a new MAC-only asset.
fn host_for_mac(
    conn: &rusqlite::Connection,
    state: &mut IngestState,
    mac: [u8; 6],
    link: u8,
    timestamp: f64,
) -> Result<i64, CoreError> {
    let known = state
        .mac_index
        .get(&mac)
        .or_else(|| state.frame_mac_index.get(&mac))
        .and_then(|ids| match ids.as_slice() {
            [only] => Some(*only),
            _ => None,
        });
    if let Some(id) = known {
        if let Some(agg) = state.hosts.values_mut().find(|agg| agg.id == id) {
            agg.touch(timestamp, link);
        }
        return Ok(id);
    }
    upsert_mac_host(conn, state, mac, link, timestamp)
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
    state: &mut IngestState,
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
                            process_frame(data, orig_len, ts, info.linktype, conn, state)?;
                        } else {
                            state.frames_read += 1;
                            state.skipped.malformed += 1;
                        }
                    }
                    // Simple Packet Blocks carry no timestamp; inventing one
                    // would poison first/last-seen, so they are skipped and
                    // counted instead.
                    PcapBlockOwned::NG(Block::SimplePacket(_)) => {
                        state.frames_read += 1;
                        state.skipped.no_timestamp += 1;
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
                state.frames_read += 1;
                state.skipped.malformed += 1;
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
    state: &mut IngestState,
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
                        process_frame(packet.data, orig_len, ts, linktype, conn, state)?;
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
                state.frames_read += 1;
                state.skipped.malformed += 1;
                break;
            }
            Err(e) => return Err(CoreError::Parse(format!("pcap: {e}"))),
        }
    }
    Ok(())
}

/// Decode one capture record and fold it into the session. `orig_len` is the
/// packet's length on the wire — captures taken with a snaplen truncate
/// `data`, and byte counts must reflect the wire, not the truncation.
fn process_frame(
    data: &[u8],
    orig_len: u32,
    timestamp: f64,
    linktype: Linktype,
    conn: &rusqlite::Connection,
    state: &mut IngestState,
) -> Result<(), CoreError> {
    state.frames_read += 1;
    // A zero or negative timestamp cannot be placed on the timeline, and
    // recording it would pin first-seen to 1970 for every host in the frame.
    if timestamp <= 0.0 {
        state.skipped.no_timestamp += 1;
        return Ok(());
    }
    let cut_by_snaplen = (data.len() as u32) < orig_len;

    let (parsed, macs) = match link::decode(linktype, data) {
        LinkDecode::Ok { parsed, macs } => (parsed, macs),
        LinkDecode::UnsupportedLinkType => {
            state.skipped.unsupported_link_type += 1;
            state
                .unsupported_linktype
                .get_or_insert_with(|| linktype.to_string());
            return Ok(());
        }
        LinkDecode::TooShort => {
            if cut_by_snaplen {
                state.skipped.truncated += 1;
            } else {
                state.skipped.malformed += 1;
            }
            return Ok(());
        }
        LinkDecode::Malformed => {
            state.skipped.malformed += 1;
            return Ok(());
        }
    };

    let classified = frame::classify(&parsed, macs, cut_by_snaplen);
    match classified.frame {
        Frame::Ip(ip) => ingest_ip(
            conn,
            state,
            &ip,
            classified.macs,
            classified.vlan,
            orig_len,
            timestamp,
        ),
        Frame::Fragment { src, dst } => {
            upsert_pair(conn, state, (src, dst), classified.macs, timestamp)?;
            state.skipped.fragment += 1;
            Ok(())
        }
        Frame::Arp(info) => {
            ingest_arp(conn, state, info, timestamp)?;
            insert_packet(conn, state, None, timestamp, orig_len)?;
            state.decoded.arp += 1;
            Ok(())
        }
        Frame::Lldp(info) => {
            queue_announcement(
                state,
                classified.macs.src,
                identity::lldp_facts(&info),
                timestamp,
            );
            insert_packet(conn, state, None, timestamp, orig_len)?;
            state.decoded.lldp += 1;
            Ok(())
        }
        Frame::Cdp(info) => {
            queue_announcement(
                state,
                classified.macs.src,
                identity::cdp_facts(&info),
                timestamp,
            );
            insert_packet(conn, state, None, timestamp, orig_len)?;
            state.decoded.cdp += 1;
            Ok(())
        }
        Frame::OtherEthertype => {
            state.skipped.other_ethertype += 1;
            Ok(())
        }
        Frame::Truncated { hosts } => {
            if let Some(pair) = hosts {
                upsert_pair(conn, state, pair, classified.macs, timestamp)?;
            }
            state.skipped.truncated += 1;
            Ok(())
        }
        Frame::Malformed { hosts } => {
            if let Some(pair) = hosts {
                upsert_pair(conn, state, pair, classified.macs, timestamp)?;
            }
            state.skipped.malformed += 1;
            Ok(())
        }
    }
}

/// The hosts an ARP packet vouches for, with the MAC it names for each.
fn ingest_arp(
    conn: &rusqlite::Connection,
    state: &mut IngestState,
    info: Option<arp::ArpInfo>,
    timestamp: f64,
) -> Result<(), CoreError> {
    let Some(info) = info else {
        return Ok(());
    };
    for (ip, mac) in arp::hosts_from(&info) {
        upsert_host(
            conn,
            state,
            IpAddr::V4(ip),
            Some(&mac),
            MacSource::Arp,
            LINK_ARP,
            timestamp,
        )?;
    }
    Ok(())
}

/// Park an LLDP/CDP announcement under its sender MAC until the end of the
/// parse, when every host is known and it can be attributed.
fn queue_announcement(
    state: &mut IngestState,
    sender: Option<[u8; 6]>,
    facts: L2Facts,
    timestamp: f64,
) {
    if let Some(mac) = sender {
        state
            .l2_pending
            .entry(mac)
            .or_default()
            .push((facts, timestamp));
    }
}

/// An IP packet: both hosts, its flow, any Modbus frames, a packet row, and
/// whatever identity its UDP payload gives away.
fn ingest_ip(
    conn: &rusqlite::Connection,
    state: &mut IngestState,
    ip: &IpFrame<'_>,
    macs: Macs,
    vlan: Option<u16>,
    orig_len: u32,
    timestamp: f64,
) -> Result<(), CoreError> {
    let (src_port, dst_port, tcp_payload) = match ip.transport {
        Transport::Tcp {
            src_port,
            dst_port,
            payload,
        } => (src_port, dst_port, Some(payload)),
        Transport::Udp {
            src_port, dst_port, ..
        } => (src_port, dst_port, None),
        Transport::Portless => (0, 0, None),
    };

    let is_modbus_request = dst_port == modbus::MODBUS_PORT;
    let modbus_frames = match tcp_payload {
        Some(payload) if modbus::is_modbus_tcp(src_port, dst_port, payload) => {
            modbus::parse_frames(payload, is_modbus_request)
        }
        _ => Vec::new(),
    };
    let app_protocol = if modbus_frames.is_empty() {
        None
    } else {
        Some("modbus")
    };

    // Hosts and flows accumulate in memory; only first sight touches the DB.
    let src_host_id = upsert_host(
        conn,
        state,
        ip.src,
        macs.src.as_ref(),
        MacSource::Frame,
        0,
        timestamp,
    )?;
    let dst_host_id = upsert_host(
        conn,
        state,
        ip.dst,
        macs.dst.as_ref(),
        MacSource::Frame,
        0,
        timestamp,
    )?;

    let protocol = ip_proto::name(ip.ip_proto);
    let flow_key = (ip.src, ip.dst, src_port, dst_port, ip.ip_proto);
    let conn_id = upsert_connection(
        conn,
        state,
        flow_key,
        (src_host_id, dst_host_id, src_port, dst_port),
        &protocol,
        app_protocol,
        vlan,
        i64::from(orig_len),
        timestamp,
    )?;

    insert_modbus_events(
        conn,
        conn_id,
        src_host_id,
        dst_host_id,
        timestamp,
        is_modbus_request,
        &modbus_frames,
    )?;

    insert_packet(conn, state, Some(conn_id), timestamp, orig_len)?;
    match ip.src {
        IpAddr::V4(_) => state.decoded.ipv4 += 1,
        IpAddr::V6(_) => state.decoded.ipv6 += 1,
    }

    if let Transport::Udp {
        src_port,
        dst_port,
        payload,
    } = ip.transport
    {
        match identity::inspect_udp(src_port, dst_port, payload) {
            Some(UdpFacts::Sender { source, facts }) => {
                state
                    .evidence
                    .record_all(src_host_id, source, facts, timestamp);
            }
            Some(UdpFacts::Dhcp(dhcp)) => apply_dhcp(conn, state, dhcp, timestamp)?,
            None => {}
        }
    }
    Ok(())
}

/// DHCP facts belong to the client the exchange is about, not to the
/// packet's sender. Until the exchange names the client's address they wait
/// under its MAC.
fn apply_dhcp(
    conn: &rusqlite::Connection,
    state: &mut IngestState,
    dhcp: DhcpFacts,
    timestamp: f64,
) -> Result<(), CoreError> {
    let Some(ip) = dhcp.client_ip else {
        let pending = state.dhcp_pending.entry(dhcp.client_mac).or_default();
        for fact in dhcp.facts {
            pending.push((fact, timestamp));
        }
        return Ok(());
    };
    let id = upsert_host(
        conn,
        state,
        IpAddr::V4(ip),
        Some(&dhcp.client_mac),
        MacSource::Dhcp,
        0,
        timestamp,
    )?;
    if let Some(pending) = state.dhcp_pending.remove(&dhcp.client_mac) {
        for (fact, ts) in pending {
            state.evidence.record(id, "dhcp", fact, ts);
        }
    }
    state.evidence.record_all(id, "dhcp", dhcp.facts, timestamp);
    Ok(())
}

/// Record a decoded frame. This is the only place `packet_count` and the
/// capture's time range move, so the timeline and the counters agree.
fn insert_packet(
    conn: &rusqlite::Connection,
    state: &mut IngestState,
    connection_id: Option<i64>,
    timestamp: f64,
    orig_len: u32,
) -> Result<(), CoreError> {
    conn.prepare_cached(
        "INSERT INTO packets (connection_id, timestamp, length) VALUES (?1, ?2, ?3)",
    )?
    .execute(params![connection_id, timestamp, i64::from(orig_len)])?;
    state.packet_count += 1;
    if timestamp < state.min_ts {
        state.min_ts = timestamp;
    }
    if timestamp > state.max_ts {
        state.max_ts = timestamp;
    }
    Ok(())
}

fn upsert_pair(
    conn: &rusqlite::Connection,
    state: &mut IngestState,
    (src, dst): (IpAddr, IpAddr),
    macs: Macs,
    timestamp: f64,
) -> Result<(), CoreError> {
    upsert_host(
        conn,
        state,
        src,
        macs.src.as_ref(),
        MacSource::Frame,
        0,
        timestamp,
    )?;
    upsert_host(
        conn,
        state,
        dst,
        macs.dst.as_ref(),
        MacSource::Frame,
        0,
        timestamp,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn upsert_connection(
    conn: &rusqlite::Connection,
    state: &mut IngestState,
    flow_key: FlowKey,
    (src_host_id, dst_host_id, src_port, dst_port): (i64, i64, u16, u16),
    protocol: &str,
    app_protocol: Option<&'static str>,
    vlan: Option<u16>,
    packet_len: i64,
    timestamp: f64,
) -> Result<i64, CoreError> {
    if let Some(agg) = state.flows.get_mut(&flow_key) {
        agg.packets += 1;
        agg.bytes += packet_len;
        agg.first_seen = agg.first_seen.min(timestamp);
        agg.last_seen = agg.last_seen.max(timestamp);
        // A TCP flow opens with an empty SYN, so the app protocol is only
        // recognizable once payload arrives — tag the flow late.
        if !agg.tagged {
            if let Some(tag) = app_protocol {
                agg.late_tag = Some(tag);
                agg.tagged = true;
            }
        }
        return Ok(agg.id);
    }

    // Counts start at zero: the flush adds this parse's aggregate on top.
    conn.prepare_cached(
        "INSERT INTO connections
            (src_host_id, dst_host_id, src_port, dst_port, protocol, app_protocol, vlan_id,
             packet_count, byte_count, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 0, ?8, ?8)",
    )?
    .execute(params![
        src_host_id,
        dst_host_id,
        src_port,
        dst_port,
        protocol,
        app_protocol,
        vlan.map(i64::from),
        timestamp,
    ])?;
    let id = conn.last_insert_rowid();
    state.flows.insert(
        flow_key,
        FlowAgg {
            id,
            packets: 1,
            bytes: packet_len,
            first_seen: timestamp,
            last_seen: timestamp,
            tagged: app_protocol.is_some(),
            late_tag: None,
        },
    );
    Ok(id)
}

fn insert_modbus_events(
    conn: &rusqlite::Connection,
    conn_id: i64,
    src_host_id: i64,
    dst_host_id: i64,
    timestamp: f64,
    is_request: bool,
    frames: &[modbus::ModbusFrame],
) -> Result<(), CoreError> {
    for frame in frames {
        conn.prepare_cached(
            "INSERT INTO modbus_events
                (connection_id, src_host_id, dst_host_id, timestamp, is_request,
                 transaction_id, unit_id, function_code, is_exception, exception_code,
                 start_address, quantity, is_write)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        )?
        .execute(params![
            conn_id,
            src_host_id,
            dst_host_id,
            timestamp,
            i64::from(is_request),
            i64::from(frame.transaction_id),
            i64::from(frame.unit_id),
            i64::from(frame.function_code),
            i64::from(frame.is_exception),
            frame.exception_code.map(i64::from),
            frame.start_address.map(i64::from),
            frame.quantity.map(i64::from),
            i64::from(frame.is_write),
        ])?;
    }
    Ok(())
}

/// Return the host's id, inserting it on first sight. The MAC string, vendor
/// lookup, and IP formatting only happen on that first sight — never in the
/// per-packet hot path. `link` flags which link-layer protocol (if any) this
/// sighting came from; `mac` and its source become `mac` evidence, from
/// which the analysis stage picks the device's own address.
fn upsert_host(
    conn: &rusqlite::Connection,
    state: &mut IngestState,
    ip: IpAddr,
    mac: Option<&[u8; 6]>,
    source: MacSource,
    link: u8,
    timestamp: f64,
) -> Result<i64, CoreError> {
    let IngestState {
        hosts,
        evidence,
        mac_index,
        frame_mac_index,
        ..
    } = state;
    let agg = if let Some(agg) = hosts.get_mut(&ip) {
        agg.touch(timestamp, link);
        agg
    } else {
        // `IpAddr::to_string` is the one and only address formatter — IPv6
        // comes out in its canonical compressed form, so the same address
        // always maps to the same row.
        let ip_str = ip.to_string();
        let mac_str = format_mac(mac);
        let vendor = mac.and_then(|m| oui::lookup_vendor(m));
        let id = queries::insert_host(conn, &mac_str, Some(&ip_str), vendor, timestamp)?;
        hosts.entry(ip).or_insert(HostAgg::new(id, timestamp, link))
    };
    // A pseudo-host's MAC is a group address or a client's before it has an
    // address; it must not become evidence or an attribution target.
    if let Some(mac) = mac.filter(|_| !is_pseudo_host(ip)) {
        let index = match source {
            MacSource::Frame => {
                if agg.last_frame_mac == Some(*mac) {
                    return Ok(agg.id);
                }
                agg.last_frame_mac = Some(*mac);
                frame_mac_index
            }
            _ => mac_index,
        };
        let ids = index.entry(*mac).or_default();
        if !ids.contains(&agg.id) {
            ids.push(agg.id);
        }
        evidence.record(
            agg.id,
            source.name(),
            Fact::new(kind::MAC, format_mac(Some(mac)), source.confidence()),
            timestamp,
        );
    }
    Ok(agg.id)
}

/// A device known only by its MAC. Its `mac_address` is its identity, so no
/// `mac` evidence is recorded for it.
fn upsert_mac_host(
    conn: &rusqlite::Connection,
    state: &mut IngestState,
    mac: [u8; 6],
    link: u8,
    timestamp: f64,
) -> Result<i64, CoreError> {
    if let Some(agg) = state.mac_hosts.get_mut(&mac) {
        agg.touch(timestamp, link);
        return Ok(agg.id);
    }
    let id = queries::insert_host(
        conn,
        &format_mac(Some(&mac)),
        None,
        oui::lookup_vendor(&mac),
        timestamp,
    )?;
    state
        .mac_hosts
        .insert(mac, HostAgg::new(id, timestamp, link));
    Ok(id)
}

/// Lowercase colon-separated MAC, or empty when the link type carries none.
fn format_mac(mac: Option<&[u8; 6]>) -> String {
    use std::fmt::Write as _;
    let Some(bytes) = mac else {
        return String::new();
    };
    let mut out = String::with_capacity(17);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_flag_names_round_trip() {
        assert_eq!(link_names(0), "");
        assert_eq!(link_names(LINK_ARP), "arp");
        assert_eq!(link_names(LINK_ARP | LINK_CDP), "arp,cdp");
        assert_eq!(link_flags("arp,cdp"), LINK_ARP | LINK_CDP);
        assert_eq!(link_flags(""), 0);
    }

    #[test]
    fn mac_formatting_round_trips() {
        assert_eq!(format_mac(None), "");
        let mac = [0, 0x1b, 0x1b, 0xaa, 0xbb, 0xcc];
        assert_eq!(format_mac(Some(&mac)), "00:1b:1b:aa:bb:cc");
        assert_eq!(parse_mac("00:1b:1b:aa:bb:cc"), Some(mac));
        assert_eq!(parse_mac(""), None);
        assert_eq!(parse_mac("00:1b:1b:aa:bb:cc:dd"), None);
    }
}
