//! The ingester: decodes frames one at a time and folds hosts, flows,
//! packets and identity evidence into the session database. It is the one
//! path for every source of frames - a pcap file read to its end, or a live
//! interface read until the user stops it.
//!
//! Hosts and flows accumulate in memory and reach the database at a
//! *checkpoint*, which a file import does once at the end and a live capture
//! does every batch. A checkpoint writes only what changed since the last one,
//! so any number of them compose into the same rows a single one would have
//! produced. Nothing is dropped silently: every record ends up in
//! `ImportResult` either as decoded or as a counted reason for skipping, and
//! the two always add up to the frames read.

use std::collections::HashMap;
use std::net::IpAddr;

use pcap_parser::Linktype;
use rusqlite::params;

use crate::ingest::evidence::{kind, EvidenceSink, Fact};
use crate::ingest::frame::{self, Frame, IpFrame, Transport};
use crate::ingest::identity::{self, DhcpFacts, L2Facts, UdpFacts};
use crate::ingest::link::{self, LinkDecode, Macs};
use crate::oui;
use crate::protocols::{arp, ip_proto, modbus};
use crate::store::queries;
use crate::types::{ImportResult, LinkLayerCounts, SkippedPackets};
use crate::CoreError;

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
/// A frame's source MAC is the last hop's - a router's for anything beyond
/// the local segment - whereas ARP, DHCP and LLDP/CDP name the device's own.
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

/// Per-host aggregate accumulated in memory between checkpoints and flushed
/// at each one, instead of issuing an UPDATE per packet.
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

    /// Everything up to now is in the row; start a new delta. The empty
    /// range (`MAX..MIN`) is what a preloaded entry starts with, so a host
    /// seen again later touches the row exactly as an append would.
    fn mark_flushed(&mut self) {
        self.first_seen = f64::MAX;
        self.last_seen = f64::MIN;
        self.link_stored |= self.link_seen;
    }
}

/// Per-flow aggregate, same idea. `packets`/`bytes` count only since the
/// last checkpoint - the flush adds them to whatever the row already holds,
/// so appends and checkpoints compose.
struct FlowAgg {
    id: i64,
    packets: i64,
    bytes: i64,
    first_seen: f64,
    last_seen: f64,
    tagged: bool,
    late_tag: Option<&'static str>,
}

impl FlowAgg {
    fn mark_flushed(&mut self) {
        self.packets = 0;
        self.bytes = 0;
        self.first_seen = f64::MAX;
        self.last_seen = f64::MIN;
        self.late_tag = None;
    }
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
    /// Rows inserted since the last checkpoint, reported by the next one.
    new_hosts: usize,
    new_flows: usize,
    new_modbus_events: usize,
    new_packets: usize,
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
         Linux cooked (tcpdump -i any), raw IP and loopback captures - convert \
         it with Wireshark or editcap, or re-capture on an Ethernet interface"
    ))
}

/// What a checkpoint wrote, so a caller can tell whether anything the
/// analysis stage reads has changed since the previous one.
#[derive(Debug, Default, Clone, Copy)]
pub struct CheckpointReport {
    /// Hosts inserted since the previous checkpoint.
    pub new_hosts: usize,
    /// Flows inserted since the previous checkpoint.
    pub new_flows: usize,
    /// Evidence rows this checkpoint wrote (new or merged into existing).
    pub evidence_rows: usize,
    /// Modbus events inserted since the previous checkpoint.
    pub modbus_events: usize,
    /// Packet rows inserted since the previous checkpoint.
    pub packets: usize,
}

impl CheckpointReport {
    /// Whether roles, levels or findings could come out differently now.
    /// Packets alone cannot: the analysis never reads them.
    #[must_use]
    pub fn changed(&self) -> bool {
        self.new_hosts + self.new_flows + self.evidence_rows + self.modbus_events > 0
    }
}

/// Folds frames into a session, one at a time, from any source.
///
/// Call [`Ingester::begin`] on a connection, [`push_frame`](Self::push_frame)
/// for every record, and [`checkpoint`](Self::checkpoint) whenever the
/// database should catch up with what has been seen. A file import checkpoints
/// once at the end; a live capture checkpoints every batch. The caller owns
/// the transaction: every method writes through the connection it is given
/// and never commits.
pub struct Ingester {
    state: IngestState,
}

impl Ingester {
    /// Start folding frames into `conn`. With `append`, the host and flow
    /// caches are seeded from the rows already there so the same host or flow
    /// resolves to its existing id instead of being inserted again. An empty
    /// session seeds nothing, so `append` is right for a fresh one too.
    pub fn begin(conn: &rusqlite::Connection, append: bool) -> Result<Self, CoreError> {
        let mut state = IngestState::new();
        if append {
            preload_caches(conn, &mut state)?;
        }
        Ok(Self { state })
    }

    /// Decode one capture record and fold it in. `orig_len` is the packet's
    /// length on the wire (a snaplen may have cut `data` shorter) and
    /// `timestamp` is epoch seconds.
    pub fn push_frame(
        &mut self,
        conn: &rusqlite::Connection,
        linktype: Linktype,
        data: &[u8],
        orig_len: u32,
        timestamp: f64,
    ) -> Result<(), CoreError> {
        process_frame(data, orig_len, timestamp, linktype, conn, &mut self.state)
    }

    /// A record the reader could not hand over at all: cut off by the end of
    /// the file, or on an interface its section never described.
    pub fn count_malformed_record(&mut self) {
        self.state.frames_read += 1;
        self.state.skipped.malformed += 1;
    }

    /// A record without a usable timestamp (a pcapng Simple Packet Block).
    pub fn count_untimed_record(&mut self) {
        self.state.frames_read += 1;
        self.state.skipped.no_timestamp += 1;
    }

    /// Write everything that changed since the last checkpoint: pending
    /// identity facts, host and flow aggregates, evidence. Any number of
    /// checkpoints produce the same rows one would have.
    ///
    /// `grace` is how many seconds of the newest traffic keep their DHCP and
    /// LLDP/CDP facts waiting. Those facts are keyed by MAC and are attributed
    /// to a host only once the IP traffic that names it has had a chance to
    /// arrive, so a device is not split into a MAC-only asset and an IP one.
    /// A file import, which has seen everything, passes `0.0`; a live capture
    /// passes a few seconds. `f64::INFINITY` attributes nothing yet.
    pub fn checkpoint(
        &mut self,
        conn: &rusqlite::Connection,
        grace: f64,
    ) -> Result<CheckpointReport, CoreError> {
        let state = &mut self.state;
        let cutoff = state.max_ts - grace;
        resolve_pending(conn, state, cutoff)?;
        flush_aggregates(conn, state)?;
        let evidence_rows = state.evidence.flush(conn)?;
        let report = CheckpointReport {
            new_hosts: state.new_hosts,
            new_flows: state.new_flows,
            evidence_rows,
            modbus_events: state.new_modbus_events,
            packets: state.new_packets,
        };
        state.new_hosts = 0;
        state.new_flows = 0;
        state.new_modbus_events = 0;
        state.new_packets = 0;
        Ok(report)
    }

    /// The error to report when every frame so far sat on a link type the
    /// reader cannot decode: such a capture should say so rather than import
    /// as empty.
    #[must_use]
    pub fn unsupported_only(&self) -> Option<CoreError> {
        let state = &self.state;
        if state.packet_count == 0
            && state.frames_read > 0
            && state.skipped.unsupported_link_type == state.frames_read
        {
            return state
                .unsupported_linktype
                .as_deref()
                .map(unsupported_linktype_error);
        }
        None
    }

    /// What has been folded in so far. Frame accounting always reconciles:
    /// `frames_read == packet_count + skipped.total()`. Host and flow counts
    /// are session totals, preloaded rows included.
    #[must_use]
    pub fn result(&self) -> ImportResult {
        let state = &self.state;
        debug_assert_eq!(
            state.frames_read,
            state.packet_count + state.skipped.total(),
            "frame accounting must reconcile"
        );
        debug_assert_eq!(state.packet_count, state.decoded.total());
        let time_range = if state.min_ts > state.max_ts {
            (0.0, 0.0)
        } else {
            (state.min_ts, state.max_ts)
        };
        ImportResult {
            frames_read: state.frames_read,
            packet_count: state.packet_count,
            decoded: state.decoded,
            skipped: state.skipped,
            host_count: state.hosts.len() + state.mac_hosts.len(),
            connection_count: state.flows.len(),
            time_range,
        }
    }
}

/// Addresses are only ever written by `IpAddr::to_string`, so a stored row
/// that fails to parse means the session is corrupt - better to say so than
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
/// existing ids. Aggregates start empty - the flush only adds what this
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

/// Write the accumulated per-host and per-flow aggregates in one pass, then
/// start the next delta. Untouched entries (preloaded, or unchanged since the
/// last checkpoint) are skipped so each flush only writes what changed.
fn flush_aggregates(conn: &rusqlite::Connection, state: &mut IngestState) -> Result<(), CoreError> {
    let mut host_stmt = conn.prepare_cached(
        "UPDATE hosts SET
            first_seen = MIN(first_seen, ?1),
            last_seen = MAX(last_seen, ?2)
         WHERE id = ?3",
    )?;
    let mut link_stmt =
        conn.prepare_cached("UPDATE hosts SET link_protocols = ?1 WHERE id = ?2")?;
    for agg in state.hosts.values_mut().chain(state.mac_hosts.values_mut()) {
        if agg.first_seen <= agg.last_seen {
            host_stmt.execute(params![agg.first_seen, agg.last_seen, agg.id])?;
        }
        let links = agg.link_seen | agg.link_stored;
        if links != agg.link_stored {
            link_stmt.execute(params![link_names(links), agg.id])?;
        }
        agg.mark_flushed();
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
    for agg in state.flows.values_mut() {
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
        agg.mark_flushed();
    }
    Ok(())
}

/// Attribute the facts that could not be placed while parsing: DHCP client
/// facts whose exchange never named an address, and LLDP/CDP announcements,
/// which are keyed by MAC. Only facts seen at or before `cutoff` are
/// attributed; newer ones wait for a later checkpoint, so the IP traffic that
/// names their host has had a chance to arrive and a device is not split into
/// a MAC-only asset and an IP one. A file import passes its last timestamp as
/// the cutoff, so everything is attributed once every host is known.
fn resolve_pending(
    conn: &rusqlite::Connection,
    state: &mut IngestState,
    cutoff: f64,
) -> Result<(), CoreError> {
    // Sorted by MAC so ids come out the same for the same traffic.
    let mut dhcp_macs: Vec<[u8; 6]> = state.dhcp_pending.keys().copied().collect();
    dhcp_macs.sort_unstable();
    for mac in dhcp_macs {
        // A client's facts travel together: the exchange is attributed as a
        // whole once its newest packet is old enough.
        let newest = state.dhcp_pending[&mac]
            .iter()
            .map(|(_, ts)| *ts)
            .fold(f64::MIN, f64::max);
        if newest > cutoff {
            continue;
        }
        let facts: PendingFacts = state.dhcp_pending.remove(&mac).unwrap_or_default();
        let first_ts = facts.iter().map(|(_, ts)| *ts).fold(f64::MAX, f64::min);
        let id = host_for_mac(conn, state, mac, 0, first_ts)?;
        for (fact, ts) in facts {
            state.evidence.record(id, "dhcp", fact, ts);
        }
    }

    let mut l2_macs: Vec<[u8; 6]> = state.l2_pending.keys().copied().collect();
    l2_macs.sort_unstable();
    for mac in l2_macs {
        let items: PendingAnnouncements = state.l2_pending.remove(&mac).unwrap_or_default();
        let (due, later): (PendingAnnouncements, PendingAnnouncements) =
            items.into_iter().partition(|(_, ts)| *ts <= cutoff);
        if !later.is_empty() {
            state.l2_pending.insert(mac, later);
        }
        for (l2, ts) in due {
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

/// Decode one capture record and fold it into the session. `orig_len` is the
/// packet's length on the wire - captures taken with a snaplen truncate
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
    state.new_modbus_events += modbus_frames.len();

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
    state.new_packets += 1;
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
        // recognizable once payload arrives - tag the flow late.
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
    state.new_flows += 1;
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
/// lookup, and IP formatting only happen on that first sight - never in the
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
        new_hosts,
        ..
    } = state;
    let agg = if let Some(agg) = hosts.get_mut(&ip) {
        agg.touch(timestamp, link);
        agg
    } else {
        // `IpAddr::to_string` is the one and only address formatter - IPv6
        // comes out in its canonical compressed form, so the same address
        // always maps to the same row.
        let ip_str = ip.to_string();
        let mac_str = format_mac(mac);
        let vendor = mac.and_then(|m| oui::lookup_vendor(m));
        let id = queries::insert_host(conn, &mac_str, Some(&ip_str), vendor, timestamp)?;
        *new_hosts += 1;
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
    state.new_hosts += 1;
    state
        .mac_hosts
        .insert(mac, HostAgg::new(id, timestamp, link));
    Ok(id)
}

/// Lowercase colon-separated MAC, or empty when the link type carries none.
pub(crate) fn format_mac(mac: Option<&[u8; 6]>) -> String {
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

    /// Two checkpoints must leave the same rows as one: deltas restart after
    /// a flush, and the evidence sink drains.
    #[test]
    fn checkpoints_compose_without_double_counting() {
        let (conn, path) = crate::store::schema::init_db().unwrap();
        let mut frame = Vec::new();
        etherparse::PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(40000, 502, 1, 1024)
            .write(&mut frame, &[0u8; 4])
            .unwrap();
        let len = frame.len() as u32;

        let mut ingester = Ingester::begin(&conn, false).unwrap();
        ingester
            .push_frame(&conn, Linktype::ETHERNET, &frame, len, 1.0)
            .unwrap();
        let first = ingester.checkpoint(&conn, 0.0).unwrap();
        ingester
            .push_frame(&conn, Linktype::ETHERNET, &frame, len, 2.0)
            .unwrap();
        let second = ingester.checkpoint(&conn, 0.0).unwrap();

        assert_eq!((first.new_hosts, first.new_flows, first.packets), (2, 1, 1));
        assert_eq!(
            (second.new_hosts, second.new_flows, second.packets),
            (0, 0, 1)
        );
        assert!(first.changed());
        assert!(!second.changed());

        let flow: (i64, i64, f64, f64) = conn
            .query_row(
                "SELECT packet_count, byte_count, first_seen, last_seen FROM connections",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(flow, (2, 2 * i64::from(len), 1.0, 2.0));
        let host: (f64, f64) = conn
            .query_row(
                "SELECT first_seen, last_seen FROM hosts WHERE ip_address = '10.0.0.1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(host, (1.0, 2.0));
        // One MAC sighting per host; a second flush must not add it again.
        let mac_sightings: i64 = conn
            .query_row(
                "SELECT SUM(count) FROM evidence WHERE kind = 'mac'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(mac_sightings, 2);
        assert_eq!(ingester.result().packet_count, 2);

        drop(conn);
        crate::store::schema::cleanup_db(&path);
    }
}
