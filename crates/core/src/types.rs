use serde::Serialize;

/// Stages of an import, in order. Each one reflects real work; the UI shows
/// them as the loading sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImportStage {
    ReadingPackets,
    IdentifyingDevices,
    MappingConversations,
    InferringRoles,
    SurfacingFindings,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub id: i64,
    pub kind: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub host_ids: Vec<i64>,
    pub connection_ids: Vec<i64>,
}

/// Frames that were decoded, by what they carried. Every one of these became
/// a row in `packets`, so the timeline counts them too.
#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct LinkLayerCounts {
    pub ipv4: usize,
    pub ipv6: usize,
    /// ARP announcements: they add devices but carry no IP conversation.
    pub arp: usize,
    /// LLDP and CDP are recognised and counted; their contents become device
    /// evidence in a later release.
    pub lldp: usize,
    pub cdp: usize,
}

impl LinkLayerCounts {
    #[must_use]
    pub fn total(&self) -> usize {
        self.ipv4 + self.ipv6 + self.arp + self.lldp + self.cdp
    }
}

/// Frames read but not decoded, by reason. Lets the UI say *why* a capture
/// looks thin instead of leaving "0 packets" ambiguous.
#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct SkippedPackets {
    /// The interface's link type is one we do not read (Wi-Fi, USB, …).
    pub unsupported_link_type: usize,
    /// Ethernet payloads we do not read: other ethertypes (PROFINET RT,
    /// `EtherCAT`, …) and non-CDP 802.3/LLC frames (spanning tree, …).
    pub other_ethertype: usize,
    /// Non-first IP fragments; hosts are recorded, the transport is unknown.
    pub fragment: usize,
    /// A header was cut off by the capture's snapshot length.
    pub truncated: usize,
    /// A header that could not be decoded, or a record cut off by the end of
    /// the file.
    pub malformed: usize,
    /// Records without a usable timestamp (pcapng Simple Packet Blocks, or a
    /// zero timestamp).
    pub no_timestamp: usize,
}

impl SkippedPackets {
    #[must_use]
    pub fn total(&self) -> usize {
        self.unsupported_link_type
            + self.other_ethertype
            + self.fragment
            + self.truncated
            + self.malformed
            + self.no_timestamp
    }
}

/// What one import did. `frames_read == packet_count + skipped.total()` and
/// `packet_count == decoded.total()` always hold — the counters reconcile
/// with the file, nothing is dropped unaccounted for.
#[derive(Debug, Clone, Serialize)]
pub struct ImportResult {
    /// Every record in the file, whatever became of it.
    pub frames_read: usize,
    /// Frames that were decoded and recorded (IP packets and link-layer
    /// announcements alike).
    pub packet_count: usize,
    pub decoded: LinkLayerCounts,
    pub skipped: SkippedPackets,
    /// Session totals after this import (cumulative on append).
    pub host_count: usize,
    pub connection_count: usize,
    pub time_range: (f64, f64),
}

#[derive(Debug, Serialize)]
pub struct Host {
    pub id: i64,
    /// Empty when the capture's link type carries no MAC (cooked, raw IP).
    /// The best-evidenced MAC: ARP, DHCP and LLDP/CDP outrank a frame's.
    pub mac_address: String,
    /// IPv4 dotted quad or IPv6 in RFC 5952 compressed form; `None` for a
    /// device known only by its MAC (seen in LLDP/CDP/DHCP, never in IP
    /// traffic).
    pub ip_address: Option<String>,
    /// The best-evidenced name (DHCP, `NetBIOS`, mDNS, LLMNR, SNMP, LLDP, CDP).
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub role: String,
    pub role_confidence: f64,
    pub role_evidence: Option<String>,
    pub purdue_level: Option<i64>,
    pub role_override: Option<String>,
    pub level_override: Option<i64>,
    pub protocols: String,
    /// Comma-joined link-layer protocols the host was seen in (e.g. `arp`).
    pub link_protocols: String,
    pub is_external: bool,
    pub first_seen: f64,
    pub last_seen: f64,
}

#[derive(Debug, Serialize)]
pub struct Connection {
    pub id: i64,
    pub src_host_id: i64,
    pub dst_host_id: i64,
    pub src_port: u16,
    pub dst_port: u16,
    /// IP protocol name: TCP, UDP, ICMP, `ICMPv6`, IGMP, VRRP, … Port-less
    /// protocols use ports 0/0.
    pub protocol: String,
    pub app_protocol: Option<String>,
    /// 802.1Q VLAN id of the first frame seen on this flow; `None` when
    /// untagged.
    pub vlan_id: Option<i64>,
    pub packet_count: i64,
    pub byte_count: i64,
    pub first_seen: f64,
    pub last_seen: f64,
}

/// One time-bucket of traffic volume, for the timeline histogram.
#[derive(Debug, Clone, Serialize)]
pub struct HistogramBucket {
    pub start: f64,
    pub packet_count: i64,
    pub byte_count: i64,
}

/// One thing a protocol said about a device. Every identity claim in the UI
/// and the exports traces back to rows like this.
#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub id: i64,
    pub host_id: i64,
    /// `hostname`, `mac`, `os`, `vendor`, `description`, `model`,
    /// `capabilities`, `port`, `service`, `management-address`, …
    pub kind: String,
    pub value: String,
    /// `arp`, `ethernet`, `dhcp`, `nbns`, `mdns`, `llmnr`, `snmp`, `lldp`, `cdp`.
    pub source_protocol: String,
    pub first_seen: f64,
    pub last_seen: f64,
    /// How far the value can be trusted to describe this device: a
    /// self-declared name is high, a guessed operating system is low.
    pub confidence: f64,
    /// How many packets said so.
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct HostDetail {
    pub host: Host,
    pub connections: Vec<HostConnection>,
    pub total_packets: i64,
    pub total_bytes: i64,
    /// Distinct VLAN ids across the host's conversations, sorted.
    pub vlans: Vec<i64>,
    /// Everything the capture said about this device, by kind then confidence.
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Serialize)]
pub struct HostConnection {
    pub connection_id: i64,
    pub peer_ip: String,
    pub peer_mac: String,
    pub direction: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub app_protocol: Option<String>,
    pub packet_count: i64,
    pub byte_count: i64,
    pub first_seen: f64,
    pub last_seen: f64,
}

#[derive(Debug, Serialize)]
pub struct ModbusFunctionStat {
    pub function_code: i64,
    pub function_name: String,
    pub count: i64,
    pub is_write: bool,
}

#[derive(Debug, Serialize)]
pub struct RegisterAccess {
    pub kind: String,
    pub start: i64,
    pub quantity: i64,
    pub reads: i64,
    pub writes: i64,
}

#[derive(Debug, Serialize)]
pub struct ModbusHostActivity {
    /// Requests this host sends to other devices
    pub as_client: Vec<ModbusFunctionStat>,
    /// Requests other devices send to this host
    pub as_server: Vec<ModbusFunctionStat>,
    pub unit_ids_served: Vec<i64>,
    /// Data points on this device touched by its clients
    pub registers: Vec<RegisterAccess>,
    /// Data points this host touches on other devices
    pub registers_remote: Vec<RegisterAccess>,
    pub exceptions_returned: i64,
}

#[derive(Debug, Serialize)]
pub struct ModbusConversation {
    pub functions: Vec<ModbusFunctionStat>,
    pub unit_ids: Vec<i64>,
    pub requests: i64,
    pub reads: i64,
    pub writes: i64,
    pub exceptions: i64,
    pub poll_interval_ms: Option<f64>,
}
