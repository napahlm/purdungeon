//! What a live capture reports to the UI: the packet list rows, the decoded
//! view of one packet, the running status, and the capture's own errors.

use serde::{Deserialize, Serialize};

use crate::types::ImportResult;
use crate::CoreError;

/// One row of the packet list.
#[derive(Debug, Clone, Serialize)]
pub struct PacketRow {
    /// 1-based frame number, monotonic for the whole capture run.
    pub no: u64,
    /// Epoch seconds.
    pub timestamp: f64,
    pub src: String,
    pub dst: String,
    /// What the Protocol column shows: `Modbus`, `TCP`, `ARP`, `LLDP`, ...
    pub protocol: String,
    /// The lowercase application tag the topology colours by (`modbus`,
    /// `http`, ...), when the packet has one.
    pub app_protocol: Option<String>,
    /// Length on the wire.
    pub length: u32,
    pub info: String,
    /// Where the frame's record starts in the spool.
    #[serde(skip)]
    pub spool_offset: u64,
}

/// A window of the packet list.
#[derive(Debug, Clone, Serialize)]
pub struct PacketPage {
    /// Rows matching the query across the whole ring.
    pub total: usize,
    /// The oldest frame number still in the ring.
    pub first_no: u64,
    /// The offset this page starts at within the matching rows.
    pub offset: usize,
    pub rows: Vec<PacketRow>,
}

/// One decoded field group of a packet, as label/value rows.
#[derive(Debug, Clone, Serialize)]
pub struct DetailSection {
    pub title: String,
    pub rows: Vec<(String, String)>,
}

/// The decoded view of one packet, as much of it as the decoders read.
#[derive(Debug, Clone, Serialize)]
pub struct PacketDetail {
    pub no: u64,
    pub timestamp: f64,
    pub length: u32,
    pub captured: u32,
    pub protocol: String,
    pub info: String,
    pub sections: Vec<DetailSection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureState {
    Running,
    Stopped,
    Failed,
}

/// The running counters of a capture, published on every committed batch.
#[derive(Debug, Clone, Serialize)]
pub struct CaptureStatus {
    /// Increments on every publish.
    pub seq: u64,
    pub state: CaptureState,
    pub interface: String,
    /// The interface's link type, as libpcap names it.
    pub linktype: String,
    /// Whether promiscuous mode was granted.
    pub promiscuous: bool,
    /// Epoch seconds when the capture started.
    pub started_at: f64,
    /// Frame accounting, the same shape a file import reports.
    pub counts: ImportResult,
    /// Bytes on the wire across every frame read.
    pub bytes: u64,
    /// Frames per second over the last batch interval.
    pub pps: f64,
    pub kernel_received: u64,
    /// Frames the OS dropped for want of buffer space.
    pub kernel_dropped: u64,
    /// Frames the interface or its driver dropped.
    pub if_dropped: u64,
    /// Frames this process dropped because the database fell behind.
    pub app_dropped: u64,
    /// Rows the packet list can page over.
    pub ring_total: usize,
    pub ring_first_no: u64,
    /// Frames per Protocol column value, most frequent first.
    pub protocol_counts: Vec<(String, u64)>,
    pub last_analysis_ms: u32,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<String>,
    pub is_up: bool,
    pub is_loopback: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CaptureOptions {
    pub interface: String,
    /// A BPF capture filter, `tcp port 502` and the like.
    pub filter: Option<String>,
    pub promiscuous: bool,
}

/// Why a capture could not start or stopped on its own. Serialises as
/// `{ code, message }` so the UI can pick advice by code and quote the
/// message.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("permission to capture on {device} was denied")]
    PermissionDenied { device: String },
    #[error("no such interface: {0}")]
    NoSuchDevice(String),
    #[error("the packet capture driver is not installed")]
    DriverMissing,
    #[error("capture filter rejected: {0}")]
    BadFilter(String),
    #[error("capture error: {0}")]
    Pcap(String),
    #[error("a capture is already running")]
    AlreadyRunning,
    #[error(transparent)]
    Core(#[from] CoreError),
}

impl CaptureError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::PermissionDenied { .. } => "permission-denied",
            Self::NoSuchDevice(_) => "no-such-device",
            Self::DriverMissing => "driver-missing",
            Self::BadFilter(_) => "bad-filter",
            Self::Pcap(_) => "pcap",
            Self::AlreadyRunning => "already-running",
            Self::Core(_) => "core",
        }
    }
}

impl Serialize for CaptureError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("CaptureError", 2)?;
        s.serialize_field("code", self.code())?;
        s.serialize_field("message", &self.to_string())?;
        s.end()
    }
}
