//! Live capture: frames read from a network interface, folded into the
//! session as they arrive instead of from a file with an end.
//!
//! The pieces are independent and testable without a network interface:
//! [`LiveWriter`] batches frames into the session database through the same
//! [`Ingester`](crate::ingest::Ingester) a file import uses; the spool keeps
//! every frame on disk as a pcap; the ring keeps the packet list's rows. The
//! libpcap driver that reads the interface is the only part that needs the
//! `capture` cargo feature.

#[cfg(feature = "capture")]
mod driver;
mod ring;
mod spool;
mod summary;
mod types;
mod writer;

#[cfg(feature = "capture")]
pub use driver::{list_interfaces, start, CaptureHandle};
pub use ring::{PacketRing, DEFAULT_RING_CAPACITY};
pub use spool::{read_record, SpoolRecord, SpoolWriter};
pub use summary::{detail, summarize};
pub use types::{
    CaptureError, CaptureOptions, CaptureState, CaptureStatus, DetailSection, InterfaceInfo,
    PacketDetail, PacketPage, PacketRow,
};
pub use writer::{BatchReport, LiveWriter, OwnedFrame, LIVE_GRACE_SECS};
