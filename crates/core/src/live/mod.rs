//! Live capture: frames read from a network interface, folded into the
//! session as they arrive instead of from a file with an end.
//!
//! The pieces are independent and testable without a network interface:
//! [`LiveWriter`] batches frames into the session database through the same
//! [`Ingester`](crate::ingest::Ingester) a file import uses. The libpcap
//! driver that reads the interface is the only part that needs the `capture`
//! cargo feature.

mod writer;

pub use writer::{BatchReport, LiveWriter, OwnedFrame, LIVE_GRACE_SECS};
