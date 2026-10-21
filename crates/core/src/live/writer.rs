//! Batches of live frames into the session database.
//!
//! A file import holds one transaction for the whole file and runs the
//! analysis once at the end. A live capture has no end, so the writer commits
//! every batch in a short transaction (the UI queries in between) and re-runs
//! the analysis when something it reads has changed, backing off while it is
//! slow so a long capture stays responsive.
//!
//! Pending identity facts are attributed with a grace window
//! ([`LIVE_GRACE_SECS`]) rather than at the end of the file. The one
//! limitation that buys: a device first seen only by MAC (an LLDP or CDP
//! announcement, a DHCP exchange that never completes) becomes a MAC-only
//! asset after the window, and an IP host that turns up for the same MAC
//! later is not merged with it. A file import defers attribution to the end
//! and never hits this.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rusqlite::{Connection, TransactionBehavior};

use crate::analysis;
use crate::ingest::{CheckpointReport, Ingester, Linktype};
use crate::store::schema;
use crate::types::ImportResult;
use crate::CoreError;

/// How long the newest traffic keeps its DHCP and LLDP/CDP facts waiting
/// before they are attributed by MAC. A DHCP exchange completes within a
/// second or two; an LLDP sender's own IP traffic usually shows up well
/// within this.
pub const LIVE_GRACE_SECS: f64 = 5.0;

/// The analysis never runs more often than this ...
const ANALYSIS_MIN_INTERVAL: Duration = Duration::from_secs(2);
/// ... nor sooner than this many times its own last duration, so a capture
/// whose analysis has grown slow spends most of its time ingesting.
const ANALYSIS_BACKOFF: u32 = 5;

/// One captured frame, owned so a batch can outlive the capture buffer.
#[derive(Debug, Clone)]
pub struct OwnedFrame {
    /// Epoch seconds.
    pub timestamp: f64,
    /// Length on the wire; `data` may be shorter when a snaplen cut it.
    pub orig_len: u32,
    pub data: Vec<u8>,
}

/// What one committed batch did.
#[derive(Debug, Clone)]
pub struct BatchReport {
    /// Cumulative counters for this writer's lifetime.
    pub counts: ImportResult,
    pub checkpoint: CheckpointReport,
    /// Whether roles, levels and findings were re-derived after this batch.
    pub analysed: bool,
    /// Time the session lock was held for the inserts and the checkpoint.
    pub db_ms: u32,
    /// Time the session lock was held for the analysis, when it ran.
    pub analysis_ms: u32,
}

/// Folds batches of live frames into a session.
pub struct LiveWriter {
    conn: Arc<Mutex<Connection>>,
    ingester: Ingester,
    grace: f64,
    last_analysis: Option<(Instant, Duration)>,
    /// Something the analysis reads changed since it last ran.
    dirty: bool,
}

fn lock(conn: &Mutex<Connection>) -> Result<MutexGuard<'_, Connection>, CoreError> {
    conn.lock().map_err(|e| CoreError::Internal(e.to_string()))
}

fn millis(elapsed: Duration) -> u32 {
    u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX)
}

impl LiveWriter {
    /// `grace_secs` is how long the newest traffic's identity facts wait
    /// before attribution (see [`LIVE_GRACE_SECS`]); `f64::INFINITY` defers
    /// everything to [`finish`](Self::finish).
    pub(crate) fn new(conn: Arc<Mutex<Connection>>, grace_secs: f64) -> Result<Self, CoreError> {
        let ingester = {
            let guard = lock(&conn)?;
            // A fresh session has no indexes yet; a live session keeps them,
            // because the UI queries between batches.
            schema::create_packet_indexes(&guard)?;
            Ingester::begin(&guard, true)?
        };
        Ok(Self {
            conn,
            ingester,
            grace: grace_secs,
            last_analysis: None,
            dirty: false,
        })
    }

    /// Fold a batch into the session and commit it, then re-derive roles and
    /// findings if something they depend on changed and the backoff allows.
    /// The session lock is held only for those two windows.
    pub fn commit_batch(
        &mut self,
        linktype: Linktype,
        frames: &[OwnedFrame],
    ) -> Result<BatchReport, CoreError> {
        let started = Instant::now();
        let checkpoint = {
            let mut guard = lock(&self.conn)?;
            let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
            for frame in frames {
                self.ingester.push_frame(
                    &tx,
                    linktype,
                    &frame.data,
                    frame.orig_len,
                    frame.timestamp,
                )?;
            }
            let report = self.ingester.checkpoint(&tx, self.grace)?;
            tx.commit()?;
            report
        };
        let db_ms = millis(started.elapsed());

        self.dirty |= checkpoint.changed();
        let mut analysed = false;
        let mut analysis_ms = 0;
        if self.dirty && self.analysis_due() {
            let took = self.run_analysis()?;
            self.last_analysis = Some((Instant::now(), took));
            self.dirty = false;
            analysed = true;
            analysis_ms = millis(took);
        }

        Ok(BatchReport {
            counts: self.ingester.result(),
            checkpoint,
            analysed,
            db_ms,
            analysis_ms,
        })
    }

    fn analysis_due(&self) -> bool {
        match self.last_analysis {
            None => true,
            Some((at, took)) => at.elapsed() >= ANALYSIS_MIN_INTERVAL.max(took * ANALYSIS_BACKOFF),
        }
    }

    /// The analysis runs inside a transaction so a reader never sees the
    /// findings table between its delete and its reinsert.
    fn run_analysis(&self) -> Result<Duration, CoreError> {
        let started = Instant::now();
        let mut guard = lock(&self.conn)?;
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        analysis::run(&tx, &|_| {})?;
        tx.commit()?;
        Ok(started.elapsed())
    }

    /// The capture has stopped: attribute every pending fact and re-derive
    /// everything one last time.
    pub fn finish(mut self) -> Result<ImportResult, CoreError> {
        let mut guard = lock(&self.conn)?;
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.ingester.checkpoint(&tx, 0.0)?;
        analysis::run(&tx, &|_| {})?;
        tx.commit()?;
        Ok(self.ingester.result())
    }
}
