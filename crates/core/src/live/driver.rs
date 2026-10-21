//! The libpcap driver: reads an interface on its own thread, spools every
//! frame, keeps the packet list's rows, and hands batches to the
//! [`LiveWriter`] on a steady cadence. Nothing here blocks the caller for
//! longer than a lock around a counter.
//!
//! Opening the interface happens on the caller's thread so the errors a user
//! can act on (no permission, no such interface, a bad filter) come back
//! from [`start`] at once.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pcap::{Active, Capture, Device};

use crate::ingest::Linktype;
use crate::live::ring::{PacketRing, DEFAULT_RING_CAPACITY};
use crate::live::spool::{self, SpoolWriter};
use crate::live::summary;
use crate::live::types::{
    CaptureError, CaptureOptions, CaptureState, CaptureStatus, InterfaceInfo, PacketDetail,
    PacketPage, PacketRow,
};
use crate::live::writer::{LiveWriter, OwnedFrame};
use crate::types::ImportResult;

/// How long `next_packet` waits before handing control back so the stop
/// flag and the batch clock are checked on a quiet interface.
const READ_TIMEOUT_MS: i32 = 200;
const SNAPLEN: i32 = 65535;
/// libpcap's kernel buffer. Generous, so a burst is dropped by neither the
/// OS nor this process while a batch is being committed.
const BUFFER_SIZE: i32 = 4 << 20;
/// A batch is committed when either of these is reached.
const BATCH_INTERVAL: Duration = Duration::from_millis(500);
const BATCH_FRAMES: usize = 10_000;
/// Frames waiting for the database before the oldest are dropped and
/// counted, so a stalled commit cannot grow memory without bound.
const MAX_PENDING_FRAMES: usize = 1_000_000;

/// The interfaces libpcap can open, interfaces that are up first and the
/// loopback last. Pseudo-interfaces that only confuse (macOS packet taps,
/// Apple Wireless Direct Link, tunnels) are left out.
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, CaptureError> {
    let mut devices: Vec<InterfaceInfo> = Device::list()
        .map_err(|e| map_error(&e))?
        .into_iter()
        .filter(|d| !is_pseudo_interface(&d.name))
        .map(|d| InterfaceInfo {
            name: d.name,
            description: d.desc,
            addresses: d.addresses.iter().map(|a| a.addr.to_string()).collect(),
            is_up: d.flags.is_up(),
            is_loopback: d.flags.is_loopback(),
        })
        .collect();
    devices.sort_by_key(|d| (d.is_loopback, !d.is_up, d.addresses.is_empty()));
    Ok(devices)
}

fn is_pseudo_interface(name: &str) -> bool {
    [
        "pktap", "awdl", "llw", "utun", "gif", "stf", "ap", "bridge", "anpi", "vmenet",
    ]
    .iter()
    .any(|prefix| {
        name.strip_prefix(prefix)
            .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit()))
    })
}

/// Interfaces a user cannot usefully capture on are not errors; the errors a
/// user can act on are told apart by what libpcap said.
fn map_error(error: &pcap::Error) -> CaptureError {
    let text = error.to_string();
    let lower = text.to_lowercase();
    if lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("cannot open bpf device")
        || lower.contains("you don't have permission")
    {
        return CaptureError::PermissionDenied { device: text };
    }
    if lower.contains("no such device") || lower.contains("doesn't exist") {
        return CaptureError::NoSuchDevice(text);
    }
    if lower.contains("wpcap") || lower.contains("entrypoint") || lower.contains("npcap") {
        return CaptureError::DriverMissing;
    }
    CaptureError::Pcap(text)
}

fn open(options: &CaptureOptions) -> Result<(Capture<Active>, bool), CaptureError> {
    let configure = |promisc: bool| {
        Capture::from_device(options.interface.as_str())
            .map_err(|e| map_error(&e))?
            .promisc(promisc)
            .immediate_mode(true)
            .timeout(READ_TIMEOUT_MS)
            .snaplen(SNAPLEN)
            .buffer_size(BUFFER_SIZE)
            .open()
            .map_err(|e| map_error(&e))
    };
    let (mut capture, promiscuous) = match configure(options.promiscuous) {
        Ok(capture) => (capture, options.promiscuous),
        // Some interfaces (Wi-Fi, tunnels) refuse promiscuous mode; the
        // user still wants their own traffic.
        Err(CaptureError::Pcap(_)) if options.promiscuous => (configure(false)?, false),
        Err(e) => return Err(e),
    };
    if let Some(filter) = options
        .filter
        .as_deref()
        .map(str::trim)
        .filter(|f| !f.is_empty())
    {
        capture
            .filter(filter, true)
            .map_err(|e| CaptureError::BadFilter(e.to_string()))?;
    }
    Ok((capture, promiscuous))
}

/// What the capture thread and its handle share.
struct Shared {
    stop: AtomicBool,
    status: Mutex<CaptureStatus>,
    ring: Mutex<PacketRing>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A poisoned lock means the capture thread panicked mid-update; the
    // counters are still worth reading.
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A running (or finished) capture. Dropping it stops the capture and
/// removes the spool.
pub struct CaptureHandle {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<Result<ImportResult, CaptureError>>>,
    spool: PathBuf,
    linktype: Linktype,
}

impl CaptureHandle {
    #[must_use]
    pub fn status(&self) -> CaptureStatus {
        lock(&self.shared.status).clone()
    }

    #[must_use]
    pub fn packets(&self, offset: usize, limit: usize, query: Option<&str>) -> PacketPage {
        lock(&self.shared.ring).page(offset, limit, query)
    }

    /// The decoded view of one listed packet, read back from the spool.
    pub fn packet_detail(&self, no: u64) -> Result<PacketDetail, CaptureError> {
        let (timestamp, offset) = {
            let ring = lock(&self.shared.ring);
            let row = ring
                .get(no)
                .ok_or_else(|| CaptureError::Pcap(format!("packet {no} has left the buffer")))?;
            (row.timestamp, row.spool_offset)
        };
        let record = spool::read_record(&self.spool, offset)?;
        Ok(summary::detail(
            no,
            timestamp,
            self.linktype,
            &record.data,
            record.orig_len,
        ))
    }

    #[must_use]
    pub fn spool_path(&self) -> &Path {
        &self.spool
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.thread.as_ref().is_some_and(|t| !t.is_finished())
    }

    /// Ask the thread to stop and wait for it: it commits what it has,
    /// attributes every pending fact and re-derives roles one last time.
    pub fn stop(&mut self) -> Result<CaptureStatus, CaptureError> {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            match thread.join() {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(CaptureError::Pcap("the capture thread panicked".into()));
                }
            }
        }
        Ok(self.status())
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        let _ = self.stop();
        let _ = std::fs::remove_file(&self.spool);
    }
}

/// Open `options.interface` and start reading it. Frames are spooled to
/// `spool_path`, folded into the session through `writer`, and `on_tick`
/// is called with the running status after every committed batch and once
/// more when the capture stops.
pub fn start(
    options: &CaptureOptions,
    writer: LiveWriter,
    spool_path: PathBuf,
    on_tick: Box<dyn Fn(&CaptureStatus) + Send>,
) -> Result<CaptureHandle, CaptureError> {
    let (capture, promiscuous) = open(options)?;
    let datalink = capture.get_datalink();
    let linktype = Linktype(datalink.0);
    if let Some(parent) = spool_path.parent() {
        std::fs::create_dir_all(parent).map_err(crate::CoreError::from)?;
    }
    let spool = SpoolWriter::create(&spool_path, linktype, SNAPLEN as u32)?;

    let status = CaptureStatus {
        seq: 0,
        state: CaptureState::Running,
        interface: options.interface.clone(),
        linktype: datalink.get_name().unwrap_or_else(|_| linktype.to_string()),
        promiscuous,
        started_at: now(),
        stopped_at: None,
        counts: ImportResult {
            frames_read: 0,
            packet_count: 0,
            decoded: crate::types::LinkLayerCounts::default(),
            skipped: crate::types::SkippedPackets::default(),
            host_count: 0,
            connection_count: 0,
            time_range: (0.0, 0.0),
        },
        bytes: 0,
        pps: 0.0,
        kernel_received: 0,
        kernel_dropped: 0,
        if_dropped: 0,
        app_dropped: 0,
        ring_total: 0,
        ring_first_no: 1,
        protocol_counts: Vec::new(),
        last_analysis_ms: 0,
        error: None,
    };
    let shared = Arc::new(Shared {
        stop: AtomicBool::new(false),
        status: Mutex::new(status),
        ring: Mutex::new(PacketRing::new(DEFAULT_RING_CAPACITY)),
    });

    let worker = Worker {
        shared: Arc::clone(&shared),
        capture,
        linktype,
        spool,
        writer: Some(writer),
        on_tick,
        pending: Vec::new(),
        rows: Vec::new(),
        next_no: 1,
        bytes: 0,
        app_dropped: 0,
        protocol_counts: std::collections::HashMap::new(),
        last_batch: Instant::now(),
        last_batch_frames: 0,
        frames_read: 0,
    };
    let thread = std::thread::Builder::new()
        .name("purdungeon-capture".into())
        .spawn(move || worker.run())
        .map_err(crate::CoreError::from)?;

    Ok(CaptureHandle {
        shared,
        thread: Some(thread),
        spool: spool_path,
        linktype,
    })
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

struct Worker {
    shared: Arc<Shared>,
    capture: Capture<Active>,
    linktype: Linktype,
    spool: SpoolWriter,
    /// Taken by `finish`, which consumes it.
    writer: Option<LiveWriter>,
    on_tick: Box<dyn Fn(&CaptureStatus) + Send>,
    /// Frames read since the last batch, waiting for the database.
    pending: Vec<OwnedFrame>,
    /// Their list rows, published to the ring once the spool is flushed.
    rows: Vec<PacketRow>,
    next_no: u64,
    bytes: u64,
    app_dropped: u64,
    protocol_counts: std::collections::HashMap<String, u64>,
    last_batch: Instant,
    last_batch_frames: u64,
    frames_read: u64,
}

impl Worker {
    fn run(mut self) -> Result<ImportResult, CaptureError> {
        let outcome = self.read_loop();
        let finished = self.finish(outcome);
        let status = lock(&self.shared.status).clone();
        (self.on_tick)(&status);
        finished
    }

    fn read_loop(&mut self) -> Result<(), CaptureError> {
        while !self.shared.stop.load(Ordering::SeqCst) {
            match self.capture.next_packet() {
                Ok(packet) => {
                    let header = *packet.header;
                    let data = packet.data;
                    let timestamp =
                        header.ts.tv_sec as f64 + f64::from(header.ts.tv_usec as u32) / 1_000_000.0;
                    let offset = self.spool.write(
                        header.ts.tv_sec as u32,
                        header.ts.tv_usec as u32,
                        header.len,
                        data,
                    )?;
                    let no = self.next_no;
                    self.next_no += 1;
                    self.frames_read += 1;
                    self.bytes += u64::from(header.len.max(header.caplen));
                    let row =
                        summary::summarize(no, timestamp, self.linktype, data, header.len, offset);
                    *self
                        .protocol_counts
                        .entry(row.protocol.clone())
                        .or_insert(0) += 1;
                    self.rows.push(row);
                    if self.pending.len() >= MAX_PENDING_FRAMES {
                        self.pending.remove(0);
                        self.app_dropped += 1;
                    }
                    self.pending.push(OwnedFrame {
                        timestamp,
                        orig_len: header.len,
                        data: data.to_vec(),
                    });
                }
                Err(pcap::Error::TimeoutExpired) => {}
                Err(e) => return Err(map_error(&e)),
            }
            if self.pending.len() >= BATCH_FRAMES || self.last_batch.elapsed() >= BATCH_INTERVAL {
                self.commit()?;
            }
        }
        Ok(())
    }

    /// Spool, commit, publish rows, refresh the counters, tick.
    fn commit(&mut self) -> Result<(), CaptureError> {
        self.spool.flush()?;
        let frames = std::mem::take(&mut self.pending);
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| CaptureError::Pcap("the writer was already finished".into()))?;
        let report = writer.commit_batch(self.linktype, &frames)?;
        {
            let mut ring = lock(&self.shared.ring);
            for row in self.rows.drain(..) {
                ring.push(row);
            }
        }
        let elapsed = self.last_batch.elapsed().as_secs_f64().max(1e-3);
        let pps = (self.frames_read - self.last_batch_frames) as f64 / elapsed;
        self.last_batch = Instant::now();
        self.last_batch_frames = self.frames_read;
        let kernel = self.capture.stats().ok();

        let mut protocol_counts: Vec<(String, u64)> = self
            .protocol_counts
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        protocol_counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        let (ring_total, ring_first_no) = {
            let ring = lock(&self.shared.ring);
            (ring.len(), ring.first_no())
        };
        let mut status = lock(&self.shared.status);
        status.seq += 1;
        status.counts = report.counts;
        status.bytes = self.bytes;
        status.pps = pps;
        if let Some(kernel) = kernel {
            status.kernel_received = u64::from(kernel.received);
            status.kernel_dropped = u64::from(kernel.dropped);
            status.if_dropped = u64::from(kernel.if_dropped);
        }
        status.app_dropped = self.app_dropped;
        status.ring_total = ring_total;
        status.ring_first_no = ring_first_no;
        status.protocol_counts = protocol_counts;
        if report.analysed {
            status.last_analysis_ms = report.analysis_ms;
        }
        let snapshot = status.clone();
        drop(status);
        (self.on_tick)(&snapshot);
        Ok(())
    }

    /// Commit what is pending, attribute every waiting fact and re-derive
    /// roles one last time, then record how the capture ended. A read error
    /// still keeps everything read before it.
    fn finish(&mut self, outcome: Result<(), CaptureError>) -> Result<ImportResult, CaptureError> {
        let committed = self.commit();
        let finished = match self.writer.take() {
            Some(writer) => writer.finish().map_err(CaptureError::from),
            None => Err(CaptureError::Pcap("the writer was already finished".into())),
        };
        let result = outcome.and(committed).and(finished);
        let mut status = lock(&self.shared.status);
        status.seq += 1;
        status.stopped_at = Some(now());
        match &result {
            Ok(counts) => {
                status.state = CaptureState::Stopped;
                status.counts = counts.clone();
            }
            Err(e) => {
                status.state = CaptureState::Failed;
                status.error = Some(e.to_string());
            }
        }
        result
    }
}
