//! Live capture commands: list interfaces, start and stop a capture, page
//! the packet list, read one packet back, save the spool as a pcap, and
//! close the session. The capture thread lives in the core; the shell owns
//! its handle and forwards every tick as a `capture-tick` event.

use std::path::PathBuf;

use purdungeon_core::live::{
    self, CaptureError, CaptureHandle, CaptureOptions, CaptureStatus, InterfaceInfo, PacketDetail,
    PacketPage, LIVE_GRACE_SECS,
};
use purdungeon_core::{CoreError, Session};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::AppState;

/// `{ code, message }`: the UI picks its advice by code and quotes the
/// message.
#[derive(Debug, Clone, Serialize)]
pub struct CaptureFailure {
    code: String,
    message: String,
}

impl CaptureFailure {
    fn new(code: &str, message: impl std::fmt::Display) -> Self {
        Self {
            code: code.into(),
            message: message.to_string(),
        }
    }
}

impl From<CaptureError> for CaptureFailure {
    fn from(e: CaptureError) -> Self {
        Self::new(e.code(), e)
    }
}

impl From<CoreError> for CaptureFailure {
    fn from(e: CoreError) -> Self {
        Self::new("core", e)
    }
}

fn internal(e: impl std::fmt::Display) -> CaptureFailure {
    CaptureFailure::new("internal", e)
}

/// Run `f` on the current capture handle, or fail when there is none.
fn with_capture<T>(
    state: &AppState,
    f: impl FnOnce(&CaptureHandle) -> Result<T, CaptureFailure>,
) -> Result<T, CaptureFailure> {
    let lock = state.capture.lock().map_err(internal)?;
    let handle = lock
        .as_ref()
        .ok_or_else(|| CaptureFailure::new("no-capture", "no capture has been started"))?;
    f(handle)
}

#[tauri::command]
pub async fn list_interfaces() -> Result<Vec<InterfaceInfo>, CaptureFailure> {
    Ok(live::list_interfaces()?)
}

/// Open the interface and start reading it into the loaded session, or into
/// a fresh one when nothing is loaded. Returns the initial status, so the
/// UI knows the link type and whether promiscuous mode was granted.
#[tauri::command]
pub async fn start_capture(
    options: CaptureOptions,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<CaptureStatus, CaptureFailure> {
    let mut slot = state.capture.lock().map_err(internal)?;
    if slot.as_ref().is_some_and(CaptureHandle::is_running) {
        return Err(CaptureError::AlreadyRunning.into());
    }
    // A finished capture's spool is kept for Save until the next one starts.
    *slot = None;

    let writer = {
        let mut session = state.session.lock().map_err(internal)?;
        if session.is_none() {
            *session = Some(Session::empty()?);
        }
        session
            .as_ref()
            .ok_or_else(|| internal("no session"))?
            .live_writer(LIVE_GRACE_SECS)?
    };
    let spool: PathBuf = app
        .path()
        .app_cache_dir()
        .map_err(internal)?
        .join("live")
        .join(format!("{}.pcap", uuid::Uuid::new_v4()));

    let emitter = app.clone();
    let handle = live::start(
        &options,
        writer,
        spool,
        Box::new(move |status| {
            let _ = emitter.emit("capture-tick", status);
        }),
    )?;
    let status = handle.status();
    *slot = Some(handle);
    Ok(status)
}

/// Stop reading. Joining the capture thread waits for its final batch and
/// analysis, so it runs on the blocking pool.
#[tauri::command]
pub async fn stop_capture(state: State<'_, AppState>) -> Result<CaptureStatus, CaptureFailure> {
    let capture = std::sync::Arc::clone(&state.capture);
    tauri::async_runtime::spawn_blocking(move || {
        let mut lock = capture.lock().map_err(internal)?;
        let handle = lock
            .as_mut()
            .ok_or_else(|| CaptureFailure::new("no-capture", "no capture has been started"))?;
        Ok(handle.stop()?)
    })
    .await
    .map_err(internal)?
}

#[tauri::command]
pub async fn capture_status(
    state: State<'_, AppState>,
) -> Result<Option<CaptureStatus>, CaptureFailure> {
    let lock = state.capture.lock().map_err(internal)?;
    Ok(lock.as_ref().map(CaptureHandle::status))
}

#[tauri::command]
pub async fn get_packets(
    offset: usize,
    limit: usize,
    query: Option<String>,
    state: State<'_, AppState>,
) -> Result<PacketPage, CaptureFailure> {
    with_capture(&state, |h| {
        Ok(h.packets(offset, limit.min(1000), query.as_deref()))
    })
}

#[tauri::command]
pub async fn get_packet_detail(
    no: u64,
    state: State<'_, AppState>,
) -> Result<PacketDetail, CaptureFailure> {
    with_capture(&state, |h| Ok(h.packet_detail(no)?))
}

/// Copy the spool to `path`. Only once the capture has stopped: the spool
/// is still being appended to while it runs, and a saved file must be
/// whole.
#[tauri::command]
pub async fn save_capture(path: String, state: State<'_, AppState>) -> Result<u64, CaptureFailure> {
    with_capture(&state, |h| {
        if h.is_running() {
            return Err(CaptureFailure::new(
                "still-running",
                "stop the capture before saving it",
            ));
        }
        std::fs::copy(h.spool_path(), &path).map_err(|e| CaptureFailure::new("io", e))
    })
}

/// Close whatever is loaded: stop a running capture, remove its spool, and
/// drop the session with its temp database. In that order, so the writer's
/// connection is gone before the database file is deleted.
#[tauri::command]
pub async fn close_session(state: State<'_, AppState>) -> Result<(), CaptureFailure> {
    let capture = std::sync::Arc::clone(&state.capture);
    let session = std::sync::Arc::clone(&state.session);
    tauri::async_runtime::spawn_blocking(move || {
        let taken = capture.lock().map_err(internal)?.take();
        drop(taken);
        *session.lock().map_err(internal)? = None;
        Ok(())
    })
    .await
    .map_err(internal)?
}
