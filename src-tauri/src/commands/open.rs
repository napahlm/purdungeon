//! Captures reach the app by more than a drop: paths on the command line, a
//! file double-clicked or "opened with" purdungeon (macOS delivers those as
//! `RunEvent::Opened`, not as arguments), and the sample captures bundled into
//! the binary behind the start screen's "open the sample captures" button.

use std::path::PathBuf;

use purdungeon_core::CoreError;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::AppState;

/// Files the OS asked us to open, held until the webview says it is listening.
#[derive(Default)]
pub struct PendingOpens {
    ready: bool,
    paths: Vec<PathBuf>,
}

/// The same files as `examples/` and the golden tests, so what a new user sees
/// first is also what CI checks on every change. About 260 KB in the binary.
const SAMPLES: &[(&str, &[u8])] = &[
    (
        "icsnpp-modbus.pcap",
        include_bytes!("../../../examples/icsnpp-modbus.pcap"),
    ),
    (
        "icsnpp-s7comm-plus.pcap",
        include_bytes!("../../../examples/icsnpp-s7comm-plus.pcap"),
    ),
    (
        "icsnpp-profinet-mixed.pcap",
        include_bytes!("../../../examples/icsnpp-profinet-mixed.pcap"),
    ),
];

fn internal(e: impl std::fmt::Display) -> CoreError {
    CoreError::Internal(e.to_string())
}

fn to_strings(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect()
}

/// Captures named on the command line, plus any the OS handed over before the
/// window was listening. Calling this marks the webview ready, so later opens
/// go straight to it as `open-captures` events instead of queueing.
///
/// Async like every other command, so Tauri runs it off the main thread.
#[tauri::command]
pub async fn initial_captures(state: State<'_, AppState>) -> Result<Vec<String>, CoreError> {
    let mut paths: Vec<PathBuf> = std::env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .filter(|p| p.is_file())
        .collect();
    let mut pending = state.opens.lock().map_err(internal)?;
    pending.ready = true;
    paths.append(&mut pending.paths);
    Ok(to_strings(&paths))
}

/// Route an OS open request (`RunEvent::Opened`): to the window if it is
/// listening, otherwise into the queue `initial_captures` drains.
pub fn opened(app: &AppHandle, urls: &[tauri::Url]) {
    let paths: Vec<PathBuf> = urls.iter().filter_map(|u| u.to_file_path().ok()).collect();
    if paths.is_empty() {
        return;
    }
    let state = app.state::<AppState>();
    let Ok(mut pending) = state.opens.lock() else {
        return;
    };
    if pending.ready {
        let _ = app.emit("open-captures", to_strings(&paths));
    } else {
        pending.paths.extend(paths);
    }
}

/// Write the bundled sample captures to the app's cache folder and return
/// their paths, for the frontend to import like any dropped file. Rewritten on
/// every call so a copy left by an older build never goes stale.
#[tauri::command]
pub async fn sample_captures(app: AppHandle) -> Result<Vec<String>, CoreError> {
    let dir = app
        .path()
        .app_cache_dir()
        .map_err(internal)?
        .join("examples");
    std::fs::create_dir_all(&dir)?;
    let mut paths = Vec::with_capacity(SAMPLES.len());
    for (name, bytes) in SAMPLES {
        let path = dir.join(name);
        std::fs::write(&path, bytes)?;
        paths.push(path);
    }
    Ok(to_strings(&paths))
}
