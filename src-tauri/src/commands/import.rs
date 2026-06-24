use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use purdungeon_core::types::{ImportResult, ImportStage};
use purdungeon_core::{CoreError, Session};
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};

use crate::AppState;

#[derive(Clone, Serialize)]
struct ImportProgress {
    bytes_done: u64,
    bytes_total: u64,
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn import_pcap(
    path: String,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<ImportResult, CoreError> {
    // Drop previous session (cleans up its temp DB on drop)
    {
        let mut lock = state
            .session
            .lock()
            .map_err(|e| CoreError::Internal(e.to_string()))?;
        *lock = None;
    }

    let pcap_path = PathBuf::from(&path);
    let progress = Arc::new(AtomicU64::new(0));
    let file_size = std::fs::metadata(&pcap_path)?.len();

    // Spawn progress reporter
    let progress_clone = Arc::clone(&progress);
    let app_clone = app.clone();
    let progress_task = tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            let done = progress_clone.load(Ordering::Relaxed);
            let _ = app_clone.emit("import-progress", ImportProgress {
                bytes_done: done,
                bytes_total: file_size,
            });
            if done >= file_size {
                break;
            }
        }
    });

    let progress_for_parser = Arc::clone(&progress);
    let app_for_stages = app.clone();
    let (session, import_result) = tauri::async_runtime::spawn_blocking(move || {
        let on_stage = move |stage: ImportStage| {
            let _ = app_for_stages.emit("import-stage", stage);
        };
        Session::import(&pcap_path, &progress_for_parser, &on_stage)
    })
    .await
    .map_err(|e| CoreError::Internal(format!("task join: {e}")))??;

    // Signal completion and stop progress reporter
    progress.store(file_size, Ordering::Relaxed);
    let _ = app.emit("import-progress", ImportProgress {
        bytes_done: file_size,
        bytes_total: file_size,
    });
    let _ = progress_task.await;

    let mut lock = state
        .session
        .lock()
        .map_err(|e| CoreError::Internal(e.to_string()))?;
    *lock = Some(session);

    Ok(import_result)
}

/// Merge another capture into the loaded session. Unlike `import_pcap`, this
/// keeps the current session and adds to it, then re-derives roles and findings
/// over the combined dataset.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn add_pcap(
    path: String,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<ImportResult, CoreError> {
    let pcap_path = PathBuf::from(&path);
    let progress = Arc::new(AtomicU64::new(0));
    let file_size = std::fs::metadata(&pcap_path)?.len();

    // Spawn progress reporter
    let progress_clone = Arc::clone(&progress);
    let app_clone = app.clone();
    let progress_task = tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            let done = progress_clone.load(Ordering::Relaxed);
            let _ = app_clone.emit("import-progress", ImportProgress {
                bytes_done: done,
                bytes_total: file_size,
            });
            if done >= file_size {
                break;
            }
        }
    });

    // Hand a clone of the shared session to the blocking parse task.
    let session_arc = Arc::clone(&state.session);
    let progress_for_parser = Arc::clone(&progress);
    let app_for_stages = app.clone();
    let import_result = tauri::async_runtime::spawn_blocking(move || {
        let on_stage = move |stage: ImportStage| {
            let _ = app_for_stages.emit("import-stage", stage);
        };
        let guard = session_arc
            .lock()
            .map_err(|e| CoreError::Internal(e.to_string()))?;
        let session = guard
            .as_ref()
            .ok_or_else(|| CoreError::Internal("no capture loaded".into()))?;
        session.add_capture(&pcap_path, &progress_for_parser, &on_stage)
    })
    .await
    .map_err(|e| CoreError::Internal(format!("task join: {e}")))??;

    // Signal completion and stop progress reporter
    progress.store(file_size, Ordering::Relaxed);
    let _ = app.emit("import-progress", ImportProgress {
        bytes_done: file_size,
        bytes_total: file_size,
    });
    let _ = progress_task.await;

    Ok(import_result)
}
