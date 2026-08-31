use std::path::{Path, PathBuf};
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

/// Run a parse job on the blocking pool while a reporter task emits
/// `import-progress` every 150 ms. The reporter is stopped by an explicit
/// signal — success or failure — so a failed import never leaves it spinning.
async fn run_import<R: Send + 'static>(
    app: &AppHandle,
    path: &Path,
    work: impl FnOnce(&AtomicU64, &(dyn Fn(ImportStage) + Send + Sync)) -> Result<R, CoreError>
        + Send
        + 'static,
) -> Result<R, CoreError> {
    let file_size = std::fs::metadata(path)?.len();
    let progress = Arc::new(AtomicU64::new(0));

    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<()>();
    let progress_for_reporter = Arc::clone(&progress);
    let app_for_reporter = app.clone();
    let reporter = tauri::async_runtime::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut done_rx => break,
                () = tokio::time::sleep(std::time::Duration::from_millis(150)) => {
                    let done = progress_for_reporter.load(Ordering::Relaxed);
                    let _ = app_for_reporter.emit("import-progress", ImportProgress {
                        bytes_done: done,
                        bytes_total: file_size,
                    });
                }
            }
        }
    });

    let progress_for_parser = Arc::clone(&progress);
    let app_for_stages = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let on_stage = move |stage: ImportStage| {
            let _ = app_for_stages.emit("import-stage", stage);
        };
        work(&progress_for_parser, &on_stage)
    })
    .await
    .map_err(|e| CoreError::Internal(format!("task join: {e}")))?;

    let _ = done_tx.send(());
    let _ = reporter.await;
    if result.is_ok() {
        let _ = app.emit(
            "import-progress",
            ImportProgress {
                bytes_done: file_size,
                bytes_total: file_size,
            },
        );
    }
    result
}

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
    let parse_path = pcap_path.clone();
    let (session, import_result) = run_import(&app, &pcap_path, move |progress, on_stage| {
        Session::import(&parse_path, progress, on_stage)
    })
    .await?;

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
#[tauri::command]
pub async fn add_pcap(
    path: String,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<ImportResult, CoreError> {
    let pcap_path = PathBuf::from(&path);
    let parse_path = pcap_path.clone();
    // Hand a clone of the shared session to the blocking parse task.
    let session_arc = Arc::clone(&state.session);
    run_import(&app, &pcap_path, move |progress, on_stage| {
        let guard = session_arc
            .lock()
            .map_err(|e| CoreError::Internal(e.to_string()))?;
        let session = guard
            .as_ref()
            .ok_or_else(|| CoreError::Internal("no capture loaded".into()))?;
        session.add_capture(&parse_path, progress, on_stage)
    })
    .await
}
