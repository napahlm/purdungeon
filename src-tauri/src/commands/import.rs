use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{AppHandle, Emitter, State};

use crate::db::schema;
use crate::parser::pcap;
use crate::{AppState, DbHandle, CoilSnifferError};

#[derive(Debug, Clone, Serialize)]
pub struct ImportResult {
    pub host_count: usize,
    pub connection_count: usize,
    pub packet_count: usize,
    pub time_range: (f64, f64),
}

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
) -> Result<ImportResult, CoilSnifferError> {
    // Drop previous DB (cleans up temp file via DbHandle::drop)
    {
        let mut db_lock = state.db.lock().map_err(|e| CoilSnifferError::Parse(e.to_string()))?;
        *db_lock = None;
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
    let result = tauri::async_runtime::spawn_blocking(move || {
        let (conn, db_path) = schema::init_db()?;
        let conn = Arc::new(Mutex::new(conn));
        let parse_result = pcap::parse_pcap(&pcap_path, &conn, &progress_for_parser)?;
        Ok::<_, CoilSnifferError>((conn, db_path, parse_result))
    })
    .await
    .map_err(|e| CoilSnifferError::Parse(format!("task join: {e}")))??
    ;

    let (conn, db_path, import_result) = result;

    // Signal completion and stop progress reporter
    progress.store(file_size, Ordering::Relaxed);
    let _ = app.emit("import-progress", ImportProgress {
        bytes_done: file_size,
        bytes_total: file_size,
    });
    let _ = progress_task.await;

    let mut db_lock = state.db.lock().map_err(|e| CoilSnifferError::Parse(e.to_string()))?;
    *db_lock = Some(DbHandle { conn, path: db_path });

    Ok(import_result)
}
