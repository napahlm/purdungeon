mod commands;
mod db;
mod error;
mod oui;
mod parser;
mod protocols;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub use error::CoilSnifferError;

pub struct DbHandle {
    pub conn: Arc<Mutex<rusqlite::Connection>>,
    pub path: PathBuf,
}

impl Drop for DbHandle {
    fn drop(&mut self) {
        db::schema::cleanup_db(&self.path);
    }
}

pub struct AppState {
    pub db: Mutex<Option<DbHandle>>,
}

impl AppState {
    pub fn get_conn(&self) -> Result<Arc<Mutex<rusqlite::Connection>>, CoilSnifferError> {
        let lock = self.db.lock().map_err(|e| CoilSnifferError::Parse(e.to_string()))?;
        lock.as_ref()
            .map(|h| Arc::clone(&h.conn))
            .ok_or_else(|| CoilSnifferError::Parse("no database loaded".into()))
    }
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            db: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            commands::import::import_pcap,
            commands::query::get_hosts,
            commands::query::get_connections,
            commands::query::get_time_range,
            commands::query::save_node_position,
            commands::query::get_host_detail,
            commands::query::get_connection_packets,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run coil-sniffer");
}
