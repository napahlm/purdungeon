mod commands;

use std::sync::Mutex;

use coil_core::{CoreError, Session};

pub struct AppState {
    pub session: Mutex<Option<Session>>,
}

impl AppState {
    pub fn with_session<T>(
        &self,
        f: impl FnOnce(&Session) -> Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        let lock = self
            .session
            .lock()
            .map_err(|e| CoreError::Internal(e.to_string()))?;
        let session = lock
            .as_ref()
            .ok_or_else(|| CoreError::Internal("no capture loaded".into()))?;
        f(session)
    }
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            session: Mutex::new(None),
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
