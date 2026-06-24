mod commands;

use std::sync::{Arc, Mutex};

use purdungeon_core::{CoreError, Session};

pub struct AppState {
    // Arc so an async command can hand a clone to a blocking task while the
    // session lives on in shared state.
    pub session: Arc<Mutex<Option<Session>>>,
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
            session: Arc::new(Mutex::new(None)),
        })
        .invoke_handler(tauri::generate_handler![
            commands::import::import_pcap,
            commands::import::add_pcap,
            commands::query::get_hosts,
            commands::query::get_connections,
            commands::query::get_time_range,
            commands::query::save_node_position,
            commands::query::get_node_positions,
            commands::query::get_host_detail,
            commands::query::get_connection_packets,
            commands::query::set_role_override,
            commands::query::set_level_override,
            commands::query::get_modbus_host_activity,
            commands::query::get_modbus_conversation,
            commands::query::get_findings,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run purdungeon");
}
