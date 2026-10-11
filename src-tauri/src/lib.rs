mod commands;

use std::sync::{Arc, Mutex};

use purdungeon_core::{CoreError, Session};

pub struct AppState {
    // Arc so an async command can hand a clone to a blocking task while the
    // session lives on in shared state.
    pub session: Arc<Mutex<Option<Session>>>,
    // Files the OS asked us to open before the window was ready to hear it.
    pub opens: Mutex<commands::open::PendingOpens>,
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
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            session: Arc::new(Mutex::new(None)),
            opens: Mutex::new(commands::open::PendingOpens::default()),
        })
        .invoke_handler(tauri::generate_handler![
            commands::import::import_pcap,
            commands::import::add_pcap,
            commands::open::initial_captures,
            commands::open::sample_captures,
            commands::query::get_hosts,
            commands::query::get_connections,
            commands::query::get_time_range,
            commands::query::get_traffic_histogram,
            commands::query::save_node_position,
            commands::query::get_node_positions,
            commands::query::get_host_detail,
            commands::query::set_role_override,
            commands::query::set_level_override,
            commands::query::get_modbus_host_activity,
            commands::query::get_modbus_conversation,
            commands::query::get_findings,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build purdungeon");

    app.run(|app, event| {
        // macOS hands double-clicked and "Open with" files over as an event
        // rather than on the command line.
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        if let tauri::RunEvent::Opened { urls } = event {
            commands::open::opened(app, &urls);
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        let _ = (app, event);
    });
}
