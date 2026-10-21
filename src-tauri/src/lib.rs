mod commands;

use std::sync::{Arc, Mutex};

use purdungeon_core::live::CaptureHandle;
use purdungeon_core::{CoreError, Session};
use tauri::Manager;

pub struct AppState {
    // Arc so an async command can hand a clone to a blocking task while the
    // session lives on in shared state.
    pub session: Arc<Mutex<Option<Session>>>,
    // Files the OS asked us to open before the window was ready to hear it.
    pub opens: Mutex<commands::open::PendingOpens>,
    // The live capture feeding the session, kept after it stops so its
    // packets stay listed and its spool can be saved.
    pub capture: Arc<Mutex<Option<CaptureHandle>>>,
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

    pub fn capture_running(&self) -> bool {
        self.capture
            .lock()
            .is_ok_and(|lock| lock.as_ref().is_some_and(CaptureHandle::is_running))
    }

    /// Stop any capture and remove its spool. Dropping the handle does both.
    pub fn drop_capture(&self) {
        if let Ok(mut lock) = self.capture.lock() {
            *lock = None;
        }
    }
}

pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            session: Arc::new(Mutex::new(None)),
            opens: Mutex::new(commands::open::PendingOpens::default()),
            capture: Arc::new(Mutex::new(None)),
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
            commands::capture::list_interfaces,
            commands::capture::start_capture,
            commands::capture::stop_capture,
            commands::capture::capture_status,
            commands::capture::get_packets,
            commands::capture::get_packet_detail,
            commands::capture::save_capture,
            commands::capture::close_session,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build purdungeon");

    app.run(|app, event| {
        match event {
            // macOS hands double-clicked and "Open with" files over as an
            // event rather than on the command line.
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            tauri::RunEvent::Opened { urls } => commands::open::opened(app, &urls),
            // A capture must not outlive the window: stop it (which commits
            // what it read) and remove its spool before the process goes.
            tauri::RunEvent::ExitRequested { .. } => app.state::<AppState>().drop_capture(),
            _ => {}
        }
    });
}
