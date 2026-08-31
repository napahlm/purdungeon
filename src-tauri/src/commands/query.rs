//! Read commands over the loaded session. All of these are `async` so Tauri
//! runs them off the main thread — a long-running query (or one waiting on
//! the session mutex during an import) must never freeze the window.

use purdungeon_core::types::{
    Connection, Finding, HistogramBucket, Host, HostDetail, ModbusConversation, ModbusHostActivity,
};
use purdungeon_core::{CoreError, Session};
use tauri::State;

use crate::AppState;

#[tauri::command]
pub async fn get_hosts(state: State<'_, AppState>) -> Result<Vec<Host>, CoreError> {
    state.with_session(Session::hosts)
}

#[tauri::command]
pub async fn get_connections(state: State<'_, AppState>) -> Result<Vec<Connection>, CoreError> {
    state.with_session(Session::connections)
}

#[tauri::command]
pub async fn get_time_range(state: State<'_, AppState>) -> Result<(f64, f64), CoreError> {
    state.with_session(Session::time_range)
}

#[tauri::command]
pub async fn get_traffic_histogram(
    buckets: usize,
    state: State<'_, AppState>,
) -> Result<Vec<HistogramBucket>, CoreError> {
    state.with_session(|s| s.traffic_histogram(buckets))
}

#[tauri::command]
pub async fn save_node_position(
    host_id: i64,
    x: f64,
    y: f64,
    state: State<'_, AppState>,
) -> Result<(), CoreError> {
    state.with_session(|s| s.save_node_position(host_id, x, y))
}

#[tauri::command]
pub async fn get_node_positions(
    state: State<'_, AppState>,
) -> Result<Vec<(i64, f64, f64)>, CoreError> {
    state.with_session(Session::node_positions)
}

#[tauri::command]
pub async fn get_host_detail(
    host_id: i64,
    state: State<'_, AppState>,
) -> Result<HostDetail, CoreError> {
    state.with_session(|s| s.host_detail(host_id))
}

#[tauri::command]
pub async fn get_findings(state: State<'_, AppState>) -> Result<Vec<Finding>, CoreError> {
    state.with_session(Session::findings)
}

#[tauri::command]
pub async fn get_modbus_host_activity(
    host_id: i64,
    state: State<'_, AppState>,
) -> Result<ModbusHostActivity, CoreError> {
    state.with_session(|s| s.modbus_host_activity(host_id))
}

#[tauri::command]
pub async fn get_modbus_conversation(
    connection_id: i64,
    state: State<'_, AppState>,
) -> Result<ModbusConversation, CoreError> {
    state.with_session(|s| s.modbus_conversation(connection_id))
}

#[tauri::command]
pub async fn set_role_override(
    host_id: i64,
    role: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), CoreError> {
    state.with_session(|s| s.set_role_override(host_id, role.as_deref()))
}

#[tauri::command]
pub async fn set_level_override(
    host_id: i64,
    level: Option<i64>,
    state: State<'_, AppState>,
) -> Result<(), CoreError> {
    state.with_session(|s| s.set_level_override(host_id, level))
}
