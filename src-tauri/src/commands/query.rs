use purdungeon_core::types::{
    Connection, Finding, Host, HostDetail, ModbusConversation, ModbusHostActivity, Packet,
};
use purdungeon_core::{CoreError, Session};
use tauri::State;

use crate::AppState;

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_hosts(state: State<'_, AppState>) -> Result<Vec<Host>, CoreError> {
    state.with_session(Session::hosts)
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_connections(state: State<'_, AppState>) -> Result<Vec<Connection>, CoreError> {
    state.with_session(Session::connections)
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_time_range(state: State<'_, AppState>) -> Result<(f64, f64), CoreError> {
    state.with_session(Session::time_range)
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn save_node_position(
    host_id: i64,
    x: f64,
    y: f64,
    state: State<'_, AppState>,
) -> Result<(), CoreError> {
    state.with_session(|s| s.save_node_position(host_id, x, y))
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_node_positions(state: State<'_, AppState>) -> Result<Vec<(i64, f64, f64)>, CoreError> {
    state.with_session(Session::node_positions)
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_host_detail(
    host_id: i64,
    state: State<'_, AppState>,
) -> Result<HostDetail, CoreError> {
    state.with_session(|s| s.host_detail(host_id))
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_findings(state: State<'_, AppState>) -> Result<Vec<Finding>, CoreError> {
    state.with_session(Session::findings)
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_modbus_host_activity(
    host_id: i64,
    state: State<'_, AppState>,
) -> Result<ModbusHostActivity, CoreError> {
    state.with_session(|s| s.modbus_host_activity(host_id))
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_modbus_conversation(
    connection_id: i64,
    state: State<'_, AppState>,
) -> Result<ModbusConversation, CoreError> {
    state.with_session(|s| s.modbus_conversation(connection_id))
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn set_role_override(
    host_id: i64,
    role: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), CoreError> {
    state.with_session(|s| s.set_role_override(host_id, role.as_deref()))
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn set_level_override(
    host_id: i64,
    level: Option<i64>,
    state: State<'_, AppState>,
) -> Result<(), CoreError> {
    state.with_session(|s| s.set_level_override(host_id, level))
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_connection_packets(
    connection_id: i64,
    limit: i64,
    state: State<'_, AppState>,
) -> Result<Vec<Packet>, CoreError> {
    state.with_session(|s| s.connection_packets(connection_id, limit))
}
