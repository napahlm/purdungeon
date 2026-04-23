use serde::Serialize;
use tauri::State;

use crate::db::queries;
use crate::{AppState, CoilSnifferError};

#[derive(Debug, Serialize)]
pub struct Host {
    pub id: i64,
    pub mac_address: String,
    pub ip_address: String,
    pub device_type: String,
    pub first_seen: f64,
    pub last_seen: f64,
}

#[derive(Debug, Serialize)]
pub struct Connection {
    pub id: i64,
    pub src_host_id: i64,
    pub dst_host_id: i64,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub app_protocol: Option<String>,
    pub packet_count: i64,
    pub byte_count: i64,
    pub first_seen: f64,
    pub last_seen: f64,
}

#[derive(Debug, Serialize)]
pub struct HostDetail {
    pub host: Host,
    pub connections: Vec<HostConnection>,
    pub total_packets: i64,
    pub total_bytes: i64,
}

#[derive(Debug, Serialize)]
pub struct HostConnection {
    pub connection_id: i64,
    pub peer_ip: String,
    pub peer_mac: String,
    pub direction: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub app_protocol: Option<String>,
    pub packet_count: i64,
    pub byte_count: i64,
    pub first_seen: f64,
    pub last_seen: f64,
}

#[derive(Debug, Serialize)]
pub struct Packet {
    pub id: i64,
    pub timestamp: f64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub length: i64,
}

fn get_db(
    state: &State<'_, AppState>,
) -> Result<std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>, CoilSnifferError> {
    state.get_conn()
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_hosts(state: State<'_, AppState>) -> Result<Vec<Host>, CoilSnifferError> {
    let db = get_db(&state)?;
    let conn = db.lock().map_err(|e| CoilSnifferError::Parse(e.to_string()))?;
    queries::get_all_hosts(&conn)
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_connections(state: State<'_, AppState>) -> Result<Vec<Connection>, CoilSnifferError> {
    let db = get_db(&state)?;
    let conn = db.lock().map_err(|e| CoilSnifferError::Parse(e.to_string()))?;
    queries::get_all_connections(&conn)
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_time_range(state: State<'_, AppState>) -> Result<(f64, f64), CoilSnifferError> {
    let db = get_db(&state)?;
    let conn = db.lock().map_err(|e| CoilSnifferError::Parse(e.to_string()))?;
    queries::get_time_range(&conn)
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn save_node_position(
    host_id: i64,
    x: f64,
    y: f64,
    state: State<'_, AppState>,
) -> Result<(), CoilSnifferError> {
    let db = get_db(&state)?;
    let conn = db.lock().map_err(|e| CoilSnifferError::Parse(e.to_string()))?;
    queries::save_node_position(&conn, host_id, x, y)
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_host_detail(
    host_id: i64,
    state: State<'_, AppState>,
) -> Result<HostDetail, CoilSnifferError> {
    let db = get_db(&state)?;
    let conn = db.lock().map_err(|e| CoilSnifferError::Parse(e.to_string()))?;
    queries::get_host_detail(&conn, host_id)
}

#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_connection_packets(
    connection_id: i64,
    limit: i64,
    state: State<'_, AppState>,
) -> Result<Vec<Packet>, CoilSnifferError> {
    let db = get_db(&state)?;
    let conn = db.lock().map_err(|e| CoilSnifferError::Parse(e.to_string()))?;
    queries::get_connection_packets(&conn, connection_id, limit)
}
