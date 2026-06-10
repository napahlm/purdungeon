use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ImportResult {
    pub host_count: usize,
    pub connection_count: usize,
    pub packet_count: usize,
    pub time_range: (f64, f64),
}

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
