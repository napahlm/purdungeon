//! Headless analysis core: pcap ingest, protocol parsing, and asset discovery.
//! No UI dependencies — the Tauri shell (or a CLI) drives it through `Session`.

pub mod analysis;
pub mod error;
pub mod ingest;
pub mod oui;
pub mod protocols;
pub mod store;
pub mod types;

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

pub use error::CoreError;
use types::{
    Connection, Finding, Host, HostDetail, ImportResult, ImportStage, ModbusConversation,
    ModbusHostActivity, Packet,
};

/// One imported capture: a temp `SQLite` database plus query access.
/// Dropping the session removes the temp files.
pub struct Session {
    conn: Arc<Mutex<rusqlite::Connection>>,
    path: PathBuf,
}

impl Session {
    /// Parse a pcap/pcapng file into a fresh session database, then run the
    /// analysis pass (protocol naming, role and Purdue level inference).
    /// `progress` is advanced by bytes consumed during the reading stage;
    /// callers may poll it from another thread. `on_stage` fires as each
    /// stage begins.
    pub fn import(
        pcap_path: &Path,
        progress: &AtomicU64,
        on_stage: &(dyn Fn(ImportStage) + Send + Sync),
    ) -> Result<(Self, ImportResult), CoreError> {
        let (conn, db_path) = store::schema::init_db()?;
        on_stage(ImportStage::ReadingPackets);
        let result = ingest::pcap::parse_pcap(pcap_path, &conn, progress)?;
        analysis::run(&conn, on_stage)?;
        Ok((
            Self {
                conn: Arc::new(Mutex::new(conn)),
                path: db_path,
            },
            result,
        ))
    }

    /// Merge another capture into this session: parse it into the existing
    /// database without clearing, then re-run the analysis pass over the whole
    /// merged dataset so roles, levels, and findings reflect every file. User
    /// role/level overrides are preserved — re-inference only writes the
    /// inferred columns.
    pub fn add_capture(
        &self,
        pcap_path: &Path,
        progress: &AtomicU64,
        on_stage: &(dyn Fn(ImportStage) + Send + Sync),
    ) -> Result<ImportResult, CoreError> {
        self.with_conn(|conn| {
            on_stage(ImportStage::ReadingPackets);
            let result = ingest::pcap::append_pcap(pcap_path, conn, progress)?;
            analysis::run(conn, on_stage)?;
            Ok(result)
        })
    }

    fn with_conn<T>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CoreError::Internal(e.to_string()))?;
        f(&conn)
    }

    pub fn hosts(&self) -> Result<Vec<Host>, CoreError> {
        self.with_conn(store::queries::get_all_hosts)
    }

    pub fn connections(&self) -> Result<Vec<Connection>, CoreError> {
        self.with_conn(store::queries::get_all_connections)
    }

    pub fn time_range(&self) -> Result<(f64, f64), CoreError> {
        self.with_conn(store::queries::get_time_range)
    }

    pub fn host_detail(&self, host_id: i64) -> Result<HostDetail, CoreError> {
        self.with_conn(|c| store::queries::get_host_detail(c, host_id))
    }

    pub fn connection_packets(&self, connection_id: i64, limit: i64) -> Result<Vec<Packet>, CoreError> {
        self.with_conn(|c| store::queries::get_connection_packets(c, connection_id, limit))
    }

    pub fn save_node_position(&self, host_id: i64, x: f64, y: f64) -> Result<(), CoreError> {
        self.with_conn(|c| store::queries::save_node_position(c, host_id, x, y))
    }

    pub fn findings(&self) -> Result<Vec<Finding>, CoreError> {
        self.with_conn(store::queries::get_findings)
    }

    pub fn modbus_host_activity(&self, host_id: i64) -> Result<ModbusHostActivity, CoreError> {
        self.with_conn(|c| store::modbus::host_activity(c, host_id))
    }

    pub fn modbus_conversation(&self, connection_id: i64) -> Result<ModbusConversation, CoreError> {
        self.with_conn(|c| store::modbus::conversation(c, connection_id))
    }

    pub fn set_role_override(&self, host_id: i64, role: Option<&str>) -> Result<(), CoreError> {
        self.with_conn(|c| store::queries::set_role_override(c, host_id, role))
    }

    pub fn set_level_override(&self, host_id: i64, level: Option<i64>) -> Result<(), CoreError> {
        self.with_conn(|c| store::queries::set_level_override(c, host_id, level))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        store::schema::cleanup_db(&self.path);
    }
}
