use std::path::PathBuf;

use rusqlite::Connection;

use crate::CoreError;

pub fn init_db() -> Result<(Connection, PathBuf), CoreError> {
    let db_path = std::env::temp_dir().join(format!("purdungeon-{}.db", uuid::Uuid::new_v4()));
    let conn = Connection::open(&db_path)?;

    // The database is a disposable per-session temp file, so durability
    // doesn't matter — but ROLLBACK must still work for failed imports, which
    // rules out journal_mode=OFF. MEMORY keeps the journal in RAM.
    conn.execute_batch("PRAGMA journal_mode=MEMORY;")?;
    conn.execute_batch("PRAGMA synchronous=OFF;")?;
    conn.execute_batch("PRAGMA foreign_keys=OFF;")?;
    conn.execute_batch("PRAGMA cache_size=-64000;")?; // 64MB cache
    conn.execute_batch("PRAGMA temp_store=MEMORY;")?;
    conn.execute_batch("PRAGMA mmap_size=268435456;")?; // 256MB mmap

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY,
            mac_address TEXT NOT NULL,
            ip_address TEXT NOT NULL UNIQUE,
            hostname TEXT,
            vendor TEXT,
            role TEXT NOT NULL DEFAULT 'unknown',
            role_confidence REAL NOT NULL DEFAULT 0,
            role_evidence TEXT,
            purdue_level INTEGER,
            role_override TEXT,
            level_override INTEGER,
            protocols TEXT NOT NULL DEFAULT '',
            link_protocols TEXT NOT NULL DEFAULT '',
            is_external INTEGER NOT NULL DEFAULT 0,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY,
            src_host_id INTEGER NOT NULL,
            dst_host_id INTEGER NOT NULL,
            src_port INTEGER NOT NULL,
            dst_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            app_protocol TEXT,
            vlan_id INTEGER,
            packet_count INTEGER NOT NULL DEFAULT 1,
            byte_count INTEGER NOT NULL DEFAULT 0,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY,
            -- NULL for link-layer-only frames (ARP, LLDP, CDP)
            connection_id INTEGER,
            timestamp REAL NOT NULL,
            length INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS modbus_events (
            id INTEGER PRIMARY KEY,
            connection_id INTEGER NOT NULL,
            src_host_id INTEGER NOT NULL,
            dst_host_id INTEGER NOT NULL,
            timestamp REAL NOT NULL,
            is_request INTEGER NOT NULL,
            transaction_id INTEGER NOT NULL,
            unit_id INTEGER NOT NULL,
            function_code INTEGER NOT NULL,
            is_exception INTEGER NOT NULL DEFAULT 0,
            exception_code INTEGER,
            start_address INTEGER,
            quantity INTEGER,
            is_write INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            detail TEXT NOT NULL,
            host_ids TEXT NOT NULL DEFAULT '',
            connection_ids TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS node_positions (
            host_id INTEGER PRIMARY KEY REFERENCES hosts(id),
            x REAL NOT NULL,
            y REAL NOT NULL
        );",
    )?;

    Ok((conn, db_path))
}

pub fn cleanup_db(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
}

pub fn clear_data(conn: &Connection) -> Result<(), CoreError> {
    conn.execute_batch(
        "DELETE FROM packets;
         DELETE FROM connections;
         DELETE FROM hosts;
         DELETE FROM modbus_events;
         DELETE FROM findings;
         DELETE FROM node_positions;",
    )?;
    Ok(())
}

pub fn drop_packet_indexes(conn: &Connection) -> Result<(), CoreError> {
    conn.execute_batch(
        "DROP INDEX IF EXISTS idx_packets_timestamp;
         DROP INDEX IF EXISTS idx_packets_connection;
         DROP INDEX IF EXISTS idx_modbus_connection;
         DROP INDEX IF EXISTS idx_modbus_src_host;
         DROP INDEX IF EXISTS idx_modbus_dst_host;
         DROP INDEX IF EXISTS idx_connections_hosts;
         DROP INDEX IF EXISTS idx_connections_dst_host;",
    )?;
    Ok(())
}

pub fn create_packet_indexes(conn: &Connection) -> Result<(), CoreError> {
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
         CREATE INDEX IF NOT EXISTS idx_packets_connection ON packets(connection_id);
         CREATE INDEX IF NOT EXISTS idx_modbus_connection ON modbus_events(connection_id);
         CREATE INDEX IF NOT EXISTS idx_modbus_src_host ON modbus_events(src_host_id);
         CREATE INDEX IF NOT EXISTS idx_modbus_dst_host ON modbus_events(dst_host_id);
         CREATE INDEX IF NOT EXISTS idx_connections_hosts ON connections(src_host_id, dst_host_id);
         CREATE INDEX IF NOT EXISTS idx_connections_dst_host ON connections(dst_host_id);",
    )?;
    Ok(())
}
