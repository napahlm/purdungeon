use std::path::PathBuf;

use rusqlite::Connection;

use crate::CoreError;

pub fn init_db() -> Result<(Connection, PathBuf), CoreError> {
    let db_path = std::env::temp_dir().join(format!("coil-sniffer-{}.db", uuid::Uuid::new_v4()));
    let conn = Connection::open(&db_path)?;

    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch("PRAGMA synchronous=NORMAL;")?;
    conn.execute_batch("PRAGMA foreign_keys=OFF;")?;
    conn.execute_batch("PRAGMA cache_size=-64000;")?; // 64MB cache
    conn.execute_batch("PRAGMA temp_store=MEMORY;")?;
    conn.execute_batch("PRAGMA mmap_size=268435456;")?; // 256MB mmap

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address TEXT NOT NULL,
            ip_address TEXT NOT NULL UNIQUE,
            device_type TEXT NOT NULL DEFAULT 'unknown',
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_host_id INTEGER NOT NULL,
            dst_host_id INTEGER NOT NULL,
            src_port INTEGER NOT NULL,
            dst_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            app_protocol TEXT,
            packet_count INTEGER NOT NULL DEFAULT 1,
            byte_count INTEGER NOT NULL DEFAULT 0,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            connection_id INTEGER NOT NULL,
            timestamp REAL NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER NOT NULL,
            dst_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            length INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS modbus_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
         DELETE FROM node_positions;",
    )?;
    Ok(())
}

pub fn drop_packet_indexes(conn: &Connection) -> Result<(), CoreError> {
    conn.execute_batch(
        "DROP INDEX IF EXISTS idx_packets_timestamp;
         DROP INDEX IF EXISTS idx_packets_connection;
         DROP INDEX IF EXISTS idx_modbus_connection;
         DROP INDEX IF EXISTS idx_modbus_src_host;",
    )?;
    Ok(())
}

pub fn create_packet_indexes(conn: &Connection) -> Result<(), CoreError> {
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
         CREATE INDEX IF NOT EXISTS idx_packets_connection ON packets(connection_id);
         CREATE INDEX IF NOT EXISTS idx_modbus_connection ON modbus_events(connection_id);
         CREATE INDEX IF NOT EXISTS idx_modbus_src_host ON modbus_events(src_host_id);",
    )?;
    Ok(())
}
