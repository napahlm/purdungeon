//! Aggregations over `modbus_events` that feed the detail panels.

use rusqlite::{params, Connection};

use crate::protocols::modbus::function_name;
use crate::types::{ModbusConversation, ModbusFunctionStat, ModbusHostActivity, RegisterAccess};
use crate::CoreError;

/// SQL fragment mapping a function code to the data type it touches.
const KIND_CASE: &str = "CASE
    WHEN function_code IN (1, 5, 15) THEN 'coils'
    WHEN function_code = 2 THEN 'discrete inputs'
    WHEN function_code = 4 THEN 'input registers'
    ELSE 'holding registers'
END";

fn function_stats(
    conn: &Connection,
    where_clause: &str,
    host_id: i64,
) -> Result<Vec<ModbusFunctionStat>, CoreError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT function_code, COUNT(*), MAX(is_write)
         FROM modbus_events
         WHERE is_request = 1 AND {where_clause}
         GROUP BY function_code
         ORDER BY COUNT(*) DESC",
    ))?;
    let rows: Vec<(i64, i64, i64)> = stmt
        .query_map(params![host_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows
        .into_iter()
        .map(|(code, count, is_write)| ModbusFunctionStat {
            function_code: code,
            function_name: function_name(code as u8).to_string(),
            count,
            is_write: is_write != 0,
        })
        .collect())
}

fn register_accesses(
    conn: &Connection,
    where_clause: &str,
    host_id: i64,
) -> Result<Vec<RegisterAccess>, CoreError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {KIND_CASE}, start_address, quantity,
                SUM(CASE WHEN is_write = 0 THEN 1 ELSE 0 END),
                SUM(is_write)
         FROM modbus_events
         WHERE is_request = 1 AND start_address IS NOT NULL AND {where_clause}
         GROUP BY 1, start_address, quantity
         ORDER BY SUM(is_write) DESC, COUNT(*) DESC
         LIMIT 200",
    ))?;
    let rows = stmt.query_map(params![host_id], |row| {
        Ok(RegisterAccess {
            kind: row.get(0)?,
            start: row.get(1)?,
            quantity: row.get::<_, Option<i64>>(2)?.unwrap_or(1),
            reads: row.get(3)?,
            writes: row.get(4)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn host_activity(conn: &Connection, host_id: i64) -> Result<ModbusHostActivity, CoreError> {
    let as_client = function_stats(conn, "src_host_id = ?1", host_id)?;
    let as_server = function_stats(conn, "dst_host_id = ?1", host_id)?;

    let mut stmt = conn.prepare(
        "SELECT DISTINCT unit_id FROM modbus_events
         WHERE is_request = 1 AND dst_host_id = ?1 ORDER BY unit_id",
    )?;
    let unit_ids_served: Vec<i64> = stmt
        .query_map(params![host_id], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;

    // Data points on this device, touched by its clients
    let registers = register_accesses(conn, "dst_host_id = ?1", host_id)?;
    // Data points this host touches on other devices
    let registers_remote = register_accesses(conn, "src_host_id = ?1", host_id)?;

    let exceptions_returned: i64 = conn.query_row(
        "SELECT COUNT(*) FROM modbus_events
         WHERE is_request = 0 AND is_exception = 1 AND src_host_id = ?1",
        params![host_id],
        |row| row.get(0),
    )?;

    Ok(ModbusHostActivity {
        as_client,
        as_server,
        unit_ids_served,
        registers,
        registers_remote,
        exceptions_returned,
    })
}

/// Modbus view of the conversation behind one connection row, gathered for
/// the host pair in both directions (requests travel on one flow, responses
/// on the reverse one).
pub fn conversation(conn: &Connection, connection_id: i64) -> Result<ModbusConversation, CoreError> {
    let (host_a, host_b): (i64, i64) = conn.query_row(
        "SELECT src_host_id, dst_host_id FROM connections WHERE id = ?1",
        params![connection_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    let pair = "((src_host_id = ?1 AND dst_host_id = ?2) OR (src_host_id = ?2 AND dst_host_id = ?1))";

    let mut stmt = conn.prepare(&format!(
        "SELECT function_code, COUNT(*), MAX(is_write)
         FROM modbus_events
         WHERE is_request = 1 AND {pair}
         GROUP BY function_code ORDER BY COUNT(*) DESC",
    ))?;
    let rows: Vec<(i64, i64, i64)> = stmt
        .query_map(params![host_a, host_b], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let functions = rows
        .into_iter()
        .map(|(code, count, is_write)| ModbusFunctionStat {
            function_code: code,
            function_name: function_name(code as u8).to_string(),
            count,
            is_write: is_write != 0,
        })
        .collect();

    let mut stmt = conn.prepare(&format!(
        "SELECT DISTINCT unit_id FROM modbus_events
         WHERE is_request = 1 AND {pair} ORDER BY unit_id",
    ))?;
    let unit_ids: Vec<i64> = stmt
        .query_map(params![host_a, host_b], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;

    let (requests, reads, writes): (i64, i64, i64) = conn.query_row(
        &format!(
            "SELECT COUNT(*),
                    SUM(CASE WHEN is_write = 0 THEN 1 ELSE 0 END),
                    SUM(is_write)
             FROM modbus_events WHERE is_request = 1 AND {pair}"
        ),
        params![host_a, host_b],
        |row| {
            Ok((
                row.get(0)?,
                row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                row.get::<_, Option<i64>>(2)?.unwrap_or(0),
            ))
        },
    )?;

    let exceptions: i64 = conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM modbus_events
             WHERE is_request = 0 AND is_exception = 1 AND {pair}"
        ),
        params![host_a, host_b],
        |row| row.get(0),
    )?;

    // Median gap between consecutive requests ≈ the polling cadence
    let mut stmt = conn.prepare(&format!(
        "SELECT timestamp FROM modbus_events
         WHERE is_request = 1 AND {pair} ORDER BY timestamp",
    ))?;
    let timestamps: Vec<f64> = stmt
        .query_map(params![host_a, host_b], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let poll_interval_ms = median_gap_ms(&timestamps);

    Ok(ModbusConversation {
        functions,
        unit_ids,
        requests,
        reads,
        writes,
        exceptions,
        poll_interval_ms,
    })
}

fn median_gap_ms(timestamps: &[f64]) -> Option<f64> {
    if timestamps.len() < 3 {
        return None;
    }
    let mut gaps: Vec<f64> = timestamps.windows(2).map(|w| w[1] - w[0]).collect();
    gaps.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Some(gaps[gaps.len() / 2] * 1000.0)
}
