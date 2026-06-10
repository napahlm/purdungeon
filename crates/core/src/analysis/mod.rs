//! Post-ingest analysis: protocol classification, role inference, and
//! Purdue level placement. Runs once per import, writes results back into
//! the session database so the UI only ever queries.

mod findings;
mod ports;
mod roles;

use rusqlite::Connection;

use crate::types::ImportStage;
use crate::CoreError;

pub fn run(
    conn: &Connection,
    on_stage: &(dyn Fn(ImportStage) + Send + Sync),
) -> Result<(), CoreError> {
    on_stage(ImportStage::IdentifyingDevices);
    ports::classify_connections(conn)?;
    roles::collect_host_protocols(conn)?;

    on_stage(ImportStage::MappingConversations);
    let profiles = roles::build_profiles(conn)?;

    on_stage(ImportStage::InferringRoles);
    roles::infer_and_store(conn, &profiles)?;

    on_stage(ImportStage::SurfacingFindings);
    findings::generate(conn)?;

    Ok(())
}
