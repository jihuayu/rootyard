//! Atomic SQLite persistence for the application reducer state row.
//!
//! The row lives in `sm_app_state` and is written in the same `BEGIN IMMEDIATE` transaction as
//! `last_applied`, membership, entry records, and the Raft entry digest chain. On any failed
//! or ambiguous commit the in-memory reducer is not advanced.

use openraft::LogId;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::state_machine::app::{
    ApplicationLogId, ApplicationStateMachine, MAX_APP_STATE_BYTES, is_valid_sha256_hex, validate_domain,
};
use crate::state_machine::codec::hex_encode;
use crate::state_machine::store::read_kv_map;
use crate::{E, Res, checksum, jd, je};

pub(crate) const SM_APP_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS sm_app_state(id INTEGER PRIMARY KEY CHECK(id=1), domain TEXT NOT NULL, version INTEGER NOT NULL, last_applied TEXT, state_digest_hex TEXT NOT NULL, state_sha256_hex TEXT NOT NULL, state_bytes BLOB NOT NULL, checksum BLOB NOT NULL CHECK(length(checksum)=32));";

/// Verified persisted application row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PersistedAppRow {
    pub(crate) domain: String,
    pub(crate) version: u16,
    pub(crate) last_applied: Option<ApplicationLogId>,
    pub(crate) state_digest_hex: String,
    pub(crate) state_bytes: Vec<u8>,
}

/// Opens the application mode, restoring the reducer from its persisted row.
///
/// `None` reducer with no row means legacy KV mode. A reducer with no row may only initialize
/// over a completely empty legacy state; a row with no reducer fails closed because KV mode
/// cannot prove the application state.
pub(crate) fn validate_application_open(
    conn: &Connection,
    app: Option<Box<dyn ApplicationStateMachine>>,
    meta_last_applied: Option<LogId<u64>>,
) -> Res<Option<Box<dyn ApplicationStateMachine>>> {
    let meta_coord = meta_last_applied.map(ApplicationLogId::from_log_id);
    match read_app_row(conn)? {
        None => {
            let Some(reducer) = app else { return Ok(None) };
            if meta_last_applied.is_some() || !read_kv_map(conn)?.is_empty() || count_rows(conn, "sm_entries")? != 0 {
                return Err(E::Refused(
                    "cannot initialize application state over non-empty legacy KV state; no empty fallback".into(),
                ));
            }
            if reducer.last_applied().is_some() {
                return Err(E::Refused("application reducer must be empty when opening an empty store".into()));
            }
            write_app_row(conn, reducer.as_ref(), None)?;
            Ok(Some(reducer))
        }
        Some(row) => {
            let Some(mut reducer) = app else {
                return Err(E::Refused(
                    "state machine contains application state; open it with the matching application reducer".into(),
                ));
            };
            if !read_kv_map(conn)?.is_empty() {
                return Err(E::Refused(
                    "application state machine contains legacy KV rows; refusing mixed mode".into(),
                ));
            }
            validate_application_entry_kinds(conn)?;
            if row.domain != reducer.domain() || row.version != reducer.version() {
                return Err(E::Refused(format!(
                    "application state identity mismatch: persisted {}/{} but opened {}/{}",
                    row.domain,
                    row.version,
                    reducer.domain(),
                    reducer.version()
                )));
            }
            if row.last_applied != meta_coord {
                return Err(E::Refused(format!(
                    "application row coordinate {:?} mismatches state-machine last_applied {meta_coord:?}",
                    row.last_applied
                )));
            }
            reducer
                .restore_state(&row.state_bytes)
                .map_err(|e| E::Refused(format!("application state restore refused: {e}")))?;
            if reducer.last_applied() != row.last_applied {
                return Err(E::Refused("restored application coordinate mismatches persisted row".into()));
            }
            let digest =
                reducer.state_digest_hex().map_err(|e| E::Refused(format!("application digest refused: {e}")))?;
            if digest != row.state_digest_hex {
                return Err(E::Refused("restored application state digest mismatches persisted row".into()));
            }
            Ok(Some(reducer))
        }
    }
}

/// Reads and self-verifies the optional application row.
pub(crate) fn read_app_row(conn: &Connection) -> Res<Option<PersistedAppRow>> {
    let mut st = conn.prepare(
        "SELECT domain,version,last_applied,state_digest_hex,state_sha256_hex,state_bytes,checksum \
         FROM sm_app_state WHERE id=1",
    )?;
    let mut rows = st.query([])?;
    let Some(row) = rows.next()? else { return Ok(None) };
    let domain: String = row.get(0)?;
    validate_domain(&domain)?;
    let version_i64: i64 = row.get(1)?;
    let version = u16::try_from(version_i64).map_err(|_| E::Codec("application version outside u16".into()))?;
    if version == 0 {
        return Err(E::Codec("application version must be positive".into()));
    }
    let last_json: Option<String> = row.get(2)?;
    let last_applied: Option<ApplicationLogId> = match last_json {
        Some(ref value) => Some(jd(value)?),
        None => None,
    };
    let state_digest_hex: String = row.get(3)?;
    if !is_valid_sha256_hex(&state_digest_hex) {
        return Err(E::Codec("corrupt application state_digest_hex".into()));
    }
    let state_sha256_hex: String = row.get(4)?;
    if !is_valid_sha256_hex(&state_sha256_hex) {
        return Err(E::Codec("corrupt application state_sha256_hex".into()));
    }
    let state_bytes: Vec<u8> = row.get(5)?;
    if state_bytes.len() > MAX_APP_STATE_BYTES {
        return Err(E::Refused("persisted application state exceeds its byte ceiling".into()));
    }
    let actual_sha = hex_encode(&Sha256::digest(&state_bytes));
    if actual_sha != state_sha256_hex {
        return Err(E::Codec("persisted application state bytes checksum mismatch".into()));
    }
    let stored_checksum: Vec<u8> = row.get(6)?;
    if stored_checksum
        != row_checksum(&domain, version, last_json.as_deref(), &state_digest_hex, &state_sha256_hex, &state_bytes)
    {
        return Err(E::Codec("persisted application row checksum mismatch".into()));
    }
    Ok(Some(PersistedAppRow { domain, version, last_applied, state_digest_hex, state_bytes }))
}

/// Writes the application row and verifies the reducer coordinate/digest before mutation.
pub(crate) fn write_app_row(
    conn: &Connection,
    app: &dyn ApplicationStateMachine,
    last_applied: Option<LogId<u64>>,
) -> Res<()> {
    let domain = app.domain();
    validate_domain(domain)?;
    let version = app.version();
    if version == 0 {
        return Err(E::Refused("application version must be positive".into()));
    }
    let expected = last_applied.map(ApplicationLogId::from_log_id);
    if app.last_applied() != expected {
        return Err(E::Refused(format!(
            "application reducer coordinate {:?} mismatches state-machine coordinate {expected:?}",
            app.last_applied()
        )));
    }
    let bytes = app.export_state().map_err(|e| E::Refused(format!("application state export refused: {e}")))?;
    if bytes.len() > MAX_APP_STATE_BYTES {
        return Err(E::Refused("application state exceeds its byte ceiling".into()));
    }
    let state_digest_hex =
        app.state_digest_hex().map_err(|e| E::Refused(format!("application digest refused: {e}")))?;
    if !is_valid_sha256_hex(&state_digest_hex) {
        return Err(E::Refused("application state digest is not canonical SHA-256 hex".into()));
    }
    let state_sha256_hex = hex_encode(&Sha256::digest(&bytes));
    let last_json = expected.as_ref().map(je).transpose()?;
    let checksum = row_checksum(domain, version, last_json.as_deref(), &state_digest_hex, &state_sha256_hex, &bytes);
    conn.execute(
        "INSERT INTO sm_app_state(id,domain,version,last_applied,state_digest_hex,state_sha256_hex,state_bytes,checksum) \
         VALUES(1,?1,?2,?3,?4,?5,?6,?7) \
         ON CONFLICT(id) DO UPDATE SET domain=excluded.domain,version=excluded.version,last_applied=excluded.last_applied, \
         state_digest_hex=excluded.state_digest_hex,state_sha256_hex=excluded.state_sha256_hex, \
         state_bytes=excluded.state_bytes,checksum=excluded.checksum",
        (domain, i64::from(version), last_json, &state_digest_hex, &state_sha256_hex, bytes, checksum),
    )?;
    Ok(())
}

fn row_checksum(
    domain: &str,
    version: u16,
    last_json: Option<&str>,
    state_digest_hex: &str,
    state_sha256_hex: &str,
    bytes: &[u8],
) -> Vec<u8> {
    checksum(&[
        b"sm_app",
        domain.as_bytes(),
        &version.to_be_bytes(),
        last_json.unwrap_or("").as_bytes(),
        state_digest_hex.as_bytes(),
        state_sha256_hex.as_bytes(),
        bytes,
    ])
}

fn count_rows(conn: &Connection, table: &str) -> Res<i64> {
    match table {
        "sm_entries" => Ok(conn.query_row("SELECT count(*) FROM sm_entries", [], |r| r.get(0))?),
        "sm_app_state" => Ok(conn.query_row("SELECT count(*) FROM sm_app_state", [], |r| r.get(0))?),
        _ => Err(E::Refused("unknown application validation table".into())),
    }
}

fn validate_application_entry_kinds(conn: &Connection) -> Res<()> {
    let mut st = conn.prepare("SELECT DISTINCT kind FROM sm_entries")?;
    let mut rows = st.query([])?;
    while let Some(row) = rows.next()? {
        let kind: String = row.get(0)?;
        if !matches!(kind.as_str(), "blank" | "membership" | "application") {
            return Err(E::Refused(format!(
                "application mode contains non-application entry kind {kind:?}; refusing mixed state"
            )));
        }
    }
    Ok(())
}

/// Summary used by startup/backend qualification without exposing reducer bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationSummary {
    pub domain: String,
    pub version: u16,
    pub last_applied: Option<ApplicationLogId>,
    pub state_digest_hex: String,
    pub state_bytes: usize,
}

pub(crate) fn read_application_summary(conn: &Connection) -> Res<Option<ApplicationSummary>> {
    let Some(row) = read_app_row(conn)? else { return Ok(None) };
    Ok(Some(ApplicationSummary {
        domain: row.domain,
        version: row.version,
        last_applied: row.last_applied,
        state_digest_hex: row.state_digest_hex,
        state_bytes: row.state_bytes.len(),
    }))
}
