//! Bounded application-command envelope and deterministic reducer seam.
//!
//! The envelope is deliberately distinct from legacy KV JSON: an application command starts
//! with [`APP_COMMAND_MAGIC`], carries an explicit domain/version, and has a hard byte ceiling
//! before any Raft WAL append or state-machine mutation. The seam never performs Blob, PG,
//! Redis, clock, or network I/O inside `apply`; persistence and snapshot sealing live in the
//! SQLite store around the reducer.
//!
//! Coordinates are `(term, index)` only. Raft's leader node id is an election-routing value and
//! is never stored as an application/business coordinate.

use std::any::Any;
use std::fmt;

use openraft::LogId;

use crate::{E, Res};

/// Magic prefix that separates the application envelope from legacy KV JSON payloads.
pub const APP_COMMAND_MAGIC: &[u8; 7] = b"RYAPP1\0";
/// Maximum UTF-8 bytes in an application domain identifier.
pub const MAX_APP_DOMAIN_BYTES: usize = 64;
/// Maximum application command payload carried inside one Raft normal entry (256 KiB).
pub const MAX_APP_PAYLOAD_BYTES: usize = 256 * 1024;
/// Maximum canonical application state bytes persisted in SQLite and snapshots (8 MiB).
pub const MAX_APP_STATE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum encoded application command bytes (magic/header/domain/payload).
pub const MAX_APP_COMMAND_BYTES: usize =
    APP_COMMAND_MAGIC.len() + 2 + 2 + 4 + MAX_APP_DOMAIN_BYTES + MAX_APP_PAYLOAD_BYTES;

/// Consensus application coordinate `(term, index)`, distinct from Raft's leader node id.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationLogId {
    pub term: u64,
    pub index: u64,
}

impl ApplicationLogId {
    pub const fn new(term: u64, index: u64) -> Self {
        Self { term, index }
    }

    /// Maps a full Raft log id to the consensus coordinate used by application state.
    pub fn from_log_id(log_id: LogId<u64>) -> Self {
        Self { term: log_id.leader_id.term, index: log_id.index }
    }
}

use serde::{Deserialize, Serialize};

/// Fault returned by a deterministic application reducer. Messages must never contain payloads,
/// tokens, private keys, SQL text, or provider credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationError {
    message: String,
}

impl ApplicationError {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ApplicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ApplicationError {}

/// Strict application command envelope carried in `EntryPayload::Normal`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationCommand {
    domain: String,
    version: u16,
    payload: Vec<u8>,
}

impl ApplicationCommand {
    /// Validates and constructs one bounded application command.
    pub fn new(domain: impl Into<String>, version: u16, payload: Vec<u8>) -> Res<Self> {
        let command = Self { domain: domain.into(), version, payload };
        command.validate()?;
        Ok(command)
    }

    /// Decodes exactly one canonical application envelope, refusing extra/short bytes.
    pub fn decode(bytes: &[u8]) -> Res<Self> {
        if !is_application_wire(bytes) {
            return Err(E::Codec("application command lacks RYAPP1 magic".into()));
        }
        let mut pos = APP_COMMAND_MAGIC.len();
        let version = read_u16(bytes, &mut pos)?;
        let domain_len = read_u16(bytes, &mut pos)? as usize;
        let payload_len = read_u32(bytes, &mut pos)? as usize;
        if domain_len == 0 || domain_len > MAX_APP_DOMAIN_BYTES {
            return Err(E::Refused(format!("application domain length {domain_len} outside allowed bounds")));
        }
        if payload_len > MAX_APP_PAYLOAD_BYTES {
            return Err(E::Refused(format!(
                "application payload length {payload_len} exceeds {MAX_APP_PAYLOAD_BYTES}"
            )));
        }
        let total = pos.checked_add(domain_len).and_then(|v| v.checked_add(payload_len));
        if total != Some(bytes.len()) {
            return Err(E::Codec(format!(
                "application command length mismatch: header says {total:?}, got {}",
                bytes.len()
            )));
        }
        let domain = std::str::from_utf8(&bytes[pos..pos + domain_len])
            .map_err(|_| E::Codec("application domain is not UTF-8".into()))?
            .to_owned();
        pos += domain_len;
        let payload = bytes[pos..pos + payload_len].to_vec();
        Self::new(domain, version, payload)
    }

    /// Encodes this command as the canonical bounded wire envelope.
    pub fn encode(&self) -> Res<Vec<u8>> {
        self.validate()?;
        let domain = self.domain.as_bytes();
        let domain_len =
            u16::try_from(domain.len()).map_err(|_| E::Refused("application domain length does not fit u16".into()))?;
        let payload_len = u32::try_from(self.payload.len())
            .map_err(|_| E::Refused("application payload length does not fit u32".into()))?;
        let mut out = Vec::with_capacity(APP_COMMAND_MAGIC.len() + 8 + domain.len() + self.payload.len());
        out.extend_from_slice(APP_COMMAND_MAGIC);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&domain_len.to_be_bytes());
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.extend_from_slice(domain);
        out.extend_from_slice(&self.payload);
        if out.len() > MAX_APP_COMMAND_BYTES || out.len() > crate::MAX_ENTRY_BYTES {
            return Err(E::Refused("encoded application command exceeds its byte ceiling".into()));
        }
        Ok(out)
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    fn validate(&self) -> Res<()> {
        validate_domain(&self.domain)?;
        if self.version == 0 {
            return Err(E::Refused("application command version must be positive".into()));
        }
        if self.payload.len() > MAX_APP_PAYLOAD_BYTES {
            return Err(E::Refused(format!(
                "application payload length {} exceeds {MAX_APP_PAYLOAD_BYTES}",
                self.payload.len()
            )));
        }
        let total = APP_COMMAND_MAGIC.len() + 8 + self.domain.len() + self.payload.len();
        if total > MAX_APP_COMMAND_BYTES || total > crate::MAX_ENTRY_BYTES {
            return Err(E::Refused("application command exceeds its byte ceiling".into()));
        }
        Ok(())
    }
}

/// Returns true only for bytes carrying the application magic prefix.
pub fn is_application_wire(bytes: &[u8]) -> bool {
    bytes.starts_with(APP_COMMAND_MAGIC)
}

/// Validates the bounded application domain grammar used by both envelopes and persisted state.
pub fn validate_domain(domain: &str) -> Res<()> {
    if domain.is_empty() || domain.len() > MAX_APP_DOMAIN_BYTES {
        return Err(E::Refused("application domain is empty or exceeds its byte ceiling".into()));
    }
    if !domain.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')) {
        return Err(E::Refused(
            "application domain must contain only lowercase ASCII letters, digits, dot, underscore, or hyphen".into(),
        ));
    }
    Ok(())
}

fn read_u16(bytes: &[u8], pos: &mut usize) -> Res<u16> {
    let end = pos.checked_add(2).ok_or_else(|| E::Codec("application header overflow".into()))?;
    let slice = bytes.get(*pos..end).ok_or_else(|| E::Codec("truncated application header".into()))?;
    *pos = end;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Res<u32> {
    let end = pos.checked_add(4).ok_or_else(|| E::Codec("application header overflow".into()))?;
    let slice = bytes.get(*pos..end).ok_or_else(|| E::Codec("truncated application header".into()))?;
    *pos = end;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Deterministic application reducer used by the persistent state machine.
///
/// Implementors must not perform external I/O, wall-clock reads, or subprocess execution in
/// any method. `export_state` must be a canonical self-verifying snapshot; `restore_state`
/// must reject corrupt/unknown bytes instead of falling back to empty state.
pub trait ApplicationStateMachine: Send {
    /// Stable application domain identifier (validated by [`validate_domain`]).
    fn domain(&self) -> &'static str;

    /// Application state/command schema version; any mismatch fails closed.
    fn version(&self) -> u16;

    /// Applies one committed business command at `log_id`.
    fn apply(&mut self, log_id: ApplicationLogId, payload: &[u8]) -> Result<(), ApplicationError>;

    /// Advances applied state for a Raft blank or membership entry without business mutation.
    fn advance_applied(&mut self, log_id: ApplicationLogId) -> Result<(), ApplicationError>;

    /// Exports canonical, self-verifying application state bytes.
    fn export_state(&self) -> Result<Vec<u8>, ApplicationError>;

    /// Restores and verifies canonical application state bytes, replacing current state.
    fn restore_state(&mut self, bytes: &[u8]) -> Result<(), ApplicationError>;

    /// Current applied consensus coordinate of this reducer.
    fn last_applied(&self) -> Option<ApplicationLogId>;

    /// Stable SHA-256 hex digest over the complete materialized application state.
    fn state_digest_hex(&self) -> Result<String, ApplicationError>;

    /// Clones the reducer for copy-on-write apply/restore staging.
    fn clone_box(&self) -> Box<dyn ApplicationStateMachine>;

    /// Enables a typed adapter (for example a root Ref-CAS view) to recover its concrete reducer.
    fn as_any(&self) -> &dyn Any;
}

impl Clone for Box<dyn ApplicationStateMachine> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

/// Validates a 64-character lowercase SHA-256 hex digest.
pub fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_wire_is_bounded_and_strict() {
        let cmd = ApplicationCommand::new("rootyard.ref_store.ref_cas", 1, vec![1, 2, 3]).unwrap();
        let bytes = cmd.encode().unwrap();
        assert!(is_application_wire(&bytes));
        assert_eq!(ApplicationCommand::decode(&bytes).unwrap(), cmd);
        assert!(ApplicationCommand::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(ApplicationCommand::decode(&extra).is_err());
        assert!(ApplicationCommand::new("Upper", 1, vec![]).is_err());
        assert!(ApplicationCommand::new("ok", 0, vec![]).is_err());
        assert!(ApplicationCommand::new("ok", 1, vec![0; MAX_APP_PAYLOAD_BYTES + 1]).is_err());
    }
}
