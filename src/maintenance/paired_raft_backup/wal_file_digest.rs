//! Bind peer Ed25519 attestations to the voter's actual on-disk durable SQLite
//! WAL/SM bytes and consensus-committed Raft apply index (#153).

use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::peer_attestation::sync_file_if_exists;
use super::types::PairedBackupError;

const WAL_FILES: [&str; 4] = ["log.sqlite3", "log.sqlite3-wal", "sm.sqlite3", "sm.sqlite3-wal"];

/// OpenRaft advances `last_applied` only after a majority-committed entry is applied
/// to the state machine; `last_log_index` merely counts appended log entries.
pub(super) fn extract_committed_applied_index(metrics: &Value) -> Option<u64> {
    metrics
        .pointer("/last_applied/index")
        .and_then(Value::as_u64)
        .or_else(|| metrics.get("last_applied").and_then(Value::as_u64))
}

/// Fsync and canonically hash the voter's durable `log.sqlite3` / `sm.sqlite3` and
/// their `-wal` sidecars so an Ed25519 attestation cannot be replayed over other bytes.
pub(super) fn fsync_and_hash_voter_durable_wal(data_dir: &Path) -> Result<String, PairedBackupError> {
    for required in ["log.sqlite3", "sm.sqlite3"] {
        let path = data_dir.join(required);
        if !fs::metadata(&path).is_ok_and(|m| m.is_file() && m.len() > 0) {
            return Err(PairedBackupError::FreezeNotHeld("voter durable SQLite WAL/SM files missing on disk"));
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(b"rootyard-voter-sqlite-wal-bytes-v1\0");
    for name in WAL_FILES {
        let path = data_dir.join(name);
        match fs::metadata(&path).ok().filter(|meta| meta.is_file()) {
            Some(meta) => {
                sync_file_if_exists(&path)?;
                hasher.update([1u8]);
                hasher.update(name.as_bytes());
                hasher.update(b"\0");
                hasher.update(meta.len().to_be_bytes());
                stream_into(&path, &mut hasher)?;
            }
            None => hasher.update([0u8]),
        }
    }
    #[cfg(unix)]
    File::open(data_dir)?.sync_all()?;
    Ok(hex::encode(hasher.finalize()))
}

fn stream_into(path: &Path, hasher: &mut Sha256) -> Result<(), PairedBackupError> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        hasher.update(&buffer[..read]);
    }
}
