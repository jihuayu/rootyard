//! Durable recoverable reclaim ledger for partial or unknown quarantined Blob uploads (#183).
//!
//! Persists `0600` fsync-durable JSON records before and across remote Blob staging so
//! interrupted, partial, or ambiguous (`OutcomeUnknown`) pack/idx uploads leave a
//! deterministic recovery trail even after local `QuarantineSlot` directories are swept.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub use super::reclaim_carrier::CapacityContractBlobCarrier;
use super::types::PushCausalError;

/// Lifecycle state of a quarantined remote Blob upload batch in the reclaim ledger.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UploadReclaimState {
    InFlightStaging,
    PartialFailed,
    OutcomeUnknown,
    AbortUnpromoted,
    VerifiedPromoted,
    ReclaimedAfterAbort,
}

impl UploadReclaimState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InFlightStaging => "in_flight_staging",
            Self::PartialFailed => "partial_failed",
            Self::OutcomeUnknown => "outcome_unknown",
            Self::AbortUnpromoted => "abort_unpromoted",
            Self::VerifiedPromoted => "verified_promoted",
            Self::ReclaimedAfterAbort => "reclaimed_after_abort",
        }
    }

    pub const fn needs_recovery(self) -> bool {
        matches!(self, Self::InFlightStaging | Self::PartialFailed | Self::OutcomeUnknown | Self::AbortUnpromoted)
    }
}

/// Digest and byte lengths of one staged `.pack` + `.idx` pair (`0..=8` pairs per operation).
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StagedPairDigest {
    pub pack_sha256: String,
    pub pack_bytes: u64,
    pub idx_sha256: String,
    pub idx_bytes: u64,
}

/// Durable reclaim record persisted for partial, unknown, or unpromoted Blob uploads.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlobUploadReclaimRecord {
    pub record_version: u32,
    pub operation_id: Uuid,
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub generation: i64,
    pub backend_identity: String,
    pub pack_sha256: String,
    pub pack_bytes: u64,
    pub idx_sha256: String,
    pub idx_bytes: u64,
    #[serde(default)]
    pub staged_pairs: Vec<StagedPairDigest>,
    pub recorded_blob_paths: Vec<String>,
    pub put_bytes_observed: u64,
    pub state: UploadReclaimState,
    pub detail: String,
    pub updated_at_unix_ms: u64,
    pub record_digest: String,
}

impl BlobUploadReclaimRecord {
    pub fn recompute_digest(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"push-blob-reclaim-record-v1\n");
        for bytes in [
            self.record_version.to_be_bytes().as_slice(),
            self.operation_id.as_bytes(),
            self.tenant_id.as_bytes(),
            self.repository_id.as_bytes(),
            self.generation.to_be_bytes().as_slice(),
            self.backend_identity.as_bytes(),
            self.pack_sha256.as_bytes(),
            self.pack_bytes.to_be_bytes().as_slice(),
            self.idx_sha256.as_bytes(),
            self.idx_bytes.to_be_bytes().as_slice(),
            self.put_bytes_observed.to_be_bytes().as_slice(),
            self.state.as_str().as_bytes(),
            self.detail.as_bytes(),
            self.updated_at_unix_ms.to_be_bytes().as_slice(),
        ] {
            h.update((bytes.len() as u64).to_be_bytes());
            h.update(bytes);
        }
        h.update((self.recorded_blob_paths.len() as u64).to_be_bytes());
        for p in &self.recorded_blob_paths {
            h.update((p.len() as u64).to_be_bytes());
            h.update(p.as_bytes());
        }
        h.update((self.staged_pairs.len() as u64).to_be_bytes());
        for sp in &self.staged_pairs {
            let s = format!("{}:{}:{}:{}", sp.pack_sha256, sp.pack_bytes, sp.idx_sha256, sp.idx_bytes);
            h.update((s.len() as u64).to_be_bytes());
            h.update(s.as_bytes());
        }
        hex::encode(h.finalize())
    }

    pub fn verify_digest(&self) -> Result<(), PushCausalError> {
        if self.recompute_digest() != self.record_digest {
            return Err(PushCausalError::ProofTampered("reclaim record digest mismatch"));
        }
        Ok(())
    }
}

/// Private `0700` directory-backed ledger storing recoverable Blob upload reclaim records.
#[derive(Clone, Debug)]
pub struct QuarantineReclaimLedger {
    dir: PathBuf,
}

/// Metadata captured prior to starting an OpenDAL pack+idx upload.
pub struct StagingUploadIntent<'a> {
    pub operation_id: Uuid,
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub generation: i64,
    pub backend_identity: &'a str,
    pub pack_sha256: &'a str,
    pub pack_bytes: u64,
    pub idx_sha256: &'a str,
    pub idx_bytes: u64,
}

impl QuarantineReclaimLedger {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, PushCausalError> {
        let dir = dir.into();
        let mut builder = DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&dir).map_err(|e| PushCausalError::Io(format!("reclaim ledger dir create: {e}")))?;
        let meta = fs::symlink_metadata(&dir).map_err(|e| PushCausalError::Io(e.to_string()))?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(PushCausalError::Io("reclaim ledger root must be a private directory".into()));
        }
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn record_path(&self, operation_id: Uuid) -> PathBuf {
        self.dir.join(format!("reclaim-{operation_id}.json"))
    }

    pub fn record_inflight(
        &self,
        intent: &StagingUploadIntent<'_>,
    ) -> Result<BlobUploadReclaimRecord, PushCausalError> {
        let pair = StagedPairDigest {
            pack_sha256: intent.pack_sha256.to_owned(),
            pack_bytes: intent.pack_bytes,
            idx_sha256: intent.idx_sha256.to_owned(),
            idx_bytes: intent.idx_bytes,
        };
        self.record_inflight_multi(
            intent.operation_id,
            intent.tenant_id,
            intent.repository_id,
            intent.generation,
            intent.backend_identity,
            &[pair],
        )
    }

    pub fn record_inflight_multi(
        &self,
        operation_id: Uuid,
        tenant_id: Uuid,
        repository_id: Uuid,
        generation: i64,
        backend_identity: &str,
        pairs: &[StagedPairDigest],
    ) -> Result<BlobUploadReclaimRecord, PushCausalError> {
        let first = pairs.first().cloned().unwrap_or_default();
        let mut rec = BlobUploadReclaimRecord {
            record_version: 2,
            operation_id,
            tenant_id,
            repository_id,
            generation,
            backend_identity: backend_identity.to_owned(),
            pack_sha256: first.pack_sha256,
            pack_bytes: first.pack_bytes,
            idx_sha256: first.idx_sha256,
            idx_bytes: first.idx_bytes,
            staged_pairs: pairs.to_vec(),
            recorded_blob_paths: Vec::new(),
            put_bytes_observed: 0,
            state: UploadReclaimState::InFlightStaging,
            detail: "upload started".into(),
            updated_at_unix_ms: now_unix_ms(),
            record_digest: String::new(),
        };
        rec.record_digest = rec.recompute_digest();
        self.write_atomic(&rec)?;
        Ok(rec)
    }

    pub fn transition(
        &self,
        operation_id: Uuid,
        state: UploadReclaimState,
        recorded_blob_paths: Vec<String>,
        put_bytes_observed: u64,
        detail: impl Into<String>,
    ) -> Result<BlobUploadReclaimRecord, PushCausalError> {
        let mut rec = self.load(operation_id)?.ok_or_else(|| {
            PushCausalError::StateMachine(format!("missing inflight reclaim record for operation {operation_id}"))
        })?;
        if !recorded_blob_paths.is_empty() {
            rec.recorded_blob_paths = recorded_blob_paths;
            rec.recorded_blob_paths.sort();
            rec.recorded_blob_paths.dedup();
        }
        rec.put_bytes_observed = rec.put_bytes_observed.max(put_bytes_observed);
        rec.state = state;
        rec.detail = detail.into();
        rec.updated_at_unix_ms = now_unix_ms();
        rec.record_digest = rec.recompute_digest();
        self.write_atomic(&rec)?;
        Ok(rec)
    }

    /// Reclaim an unpromoted/partial/unknown record ONLY after the authority ledger proves the
    /// operation aborted/cancelled (`operation_proven_aborted == true`). Fails closed while
    /// outcome remains unknown.
    pub fn mark_reclaimed_if_proven_aborted(
        &self,
        operation_id: Uuid,
        operation_proven_aborted: bool,
    ) -> Result<BlobUploadReclaimRecord, PushCausalError> {
        let rec = self.load(operation_id)?.ok_or_else(|| {
            PushCausalError::StateMachine(format!("reclaim record not found for operation {operation_id}"))
        })?;
        if rec.state == UploadReclaimState::VerifiedPromoted {
            return Err(PushCausalError::StateMachine("cannot reclaim blobs of a promoted push".into()));
        }
        if !operation_proven_aborted {
            return Err(PushCausalError::CommitUnknown {
                operation_id,
                detail: "cannot reclaim partial/unknown staged blobs before operation terminal abort is proven".into(),
            });
        }
        self.transition(
            operation_id,
            UploadReclaimState::ReclaimedAfterAbort,
            Vec::new(),
            rec.put_bytes_observed,
            "operation proven aborted; unpromoted staging blobs eligible for GC sweep",
        )
    }

    pub fn load(&self, operation_id: Uuid) -> Result<Option<BlobUploadReclaimRecord>, PushCausalError> {
        let path = self.record_path(operation_id);
        if !path.is_file() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&path).map_err(|e| PushCausalError::Io(e.to_string()))?;
        let rec: BlobUploadReclaimRecord =
            serde_json::from_str(&raw).map_err(|e| PushCausalError::Io(format!("corrupt reclaim record: {e}")))?;
        rec.verify_digest()?;
        Ok(Some(rec))
    }

    pub fn list_recoverable(&self) -> Result<Vec<BlobUploadReclaimRecord>, PushCausalError> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.dir).map_err(|e| PushCausalError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| PushCausalError::Io(e.to_string()))?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
            if !name.starts_with("reclaim-") || !name.ends_with(".json") {
                continue;
            }
            let raw = fs::read_to_string(&path).map_err(|e| PushCausalError::Io(e.to_string()))?;
            let rec: BlobUploadReclaimRecord =
                serde_json::from_str(&raw).map_err(|e| PushCausalError::Io(format!("corrupt reclaim record: {e}")))?;
            rec.verify_digest()?;
            if rec.state.needs_recovery() {
                out.push(rec);
            }
        }
        out.sort_by_key(|r| r.operation_id);
        Ok(out)
    }

    fn write_atomic(&self, rec: &BlobUploadReclaimRecord) -> Result<(), PushCausalError> {
        let target = self.record_path(rec.operation_id);
        let tmp = self.dir.join(format!(".tmp-{}-{}.json", rec.operation_id, Uuid::new_v4().simple()));
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let payload = serde_json::to_vec_pretty(rec).map_err(|e| PushCausalError::Io(e.to_string()))?;
        let mut file = opts.open(&tmp).map_err(|e| PushCausalError::Io(e.to_string()))?;
        file.write_all(&payload).map_err(|e| PushCausalError::Io(e.to_string()))?;
        file.write_all(b"\n").map_err(|e| PushCausalError::Io(e.to_string()))?;
        file.sync_all().map_err(|e| PushCausalError::Io(e.to_string()))?;
        drop(file);
        fs::rename(&tmp, &target).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            PushCausalError::Io(e.to_string())
        })
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis().min(u64::MAX as u128) as u64
}
