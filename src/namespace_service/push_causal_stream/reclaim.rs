//! Durable recoverable reclaim ledger for partial or unknown quarantined Blob uploads (#183).
//!
//! Persists `0600` fsync-durable JSON records before and across remote Blob staging so
//! interrupted, partial, or ambiguous (`OutcomeUnknown`) pack/idx uploads leave a
//! deterministic recovery trail even after local `QuarantineSlot` directories are swept.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::blob_store::capacity_contract::git_ops::{GitOpsError, UploadScope, upload_pack_pair};
use crate::blob_store::closure::{BlobClosureEncryption, BlobClosureSpec, ClosureArtifactRole, ClosureEntrySpec};
use crate::blob_store::opendal::BlobStore;
use crate::blob_store::{BlobError, BlobLocator, BlobReceipt};

use super::git_proc::sha256_and_len_sync;
use super::quarantine::{BoxFuture, PushBlobCarrier, QuarantineArtifactSet, UploadedQuarantinePack, elapsed_ms};
use super::types::{FaultInjectionHook, PushCausalError};

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
        let mut rec = BlobUploadReclaimRecord {
            record_version: 1,
            operation_id: intent.operation_id,
            tenant_id: intent.tenant_id,
            repository_id: intent.repository_id,
            generation: intent.generation,
            backend_identity: intent.backend_identity.to_owned(),
            pack_sha256: intent.pack_sha256.to_owned(),
            pack_bytes: intent.pack_bytes,
            idx_sha256: intent.idx_sha256.to_owned(),
            idx_bytes: intent.idx_bytes,
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

/// Default OpenDAL S3/provider carrier delegating PUT + full read-back closure proof to `blob_store`
/// while persisting recoverable reclaim records on partial or unknown upload outcomes.
#[derive(Clone, Copy, Debug, Default)]
pub struct CapacityContractBlobCarrier;

impl PushBlobCarrier for CapacityContractBlobCarrier {
    fn upload_and_verify_closure<'a>(
        &'a self,
        store: &'a BlobStore,
        artifacts: QuarantineArtifactSet<'a>,
        deadline: Instant,
    ) -> BoxFuture<'a, Result<UploadedQuarantinePack, PushCausalError>> {
        Box::pin(async move {
            let started = Instant::now();
            let generation = artifacts.generation.max(1);
            let backend_hex = store.backend_identity().as_hex();
            let (pack_sha_pre, pack_len_pre) = sha256_and_len_sync(artifacts.pack_path)?;
            let (idx_sha_pre, idx_len_pre) = sha256_and_len_sync(artifacts.idx_path)?;
            if let Some(ledger) = artifacts.reclaim_ledger {
                ledger.record_inflight(&StagingUploadIntent {
                    operation_id: artifacts.operation_id,
                    tenant_id: artifacts.tenant_id,
                    repository_id: artifacts.repository_id,
                    generation,
                    backend_identity: backend_hex,
                    pack_sha256: &pack_sha_pre,
                    pack_bytes: pack_len_pre,
                    idx_sha256: &idx_sha_pre,
                    idx_bytes: idx_len_pre,
                })?;
            }

            let scope =
                UploadScope { tenant_id: artifacts.tenant_id, authority_id: artifacts.repository_id, generation };
            let pair = match upload_pack_pair(store, scope, artifacts.pack_path, artifacts.idx_path, deadline).await {
                Ok(pair) => pair,
                Err(GitOpsError::PartialUpload(pf)) => {
                    let state = classify_git_ops_reclaim(&pf.detail);
                    let paths = pf.locators.iter().map(BlobLocator::path).collect();
                    if let Some(ledger) = artifacts.reclaim_ledger {
                        let _ = ledger.transition(
                            artifacts.operation_id,
                            state,
                            paths,
                            pf.put_bytes,
                            pf.detail.to_string(),
                        );
                    }
                    return Err(map_git_ops_error(pf.detail, artifacts.operation_id));
                }
                Err(err) => {
                    let state = classify_git_ops_reclaim(&err);
                    if let Some(ledger) = artifacts.reclaim_ledger {
                        let _ = ledger.transition(artifacts.operation_id, state, Vec::new(), 0, err.to_string());
                    }
                    return Err(map_git_ops_error(err, artifacts.operation_id));
                }
            };

            let uploaded_paths = vec![pair.pack_receipt.locator().path(), pair.idx_receipt.locator().path()];
            let put_bytes = pair.pack_length.saturating_add(pair.idx_length);
            if artifacts.fault_hook == FaultInjectionHook::SimulatePartialBlobUpload {
                if let Some(ledger) = artifacts.reclaim_ledger {
                    ledger.transition(
                        artifacts.operation_id,
                        UploadReclaimState::PartialFailed,
                        vec![pair.pack_receipt.locator().path()],
                        pair.pack_length,
                        "simulated partial Blob upload failure after pack PUT",
                    )?;
                }
                return Err(PushCausalError::Io("simulated partial Blob upload failure".into()));
            }
            if artifacts.fault_hook == FaultInjectionHook::SimulateUnknownBlobUpload {
                if let Some(ledger) = artifacts.reclaim_ledger {
                    ledger.transition(
                        artifacts.operation_id,
                        UploadReclaimState::OutcomeUnknown,
                        uploaded_paths,
                        put_bytes,
                        "simulated ambiguous Blob upload ACK timeout",
                    )?;
                }
                return Err(PushCausalError::CommitUnknown {
                    operation_id: artifacts.operation_id,
                    detail: "simulated ambiguous Blob upload outcome; reclaim record retained".into(),
                });
            }

            let entries = vec![
                ClosureEntrySpec::provider_managed(ClosureArtifactRole::Pack, pair.pack_receipt.locator().clone())
                    .with_expected_plaintext(&pair.pack_sha256, pair.pack_length)?,
                ClosureEntrySpec::provider_managed(ClosureArtifactRole::PackIndex, pair.idx_receipt.locator().clone())
                    .with_expected_plaintext(&pair.idx_sha256, pair.idx_length)?,
            ];
            let spec = BlobClosureSpec::new(
                artifacts.tenant_id,
                artifacts.repository_id,
                generation,
                BlobClosureEncryption::ProviderManaged,
                entries,
            )?;
            let closure_proof = match store.verify_closure(&spec, None, None, deadline).await {
                Ok(proof) => proof,
                Err(err) => {
                    if let Some(ledger) = artifacts.reclaim_ledger {
                        let _ = ledger.transition(
                            artifacts.operation_id,
                            UploadReclaimState::PartialFailed,
                            uploaded_paths,
                            put_bytes,
                            format!("read-back closure proof failed: {err}"),
                        );
                    }
                    return Err(PushCausalError::BlobClosure(err));
                }
            };
            if !closure_proof.has_git_pack_pair() {
                if let Some(ledger) = artifacts.reclaim_ledger {
                    let _ = ledger.transition(
                        artifacts.operation_id,
                        UploadReclaimState::PartialFailed,
                        uploaded_paths,
                        put_bytes,
                        "closure proof missing git pack pair",
                    );
                }
                return Err(PushCausalError::Blob(BlobError::ForeignBackend));
            }
            let digest = compute_blob_closure_digest(store, &pair.pack_receipt, &pair.idx_receipt);
            Ok(UploadedQuarantinePack {
                pack_receipt: pair.pack_receipt,
                idx_receipt: pair.idx_receipt,
                pack_sha256: pair.pack_sha256,
                pack_bytes: pair.pack_length,
                idx_sha256: pair.idx_sha256,
                idx_bytes: pair.idx_length,
                closure_proof,
                blob_closure_digest: digest,
                upload_ms: elapsed_ms(started),
            })
        })
    }
}

fn classify_git_ops_reclaim(err: &GitOpsError) -> UploadReclaimState {
    match err {
        GitOpsError::DeadlineExceeded | GitOpsError::Blob(BlobError::Timeout) => UploadReclaimState::OutcomeUnknown,
        _ => UploadReclaimState::PartialFailed,
    }
}

fn map_git_ops_error(err: GitOpsError, operation_id: Uuid) -> PushCausalError {
    match err {
        GitOpsError::DeadlineExceeded | GitOpsError::Blob(BlobError::Timeout) => PushCausalError::CommitUnknown {
            operation_id,
            detail: "Blob upload timed out with unknown remote persistence".into(),
        },
        GitOpsError::Blob(b) => PushCausalError::Blob(b),
        other => PushCausalError::Io(other.to_string()),
    }
}

fn compute_blob_closure_digest(store: &BlobStore, pack: &BlobReceipt, idx: &BlobReceipt) -> String {
    let mut h = Sha256::new();
    h.update(b"push-blob-closure-v1\n");
    let pack_path = pack.locator().path();
    let idx_path = idx.locator().path();
    for s in [
        store.backend_identity().as_hex(),
        pack_path.as_str(),
        pack.verified_sha256(),
        idx_path.as_str(),
        idx.verified_sha256(),
    ] {
        h.update((s.len() as u64).to_be_bytes());
        h.update(s.as_bytes());
    }
    hex::encode(h.finalize())
}
