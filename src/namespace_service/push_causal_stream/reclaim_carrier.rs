//! Default OpenDAL `BlobStore` carrier with recoverable partial/unknown upload reclaim tracking (#183).

use std::time::Instant;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::blob_store::capacity_contract::git_ops::{GitOpsError, UploadScope, upload_pack_pair};
use crate::blob_store::closure::{BlobClosureEncryption, BlobClosureSpec, ClosureArtifactRole, ClosureEntrySpec};
use crate::blob_store::opendal::BlobStore;
use crate::blob_store::{BlobError, BlobLocator, BlobReceipt};

use super::git_proc::sha256_and_len_sync;
use super::quarantine::{BoxFuture, PushBlobCarrier, QuarantineArtifactSet, UploadedQuarantinePack, elapsed_ms};
use super::reclaim::{StagingUploadIntent, UploadReclaimState};
use super::types::{FaultInjectionHook, PushCausalError};

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
        GitOpsError::DeadlineExceeded | GitOpsError::Blob(BlobError::DeadlineExceeded) => {
            UploadReclaimState::OutcomeUnknown
        }
        _ => UploadReclaimState::PartialFailed,
    }
}

fn map_git_ops_error(err: GitOpsError, operation_id: Uuid) -> PushCausalError {
    match err {
        GitOpsError::DeadlineExceeded | GitOpsError::Blob(BlobError::DeadlineExceeded) => {
            PushCausalError::CommitUnknown {
                operation_id,
                detail: "Blob upload timed out with unknown remote persistence".into(),
            }
        }
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
