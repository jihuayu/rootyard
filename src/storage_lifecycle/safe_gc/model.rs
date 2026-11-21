//! Core contracts, arming policies, producer vocabularies, and bounds (#122).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::ref_version::pack_cover::PackRetentionState;

use super::{
    SafeGcError,
    dist_auth::{
        BackupRootEvidence, HoldBridgeEvidence, QuorumCommitEvidence, SafeGcEd25519Signer,
        verify_distributed_cursor_coverage, verify_distributed_lane_prereqs, verify_ed25519_domain,
    },
    quiescence::ReaderQuiescenceObservation,
    refcas_cut::RefCasReconciledCut,
};

pub const SAFE_GC_SCHEMA_VERSION: u32 = 2;
/// Mandatory safe-by-default invariant: destructive GC is OFF unless armed.
pub const SAFE_GC_DESTRUCTIVE_ENABLED_BY_DEFAULT: bool = false;

pub const MAX_DELETION_ROOTS: usize = 65_536;
pub const MAX_IN_FLIGHT_DECISIONS: usize = 8_192;
pub const MAX_GLOBAL_HOLDS: usize = 8_192;
pub const MAX_GROUPS_PER_PROOF: usize = 1_024;
pub const MAX_PACKS_PER_CLOSURE: usize = 4_096;
pub const MAX_CANDIDATES_PER_SWEEP: usize = 8_192;
pub const MAX_PRODUCER_ITEMS: usize = 6;
pub const MAX_STRING_FIELD_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SafeGcObjectFormat {
    Sha1,
    Sha256,
}

impl SafeGcObjectFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    pub fn oid_hex_len(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }
}

/// Authority lane under which safe-GC operates (#122).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AuthorityLane {
    /// Standalone single-node PostgreSQL gate bound to live PG tx, gc_epoch, and reader barrier.
    SingleNodePg { pg_authority_id: Uuid, pg_tx_seq: u64, pg_gc_fence_epoch: u64, reader_barrier_epoch: u64 },
    /// Distributed Ref-CAS gate requiring #151 global hold bridge + #153 backup roots.
    DistributedRefCas {
        ref_cas_authority_id: Uuid,
        quorum_epoch: u64,
        raft_commit_index: u64,
        quorum_evidence: Box<QuorumCommitEvidence>,
        hold_bridge_evidence: Box<HoldBridgeEvidence>,
        backup_root_evidence: Box<BackupRootEvidence>,
        async_projection_only: bool,
    },
}

impl AuthorityLane {
    pub fn validate_for_destructive_gc(&self) -> Result<(), SafeGcError> {
        match self {
            Self::SingleNodePg { pg_authority_id, pg_tx_seq, pg_gc_fence_epoch, reader_barrier_epoch } => {
                if pg_authority_id.is_nil() || *pg_tx_seq == 0 {
                    return Err(SafeGcError::ArmingRejected("single-node PG lane missing tx authority"));
                }
                if *pg_gc_fence_epoch == 0 || *reader_barrier_epoch == 0 {
                    return Err(SafeGcError::ArmingRejected(
                        "single-node PG lane requires live gc_epoch fence and exclusive reader barrier epoch",
                    ));
                }
                Ok(())
            }
            Self::DistributedRefCas {
                ref_cas_authority_id,
                quorum_epoch,
                raft_commit_index,
                quorum_evidence,
                hold_bridge_evidence,
                backup_root_evidence,
                async_projection_only,
            } => verify_distributed_lane_prereqs(
                *ref_cas_authority_id,
                *quorum_epoch,
                *raft_commit_index,
                (quorum_evidence.as_ref(), hold_bridge_evidence.as_ref(), backup_root_evidence.as_ref()),
                *async_projection_only,
            ),
        }
    }

    pub fn verify_cursor_coverage(
        &self,
        history_id: Uuid,
        live_ref_seq: u64,
        cursors: &PairedCursorReconciliation,
    ) -> Result<(), SafeGcError> {
        match self {
            Self::SingleNodePg { pg_tx_seq, pg_gc_fence_epoch, reader_barrier_epoch, .. } => {
                if pg_gc_fence_epoch != reader_barrier_epoch {
                    return Err(SafeGcError::StaleDeleterFenced(
                        "SingleNodePg gc_epoch fence disagrees with reader_barrier_epoch",
                    ));
                }
                let floor = (*pg_tx_seq).max(live_ref_seq);
                if cursors.pg_applied_seq < floor {
                    return Err(SafeGcError::IncompleteProof(
                        "paired PG cursor has not covered SingleNodePg tx/ref sequence",
                    ));
                }
                if cursors.refcas_required_index > 0 {
                    let Some(ref cut) = cursors.refcas_cut else {
                        return Err(SafeGcError::IncompleteProof(
                            "Ref-CAS projection stream active in PG without verified RefCasReconciledCut",
                        ));
                    };
                    cut.verify_reconciled(history_id, cursors.refcas_required_index, cut.group_epoch)?;
                } else if let Some(ref cut) = cursors.refcas_cut {
                    cut.verify_reconciled(history_id, 1, cut.group_epoch)?;
                }
                Ok(())
            }
            Self::DistributedRefCas {
                quorum_epoch, raft_commit_index, quorum_evidence, hold_bridge_evidence, ..
            } => verify_distributed_cursor_coverage(
                history_id,
                live_ref_seq,
                *quorum_epoch,
                *raft_commit_index,
                hold_bridge_evidence.bridge_seq,
                quorum_evidence.as_ref(),
                cursors,
            ),
        }
    }

    pub(crate) fn encode_canonical(&self, h: &mut Sha256) {
        match self {
            Self::SingleNodePg { pg_authority_id, pg_tx_seq, pg_gc_fence_epoch, reader_barrier_epoch } => {
                h.update(b"pg-single-v2|");
                h.update(pg_authority_id.as_bytes());
                h.update(pg_tx_seq.to_be_bytes());
                h.update(pg_gc_fence_epoch.to_be_bytes());
                h.update(reader_barrier_epoch.to_be_bytes());
            }
            Self::DistributedRefCas {
                ref_cas_authority_id,
                quorum_epoch,
                raft_commit_index,
                quorum_evidence,
                hold_bridge_evidence,
                backup_root_evidence,
                async_projection_only,
            } => {
                h.update(b"dist-refcas-v3|");
                h.update(ref_cas_authority_id.as_bytes());
                h.update(quorum_epoch.to_be_bytes());
                h.update(raft_commit_index.to_be_bytes());
                h.update([u8::from(*async_projection_only)]);
                quorum_evidence.as_ref().encode_canonical(h);
                hold_bridge_evidence.as_ref().encode_canonical(h);
                backup_root_evidence.as_ref().encode_canonical(h);
            }
        }
    }
}

/// Cryptographically sealed arming receipt required to exit `DisabledByDefault`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeGcArmReceipt {
    pub schema_version: u32,
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub incarnation_id: Uuid,
    pub incarnation_epoch: u64,
    pub operator_opt_in: bool,
    pub armed_from_cache_or_ttl_only: bool,
    pub lane: AuthorityLane,
    pub arm_pubkey_hex: String,
    pub arm_signature_hex: String,
    pub arm_digest: String,
}

impl SafeGcArmReceipt {
    pub fn seal(
        signer: &SafeGcEd25519Signer,
        tenant_id: Uuid,
        repo_id: Uuid,
        history_id: Uuid,
        incarnation_id: Uuid,
        incarnation_epoch: u64,
        operator_opt_in: bool,
        lane: AuthorityLane,
    ) -> Result<Self, SafeGcError> {
        let mut receipt = Self {
            schema_version: SAFE_GC_SCHEMA_VERSION,
            tenant_id,
            repo_id,
            history_id,
            incarnation_id,
            incarnation_epoch,
            operator_opt_in,
            armed_from_cache_or_ttl_only: false,
            lane,
            arm_pubkey_hex: signer.pubkey_hex().to_owned(),
            arm_signature_hex: String::new(),
            arm_digest: String::new(),
        };
        receipt.arm_digest = receipt.compute_digest();
        receipt.arm_signature_hex =
            signer.sign_domain(b"rootyard/safe-gc-arm-ed25519/v3", receipt.arm_digest.as_bytes());
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn compute_digest(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"safe-gc-arm-v3|");
        h.update(self.schema_version.to_be_bytes());
        h.update(self.tenant_id.as_bytes());
        h.update(self.repo_id.as_bytes());
        h.update(self.history_id.as_bytes());
        h.update(self.incarnation_id.as_bytes());
        h.update(self.incarnation_epoch.to_be_bytes());
        h.update([u8::from(self.operator_opt_in), u8::from(self.armed_from_cache_or_ttl_only)]);
        self.lane.encode_canonical(&mut h);
        encode_len_bytes(&mut h, self.arm_pubkey_hex.as_bytes());
        hex::encode(h.finalize())
    }

    pub fn validate(&self) -> Result<(), SafeGcError> {
        if self.schema_version != SAFE_GC_SCHEMA_VERSION {
            return Err(SafeGcError::ArmingRejected("arm receipt schema mismatch"));
        }
        if self.tenant_id.is_nil()
            || self.repo_id.is_nil()
            || self.history_id.is_nil()
            || self.incarnation_id.is_nil()
            || self.incarnation_epoch == 0
        {
            return Err(SafeGcError::ArmingRejected("arm receipt identity/epoch invalid"));
        }
        if !self.operator_opt_in || self.armed_from_cache_or_ttl_only {
            return Err(SafeGcError::ArmingRejected("TTL/cache-only or un-opted arming rejected"));
        }
        self.lane.validate_for_destructive_gc()?;
        if self.arm_digest != self.compute_digest() {
            return Err(SafeGcError::ArmingRejected("arm receipt digest mismatch"));
        }
        verify_ed25519_domain(
            &self.arm_pubkey_hex,
            b"rootyard/safe-gc-arm-ed25519/v3",
            self.arm_digest.as_bytes(),
            &self.arm_signature_hex,
        )
        .map_err(|_| SafeGcError::ArmingRejected("arm receipt Ed25519 signature verification failed"))
    }
}

/// Top-level GC mode: strictly disabled unless validly armed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum GcMode {
    #[default]
    DisabledByDefault,
    ArmedDestructive(Box<SafeGcArmReceipt>),
}

impl GcMode {
    pub fn require_armed(&self) -> Result<&SafeGcArmReceipt, SafeGcError> {
        match self {
            Self::DisabledByDefault => Err(SafeGcError::DestructiveGcDisabledByDefault),
            Self::ArmedDestructive(receipt) => {
                receipt.validate()?;
                Ok(receipt.as_ref())
            }
        }
    }
}

/// Every producer domain whose retention roots must reconcile before GC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RetentionProducer {
    PullRequest,
    CiPin,
    Workspace,
    Namespace,
    Lfs,
    Backup,
}

impl RetentionProducer {
    pub const ALL: [Self; MAX_PRODUCER_ITEMS] =
        [Self::PullRequest, Self::CiPin, Self::Workspace, Self::Namespace, Self::Lfs, Self::Backup];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PullRequest => "pull_request",
            Self::CiPin => "ci_pin",
            Self::Workspace => "workspace",
            Self::Namespace => "namespace",
            Self::Lfs => "lfs",
            Self::Backup => "backup",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SourceFreshness {
    Reconciled,
    Unknown,
    Stale,
    Lagging { behind_seq: u64 },
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveRefRoot {
    pub ref_name: String,
    pub target_oid: String,
    pub version_seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerReconciliationEntry {
    pub producer: RetentionProducer,
    pub freshness: SourceFreshness,
    pub observed_cursor_seq: u64,
    pub required_cursor_seq: u64,
    pub authority_epoch: u64,
    pub expected_authority_epoch: u64,
    pub root_oids: Vec<String>,
    pub pinned_pack_ids: Vec<Uuid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GlobalHoldState {
    Active,
    Released { released_at_seq: u64 },
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalHoldEntry {
    pub hold_id: Uuid,
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub incarnation_epoch: u64,
    pub registered_seq: u64,
    pub state: GlobalHoldState,
    pub protected_pack_ids: Vec<Uuid>,
    pub protected_oids: Vec<String>,
    pub protected_physical_keys: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DecisionKind {
    Push,
    PullMerge,
    Compaction,
    BackupSnapshot,
    NamespaceSync,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DecisionState {
    Pending,
    Committed,
    Cancelled,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InFlightDecisionRecord {
    pub decision_id: Uuid,
    pub kind: DecisionKind,
    pub state: DecisionState,
    pub snapshot_seq: u64,
    pub protected_pack_ids: Vec<Uuid>,
    pub protected_oids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairedCursorReconciliation {
    pub pg_freshness: SourceFreshness,
    pub pg_applied_seq: u64,
    pub pg_required_seq: u64,
    pub refcas_freshness: SourceFreshness,
    pub refcas_applied_index: u64,
    pub refcas_required_index: u64,
    #[serde(default)]
    pub refcas_cut: Option<RefCasReconciledCut>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupClosureReceipt {
    pub group_id: String,
    pub epoch: u64,
    pub retired_at_generation: u64,
    pub retired_pack_ids: Vec<Uuid>,
    pub replacement_pack_ids: Vec<Uuid>,
    #[serde(default)]
    pub replacement_oids: Vec<String>,
    pub replacement_closure_verified: bool,
    pub reader_quiescence: ReaderQuiescenceObservation,
    pub receipt_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatePackTarget {
    pub pack_id: Uuid,
    pub key_role: String,
    pub group_id: String,
    pub physical_key: String,
    pub object_sha256: String,
    pub remote_etag: String,
    pub remote_version_id: Option<String>,
    pub provider_generation: i64,
    pub key_epoch: u64,
    pub retention_state: PackRetentionState,
    pub contained_oids: Vec<String>,
}

#[path = "codec.rs"]
mod codec;

pub(crate) use codec::{encode_len_bytes, validate_bounded_name, validate_non_zero_oid, validate_sha256_hex};

pub(crate) fn check_missing_producers(present: &BTreeSet<RetentionProducer>) -> Result<(), SafeGcError> {
    if present.len() != MAX_PRODUCER_ITEMS {
        return Err(SafeGcError::IncompleteProof("missing one or more required retention producers"));
    }
    Ok(())
}
