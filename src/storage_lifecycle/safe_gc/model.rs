//! Core contracts, arming policies, producer vocabularies, and bounds (#122).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::SafeGcError;

pub const SAFE_GC_SCHEMA_VERSION: u32 = 1;
/// Mandatory safe-by-default invariant: destructive GC is OFF unless armed.
pub const SAFE_GC_DESTRUCTIVE_ENABLED_BY_DEFAULT: bool = false;

pub const MAX_DELETION_ROOTS: usize = 65_536;
pub const MAX_IN_FLIGHT_DECISIONS: usize = 8_192;
pub const MAX_GLOBAL_HOLDS: usize = 8_192;
pub const MAX_GROUPS_PER_PROOF: usize = 1_024;
pub const MAX_PACKS_PER_CLOSURE: usize = 4_096;
pub const MAX_CANDIDATES_PER_SWEEP: usize = 8_192;
pub const MAX_PRODUCER_ITEMS: usize = 6;
pub const MAX_STRING_FIELD_BYTES: usize = 256;

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
pub enum AuthorityLane {
    /// Standalone single-node PostgreSQL gate (independently testable).
    SingleNodePg { pg_authority_id: Uuid, pg_tx_seq: u64, local_quiesced: bool },
    /// Distributed Ref-CAS gate requiring #151 global hold bridge + #153 backup roots.
    DistributedRefCas {
        ref_cas_authority_id: Uuid,
        quorum_epoch: u64,
        raft_commit_index: u64,
        quorum_verified: bool,
        global_hold_bridge_verified: bool,
        global_hold_bridge_seq: u64,
        remote_backup_root_verified: bool,
        remote_backup_root_epoch: u64,
        async_projection_only: bool,
    },
}

impl AuthorityLane {
    pub fn validate_for_destructive_gc(&self) -> Result<(), SafeGcError> {
        match self {
            Self::SingleNodePg { pg_authority_id, pg_tx_seq, local_quiesced } => {
                if pg_authority_id.is_nil() || *pg_tx_seq == 0 {
                    return Err(SafeGcError::ArmingRejected("single-node PG lane missing tx authority"));
                }
                if !*local_quiesced {
                    return Err(SafeGcError::ArmingRejected("single-node PG repo not quiesced/fenced"));
                }
                Ok(())
            }
            Self::DistributedRefCas {
                ref_cas_authority_id,
                quorum_epoch,
                raft_commit_index,
                quorum_verified,
                global_hold_bridge_verified,
                global_hold_bridge_seq,
                remote_backup_root_verified,
                remote_backup_root_epoch,
                async_projection_only,
            } => {
                if *async_projection_only {
                    return Err(SafeGcError::DistributedPrereqsMissing(
                        "distributed GC cannot rely on async PG projection alone",
                    ));
                }
                if ref_cas_authority_id.is_nil() || !*quorum_verified || *quorum_epoch == 0 || *raft_commit_index == 0 {
                    return Err(SafeGcError::DistributedPrereqsMissing("Ref-CAS quorum not verified"));
                }
                if !*global_hold_bridge_verified || *global_hold_bridge_seq == 0 {
                    return Err(SafeGcError::DistributedPrereqsMissing("#151 global hold bridge unverified"));
                }
                if !*remote_backup_root_verified || *remote_backup_root_epoch == 0 {
                    return Err(SafeGcError::DistributedPrereqsMissing("#153 remote backup root unverified"));
                }
                Ok(())
            }
        }
    }

    pub(crate) fn encode_canonical(&self, h: &mut Sha256) {
        match self {
            Self::SingleNodePg { pg_authority_id, pg_tx_seq, local_quiesced } => {
                h.update(b"pg-single|");
                h.update(pg_authority_id.as_bytes());
                h.update(pg_tx_seq.to_be_bytes());
                h.update([u8::from(*local_quiesced)]);
            }
            Self::DistributedRefCas {
                ref_cas_authority_id,
                quorum_epoch,
                raft_commit_index,
                quorum_verified,
                global_hold_bridge_verified,
                global_hold_bridge_seq,
                remote_backup_root_verified,
                remote_backup_root_epoch,
                async_projection_only,
            } => {
                h.update(b"dist-refcas|");
                h.update(ref_cas_authority_id.as_bytes());
                h.update(quorum_epoch.to_be_bytes());
                h.update(raft_commit_index.to_be_bytes());
                h.update([
                    u8::from(*quorum_verified),
                    u8::from(*global_hold_bridge_verified),
                    u8::from(*remote_backup_root_verified),
                    u8::from(*async_projection_only),
                ]);
                h.update(global_hold_bridge_seq.to_be_bytes());
                h.update(remote_backup_root_epoch.to_be_bytes());
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
    pub arm_digest: String,
}

impl SafeGcArmReceipt {
    pub fn seal(
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
            arm_digest: String::new(),
        };
        receipt.arm_digest = receipt.compute_digest();
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn compute_digest(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"safe-gc-arm-v1|");
        h.update(self.schema_version.to_be_bytes());
        h.update(self.tenant_id.as_bytes());
        h.update(self.repo_id.as_bytes());
        h.update(self.history_id.as_bytes());
        h.update(self.incarnation_id.as_bytes());
        h.update(self.incarnation_epoch.to_be_bytes());
        h.update([u8::from(self.operator_opt_in), u8::from(self.armed_from_cache_or_ttl_only)]);
        self.lane.encode_canonical(&mut h);
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
        Ok(())
    }
}

/// Top-level GC mode: strictly disabled unless validly armed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum GcMode {
    #[default]
    DisabledByDefault,
    ArmedDestructive(SafeGcArmReceipt),
}

impl GcMode {
    pub fn require_armed(&self) -> Result<&SafeGcArmReceipt, SafeGcError> {
        match self {
            Self::DisabledByDefault => Err(SafeGcError::DestructiveGcDisabledByDefault),
            Self::ArmedDestructive(receipt) => {
                receipt.validate()?;
                Ok(receipt)
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupClosureReceipt {
    pub group_id: String,
    pub epoch: u64,
    pub retired_pack_ids: Vec<Uuid>,
    pub replacement_pack_ids: Vec<Uuid>,
    pub replacement_closure_verified: bool,
    pub quiesced: bool,
    pub receipt_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatePackTarget {
    pub pack_id: Uuid,
    pub group_id: String,
    pub physical_key: String,
    pub object_sha256: String,
    pub key_epoch: u64,
    pub contained_oids: Vec<String>,
}

pub(crate) fn validate_non_zero_oid(format: SafeGcObjectFormat, oid: &str) -> Result<(), SafeGcError> {
    if oid.len() != format.oid_hex_len()
        || !oid.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || oid.bytes().all(|b| b == b'0')
    {
        return Err(SafeGcError::InvalidInput("invalid or zero Git OID".into()));
    }
    Ok(())
}

pub(crate) fn validate_sha256_hex(value: &str) -> Result<(), SafeGcError> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(SafeGcError::InvalidInput("invalid 64-hex SHA-256 digest".into()));
    }
    Ok(())
}

pub(crate) fn validate_bounded_name(label: &str, value: &str) -> Result<(), SafeGcError> {
    if value.is_empty() || value.len() > MAX_STRING_FIELD_BYTES || value.contains('\0') || value.contains("..") {
        return Err(SafeGcError::InvalidInput(format!("invalid {label}")));
    }
    Ok(())
}

pub(crate) fn encode_len_bytes(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}

pub(crate) fn check_missing_producers(present: &BTreeSet<RetentionProducer>) -> Result<(), SafeGcError> {
    if present.len() != MAX_PRODUCER_ITEMS {
        return Err(SafeGcError::IncompleteProof("missing one or more required retention producers"));
    }
    Ok(())
}
