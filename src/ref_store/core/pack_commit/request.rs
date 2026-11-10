//! Requests of the A4a pack commit slice.
//!
//! Cardinality is deliberately simple and exact: **one** `ProtectedPublication`
//! = one A3 acquire/consume batch of exactly two artifacts = **one** planned
//! pack pair registration. A plan may name up to eight new packs, and the caller
//! performs one A3 pair upload plus one registration per pack under the same
//! parent digest. Splitting or reusing one 16-artifact publication across packs
//! is not permitted in this slice and is refused as a typed capacity error, which
//! keeps the global `UNIQUE` acquire/consume ids correct per registration.
use super::contract::{ARTIFACTS_PER_PACK, PackArtifactRole, PackMode};
use super::error::PackCommitError;
use super::plan::{ContentDigest, PackCommitPlan, PlannedPack};
use crate::blob_store::protected::ProtectedPublication;
use crate::ref_store::contract::RequestDigest;
use uuid::Uuid;

/// The first (and only) two A3 pair slots of one registration.
pub const PAIR_SLOTS: [i32; ARTIFACTS_PER_PACK] = [0, 1];

/// One artifact of the pair, verified against the plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairArtifact {
    role: PackArtifactRole,
    slot: i32,
    hold_id: Uuid,
    sha256: ContentDigest,
    length: u64,
}

impl PairArtifact {
    pub fn role(&self) -> PackArtifactRole {
        self.role
    }
    pub fn slot(&self) -> i32 {
        self.slot
    }
    pub fn hold_id(&self) -> Uuid {
        self.hold_id
    }
    pub fn sha256(&self) -> &ContentDigest {
        &self.sha256
    }
    pub fn length(&self) -> u64 {
        self.length
    }
}

/// Actual A3 publication plus the plan/pack it claims to fulfil.
#[derive(Debug)]
pub struct PackRegistrationRequest<'a> {
    plan: &'a PackCommitPlan,
    planned_pack: &'a PlannedPack,
    publication: &'a ProtectedPublication,
    artifacts: Vec<PairArtifact>,
}

impl<'a> PackRegistrationRequest<'a> {
    /// Selects exactly one planned pack and verifies the publication is the
    /// matching two-artifact A3 pair (slot 0 = `.pack`, slot 1 = `.idx`) with the
    /// planned content digests and lengths. Durable A3 row/body verification is
    /// performed separately in the owned short transaction through
    /// `artifact_hold::read_registration_ledger`.
    pub fn new(
        plan: &'a PackCommitPlan,
        pack_id: Uuid,
        publication: &'a ProtectedPublication,
    ) -> Result<Self, PackCommitError> {
        if pack_id.is_nil() {
            return Err(PackCommitError::Invalid("pack id must be non-nil"));
        }
        let planned_pack = plan
            .packs()
            .iter()
            .find(|pack| pack.pack_id() == pack_id)
            .ok_or(PackCommitError::Invalid("pack id is not planned by this commit"))?;
        if publication.acquire_request_id().is_nil() || publication.consume_request_id().is_nil() {
            return Err(PackCommitError::Invalid("publication ids must be non-nil"));
        }
        if publication.acquire_request_id() == publication.consume_request_id() {
            return Err(PackCommitError::Invalid("acquire and consume ids must differ"));
        }
        if plan.expected().mode() == PackMode::MetadataOnly && plan.packs().is_empty() {
            return Err(PackCommitError::Invalid("a verified commit must register at least one pack pair"));
        }
        if publication.receipts().len() != ARTIFACTS_PER_PACK {
            return Err(PackCommitError::Capacity {
                limit: "publication_artifacts",
                bound: ARTIFACTS_PER_PACK as i64,
                actual: publication.receipts().len() as i64,
            });
        }
        let mut artifacts = Vec::with_capacity(ARTIFACTS_PER_PACK);
        let mut backend: Option<String> = None;
        for receipt in publication.receipts() {
            let slot = receipt.slot();
            let role = match slot {
                0 => PackArtifactRole::Pack,
                1 => PackArtifactRole::Idx,
                _ => {
                    return Err(PackCommitError::Capacity { limit: "pair_slot", bound: 1, actual: i64::from(slot) });
                }
            };
            let verified = receipt.receipt();
            let identity = verified.backend_identity().as_hex().to_owned();
            match &backend {
                None => backend = Some(identity),
                Some(existing) if existing != &identity => {
                    return Err(PackCommitError::Invalid("publication receipts name different physical backends"));
                }
                Some(_) => {}
            }
            let planned = planned_pack.artifact(role);
            if verified.verified_sha256() != planned.content().as_str()
                || verified.verified_length() != planned.length()
            {
                return Err(PackCommitError::Invalid("publication receipt content differs from the plan"));
            }
            artifacts.push(PairArtifact {
                role,
                slot,
                hold_id: receipt.hold_id(),
                sha256: ContentDigest::parse(verified.verified_sha256().to_owned())?,
                length: verified.verified_length(),
            });
        }
        artifacts.sort_by_key(|artifact| artifact.slot);
        if artifacts.iter().map(|artifact| artifact.role).collect::<Vec<_>>()
            != vec![PackArtifactRole::Pack, PackArtifactRole::Idx]
        {
            return Err(PackCommitError::Invalid("publication is not exactly one pack and one idx"));
        }
        Ok(Self { plan, planned_pack, publication, artifacts })
    }

    pub fn plan(&self) -> &PackCommitPlan {
        self.plan
    }

    pub fn planned_pack(&self) -> &PlannedPack {
        self.planned_pack
    }

    pub fn publication(&self) -> &ProtectedPublication {
        self.publication
    }

    pub fn artifacts(&self) -> &[PairArtifact] {
        &self.artifacts
    }

    pub fn artifact(&self, role: PackArtifactRole) -> &PairArtifact {
        &self.artifacts[role as usize]
    }
}

/// Opaque identity of one durable Pending pack commit.
///
/// The token is *identity*, not a transaction or a connection: it carries no
/// grant, holds no lease and may be used only to name the pending operation that
/// `PgPackCommit::begin_pending` established. It is not `Clone`, so a handle
/// cannot be multiplied into extra commit attempts.
pub struct PackPendingToken {
    repository_id: Uuid,
    tenant_id: Uuid,
    operation_id: Uuid,
    parent_digest: RequestDigest,
}

impl PackPendingToken {
    /// Internal mint surface. Only the owned short-transaction adapter creates
    /// a token, and only after the migration-138 registry confirmed (or newly
    /// created) exactly this pending operation under exactly this digest.
    pub(crate) fn established(
        repository_id: Uuid,
        tenant_id: Uuid,
        operation_id: Uuid,
        parent_digest: RequestDigest,
    ) -> Result<Self, PackCommitError> {
        if repository_id.is_nil() || tenant_id.is_nil() || operation_id.is_nil() {
            return Err(PackCommitError::Invalid("pending token ids must be non-nil"));
        }
        Ok(Self { repository_id, tenant_id, operation_id, parent_digest })
    }

    pub fn repository_id(&self) -> Uuid {
        self.repository_id
    }

    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    pub fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    pub fn parent_digest(&self) -> &RequestDigest {
        &self.parent_digest
    }

    /// A token is bound to exactly one plan identity.
    pub fn binds(&self, plan: &PackCommitPlan) -> bool {
        self.repository_id == plan.repository_id()
            && self.tenant_id == plan.tenant_id()
            && self.operation_id == plan.identity().operation_id()
            && &self.parent_digest == plan.parent_digest()
    }
}

impl std::fmt::Debug for PackPendingToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PackPendingToken")
            .field("repository_id", &self.repository_id)
            .field("operation_id", &self.operation_id)
            .field("parent_digest", &"<bound>")
            .finish()
    }
}
