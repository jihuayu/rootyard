//! Data rows of the pure source-ledger validator.
//!
//! These types are the decoded inputs of [`super::ledger_sets`] checks: the
//! archive's declared registration pairs, their A4 publication/artifact/hold
//! rows, A5 snapshot descriptors, retained-root captures and lifetime rows.
//! They carry no decisions and no database access, so the sibling checkers can
//! be unit-tested without PostgreSQL; parent re-exports keep the historical
//! `super::Type` paths stable.
use super::serving_reads::ServingReads;
use uuid::Uuid;

/// One declared registration, the set kinds that declare it and the A4 rows
/// beneath it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::backup) struct DeclaredPair {
    pub repository_id: Uuid,
    pub pack_id: Uuid,
    pub registration_id: Uuid,
    /// Sorted, unique declaring set kinds.
    pub declared_by: Vec<String>,
    /// `(source, artifact_set_digest, joined_revision)` of every declaring row.
    pub declared_sets: Vec<(String, String, i64)>,
    /// Registration realm; `None` only when no publication row exists.
    pub publication: Option<PublishedPack>,
    /// The actual repository tenant and core gate tenant.
    pub actual: ActualRepository,
    pub artifacts: Vec<PairArtifact>,
    /// Every owner/tenant/repository/pack scope violation of the rows above,
    /// in a stable order; empty when they all agree with the publication.
    pub scope: Vec<String>,
}

/// Publication realm, live issuer ids and stored artifact-set digest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::backup) struct PublishedPack {
    pub repository_id: Uuid,
    pub pack_id: Uuid,
    /// The repository tenant (`repositories.owner_id` / core gate tenant).
    pub tenant_id: Uuid,
    /// The pack producer, i.e. the A3 artifact-hold requester. Not the tenant.
    pub owner_id: Uuid,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub object_format: String,
    pub gate_revision: i64,
    pub acquire_request_id: Uuid,
    pub consume_request_id: Uuid,
    pub digest: String,
}

/// What the actual repository and the core gate say about one declared
/// registration: the repository tenant must be exactly the publication tenant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::backup) struct ActualRepository {
    /// `repositories.owner_id` (`None` only when the repository row is absent).
    pub owner_id: Option<Uuid>,
    /// `ref_store_core_gates.tenant_id` (`None` only when the gate row is absent).
    pub gate_tenant_id: Option<Uuid>,
}

/// One `ref_store_core_pack_artifacts` row joined with its durable hold,
/// consume receipt and the hold's live issuer operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::backup) struct PairArtifact {
    pub role: String,
    pub slot: i32,
    pub hold_id: Uuid,
    pub acquire_request_id: Uuid,
    pub consume_request_id: Uuid,
    pub provider: String,
    pub backend_identity: String,
    pub sha256: String,
    pub length: u64,
    /// Locator tenant of the artifact row: the actual repository tenant.
    pub tenant_id: Uuid,
    pub authority_id: Uuid,
    pub generation: i64,
    pub attempt_id: Uuid,
    pub namespace: String,
    /// The artifact row's own repository and pack. Neither is part of the
    /// locator digest, so each is checked directly against the declared key.
    pub repository_id: Uuid,
    pub pack_id: Uuid,
    /// The acquire request the hold was minted for: its repository, tenant and
    /// owner (`None` only when the `artifact_hold_requests` row is absent).
    pub request: Option<RequestRow>,
    /// `None` when the durable `artifact_holds` row is absent.
    pub hold: Option<HoldRow>,
    pub receipt: bool,
    /// The consume receipt's own repository, tenant and owner (`None` only when
    /// the `artifact_hold_consume_receipts` row is absent).
    pub receipt_scope: Option<ReceiptRow>,
    pub issuer_operation: bool,
    /// The durable hold's own slot, read through its LEFT JOIN (`None` only when
    /// the hold row is absent).
    pub hold_slot: Option<i32>,
}

/// The issuing scope of one `artifact_hold_requests` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::backup) struct RequestRow {
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    /// The A3 owner: the pack producer, never the repository tenant.
    pub owner_id: Uuid,
}

/// The scope of one `artifact_hold_consume_receipts` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::backup) struct ReceiptRow {
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
}

/// The physical coordinates of one durable `artifact_holds` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::backup) struct HoldRow {
    pub request_id: Uuid,
    pub slot: i32,
    pub repository_id: Uuid,
    /// The hold's own `tenant_id` column, never copied from the artifact row.
    pub tenant_id: Uuid,
    /// The hold's own `owner_id` column: the A3 owner of the hold.
    pub owner_id: Uuid,
    pub provider: String,
    pub backend_identity: String,
    pub storage_tenant_id: Uuid,
    pub authority_id: Uuid,
    pub generation: i64,
    pub attempt_id: Uuid,
    pub namespace: String,
    pub sha256: String,
    pub length: u64,
}

/// One A5 snapshot header with its declared pack descriptors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::backup) struct SnapshotSet {
    pub repository_id: Uuid,
    pub snapshot_id: Uuid,
    pub realm: Realm,
    pub pack_mode: String,
    pub pack_count: i32,
    pub membership_digest: String,
    /// `(pack_id, registration_id, artifact_set_digest, joined_revision)`.
    pub packs: Vec<(Uuid, Uuid, String, i64)>,
}

/// One retained root capture: header, captured refs, selector OIDs and packs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::backup) struct RootCapture {
    pub repository_id: Uuid,
    pub root_id: Uuid,
    pub generation: i64,
    pub tenant_id: Uuid,
    /// The capture's producer/requester; it may differ from the tenant.
    pub owner_id: Uuid,
    pub purpose: String,
    pub business_intent_digest: String,
    pub realm: Realm,
    pub ref_count: i32,
    pub oid_count: i32,
    pub pack_count: i32,
    pub refs_digest: String,
    pub pack_set_digest: String,
    /// The stored register digest, held by the head and, once released, by the
    /// tombstone; it must be this capture's own recomputed register digest.
    pub register_digest: String,
    /// Stored `selector_kind` (`snapshot` or `oids`).
    pub selector_kind: String,
    /// Stored HEAD ref and (optionally) its object id.
    pub head_ref: String,
    pub head_oid: Option<String>,
    /// Stored native binding digest (`core-root-binding-v1`).
    pub native_binding_digest: String,
    /// `(ref_name, oid)` of `ref_store_core_root_refs`.
    pub refs: Vec<(String, String)>,
    /// `(ordinal, oid)` of `ref_store_core_root_oids`.
    pub oids: Vec<(i32, String)>,
    /// The core's own verdict on this capture: `None` when the real
    /// `retention_root` algorithm refused it, otherwise its re-proven metadata.
    pub proof: Option<RootProof>,
    pub packs: Vec<RetainedPack>,
}

/// What the real `retention_root` capture validator proved about one capture.
/// Every digest is recomputed by the core from the stored rows; none is trusted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::backup) struct RootProof {
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: String,
    pub business_intent_digest: String,
    pub register_digest: String,
    pub head_ref: String,
    pub head_oid: Option<String>,
    pub selector_kind: String,
    /// Exact selector object ids (`resolve_oids`), not the stored row order.
    pub oids: Vec<String>,
    pub refs_digest: String,
    pub pack_set_digest: String,
    pub native_binding_digest: String,
}

/// One `ref_store_core_root_heads` row (the root's current lifetime state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::backup) struct RootHead {
    pub repository_id: Uuid,
    pub root_id: Uuid,
    pub tenant_id: Uuid,
    /// `owner_id` is the producer/requester; it may differ from the tenant.
    pub owner_id: Uuid,
    pub purpose: String,
    pub business_intent_digest: String,
    /// Recomputed from the capture's native binding by the real register
    /// algorithm (`register_digest`), never copied out of the capture row.
    pub register_digest: String,
    pub state: String,
    pub last_generation: i64,
}

/// One `ref_store_core_root_tombstones` release fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::backup) struct RootTombstone {
    pub repository_id: Uuid,
    pub root_id: Uuid,
    pub generation: i64,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: String,
    pub business_intent_digest: String,
    pub expected_register_digest: String,
    pub release_digest: String,
}

/// The core realm a snapshot or root was captured under. `owner_id` is the
/// producer/requester of the capture, so it is deliberately absent: a producer
/// owner distinct from the repository tenant is valid.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::backup) struct Realm {
    pub tenant_id: Uuid,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub object_format: String,
}

/// One `ref_store_core_root_packs` row: the complete retained pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::backup) struct RetainedPack {
    pub pack_id: Uuid,
    pub registration_id: Uuid,
    pub artifact_set_digest: String,
    pub joined_revision: i64,
    pub pack: RetainedArtifact,
    pub idx: RetainedArtifact,
}

/// One retained artifact identity of a root pack row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::backup) struct RetainedArtifact {
    pub slot: i32,
    pub hold_id: Uuid,
    pub tenant_id: Uuid,
    pub authority_id: Uuid,
    pub generation: i64,
    pub attempt_id: Uuid,
    pub namespace: String,
    pub sha256: String,
    pub length: i64,
    pub provider: String,
    pub backend_identity: String,
    pub verified_sha256: String,
    pub verified_length: i64,
}

/// Every pure input of the source validation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::backup) struct SourceSets {
    pub declared: Vec<DeclaredPair>,
    pub snapshots: Vec<SnapshotSet>,
    pub roots: Vec<RootCapture>,
    pub heads: Vec<RootHead>,
    pub tombstones: Vec<RootTombstone>,
    /// The transient serving read headers and their own decoded rows (#169).
    pub serving_reads: ServingReads,
}
