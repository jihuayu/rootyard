//! Read-only discovery of the durable holds that belong to both migration-152
//! attempts of one public operation.
//!
//! This module is intentionally not a reclaim/deletion capability. It proves
//! the exact public wrapper and both private attempts through the reviewed
//! [`PublicAttemptLookup`] validator, then reads only the migration-141 holds
//! and migration-142 registration/consumption bindings selected by those exact
//! private identities. It never consults a local scratch ledger, never takes a
//! lease, never issues a provider HEAD/DELETE and never writes any row.
//!
//! A caller receives one entry per durable attempt slot (including slots with
//! zero holds) and, per hold, one of four explicit dispositions:
//! * `Unconsumed` - no migration-141 consume receipt;
//! * `Consumed` - an exact consume receipt exists but no migration-142 pair is
//!   registered for that hold;
//! * `Registered` - the hold and its counterpart pack/idx hold both exactly bind
//!   to one migration-142 publication, its plan digest, physical backend and
//!   consume request;
//! * `Unresolved` - a missing, partial, mismatched or otherwise inconclusive
//!   binding. Unresolved evidence is never certified or made deletable.
//!
//! Migration-142 publications are retention roots for this increment: every
//! registered pair is retained because a backup may enumerate every migration-142
//! artifact. Consumption is not quiescence; I/O can continue after PostgreSQL
//! records a consume receipt, so no status here grants object deletion.
//!
//! A successful bounded read, even with no unresolved rows, grants neither
//! quiescence, deletion authority, nor proof of completion. The runtime consumer
//! remains deferred and this module never opens a provider, filesystem, lease or
//! publication path.
use super::{
    PgRefStore, bound,
    public_attempt::{
        PublicAttempt, PublicAttemptEvidence, PublicAttemptLookup, PublicAttemptRequest, ledger, lookup_db_error,
    },
};
use crate::blob_store::BlobLocator;
use crate::ref_store::core::artifact_hold::REPO_MAX_HOLDS;
use crate::ref_store::{OperationState, RequestDigest, core::pack_commit::PackCommitError};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;

/// The exact hold inventory selected by both migration-152 attempts.
const SELECT_RECLAIM_HOLDS: &str = r#"
SELECT jsonb_build_object(
    'hold', jsonb_build_object(
        'request_id', h.request_id,
        'hold_id', h.hold_id,
        'slot', h.slot,
        'repository_id', h.repository_id,
        'tenant_id', h.tenant_id,
        'owner_id', h.owner_id,
        'purpose', h.purpose,
        'operation_id', h.operation_id,
        'operation_digest', h.operation_digest,
        'provider', h.provider,
        'backend_identity', h.backend_identity,
        'storage_tenant_id', h.storage_tenant_id,
        'authority_id', h.authority_id,
        'authority_generation', h.authority_generation,
        'attempt_id', h.attempt_id,
        'namespace', h.namespace,
        'sha256', h.sha256,
        'content_length', h.content_length,
        'generation', h.generation
    ),
    'request', CASE WHEN r.request_id IS NULL THEN NULL ELSE jsonb_build_object(
        'request_id', r.request_id,
        'repository_id', r.repository_id,
        'tenant_id', r.tenant_id,
        'owner_id', r.owner_id,
        'purpose', r.purpose,
        'object_format', r.object_format,
        'history_incarnation', r.history_incarnation,
        'authority_epoch', r.authority_epoch,
        'group_epoch', r.group_epoch,
        'operation_issuer_id', r.operation_issuer_id,
        'operation_lane', r.operation_lane,
        'operation_sequence', r.operation_sequence,
        'operation_id', r.operation_id,
        'operation_digest', r.operation_digest,
        'backend_identity', r.backend_identity
    ) END,
    'receipt', CASE WHEN c.hold_id IS NULL THEN NULL ELSE jsonb_build_object(
        'hold_id', c.hold_id,
        'request_id', c.request_id,
        'consume_request_id', c.consume_request_id,
        'repository_id', c.repository_id,
        'tenant_id', c.tenant_id,
        'owner_id', c.owner_id,
        'operation_id', c.operation_id,
        'operation_digest', c.operation_digest,
        'slot', c.slot
    ) END,
    'artifact', CASE WHEN a.hold_id IS NULL THEN NULL ELSE jsonb_build_object(
        'hold_id', a.hold_id,
        'registration_id', a.registration_id,
        'role', a.role,
        'slot', a.slot,
        'pack_id', a.pack_id,
        'repository_id', a.repository_id,
        'tenant_id', a.tenant_id,
        'provider', a.provider,
        'backend_identity', a.backend_identity,
        'namespace', a.namespace,
        'sha256', a.sha256,
        'content_length', a.content_length,
        'acquire_request_id', a.acquire_request_id,
        'consume_request_id', a.consume_request_id
    ) END,
    'publication', CASE WHEN p.registration_id IS NULL THEN NULL ELSE jsonb_build_object(
        'registration_id', p.registration_id,
        'pack_id', p.pack_id,
        'repository_id', p.repository_id,
        'tenant_id', p.tenant_id,
        'owner_id', p.owner_id,
        'purpose', p.purpose,
        'object_format', p.object_format,
        'history_incarnation', p.history_incarnation,
        'authority_epoch', p.authority_epoch,
        'group_epoch', p.group_epoch,
        'parent_digest', p.parent_digest,
        'plan_operation_id', p.plan_operation_id,
        'backend_identity', p.backend_identity,
        'acquire_request_id', p.acquire_request_id,
        'consume_request_id', p.consume_request_id
    ) END
) AS row
FROM artifact_holds h
LEFT JOIN artifact_hold_requests r ON r.request_id = h.request_id
LEFT JOIN artifact_hold_consume_receipts c ON c.hold_id = h.hold_id
LEFT JOIN ref_store_core_pack_artifacts a
       ON a.acquire_request_id = h.request_id AND a.hold_id = h.hold_id
LEFT JOIN ref_store_core_pack_publications p ON p.registration_id = a.registration_id
WHERE h.repository_id = $1
  AND h.operation_id = ANY($2::uuid[])
ORDER BY h.operation_id ASC, h.request_id ASC, h.slot ASC
LIMIT $3
"#;

/// Migration-141 `REPO_MAX_HOLDS` is the retained all-history repository hold
/// ceiling, not an active-only count. Holds are immutable and there is no
/// release path, so this SELECT (one row per retained hold via unique left
/// joins) reads `cap + 1` rows and refuses an over-cap inventory before any row
/// is decoded. It never truncates and never returns a partial success payload.
const HOLD_INVENTORY_CAP_EXCEEDED: &str = "public reclaim discovery hold inventory exceeds the repository cap";
const HOLD_INVENTORY_CAP_INVALID: &str = "public reclaim discovery hold inventory cap is not representable";

/// The standalone discovery API is only valid inside one stable read-only
/// snapshot. This one statement both proves that contract and checks that the
/// migration-141/142 relations and version rows are present before any attempt
/// or hold read is prepared.
const SNAPSHOT_AND_CATALOG_PROBE: &str = r#"
SELECT current_setting('transaction_isolation'),
       current_setting('transaction_read_only'),
       EXISTS(SELECT 1 FROM schema_migrations WHERE version=141),
       EXISTS(SELECT 1 FROM schema_migrations WHERE version=142),
       to_regclass('artifact_holds') IS NOT NULL,
       to_regclass('artifact_hold_requests') IS NOT NULL,
       to_regclass('artifact_hold_consume_receipts') IS NOT NULL,
       to_regclass('ref_store_core_pack_artifacts') IS NOT NULL,
       to_regclass('ref_store_core_pack_publications') IS NOT NULL
"#;

const STABLE_SNAPSHOT_REQUIRED: &str = "public reclaim discovery requires a read-only repeatable read transaction";
const RECLAIM_CATALOG_REQUIRED: &str = "public reclaim discovery requires migrations 141 and 142";

/// Read-only request-aware discovery result. The marker variants carry no rows;
/// only a fully validated public wrapper can produce [`Found`](Self::Found).
#[allow(dead_code)]
#[derive(Clone, Eq, PartialEq)]
pub(crate) enum PublicReclaimLookup {
    Unknown,
    PrivateIdentifier,
    LegacyPath,
    /// Sealed success witness. The wrapped value is constructible only inside
    /// this module and is not itself a quiescence, completion or deletion token.
    Found(PublicReclaimDiscovery),
}

impl std::fmt::Debug for PublicReclaimLookup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => formatter.write_str("Unknown"),
            Self::PrivateIdentifier => formatter.write_str("PrivateIdentifier"),
            Self::LegacyPath => formatter.write_str("LegacyPath"),
            Self::Found(found) => formatter.debug_tuple("Found").field(found).finish(),
        }
    }
}

/// One validated public wrapper with exactly one entry per durable attempt slot.
///
/// This is a sealed witness: all fields are private and only [`build_discovery`]
/// can create a value. A successful bounded read does not imply quiescence,
/// does not grant deletion authority, and does not prove completion of any hold
/// or attempt; the runtime consumer remains deferred.
#[allow(dead_code)]
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PublicReclaimDiscovery {
    public_id: Uuid,
    state: OperationState,
    slots: Vec<PublicReclaimSlot>,
}

impl std::fmt::Debug for PublicReclaimDiscovery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublicReclaimDiscovery")
            .field("public_id", &"<redacted>")
            .field("state", &self.state)
            .field("slots", &self.slots)
            .finish()
    }
}

/// The discoverable facts of one migration-152 attempt. A slot remains present
/// when it has no holds, so a zero-hold result cannot be confused with a slot
/// that was not examined.
#[allow(dead_code)]
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PublicReclaimSlot {
    slot: i16,
    private_id: Uuid,
    plan_digest: RequestDigest,
    proof_digest: RequestDigest,
    base_revision: i64,
    state: OperationState,
    event_id: Option<Uuid>,
    event_revision: Option<i64>,
    holds: Vec<PublicReclaimHold>,
}

impl std::fmt::Debug for PublicReclaimSlot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublicReclaimSlot")
            .field("slot", &self.slot)
            .field("private_id", &"<redacted>")
            .field("plan_digest", &"<redacted>")
            .field("proof_digest", &"<redacted>")
            .field("base_revision", &self.base_revision)
            .field("state", &self.state)
            .field("event_id", &self.event_id.map(|_| "<redacted>"))
            .field("event_revision", &self.event_revision)
            .field("holds", &self.holds)
            .finish()
    }
}

/// The physical role of one migration-142 artifact row.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum PublicReclaimArtifactRole {
    Pack,
    Index,
}

/// Explicit, non-deletable disposition of one exact hold row.
#[allow(dead_code)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum PublicReclaimHoldDisposition {
    Unconsumed,
    Consumed,
    Registered { registration_id: Uuid, pack_id: Uuid },
    Unresolved(PublicReclaimUnresolved),
}

impl std::fmt::Debug for PublicReclaimHoldDisposition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unconsumed => formatter.write_str("Unconsumed"),
            Self::Consumed => formatter.write_str("Consumed"),
            Self::Registered { .. } => formatter
                .debug_struct("Registered")
                .field("registration_id", &"<redacted>")
                .field("pack_id", &"<redacted>")
                .finish(),
            Self::Unresolved(reason) => formatter.debug_tuple("Unresolved").field(reason).finish(),
        }
    }
}

/// Closed unresolved reasons for audit and deterministic tests.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicReclaimUnresolved {
    MissingRequest,
    RequestScopeMismatch,
    InvalidLocator,
    MissingReceipt,
    ReceiptMismatch,
    ArtifactMismatch,
    RegistrationMismatch,
    PairIncomplete,
}

/// One migration-141 hold with its migration-142 binding evidence. The locator
/// is the read-only physical address reconstructed from PostgreSQL; it is not a
/// write capability and no method on this result deletes it.
#[allow(dead_code)]
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PublicReclaimHold {
    request_id: Uuid,
    hold_id: Uuid,
    slot: i16,
    role: Option<PublicReclaimArtifactRole>,
    disposition: PublicReclaimHoldDisposition,
    locator: Option<BlobLocator>,
    backend_identity: String,
    provider: String,
    storage_attempt_id: Uuid,
    content_sha256: String,
    content_length: u64,
}

impl std::fmt::Debug for PublicReclaimHold {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublicReclaimHold")
            .field("request_id", &"<redacted>")
            .field("hold_id", &"<redacted>")
            .field("slot", &self.slot)
            .field("role", &self.role)
            .field("disposition", &self.disposition)
            .field("locator", &self.locator)
            .field("backend_identity", &"<redacted>")
            .field("provider", &self.provider)
            .field("storage_attempt_id", &"<redacted>")
            .field("content_sha256", &"<redacted>")
            .field("content_length", &self.content_length)
            .finish()
    }
}

impl PgRefStore {
    /// Discover both durable attempts and their exact holds inside the
    /// caller-owned read transaction. The caller has already authenticated the
    /// public request; this method reuses the same migration-152 wrapper/attempt
    /// validator as the serving lookup, then performs one bounded read of the
    /// migration-141/142 rows selected by those private identities.
    ///
    /// The caller must already own a `READ ONLY`, `REPEATABLE READ` transaction.
    /// The method proves both transaction modes and the exact migration-141/142
    /// catalog before reading anything. Because PostgreSQL fixes the
    /// repeatable-read snapshot at the first statement, the migration-152
    /// validator and the migration-141/142 hold read observe one stable
    /// snapshot even if a concurrent slot rotation commits between them.
    ///
    /// There is deliberately no scratch path, local ledger, filesystem, lease,
    /// provider HEAD/DELETE, schema probe write or catalog mutation in this
    /// signature. Missing/inconsistent PostgreSQL evidence is an explicit
    /// unresolved hold or a fixed ledger-integrity refusal, never a certified
    /// object.
    #[allow(dead_code)] // No production reclaim caller until the later deletion checkpoint.
    pub(crate) async fn discover_public_reclaim(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        request: &PublicAttemptRequest,
        deadline: Instant,
    ) -> Result<PublicReclaimLookup, PackCommitError> {
        require_stable_snapshot(tx, deadline).await?;
        let (state, evidence) = match self.lookup_public_attempt(tx, request, deadline).await? {
            PublicAttemptLookup::Unknown => return Ok(PublicReclaimLookup::Unknown),
            PublicAttemptLookup::PrivateIdentifier => return Ok(PublicReclaimLookup::PrivateIdentifier),
            PublicAttemptLookup::LegacyPath => return Ok(PublicReclaimLookup::LegacyPath),
            PublicAttemptLookup::Pending(evidence) => (OperationState::Pending, evidence),
            PublicAttemptLookup::Committed(evidence) => (OperationState::Committed, evidence),
            PublicAttemptLookup::Rejected(evidence) => (OperationState::Rejected, evidence),
            PublicAttemptLookup::Cancelled(evidence) => (OperationState::Cancelled, evidence),
        };
        let rows = read_hold_rows(tx, request, &evidence, deadline).await?;
        Ok(PublicReclaimLookup::Found(build_discovery(request, state, evidence, rows)?))
    }
}

fn ensure_hold_inventory_within_cap(rows: usize, cap: usize) -> Result<(), PackCommitError> {
    if rows > cap { Err(ledger(HOLD_INVENTORY_CAP_EXCEEDED)) } else { Ok(()) }
}

/// Prove the API's single-snapshot contract before any wrapper, attempt or hold
/// read. The first statement fixes the repeatable-read snapshot; every later
/// read in this caller-owned transaction therefore sees that same snapshot.
async fn require_stable_snapshot(
    tx: &tokio_postgres::Transaction<'_>,
    deadline: Instant,
) -> Result<(), PackCommitError> {
    bound(tx, deadline).await.map_err(discovery_bound_error)?;
    let row = timeout_at(deadline, tx.query_one(SNAPSHOT_AND_CATALOG_PROBE, &[]))
        .await
        .map_err(|_| PackCommitError::from(crate::ref_store::RefStoreError::Timeout))?
        .map_err(lookup_db_error)
        .map_err(PackCommitError::from)?;
    let isolation: String = row.get(0);
    let read_only: String = row.get(1);
    if isolation != "repeatable read" || read_only != "on" {
        return Err(PackCommitError::from(crate::ref_store::RefStoreError::Unsupported(
            STABLE_SNAPSHOT_REQUIRED,
        )));
    }
    if !row.get::<_, bool>(2)
        || !row.get::<_, bool>(3)
        || !row.get::<_, bool>(4)
        || !row.get::<_, bool>(5)
        || !row.get::<_, bool>(6)
        || !row.get::<_, bool>(7)
        || !row.get::<_, bool>(8)
    {
        return Err(PackCommitError::from(crate::ref_store::RefStoreError::Unsupported(
            RECLAIM_CATALOG_REQUIRED,
        )));
    }
    Ok(())
}

fn discovery_bound_error(error: crate::ref_store::RefStoreError) -> PackCommitError {
    match error {
        crate::ref_store::RefStoreError::Timeout => {
            PackCommitError::from(crate::ref_store::RefStoreError::Timeout)
        }
        _ => PackCommitError::from(crate::ref_store::RefStoreError::Database(
            "public reclaim discovery database error".into(),
        )),
    }
}

async fn read_hold_rows(
    tx: &tokio_postgres::Transaction<'_>,
    request: &PublicAttemptRequest,
    evidence: &PublicAttemptEvidence,
    deadline: Instant,
) -> Result<Vec<RawReclaimRow>, PackCommitError> {
    bound(tx, deadline).await.map_err(discovery_bound_error)?;
    let cap = usize::try_from(REPO_MAX_HOLDS).map_err(|_| ledger(HOLD_INVENTORY_CAP_INVALID))?;
    let limit = cap.checked_add(1).ok_or_else(|| ledger(HOLD_INVENTORY_CAP_INVALID))?;
    let limit = i64::try_from(limit).map_err(|_| ledger(HOLD_INVENTORY_CAP_INVALID))?;
    let mut private_ids = vec![evidence.current.private_id];
    if let Some(retired) = evidence.retired.as_ref() {
        private_ids.push(retired.private_id);
    }
    let rows = timeout_at(
        deadline,
        tx.query(
            SELECT_RECLAIM_HOLDS,
            &[&request.repository_id, &private_ids, &limit],
        ),
    )
    .await
    .map_err(|_| PackCommitError::from(crate::ref_store::RefStoreError::Timeout))?
    .map_err(lookup_db_error)
    .map_err(PackCommitError::from)?;
    ensure_hold_inventory_within_cap(rows.len(), cap)?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let raw: Value = row.get(0);
        out.push(
            serde_json::from_value::<RawReclaimRow>(raw)
                .map_err(|_| ledger("public reclaim discovery row shape is not recognized"))?,
        );
    }
    Ok(out)
}

fn build_discovery(
    request: &PublicAttemptRequest,
    state: OperationState,
    evidence: PublicAttemptEvidence,
    rows: Vec<RawReclaimRow>,
) -> Result<PublicReclaimDiscovery, PackCommitError> {
    let mut by_slot: BTreeMap<i16, Vec<RawReclaimRow>> = BTreeMap::new();
    for row in rows {
        let slot = if row.hold.operation_id == evidence.current.private_id {
            evidence.current.slot
        } else if let Some(retired) = evidence.retired.as_ref()
            && row.hold.operation_id == retired.private_id
        {
            retired.slot
        } else {
            return Err(ledger("public reclaim hold names an unselected attempt"));
        };
        by_slot.entry(slot).or_default().push(row);
    }

    let mut attempts = vec![evidence.current];
    if let Some(retired) = evidence.retired {
        attempts.push(retired);
    }
    attempts.sort_by_key(|attempt| attempt.slot);
    let mut slots = Vec::with_capacity(attempts.len());
    for attempt in attempts {
        let rows = by_slot.remove(&attempt.slot).unwrap_or_default();
        let holds = classify_holds(request, &attempt, rows)?;
        slots.push(PublicReclaimSlot {
            slot: attempt.slot,
            private_id: attempt.private_id,
            plan_digest: attempt.plan_digest,
            proof_digest: attempt.proof_digest,
            base_revision: attempt.base_revision,
            state: attempt.state,
            event_id: attempt.event_id,
            event_revision: attempt.event_revision,
            holds,
        });
    }
    Ok(PublicReclaimDiscovery { public_id: evidence.public_id, state, slots })
}

fn classify_holds(
    request: &PublicAttemptRequest,
    attempt: &PublicAttempt,
    rows: Vec<RawReclaimRow>,
) -> Result<Vec<PublicReclaimHold>, PackCommitError> {
    let mut holds = Vec::with_capacity(rows.len());
    let mut registrations: BTreeMap<Uuid, Vec<usize>> = BTreeMap::new();
    let mut registration_pack: BTreeMap<Uuid, Uuid> = BTreeMap::new();

    for row in rows {
        let validation = validate_hold(request, attempt, &row);
        let identity = (row.hold.request_id, row.hold.hold_id, row.hold.slot, row.hold.attempt_id);
        if let (Some(registration_id), Some(pack_id)) = (validation.registration_id, validation.pack_id) {
            registrations.entry(registration_id).or_default().push(holds.len());
            registration_pack.insert(registration_id, pack_id);
        }
        holds.push(PublicReclaimHold {
            request_id: identity.0,
            hold_id: identity.1,
            slot: identity.2,
            role: validation.role,
            disposition: validation.disposition,
            locator: validation.locator,
            backend_identity: row.hold.backend_identity,
            provider: row.hold.provider,
            storage_attempt_id: identity.3,
            content_sha256: row.hold.sha256,
            content_length: u64::try_from(row.hold.content_length).unwrap_or(0),
        });
    }

    for (registration_id, indexes) in registrations {
        let roles: BTreeSet<PublicReclaimArtifactRole> =
            indexes.iter().filter_map(|index| holds[*index].role).collect();
        let complete = indexes.len() == 2
            && roles.contains(&PublicReclaimArtifactRole::Pack)
            && roles.contains(&PublicReclaimArtifactRole::Index);
        if complete {
            let pack_id = registration_pack[&registration_id];
            for index in indexes {
                holds[index].disposition =
                    PublicReclaimHoldDisposition::Registered { registration_id, pack_id };
            }
        } else {
            for index in indexes {
                holds[index].disposition = PublicReclaimHoldDisposition::Unresolved(
                    PublicReclaimUnresolved::PairIncomplete,
                );
            }
        }
    }
    Ok(holds)
}

struct HoldValidation {
    disposition: PublicReclaimHoldDisposition,
    role: Option<PublicReclaimArtifactRole>,
    locator: Option<BlobLocator>,
    registration_id: Option<Uuid>,
    pack_id: Option<Uuid>,
}

fn validate_hold(request: &PublicAttemptRequest, attempt: &PublicAttempt, row: &RawReclaimRow) -> HoldValidation {
    let unresolved = |reason| HoldValidation {
        disposition: PublicReclaimHoldDisposition::Unresolved(reason),
        role: None,
        locator: None,
        registration_id: None,
        pack_id: None,
    };
    let hold = &row.hold;
    let Some(req) = row.request.as_ref() else {
        return unresolved(PublicReclaimUnresolved::MissingRequest);
    };
    if req.request_id != hold.request_id
        || req.repository_id != request.repository_id
        || req.tenant_id != request.admission_owner_id
        || req.owner_id != request.admission_owner_id
        || req.purpose != "ref_publication"
        || req.object_format != request.object_format.as_str()
        || req.history_incarnation != request.history_incarnation
        || req.authority_epoch != request.authority_epoch
        || req.group_epoch != request.group_epoch
        || req.operation_issuer_id != request.issuer_id
        || req.operation_lane != attempt.lane.as_str()
        || req.operation_sequence != attempt.sequence
        || req.operation_id != attempt.private_id
        || req.operation_digest != attempt.plan_digest.as_hex()
        || req.backend_identity != request.backend_identity
        || hold.repository_id != request.repository_id
        || hold.tenant_id != request.admission_owner_id
        || hold.owner_id != request.admission_owner_id
        || hold.purpose != "ref_publication"
        || hold.operation_id != attempt.private_id
        || hold.operation_digest != attempt.plan_digest.as_hex()
        || hold.backend_identity != request.backend_identity
        || hold.generation != 1
        || !matches!(hold.provider.as_str(), "s3" | "azblob")
    {
        return unresolved(PublicReclaimUnresolved::RequestScopeMismatch);
    }

    let Some(content_length) = u64::try_from(hold.content_length).ok() else {
        return unresolved(PublicReclaimUnresolved::InvalidLocator);
    };
    let locator = match BlobLocator::new(
        hold.storage_tenant_id,
        hold.authority_id,
        hold.authority_generation,
        hold.attempt_id,
        &hold.namespace,
        &hold.sha256,
        content_length,
    ) {
        Ok(locator) => locator,
        Err(_) => return unresolved(PublicReclaimUnresolved::InvalidLocator),
    };

    let receipt = match row.receipt.as_ref() {
        Some(receipt) => {
            if receipt.hold_id != hold.hold_id
                || receipt.request_id != hold.request_id
                || receipt.consume_request_id.is_nil()
                || receipt.repository_id != hold.repository_id
                || receipt.tenant_id != hold.tenant_id
                || receipt.owner_id != hold.owner_id
                || receipt.operation_id != hold.operation_id
                || receipt.operation_digest != hold.operation_digest
                || receipt.slot != hold.slot
            {
                return unresolved(PublicReclaimUnresolved::ReceiptMismatch);
            }
            Some(receipt)
        }
        None => None,
    };

    let Some(artifact) = row.artifact.as_ref() else {
        let disposition = if receipt.is_some() {
            PublicReclaimHoldDisposition::Consumed
        } else {
            PublicReclaimHoldDisposition::Unconsumed
        };
        return HoldValidation {
            disposition,
            role: None,
            locator: Some(locator),
            registration_id: None,
            pack_id: None,
        };
    };
    let Some(receipt) = receipt else {
        return unresolved(PublicReclaimUnresolved::MissingReceipt);
    };
    let role = match artifact.role.as_str() {
        "pack" => PublicReclaimArtifactRole::Pack,
        "idx" => PublicReclaimArtifactRole::Index,
        _ => return unresolved(PublicReclaimUnresolved::ArtifactMismatch),
    };
    let role_slot = match role {
        PublicReclaimArtifactRole::Pack => 0,
        PublicReclaimArtifactRole::Index => 1,
    };
    if artifact.hold_id != hold.hold_id
        || artifact.acquire_request_id != hold.request_id
        || artifact.registration_id.is_nil()
        || artifact.slot != role_slot
        || artifact.slot != i32::from(hold.slot)
        || artifact.pack_id.is_nil()
        || artifact.repository_id != hold.repository_id
        || artifact.tenant_id != hold.tenant_id
        || artifact.provider != hold.provider
        || artifact.backend_identity != hold.backend_identity
        || artifact.namespace != hold.namespace
        || artifact.sha256 != hold.sha256
        || artifact.content_length != hold.content_length
        || artifact.content_length <= 0
        || artifact.consume_request_id != receipt.consume_request_id
    {
        return unresolved(PublicReclaimUnresolved::ArtifactMismatch);
    }
    let Some(publication) = row.publication.as_ref() else {
        return unresolved(PublicReclaimUnresolved::RegistrationMismatch);
    };
    if publication.registration_id != artifact.registration_id
        || publication.pack_id != artifact.pack_id
        || publication.repository_id != hold.repository_id
        || publication.tenant_id != hold.tenant_id
        || publication.owner_id != request.admission_owner_id
        || publication.purpose != "ref_publication"
        || publication.object_format != request.object_format.as_str()
        || publication.history_incarnation != request.history_incarnation
        || publication.authority_epoch != request.authority_epoch
        || publication.group_epoch != request.group_epoch
        || publication.parent_digest != attempt.plan_digest.as_hex()
        || publication.plan_operation_id != attempt.private_id
        || publication.backend_identity != hold.backend_identity
        || publication.acquire_request_id != hold.request_id
        || publication.consume_request_id != receipt.consume_request_id
    {
        return unresolved(PublicReclaimUnresolved::RegistrationMismatch);
    }
    HoldValidation {
        disposition: PublicReclaimHoldDisposition::Registered {
            registration_id: artifact.registration_id,
            pack_id: artifact.pack_id,
        },
        role: Some(role),
        locator: Some(locator),
        registration_id: Some(artifact.registration_id),
        pack_id: Some(artifact.pack_id),
    }
}

#[derive(Clone, Deserialize)]
struct RawReclaimRow {
    hold: RawHold,
    request: Option<RawRequest>,
    receipt: Option<RawReceipt>,
    artifact: Option<RawArtifact>,
    publication: Option<RawPublication>,
}

#[derive(Clone, Deserialize)]
struct RawHold {
    request_id: Uuid,
    hold_id: Uuid,
    slot: i16,
    repository_id: Uuid,
    tenant_id: Uuid,
    owner_id: Uuid,
    purpose: String,
    operation_id: Uuid,
    operation_digest: String,
    provider: String,
    backend_identity: String,
    storage_tenant_id: Uuid,
    authority_id: Uuid,
    authority_generation: i64,
    attempt_id: Uuid,
    namespace: String,
    sha256: String,
    content_length: i64,
    generation: i32,
}

#[derive(Clone, Deserialize)]
struct RawRequest {
    request_id: Uuid,
    repository_id: Uuid,
    tenant_id: Uuid,
    owner_id: Uuid,
    purpose: String,
    object_format: String,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
    operation_issuer_id: Uuid,
    operation_lane: String,
    operation_sequence: i64,
    operation_id: Uuid,
    operation_digest: String,
    backend_identity: String,
}

#[derive(Clone, Deserialize)]
struct RawReceipt {
    hold_id: Uuid,
    request_id: Uuid,
    consume_request_id: Uuid,
    repository_id: Uuid,
    tenant_id: Uuid,
    owner_id: Uuid,
    operation_id: Uuid,
    operation_digest: String,
    slot: i16,
}

#[derive(Clone, Deserialize)]
struct RawArtifact {
    hold_id: Uuid,
    registration_id: Uuid,
    role: String,
    slot: i32,
    pack_id: Uuid,
    repository_id: Uuid,
    tenant_id: Uuid,
    provider: String,
    backend_identity: String,
    namespace: String,
    sha256: String,
    content_length: i64,
    acquire_request_id: Uuid,
    consume_request_id: Uuid,
}

#[derive(Clone, Deserialize)]
struct RawPublication {
    registration_id: Uuid,
    pack_id: Uuid,
    repository_id: Uuid,
    tenant_id: Uuid,
    owner_id: Uuid,
    purpose: String,
    object_format: String,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
    parent_digest: String,
    plan_operation_id: Uuid,
    backend_identity: String,
    acquire_request_id: Uuid,
    consume_request_id: Uuid,
}

/// Test-only, owned view of the sealed witness. It exposes no mutable reference,
/// locator/write capability or constructor path into the production type.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublicReclaimTestView {
    pub public_id: Uuid,
    pub state: OperationState,
    pub slots: Vec<PublicReclaimSlotTestView>,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublicReclaimSlotTestView {
    pub slot: i16,
    pub private_id: Uuid,
    pub plan_digest: RequestDigest,
    pub proof_digest: RequestDigest,
    pub base_revision: i64,
    pub state: OperationState,
    pub event_id: Option<Uuid>,
    pub event_revision: Option<i64>,
    pub holds: Vec<PublicReclaimHoldTestView>,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublicReclaimHoldTestView {
    pub request_id: Uuid,
    pub hold_id: Uuid,
    pub slot: i16,
    pub role: Option<PublicReclaimArtifactRole>,
    pub disposition: PublicReclaimHoldDisposition,
    pub locator_path: Option<String>,
    pub backend_identity: String,
    pub provider: String,
    pub storage_attempt_id: Uuid,
    pub content_sha256: String,
    pub content_length: u64,
}

#[cfg(test)]
impl PublicReclaimDiscovery {
    pub(crate) fn test_view(&self) -> PublicReclaimTestView {
        PublicReclaimTestView {
            public_id: self.public_id,
            state: self.state,
            slots: self
                .slots
                .iter()
                .map(|slot| PublicReclaimSlotTestView {
                    slot: slot.slot,
                    private_id: slot.private_id,
                    plan_digest: slot.plan_digest,
                    proof_digest: slot.proof_digest,
                    base_revision: slot.base_revision,
                    state: slot.state,
                    event_id: slot.event_id,
                    event_revision: slot.event_revision,
                    holds: slot
                        .holds
                        .iter()
                        .map(|hold| PublicReclaimHoldTestView {
                            request_id: hold.request_id,
                            hold_id: hold.hold_id,
                            slot: hold.slot,
                            role: hold.role,
                            disposition: hold.disposition,
                            locator_path: hold.locator.as_ref().map(BlobLocator::path),
                            backend_identity: hold.backend_identity.clone(),
                            provider: hold.provider.clone(),
                            storage_attempt_id: hold.storage_attempt_id,
                            content_sha256: hold.content_sha256.clone(),
                            content_length: hold.content_length,
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

/// Exact test-only projection of the fixed snapshot-mode refusal.
#[cfg(test)]
pub(crate) fn is_stable_snapshot_refusal(error: &PackCommitError) -> bool {
    match error {
        PackCommitError::RefStore(crate::ref_store::RefStoreError::Unsupported(detail)) => {
            *detail == STABLE_SNAPSHOT_REQUIRED
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ref_store::core::artifact_hold::REPO_MAX_HOLDS;
    use crate::ref_store::{CommitMode, GitObjectFormat, IssuerLane, RequestDigest};

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn request() -> PublicAttemptRequest {
        PublicAttemptRequest {
            repository_id: id(1),
            admission_owner_id: id(2),
            issuer_id: id(3),
            public_id: id(4),
            wire_digest: RequestDigest::from_bytes([0x11; 32]),
            request_mode: CommitMode::Atomic,
            backend_identity: "a".repeat(64),
            object_format: GitObjectFormat::Sha1,
            history_incarnation: id(5),
            authority_epoch: 7,
            group_epoch: 8,
            restore_incarnation: id(6),
        }
    }

    fn lane() -> IssuerLane {
        IssuerLane::new("public-reclaim").unwrap()
    }

    fn attempt(slot: i16, private_id: Uuid, plan: [u8; 32], sequence: i64, state: OperationState) -> PublicAttempt {
        PublicAttempt {
            slot,
            private_id,
            plan_digest: RequestDigest::from_bytes(plan),
            proof_digest: RequestDigest::from_bytes([0x22; 32]),
            base_revision: 9,
            lane: lane(),
            sequence,
            state,
            event_id: None,
            event_revision: None,
        }
    }

    fn evidence() -> PublicAttemptEvidence {
        PublicAttemptEvidence {
            public_id: id(4),
            current: attempt(1, id(11), [0x31; 32], 2, OperationState::Committed),
            retired: Some(attempt(0, id(10), [0x21; 32], 1, OperationState::Rejected)),
        }
    }

    fn registered_row(
        request: &PublicAttemptRequest,
        attempt: &PublicAttempt,
        hold_id: u128,
        request_id: u128,
        registration_id: u128,
        pack_id: u128,
        role: &str,
        slot: i16,
        sha256: &str,
    ) -> RawReclaimRow {
        let row_role_slot = if role == "pack" { 0 } else { 1 };
        RawReclaimRow {
            hold: RawHold {
                request_id: id(request_id),
                hold_id: id(hold_id),
                slot,
                repository_id: request.repository_id,
                tenant_id: request.admission_owner_id,
                owner_id: request.admission_owner_id,
                purpose: "ref_publication".into(),
                operation_id: attempt.private_id,
                operation_digest: attempt.plan_digest.as_hex(),
                provider: "s3".into(),
                backend_identity: request.backend_identity.clone(),
                storage_tenant_id: request.admission_owner_id,
                authority_id: request.repository_id,
                authority_generation: 1,
                attempt_id: id(1000 + slot as u128 + registration_id),
                namespace: "git-pack".into(),
                sha256: sha256.into(),
                content_length: 64,
                generation: 1,
            },
            request: Some(RawRequest {
                request_id: id(request_id),
                repository_id: request.repository_id,
                tenant_id: request.admission_owner_id,
                owner_id: request.admission_owner_id,
                purpose: "ref_publication".into(),
                object_format: request.object_format.as_str().into(),
                history_incarnation: request.history_incarnation,
                authority_epoch: request.authority_epoch,
                group_epoch: request.group_epoch,
                operation_issuer_id: request.issuer_id,
                operation_lane: attempt.lane.as_str().into(),
                operation_sequence: attempt.sequence,
                operation_id: attempt.private_id,
                operation_digest: attempt.plan_digest.as_hex(),
                backend_identity: request.backend_identity.clone(),
            }),
            receipt: Some(RawReceipt {
                hold_id: id(hold_id),
                request_id: id(request_id),
                consume_request_id: id(2000 + request_id),
                repository_id: request.repository_id,
                tenant_id: request.admission_owner_id,
                owner_id: request.admission_owner_id,
                operation_id: attempt.private_id,
                operation_digest: attempt.plan_digest.as_hex(),
                slot,
            }),
            artifact: Some(RawArtifact {
                hold_id: id(hold_id),
                registration_id: id(registration_id),
                role: role.into(),
                slot: row_role_slot,
                pack_id: id(pack_id),
                repository_id: request.repository_id,
                tenant_id: request.admission_owner_id,
                provider: "s3".into(),
                backend_identity: request.backend_identity.clone(),
                namespace: "git-pack".into(),
                sha256: sha256.into(),
                content_length: 64,
                acquire_request_id: id(request_id),
                consume_request_id: id(2000 + request_id),
            }),
            publication: Some(RawPublication {
                registration_id: id(registration_id),
                pack_id: id(pack_id),
                repository_id: request.repository_id,
                tenant_id: request.admission_owner_id,
                owner_id: request.admission_owner_id,
                purpose: "ref_publication".into(),
                object_format: request.object_format.as_str().into(),
                history_incarnation: request.history_incarnation,
                authority_epoch: request.authority_epoch,
                group_epoch: request.group_epoch,
                parent_digest: attempt.plan_digest.as_hex(),
                plan_operation_id: attempt.private_id,
                backend_identity: request.backend_identity.clone(),
                acquire_request_id: id(request_id),
                consume_request_id: id(2000 + request_id),
            }),
        }
    }

    fn project_lookup(
        request: &PublicAttemptRequest,
        lookup: PublicAttemptLookup,
        rows: Vec<RawReclaimRow>,
    ) -> Result<PublicReclaimLookup, PackCommitError> {
        let (state, evidence) = match lookup {
            PublicAttemptLookup::Unknown => return Ok(PublicReclaimLookup::Unknown),
            PublicAttemptLookup::PrivateIdentifier => return Ok(PublicReclaimLookup::PrivateIdentifier),
            PublicAttemptLookup::LegacyPath => return Ok(PublicReclaimLookup::LegacyPath),
            PublicAttemptLookup::Pending(evidence) => (OperationState::Pending, evidence),
            PublicAttemptLookup::Committed(evidence) => (OperationState::Committed, evidence),
            PublicAttemptLookup::Rejected(evidence) => (OperationState::Rejected, evidence),
            PublicAttemptLookup::Cancelled(evidence) => (OperationState::Cancelled, evidence),
        };
        Ok(PublicReclaimLookup::Found(build_discovery(request, state, evidence, rows)?))
    }

    fn registered_pair(
        request: &PublicAttemptRequest,
        attempt: &PublicAttempt,
        base: u128,
        sha256: &str,
    ) -> Vec<RawReclaimRow> {
        vec![
            registered_row(request, attempt, base, base + 1, base + 2, base + 3, "pack", 0, sha256),
            registered_row(
                request,
                attempt,
                base + 4,
                base + 1,
                base + 2,
                base + 3,
                "idx",
                1,
                sha256,
            ),
        ]
    }

    #[test]
    fn same_bytes_in_two_slots_are_discovered_independently() {
        let request = request();
        let evidence = evidence();
        let retired = evidence.retired.as_ref().unwrap();
        let current = &evidence.current;
        let mut rows = registered_pair(&request, retired, 100, &"b".repeat(64));
        rows.extend(registered_pair(&request, current, 200, &"b".repeat(64)));
        let discovery =
            build_discovery(&request, OperationState::Committed, evidence, rows).expect("valid discovery");
        assert_eq!(discovery.slots.len(), 2);
        assert_eq!(discovery.slots[0].slot, 0);
        assert_eq!(discovery.slots[1].slot, 1);
        assert_eq!(discovery.slots[0].holds.len(), 2);
        assert_eq!(discovery.slots[1].holds.len(), 2);
        for slot in &discovery.slots {
            for hold in &slot.holds {
                assert!(matches!(hold.disposition, PublicReclaimHoldDisposition::Registered { .. }));
                assert_eq!(hold.content_sha256, "b".repeat(64));
                assert_eq!(hold.backend_identity, request.backend_identity);
                assert_eq!(hold.provider, "s3");
            }
        }
        assert_ne!(
            discovery.slots[0].holds[0].locator.as_ref().unwrap().path(),
            discovery.slots[1].holds[0].locator.as_ref().unwrap().path()
        );
    }

    #[test]
    fn unconsumed_and_consumed_are_distinct_from_registered() {
        let request = request();
        let evidence = evidence();
        let retired = evidence.retired.as_ref().unwrap();
        let mut rows = registered_pair(&request, retired, 100, &"b".repeat(64));
        rows[0].receipt = None;
        rows[0].artifact = None;
        rows[1].artifact = None;
        let discovery =
            build_discovery(&request, OperationState::Committed, evidence, rows).expect("valid discovery");
        assert_eq!(discovery.slots[0].holds[0].disposition, PublicReclaimHoldDisposition::Unconsumed);
        assert_eq!(discovery.slots[0].holds[1].disposition, PublicReclaimHoldDisposition::Consumed);
    }

    #[test]
    fn partial_registration_pair_is_unresolved_not_certified() {
        let request = request();
        let evidence = evidence();
        let retired = evidence.retired.as_ref().unwrap();
        let mut rows = registered_pair(&request, retired, 100, &"b".repeat(64));
        rows.pop();
        let discovery =
            build_discovery(&request, OperationState::Committed, evidence, rows).expect("valid discovery");
        assert_eq!(
            discovery.slots[0].holds[0].disposition,
            PublicReclaimHoldDisposition::Unresolved(PublicReclaimUnresolved::PairIncomplete)
        );
    }

    #[test]
    fn wrong_scope_hold_is_unresolved_not_certified() {
        let request = request();
        let evidence = evidence();
        let retired = evidence.retired.as_ref().unwrap();
        let mut rows = registered_pair(&request, retired, 100, &"b".repeat(64));
        rows[0].request.as_mut().unwrap().operation_digest = "f".repeat(64);
        let discovery =
            build_discovery(&request, OperationState::Committed, evidence, rows).expect("valid discovery");
        assert_eq!(
            discovery.slots[0].holds[0].disposition,
            PublicReclaimHoldDisposition::Unresolved(PublicReclaimUnresolved::RequestScopeMismatch)
        );
    }

    #[test]
    fn backend_mismatch_is_unresolved_not_omitted() {
        let request = request();
        let evidence = evidence();
        let retired = evidence.retired.as_ref().unwrap();
        let mut rows = registered_pair(&request, retired, 100, &"b".repeat(64));
        rows[0].hold.backend_identity = "c".repeat(64);
        let discovery =
            build_discovery(&request, OperationState::Committed, evidence, rows).expect("valid discovery");
        assert_eq!(discovery.slots[0].holds.len(), 2, "a mismatched backend hold must not disappear");
        assert_eq!(
            discovery.slots[0].holds[0].disposition,
            PublicReclaimHoldDisposition::Unresolved(PublicReclaimUnresolved::RequestScopeMismatch)
        );
    }

    #[test]
    fn hold_inventory_cap_accepts_exactly_cap_and_refuses_cap_plus_one() {
        let cap = usize::try_from(REPO_MAX_HOLDS).expect("hold cap fits usize");
        assert!(ensure_hold_inventory_within_cap(cap, cap).is_ok());
        assert!(ensure_hold_inventory_within_cap(cap.saturating_sub(1), cap).is_ok());
        match ensure_hold_inventory_within_cap(cap + 1, cap) {
            Err(PackCommitError::Rejected(rejection)) => {
                assert_eq!(rejection.detail, HOLD_INVENTORY_CAP_EXCEEDED);
            }
            other => panic!("expected fixed cap refusal, got {other:?}"),
        }
    }

    #[test]
    fn zero_actual_holds_still_reports_both_attempt_slots() {
        let request = request();
        let discovery =
            build_discovery(&request, OperationState::Committed, evidence(), Vec::new()).expect("valid discovery");
        assert_eq!(discovery.slots.len(), 2);
        assert!(discovery.slots.iter().all(|slot| slot.holds.is_empty()));
    }

    #[test]
    fn pending_and_legacy_markers_are_distinct_from_discovery() {
        let request = request();
        let pending = PublicAttemptLookup::Pending(evidence());
        let projected = project_lookup(&request, pending, Vec::new()).expect("valid pending discovery");
        match projected {
            PublicReclaimLookup::Found(found) => assert_eq!(found.state, OperationState::Pending),
            other => panic!("expected pending discovery, got {other:?}"),
        }
        assert_eq!(
            project_lookup(&request, PublicAttemptLookup::LegacyPath, Vec::new()).expect("legacy marker"),
            PublicReclaimLookup::LegacyPath
        );
    }
}
