//! Concrete metadata-only decision API (real `CommitRefsRequest`, no fake pack plan).
//!
//! The metadata core publishes refs without native pack facts. This module therefore defines its own
//! opaque [`MetadataSelectedDecision`] derived from the **actual** [`CommitRefsRequest`] digest and the
//! captured PG ref map. It never claims a native closure proof, never accepts a caller boolean and is
//! only usable under the `metadata_only` gate.
//!
//! Policy is deliberately fail-closed: a branch rule that needs native facts (approvals, required
//! checks, fast-forward / force-push ancestry) or any LFS lock row rejects, because metadata-only
//! cannot verify those facts. Plain CAS / prefix / HEAD metadata updates work and consume the decision
//! in the same transaction.
//!
//! Integration hook: `select_and_install_metadata` runs in the caller's short metadata transaction
//! after source/repository/gate locks (or it takes them itself), and
//! `authorized_metadata_final_check` runs inside the final commit transaction before the metadata ref
//! writes. No `PackClosureProof` is involved.
use super::capability::DecisionCapability;
use super::contract::{
    DecisionError, DecisionKind, DecisionState, DenialCode, MAX_DECISION_REFS, MAX_DECISION_WINDOW_MILLIS,
    PublicationAction,
};
use super::digest;
use super::policy::{self, RepoPolicyFacts};
use super::sql_locks;
use super::usage;
use crate::db::Identity;
use crate::members::models::Role;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::command::CommitRefsRequest;
use crate::ref_store::core::types::{GitOid, RefUpdate};
use crate::token_scopes::RepoAction;
use std::collections::BTreeMap;
use tokio::time::Instant;
use tokio_postgres::Transaction;
use uuid::Uuid;

const DOMAIN_METADATA_FACTS: &str = "publication-decision-metadata-facts-v1";
const DOMAIN_METADATA_SELECTION: &str = "publication-decision-metadata-selection-v1";

/// Private, opaque metadata selection. No public constructor, no serde, no `Clone`.
pub(crate) struct MetadataSelectedDecision {
    capability: DecisionCapability,
    selection_digest: RequestDigest,
    accepted: Vec<RefUpdate>,
    verdict_rows: Vec<(String, String)>,
    captured: BTreeMap<String, String>,
}

impl MetadataSelectedDecision {
    pub(super) fn ensure_actor(&self, actor: &Identity) -> Result<(), DenialCode> {
        self.capability.ensure_actor(actor)
    }

    pub(crate) fn decision_id(&self) -> Uuid {
        self.capability.decision_id()
    }
    pub(crate) fn selection_digest(&self) -> &RequestDigest {
        &self.selection_digest
    }
    pub(crate) fn accepted(&self) -> &[RefUpdate] {
        &self.accepted
    }
    pub(crate) fn verdict_rows(&self) -> &[(String, String)] {
        &self.verdict_rows
    }
    pub(crate) fn accepted_is_empty(&self) -> bool {
        self.accepted.is_empty()
    }
    pub(crate) fn captured(&self) -> &BTreeMap<String, String> {
        &self.captured
    }
    pub(crate) fn action(&self) -> &PublicationAction {
        self.capability.action()
    }
}

impl std::fmt::Debug for MetadataSelectedDecision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MetadataSelectedDecision")
            .field("decision_id", &self.decision_id())
            .field("selection_digest", &self.selection_digest)
            .field("accepted", &self.accepted.len())
            .finish_non_exhaustive()
    }
}

pub(super) struct MetadataAuthority {
    pub(super) owner_id: Uuid,
    pub(super) object_format: String,
    pub(super) tenant_id: Uuid,
    pub(super) history_incarnation: Uuid,
    pub(super) authority_epoch: i64,
    pub(super) group_epoch: i64,
    pub(super) head_ref: String,
    pub(super) revision: i64,
    pub(super) token_expires_millis: Option<i64>,
    pub(super) authz_digest: RequestDigest,
    pub(super) gate_digest: RequestDigest,
    pub(super) token_scope_version: i64,
}

fn metadata_facts_digest(request: &CommitRefsRequest, captured: &BTreeMap<String, String>) -> RequestDigest {
    let mut fields: Vec<Vec<u8>> = vec![
        request.digest().as_bytes().to_vec(),
        b"metadata-only".to_vec(),
        (captured.len() as u64).to_be_bytes().to_vec(),
    ];
    for (name, oid) in captured {
        fields.push(name.as_bytes().to_vec());
        fields.push(oid.as_bytes().to_vec());
    }
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RequestDigest::of(DOMAIN_METADATA_FACTS, &parts)
}

fn captured_digest(captured: &BTreeMap<String, String>) -> RequestDigest {
    let mut fields: Vec<Vec<u8>> = vec![(captured.len() as u64).to_be_bytes().to_vec()];
    for (name, oid) in captured {
        fields.push(name.as_bytes().to_vec());
        fields.push(oid.as_bytes().to_vec());
    }
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RequestDigest::of("publication-decision-metadata-captured-v1", &parts)
}

pub(super) fn metadata_selection_digest(
    request: &CommitRefsRequest,
    captured: &BTreeMap<String, String>,
    rows: &[(String, String)],
) -> RequestDigest {
    let mut fields: Vec<Vec<u8>> = vec![
        request.digest().as_bytes().to_vec(),
        captured_digest(captured).as_bytes().to_vec(),
        (rows.len() as u64).to_be_bytes().to_vec(),
    ];
    for (name, canonical) in rows {
        fields.push(name.as_bytes().to_vec());
        fields.push(canonical.as_bytes().to_vec());
    }
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RequestDigest::of(DOMAIN_METADATA_SELECTION, &parts)
}

/// Real metadata authorization: exact live token, unserved repository, current RBAC and ContentsWrite.
pub(super) async fn metadata_authority(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    actor: &Identity,
) -> Result<MetadataAuthority, DecisionError> {
    let user = tx
        .query_opt("SELECT id FROM users WHERE id=$1 FOR SHARE", &[&actor.id])
        .await
        .map_err(sql_locks::sql_error)?
        .ok_or(DecisionError::Denied(DenialCode::TokenInvalid))?;
    let _: Uuid = user.get(0);
    let token = tx
        .query_opt(
            "SELECT t.read_only,t.kind,(t.expires_at IS NULL OR t.expires_at > clock_timestamp()),
                    (extract(epoch FROM t.expires_at)*1000)::bigint,t.is_restricted,t.scope_version
             FROM tokens t WHERE t.id=$1 AND t.user_id=$2 AND t.digest=$3 AND NOT t.revoked",
            &[&actor.token_id, &actor.id, &actor.token_digest],
        )
        .await
        .map_err(sql_locks::sql_error)?
        .ok_or(DecisionError::Denied(DenialCode::TokenInvalid))?;
    let read_only: bool = token.get(0);
    let kind: String = token.get(1);
    let live: bool = token.get(2);
    let token_expires_millis: Option<i64> = token.get(3);
    let restricted: bool = token.get(4);
    let scope_version: i64 = token.get(5);
    if kind != "api" {
        return Err(DecisionError::Denied(DenialCode::BrowserTokenUnsupported));
    }
    if !live {
        return Err(DecisionError::Denied(DenialCode::TokenExpired));
    }
    if read_only {
        return Err(DecisionError::Denied(DenialCode::TokenReadOnly));
    }
    // One shared strict repository predicate: the unserved gitfs fixture lane
    // or the ready `pg_refstore` serving lane with its exact durable binding.
    let locked = super::super::serving_scope::LockedScope::lock(tx, repository_id, false)
        .await
        .map_err(|_| DecisionError::Unverifiable("live repository authority resolution failed"))?
        .ok_or(DecisionError::Denied(DenialCode::RepositoryNotFound))?;
    let owner_id: Uuid = locked.owner_id();
    let lane =
        locked.require_fresh_core_lane(owner_id).map_err(|_| DecisionError::Denied(DenialCode::RepositoryUnserved))?;
    if lane.is_serving() {
        // Metadata-only receipts attest no bytes. A serving ref must instead
        // pass the pack/native proof path, even while the new repository is empty.
        return Err(DecisionError::Denied(DenialCode::UnsupportedAction));
    }
    let state: String = locked.state().to_owned();
    let backend: String = locked.storage_backend().to_owned();
    let transition: String = locked.transition_state().to_owned();
    let format: String = locked.object_format().as_str().to_owned();
    let pando: bool = locked.pando_authority();
    let storage_generation: i64 = locked.storage_generation();
    let resolved = crate::members::rbac::resolve_effective_role(tx, repository_id, owner_id, actor.id)
        .await
        .map_err(|_| DecisionError::Unverifiable("live RBAC resolution failed"))?;
    let role = resolved.map(|(effective, _, _)| effective).ok_or(DecisionError::Denied(DenialCode::RoleDenied))?;
    if role < Role::Write {
        return Err(DecisionError::Denied(DenialCode::RoleDenied));
    }
    crate::token_scopes::authorize_repository_late(
        tx,
        actor.token_id,
        actor.id,
        repository_id,
        RepoAction::ContentsWrite,
        false,
    )
    .await
    .map_err(|_| DecisionError::Denied(DenialCode::ScopeDenied))?;
    let protocol = sql_locks::protocol_state(tx, repository_id).await?;
    // The durable serving binding (pg_refstore lane) must be exactly this
    // protocol/gate realm; the gitfs fixture lane must carry none.
    locked
        .require_fresh_core(&super::super::serving_scope::CoreRealm::new(
            protocol.tenant_id,
            locked.object_format(),
            protocol.history_incarnation,
            protocol.authority_epoch,
            protocol.group_epoch,
        ))
        .map_err(|_| DecisionError::Denied(DenialCode::RepositoryUnserved))?;
    let grants = tx.query("SELECT action FROM token_repository_scopes WHERE token_id=$1 AND repository_id=$2 ORDER BY action LIMIT 65",
        &[&actor.token_id, &repository_id]).await.map_err(sql_locks::sql_error)?;
    if grants.len() > 64 {
        return Err(DecisionError::Unverifiable("token scope bound exceeded"));
    }
    let grants = grants.into_iter().map(|row| row.get::<_, String>(0)).collect::<Vec<_>>();
    let grant_bytes = serde_json::to_vec(&grants).map_err(|_| DecisionError::Ledger("token scope encoding failed"))?;
    let authz = digest::authz_digest(&digest::AuthzFacts {
        repository_id,
        tenant_id: owner_id,
        owner_id,
        actor_id: actor.id,
        token_id: actor.token_id,
        token_kind: &kind,
        token_read_only: read_only,
        token_restricted: restricted,
        token_scope_version: scope_version,
        token_expires_millis,
        role: role.as_str(),
        repository_state: &state,
        storage_backend: &backend,
        transition_state: &transition,
        pando_authority: pando,
        storage_generation,
        actions: &[RepoAction::ContentsWrite.as_str()],
        action: "push",
    });
    let authz_digest = RequestDigest::of("metadata-live-authz-v1", &[authz.as_bytes(), &grant_bytes]);
    let gate = crate::ref_store::core::sql::gate_row(tx, repository_id, false)
        .await?
        .ok_or(DecisionError::Denied(DenialCode::GateNotFound))?;
    Ok(MetadataAuthority {
        owner_id,
        object_format: format,
        tenant_id: protocol.tenant_id,
        history_incarnation: protocol.history_incarnation,
        authority_epoch: protocol.authority_epoch,
        group_epoch: protocol.group_epoch,
        head_ref: protocol.head_ref,
        revision: protocol.revision,
        token_expires_millis,
        authz_digest,
        gate_digest: *gate.digest(),
        token_scope_version: scope_version,
    })
}

pub(super) async fn capture_metadata_refs(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    format: crate::ref_store::core::types::GitObjectFormat,
) -> Result<BTreeMap<String, String>, DecisionError> {
    let rows = tx
        .query(
            "SELECT ref_name,oid FROM ref_store_core_refs WHERE repository_id=$1 ORDER BY ref_name LIMIT 4097",
            &[&repository_id],
        )
        .await
        .map_err(sql_locks::sql_error)?;
    if rows.len() > 4096 {
        return Err(DecisionError::Unverifiable("metadata ref capture exceeds fixed bound"));
    }
    let mut map = BTreeMap::new();
    for row in rows {
        let name: String = row.get(0);
        let oid: String = row.get(1);
        GitOid::parse(format, &oid).map_err(|_| DecisionError::Ledger("stored core ref object id is not canonical"))?;
        map.insert(name, oid);
    }
    Ok(map)
}

/// Metadata-only policy pass. Deterministic CAS / prefix / HEAD work; anything that needs native facts
/// fails that ref closed as policy.
pub(super) fn metadata_rows(
    request: &CommitRefsRequest,
    captured: &BTreeMap<String, String>,
    policy: &RepoPolicyFacts,
    head_ref: &str,
) -> (Vec<(String, String)>, Vec<RefUpdate>) {
    let head_keep = matches!(request.head(), crate::ref_store::core::types::HeadUpdate::Keep);
    let mut final_map = captured.clone();
    let mut rows = Vec::with_capacity(request.refs().len());
    let mut candidates: Vec<RefUpdate> = Vec::new();
    let mut rejected = false;
    for update in request.refs() {
        let name = update.name().as_str();
        let actual = captured.get(name);
        let satisfied = match update.precondition() {
            crate::ref_store::core::types::RefPrecondition::Absent => actual.is_none(),
            crate::ref_store::core::types::RefPrecondition::Present(oid) => {
                actual.map(String::as_str) == Some(oid.as_hex().as_str())
            }
        };
        if !satisfied {
            rows.push((name.to_owned(), "rejected:cas:old-oid-mismatch".to_owned()));
            rejected = true;
            continue;
        }
        let deleting = update.target().oid().is_none();
        let rule =
            if update.name().is_branch() { policy.rules.iter().find(|rule| rule.branch_ref == name) } else { None };
        let mut reason: Option<&'static str> = if deleting && actual.is_none() {
            Some("rejected:cas:delete-without-old")
        } else if deleting && final_map.keys().any(|other| other.starts_with(&format!("{name}/"))) {
            Some("rejected:prefix_conflict:surviving-descendant")
        } else {
            None
        };
        if let Some(rule) = rule {
            if deleting && rule.prevent_deletion {
                reason = Some("rejected:policy:protected_branch");
            } else if !deleting
                && (rule.required_approvals > 0
                    || !rule.required_checks.is_empty()
                    || rule.require_fast_forward
                    || rule.prevent_force_push)
            {
                reason = Some("rejected:policy:policy_denied");
            }
        }
        if reason.is_none() && !policy.lfs_locks.is_empty() {
            // Metadata-only cannot compute the changed-path set, so an active LFS lock set is unknown.
            reason = Some("rejected:policy:policy_denied");
        }
        if reason.is_none() && head_keep && name == head_ref && deleting {
            reason = Some("rejected:head_dependency:deletes-kept-head");
        }
        if reason.is_none() && !deleting {
            let conflict = final_map.keys().any(|other| {
                other != name && (other.starts_with(&format!("{name}/")) || name.starts_with(&format!("{other}/")))
            });
            if conflict {
                reason = Some("rejected:prefix_conflict:final-ref-name-conflict");
            }
        }
        if let Some(reason) = reason {
            rows.push((name.to_owned(), reason.to_owned()));
            rejected = true;
            continue;
        }
        match update.target() {
            crate::ref_store::core::types::RefTarget::Delete => {
                final_map.remove(name);
            }
            crate::ref_store::core::types::RefTarget::Oid(oid) => {
                final_map.insert(name.to_owned(), oid.as_hex());
            }
        }
        candidates.push(update.clone());
        rows.push((name.to_owned(), "accepted".to_owned()));
    }
    // A retarget must land on a live resulting branch; otherwise the whole atomic metadata batch is
    // refused rather than leaving a dangling HEAD.
    let mut head_blocked = false;
    if let crate::ref_store::core::types::HeadUpdate::Retarget(target) = request.head()
        && !final_map.contains_key(target.as_str())
    {
        head_blocked = true;
    }
    let reject_all = head_blocked || (request.mode() == crate::ref_store::CommitMode::Atomic && rejected);
    if reject_all {
        for (_, verdict) in &mut rows {
            if verdict == "accepted" {
                *verdict = if head_blocked {
                    "rejected:head_dependency:head-target-missing"
                } else {
                    "rejected:policy:atomic-batch-rejected"
                }
                .to_owned();
            }
        }
    }
    let accepted = if reject_all { Vec::new() } else { candidates };
    (rows, accepted)
}

pub(super) fn metadata_dependencies(
    request: &CommitRefsRequest,
    actor: &Identity,
    authority: &MetadataAuthority,
    policy: &RepoPolicyFacts,
) -> Vec<super::contract::DependencyObservation> {
    use super::codes::ScopeKind;
    use super::contract::DependencyObservation;
    let mut values = vec![
        DependencyObservation {
            kind: ScopeKind::Token,
            id: actor.token_id,
            version: authority.token_scope_version,
            digest: authority.authz_digest,
        },
        DependencyObservation {
            kind: ScopeKind::RepoAccess,
            id: request.repository_id(),
            version: 0,
            digest: authority.authz_digest,
        },
        DependencyObservation {
            kind: ScopeKind::RepoLifecycle,
            id: request.repository_id(),
            version: 0,
            digest: authority.gate_digest,
        },
        DependencyObservation {
            kind: ScopeKind::Authority,
            id: request.repository_id(),
            version: 0,
            digest: authority.gate_digest,
        },
        DependencyObservation {
            kind: ScopeKind::BranchRules,
            id: request.repository_id(),
            version: policy.rules.iter().map(|rule| rule.version).max().unwrap_or(0),
            digest: digest::rules_digest(&policy.rules),
        },
        DependencyObservation {
            kind: ScopeKind::LfsLocks,
            id: request.repository_id(),
            version: 0,
            digest: digest::lfs_locks_digest(&policy.lfs_locks),
        },
    ];
    values.sort_by_key(|value| (value.kind.as_str(), value.id));
    values
}

fn metadata_kind(request: &CommitRefsRequest) -> DecisionKind {
    match request.mode() {
        crate::ref_store::CommitMode::Atomic => DecisionKind::Atomic,
        crate::ref_store::CommitMode::AcceptedSubset => DecisionKind::AcceptedSubset,
    }
}

fn metadata_not_after(now: i64, token_expiry: Option<i64>) -> Result<i64, DecisionError> {
    let mut not_after =
        now.checked_add(MAX_DECISION_WINDOW_MILLIS).ok_or(DecisionError::Ledger("decision not_after overflows i64"))?;
    if let Some(expiry) = token_expiry {
        not_after = not_after.min(expiry);
    }
    if not_after <= now {
        return Err(DecisionError::Denied(DenialCode::TokenExpired));
    }
    Ok(not_after)
}

#[path = "metadata_install.rs"]
mod install;
pub(crate) use install::select_and_install_metadata;
