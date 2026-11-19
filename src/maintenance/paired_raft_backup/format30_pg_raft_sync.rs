//! Exact PostgreSQL -> live 3-voter mTLS Raft replication of one repository's gate and refs (#153).
//!
//! The delta is computed from the Raft state machine itself, never from a caller-supplied "expected"
//! set: created refs commit `Absent -> Oid`, changed refs commit `Present(old) -> Oid` and refs that
//! vanished from PostgreSQL commit `Present(old) -> Delete`. The gate row is read directly so even a
//! metadata-only or delete push that legitimately holds zero active packs replicates cleanly.

use std::collections::BTreeMap;

use tokio_postgres::GenericClient;
use uuid::Uuid;

use crate::ref_store::core::state_machine::{
    ApplyResponse, CommitRefsCommand, InitializeGateCommand, RefCasCommand, RepositoryLane, SmPackMode,
    WireCommitRefsRequest, WireGateInit,
};
use crate::ref_store::{
    CommitMode, CommitRefsRequest, CoreGateInit, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, RefName,
    RefPrecondition, RefTarget, RefUpdate,
};

use super::freeze_drain::RepoBackupRegistrationSpec;
use super::mtls_raft::MtlsLiveRaftBackend;
use super::pg_cutpoint::pg_err;
use super::quorum_wal::DurableRaftBackend;
use super::types::PairedBackupError;

const GATE: &str = "SELECT g.tenant_id, g.object_format, g.history_incarnation, g.authority_epoch, \
     g.group_epoch, g.head_ref, s.backend_identity FROM public.ref_store_core_gates g \
     JOIN public.ref_store_serving_repositories s ON s.repository_id = g.repository_id \
     WHERE g.repository_id = $1 AND s.state = 'ready'";
const REFS: &str = "SELECT ref_name, oid FROM public.ref_store_core_refs WHERE repository_id = $1 ORDER BY ref_name";
const FLOOR: &str =
    "SELECT version FROM public.ref_store_decision_scopes WHERE scope_kind = 'repo_access' AND scope_id = $1";

fn state_machine_err(error: impl std::fmt::Display) -> PairedBackupError {
    PairedBackupError::StateMachine(error.to_string())
}

fn oid(format: GitObjectFormat, hex: &str) -> Result<GitOid, PairedBackupError> {
    GitOid::parse(format, hex).map_err(state_machine_err)
}

fn ref_update(name: &str, precondition: RefPrecondition, target: RefTarget) -> Result<RefUpdate, PairedBackupError> {
    Ok(RefUpdate::new(RefName::new(name).map_err(state_machine_err)?, precondition, target))
}

/// PG-authoritative `repo_access` scope version used as the Raft `authz_floor` for replicated plans.
pub(super) async fn read_pg_repo_access_floor(
    client: &(impl GenericClient + Sync),
    repository_id: Uuid,
) -> Result<i64, PairedBackupError> {
    let row = client.query_opt(FLOOR, &[&repository_id]).await.map_err(pg_err)?;
    Ok(row.map(|r| r.get(0)).unwrap_or(1))
}

/// Read the gate row, serving backend identity and the full ref map for one repository.
pub(super) async fn read_pg_repo_state(
    client: &(impl GenericClient + Sync),
    repository_id: Uuid,
) -> Result<(RepoBackupRegistrationSpec, String, BTreeMap<String, String>), PairedBackupError> {
    let auth = client
        .query_one("SELECT authority_id, generation FROM public.pando_storage_authorities WHERE singleton = true", &[])
        .await
        .map_err(pg_err)?;
    let row = client
        .query_opt(GATE, &[&repository_id])
        .await
        .map_err(pg_err)?
        .ok_or(PairedBackupError::InvalidArgument("repository is not a ready serving repository closure"))?;
    let format: String = row.get(1);
    let object_format = match format.as_str() {
        "sha1" => GitObjectFormat::Sha1,
        "sha256" => GitObjectFormat::Sha256,
        other => return Err(PairedBackupError::Postgres(format!("unsupported format {other}"))),
    };
    let tenant_id: Uuid = row.get(0);
    let spec = RepoBackupRegistrationSpec {
        repository_id,
        tenant_id,
        owner_id: tenant_id,
        object_format,
        history_incarnation: row.get(2),
        authority_epoch: row.get(3),
        group_epoch: row.get(4),
        authority_id: auth.get(0),
        authority_generation: auth.get(1),
        backend_identity: row.get(6),
        expected_packs: Vec::new(),
    };
    let refs = client
        .query(REFS, &[&repository_id])
        .await
        .map_err(pg_err)?
        .into_iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    Ok((spec, row.get(5), refs))
}

/// Reconcile the local Raft gate/refs of one repository with PostgreSQL through exact CAS deltas.
/// The helper is synchronous so callers can run it inside `spawn_blocking` without ever holding a
/// `std::sync::MutexGuard` across an `.await`.
pub(super) fn apply_pg_repo_state_to_raft(
    raft: &mut MtlsLiveRaftBackend,
    spec: &RepoBackupRegistrationSpec,
    head_ref: &str,
    pg_refs: &BTreeMap<String, String>,
    floor: i64,
) -> Result<(), PairedBackupError> {
    let (pre_snap, _) = raft.durable_state()?;
    if !pre_snap.body.gates.iter().any(|g| g.repository_id == spec.repository_id) {
        let init = CoreGateInit::new(
            spec.repository_id,
            spec.tenant_id,
            spec.object_format,
            spec.history_incarnation,
            spec.authority_epoch,
            spec.group_epoch,
            RefName::branch(head_ref).map_err(state_machine_err)?,
        )
        .map_err(state_machine_err)?;
        let (_, init_resp) = raft.commit_and_apply(RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit::from(&init),
            pack_mode: SmPackMode::MetadataOnly,
            lane: RepositoryLane::ServingRefStore,
            authz_floor: floor.max(1),
        }))?;
        if !matches!(
            init_resp,
            ApplyResponse::GateInitialized { .. } | ApplyResponse::AlreadyApplied { .. } | ApplyResponse::Noop
        ) {
            return Err(PairedBackupError::StateMachine("Raft InitializeGate replication was rejected".into()));
        }
    }
    let (snap, _) = raft.durable_state()?;
    let raft_gate = snap
        .body
        .gates
        .iter()
        .find(|g| g.repository_id == spec.repository_id)
        .ok_or_else(|| PairedBackupError::StateMachine("Raft gate missing after InitializeGate".into()))?;
    let mut expected_rev = raft_gate.revision;
    let mut next_tick = snap.body.logical_clock_floor.saturating_add(1);
    let raft_refs = snap
        .body
        .refs
        .iter()
        .find(|r| r.repository_id == spec.repository_id)
        .map(|r| r.refs.clone())
        .unwrap_or_default();
    let mut updates = Vec::new();
    for (name, new_hex) in pg_refs {
        let precondition = match raft_refs.get(name) {
            None => RefPrecondition::Absent,
            Some(old_hex) if old_hex == new_hex => continue,
            Some(old_hex) => RefPrecondition::Present(oid(spec.object_format, old_hex)?),
        };
        updates.push(ref_update(name, precondition, RefTarget::Oid(oid(spec.object_format, new_hex)?))?);
    }
    for (name, old_hex) in &raft_refs {
        if !pg_refs.contains_key(name) {
            let precondition = RefPrecondition::Present(oid(spec.object_format, old_hex)?);
            updates.push(ref_update(name, precondition, RefTarget::Delete)?);
        }
    }
    if updates.is_empty() {
        return Ok(());
    }
    let lane = IssuerLane::new("paired-pg-raft-sync").map_err(state_machine_err)?;
    for (idx, chunk) in updates.chunks(crate::ref_store::core::pack_commit::MAX_PLAN_REFS).enumerate() {
        let request = CommitRefsRequest::new(
            spec.repository_id,
            spec.tenant_id,
            Uuid::new_v4(),
            lane.clone(),
            (idx + 1) as i64,
            Uuid::new_v4(),
            spec.object_format,
            spec.history_incarnation,
            spec.authority_epoch,
            spec.group_epoch,
            expected_rev,
            HeadUpdate::Keep,
            CommitMode::Atomic,
            chunk.to_vec(),
        )
        .map_err(state_machine_err)?;
        let (_, commit_resp) = raft.commit_and_apply(RefCasCommand::CommitRefs(CommitRefsCommand {
            request: WireCommitRefsRequest::from(&request),
            decision_id: None,
            required_holds: Vec::new(),
            policy_rejects: BTreeMap::new(),
            logical_tick: next_tick,
        }))?;
        if !matches!(commit_resp, ApplyResponse::RefsCommitted(_)) {
            return Err(PairedBackupError::StateMachine("Raft CommitRefs PG replication was rejected".into()));
        }
        expected_rev += 1;
        next_tick = next_tick.saturating_add(1);
    }
    Ok(())
}
