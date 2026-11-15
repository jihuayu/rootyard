//! Types and coordinate matching helpers for Pando PITR authority proofs (#77).
use crate::storage::remote_authority::{AuthorityEpochProof, PROOF_VERSION};
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DbCoordinates {
    pub system_identifier: String,
    pub timeline_id: i32,
    pub database_oid: i64,
    pub schema_oid: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeIdentity {
    pub deployment_id: Uuid,
    pub volume_id: Uuid,
    pub db: DbCoordinates,
    pub backend_identity: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuthorityState {
    pub authority_id: Uuid,
    pub generation: i64,
    pub restore_generation: i64,
    pub authority_epoch: i64,
    pub deployment_id: Option<Uuid>,
    pub volume_id: Option<Uuid>,
    pub db_system_identifier: Option<String>,
    pub db_database_oid: Option<i64>,
    pub db_schema_oid: Option<i64>,
    pub pg_timeline_id: Option<i32>,
    pub backend_identity: Option<String>,
    pub proof_nonce: Option<Uuid>,
    pub remote_delete_fenced: bool,
    pub remote_delete_fence_reason: Option<String>,
    pub attested_at: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PendingEpochAdvance {
    pub authority_id: Uuid,
    pub expected_epoch: i64,
    pub next_epoch: i64,
    pub restore_generation: i64,
    pub new_nonce: Uuid,
}

pub(super) fn check_local_attestation_match(
    state: &AuthorityState,
    runtime: &RuntimeIdentity,
) -> std::result::Result<(), String> {
    if state.remote_delete_fenced {
        return Err(format!(
            "Pando remote delete already fenced: {}",
            state.remote_delete_fence_reason.as_deref().unwrap_or("unspecified fence")
        ));
    }
    if state.attested_at.is_none() {
        return Ok(());
    }
    if state.deployment_id != Some(runtime.deployment_id) {
        return Err("deployment_id differs from attested authority (suspected metadata clone)".into());
    }
    if state.volume_id != Some(runtime.volume_id) {
        return Err("volume_id differs from attested authority (suspected copied database)".into());
    }
    if state.db_system_identifier.as_deref() != Some(runtime.db.system_identifier.as_str()) {
        return Err("PostgreSQL system_identifier differs from attested authority".into());
    }
    if state.db_database_oid != Some(runtime.db.database_oid) {
        return Err("PostgreSQL database OID differs from attested authority".into());
    }
    if state.db_schema_oid != Some(runtime.db.schema_oid) {
        return Err("PostgreSQL schema OID differs from attested authority".into());
    }
    if state.pg_timeline_id != Some(runtime.db.timeline_id) {
        return Err("PostgreSQL timeline_id changed since attestation (possible PITR recovery)".into());
    }
    if state.backend_identity.as_deref() != Some(runtime.backend_identity.as_str()) {
        return Err("object store backend identity differs from attested authority".into());
    }
    if state.proof_nonce.is_none() {
        return Err("attested authority row is missing proof_nonce".into());
    }
    Ok(())
}

pub(super) fn build_proof(
    state: &AuthorityState,
    runtime: &RuntimeIdentity,
    epoch: i64,
    nonce: Uuid,
    operation: &str,
) -> AuthorityEpochProof {
    AuthorityEpochProof {
        version: PROOF_VERSION,
        authority_id: state.authority_id,
        epoch,
        restore_generation: state.restore_generation,
        generation: state.generation,
        deployment_id: runtime.deployment_id,
        volume_id: runtime.volume_id,
        db_system_identifier: runtime.db.system_identifier.clone(),
        db_database_oid: runtime.db.database_oid,
        db_schema_oid: runtime.db.schema_oid,
        pg_timeline_id: runtime.db.timeline_id,
        backend_identity: runtime.backend_identity.clone(),
        proof_nonce: nonce,
        operation: operation.into(),
    }
}

pub(super) fn proof_matches_runtime(
    proof: &AuthorityEpochProof,
    state: &AuthorityState,
    runtime: &RuntimeIdentity,
    epoch: i64,
    nonce: Uuid,
) -> bool {
    proof.authority_id == state.authority_id
        && proof.epoch == epoch
        && proof.restore_generation == state.restore_generation
        && proof.deployment_id == runtime.deployment_id
        && proof.volume_id == runtime.volume_id
        && proof.db_system_identifier == runtime.db.system_identifier
        && proof.db_database_oid == runtime.db.database_oid
        && proof.db_schema_oid == runtime.db.schema_oid
        && proof.pg_timeline_id == runtime.db.timeline_id
        && proof.backend_identity == runtime.backend_identity
        && proof.proof_nonce == nonce
}
