//! Deployment-identity attestation and PITR fencing for Pando storage (#77).
//!
//! Binds PostgreSQL's `pando_storage_authorities` row to:
//! 1. Local non-DB storage coordinates (`data_dir/.volume-id` and `.pando-deployment-id`).
//! 2. PostgreSQL cluster/database coordinates (`system_identifier`, `timeline_id`, DB OID, schema OID).
//! 3. Canonical object-store backend identity (`backend_identity`).
//! 4. Immutable write-once epoch proofs in the shared object store
//!    (`pando-authorities/<authority_id>/epochs/<epoch:020>.json`).
use crate::pando_gateway::{pitr_markers, pitr_proof_model, retention};
use crate::storage::remote_authority::AuthorityCreateOutcome;
use crate::storage::remote_objects::RemoteObjectStore;
use anyhow::{Context, Result, bail, ensure};
use deadpool_postgres::Pool;
use std::path::Path;
use std::time::Duration;
use tokio::time::Instant;
use tokio_postgres::GenericClient;
use uuid::Uuid;

pub use pitr_markers::{
    clear_claim_file_best_effort, ensure_deployment_id, read_deployment_id_if_present, read_volume_id,
};
pub use pitr_proof_model::{AuthorityState, DbCoordinates, PendingEpochAdvance, RuntimeIdentity};

const MAX_FENCE_REASON_LEN: usize = 512;

pub async fn probe_db_coordinates<C: GenericClient + Sync>(client: &C) -> Result<DbCoordinates> {
    let row = client
        .query_one(
            "SELECT \
                (SELECT system_identifier::text FROM pg_control_system()), \
                (SELECT timeline_id::integer FROM pg_control_checkpoint()), \
                (SELECT oid::bigint FROM pg_database WHERE datname = current_database()), \
                (SELECT c.relnamespace::bigint FROM pg_class c WHERE c.oid = 'pando_storage_authorities'::regclass)",
            &[],
        )
        .await
        .context("probe PostgreSQL cluster and schema coordinates")?;
    Ok(DbCoordinates {
        system_identifier: row.get(0),
        timeline_id: row.get(1),
        database_oid: row.get(2),
        schema_oid: row.get(3),
    })
}

pub async fn load_authority_state<C: GenericClient + Sync>(client: &C) -> Result<AuthorityState> {
    let row = client
        .query_one(
            "SELECT authority_id, generation, restore_generation, authority_epoch, \
                    deployment_id, volume_id, db_system_identifier, db_database_oid, \
                    db_schema_oid, pg_timeline_id, backend_identity, proof_nonce, \
                    remote_delete_fenced, remote_delete_fence_reason, attested_at::text \
             FROM pando_storage_authorities WHERE singleton",
            &[],
        )
        .await
        .context("load Pando storage authority state")?;
    Ok(AuthorityState {
        authority_id: row.get(0),
        generation: row.get(1),
        restore_generation: row.get(2),
        authority_epoch: row.get(3),
        deployment_id: row.get(4),
        volume_id: row.get(5),
        db_system_identifier: row.get(6),
        db_database_oid: row.get(7),
        db_schema_oid: row.get(8),
        pg_timeline_id: row.get(9),
        backend_identity: row.get(10),
        proof_nonce: row.get(11),
        remote_delete_fenced: row.get(12),
        remote_delete_fence_reason: row.get(13),
        attested_at: row.get(14),
    })
}

pub async fn ensure_not_fenced<C: GenericClient + Sync>(client: &C) -> Result<()> {
    let state = load_authority_state(client).await?;
    ensure!(
        !state.remote_delete_fenced,
        "Pando authority {} is fenced ({}); remote mutation and delete refused until isolated",
        state.authority_id,
        state.remote_delete_fence_reason.as_deref().unwrap_or("unspecified fence")
    );
    Ok(())
}

/// Persist the fence flag best-effort (a read-only replica may reject the write
/// while still returning the refusal error to fail closed).
pub async fn latch_fence(pool: &Pool, reason: &str) {
    let truncated: String = reason.chars().take(MAX_FENCE_REASON_LEN).collect();
    if let Ok(client) = pool.get().await {
        let _ = client
            .execute(
                "UPDATE pando_storage_authorities \
                 SET remote_delete_fenced = true, \
                     remote_delete_fence_reason = COALESCE(remote_delete_fence_reason, $1), \
                     rotated_at = clock_timestamp() \
                 WHERE singleton",
                &[&truncated],
            )
            .await;
    }
}

pub async fn gather_runtime_identity(
    pool: &Pool,
    data_dir: &Path,
    backend_identity: String,
) -> Result<RuntimeIdentity> {
    let client = pool.get().await?;
    let db = probe_db_coordinates(&**client).await?;
    let volume_id = read_volume_id(data_dir)?;
    let deployment_id = ensure_deployment_id(data_dir)?;
    Ok(RuntimeIdentity { deployment_id, volume_id, db, backend_identity })
}

/// Verify PostgreSQL + local volume coordinates without contacting S3. On any
/// mismatch against an already-attested row, latch `remote_delete_fenced=true`.
pub async fn verify_local_or_latch_fence(
    pool: &Pool,
    data_dir: &Path,
    backend_identity: String,
) -> Result<(AuthorityState, RuntimeIdentity)> {
    let client = pool.get().await?;
    let state = load_authority_state(&**client).await?;
    drop(client);
    let runtime = gather_runtime_identity(pool, data_dir, backend_identity).await?;
    if let Err(reason) = pitr_proof_model::check_local_attestation_match(&state, &runtime) {
        latch_fence(pool, &reason).await;
        bail!("{reason}");
    }
    Ok((state, runtime))
}

/// Best-effort server startup fence check. Avoids remote S3 network calls when
/// neither Pando state nor `ROOTYARD_PANDO_REMOTE_DELETE=true` nor prior
/// attestation exists, while always verifying or latching fenced state when active.
pub async fn startup_check(pool: &Pool, data_dir: &Path) -> Result<()> {
    let delete_enabled = crate::storage_lifecycle::pando_delete_gate::remote_delete_env_enabled()?;
    let client = pool.get().await?;
    let state = load_authority_state(&**client).await?;
    let has_pando_state: bool = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM pando_repository_states) \
                 OR EXISTS(SELECT 1 FROM pando_remote_artifacts)",
            &[],
        )
        .await?
        .get(0);
    drop(client);
    if state.attested_at.is_none() && !has_pando_state && !delete_enabled {
        return Ok(());
    }
    let remote = match RemoteObjectStore::from_env(data_dir.join("pando-pack-work")) {
        Ok(store) => store,
        Err(error) => {
            latch_fence(pool, &format!("remote object store invalid at startup: {error}")).await;
            eprintln!("rootyard: Pando authority fenced at startup (fail closed): {error}");
            return Ok(());
        }
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    if let Err(error) = verify_or_attest(pool, data_dir, &remote, deadline, "attest").await {
        eprintln!("rootyard: Pando authority fenced at startup (fail closed): {error}");
    }
    Ok(())
}

pub async fn verify_or_attest(
    pool: &Pool,
    data_dir: &Path,
    remote: &RemoteObjectStore,
    deadline: Instant,
    operation: &str,
) -> Result<AuthorityState> {
    let backend_identity = remote.backend_identity()?;
    let (mut state, runtime) = verify_local_or_latch_fence(pool, data_dir, backend_identity).await?;

    if state.attested_at.is_none() {
        let claim = match pitr_markers::read_claim_file(data_dir, state.authority_id)? {
            Some(existing)
                if existing.target_epoch == state.authority_epoch
                    && existing.deployment_id == runtime.deployment_id
                    && existing.volume_id == runtime.volume_id
                    && existing.backend_identity == runtime.backend_identity =>
            {
                existing
            }
            _ => {
                let fresh = pitr_markers::new_claim_file(
                    state.authority_id,
                    state.authority_epoch,
                    runtime.deployment_id,
                    runtime.volume_id,
                    runtime.backend_identity.clone(),
                );
                pitr_markers::write_claim_file(data_dir, &fresh)?;
                fresh
            }
        };
        let proof =
            pitr_proof_model::build_proof(&state, &runtime, state.authority_epoch, claim.proof_nonce, operation);
        match remote.put_authority_proof_if_absent(&proof, deadline).await? {
            AuthorityCreateOutcome::Created => {}
            AuthorityCreateOutcome::AlreadyExists(Some(existing))
                if pitr_proof_model::proof_matches_runtime(
                    &existing,
                    &state,
                    &runtime,
                    state.authority_epoch,
                    claim.proof_nonce,
                ) => {}
            AuthorityCreateOutcome::AlreadyExists(_) => {
                clear_claim_file_best_effort(data_dir, state.authority_id);
                let reason = "external authority epoch 1 already claimed by another deployment";
                latch_fence(pool, reason).await;
                bail!("{reason}");
            }
        }
        let client = pool.get().await?;
        let changed = client
            .execute(
                "UPDATE pando_storage_authorities \
                 SET deployment_id = $1, volume_id = $2, db_system_identifier = $3, \
                     db_database_oid = $4, db_schema_oid = $5, pg_timeline_id = $6, \
                     backend_identity = $7, proof_nonce = $8, attested_at = clock_timestamp(), \
                     rotated_at = clock_timestamp() \
                 WHERE singleton AND authority_id = $9 AND authority_epoch = $10 \
                   AND attested_at IS NULL AND NOT remote_delete_fenced",
                &[
                    &runtime.deployment_id,
                    &runtime.volume_id,
                    &runtime.db.system_identifier,
                    &runtime.db.database_oid,
                    &runtime.db.schema_oid,
                    &runtime.db.timeline_id,
                    &runtime.backend_identity,
                    &claim.proof_nonce,
                    &state.authority_id,
                    &state.authority_epoch,
                ],
            )
            .await?;
        clear_claim_file_best_effort(data_dir, state.authority_id);
        ensure!(changed == 1, "authority state changed concurrently during initial attestation");
        return load_authority_state(&**client).await;
    }

    let next_epoch = state.authority_epoch.checked_add(1).context("authority epoch overflow")?;
    if let Some(claim) = pitr_markers::read_claim_file(data_dir, state.authority_id)? {
        if claim.target_epoch == next_epoch
            && claim.deployment_id == runtime.deployment_id
            && claim.volume_id == runtime.volume_id
            && claim.backend_identity == runtime.backend_identity
        {
            if let Some(next_proof) = remote.read_authority_proof(state.authority_id, next_epoch, deadline).await? {
                if pitr_proof_model::proof_matches_runtime(&next_proof, &state, &runtime, next_epoch, claim.proof_nonce)
                {
                    let client = pool.get().await?;
                    let changed = client
                        .execute(
                            "UPDATE pando_storage_authorities \
                             SET authority_epoch = $1, proof_nonce = $2, rotated_at = clock_timestamp() \
                             WHERE singleton AND authority_id = $3 AND authority_epoch = $4 \
                               AND NOT remote_delete_fenced",
                            &[&next_epoch, &claim.proof_nonce, &state.authority_id, &state.authority_epoch],
                        )
                        .await?;
                    clear_claim_file_best_effort(data_dir, state.authority_id);
                    ensure!(changed == 1, "authority epoch changed concurrently during claim recovery");
                    state = load_authority_state(&**client).await?;
                }
            }
        }
    }

    let expected_nonce = state.proof_nonce.context("attested authority missing proof_nonce")?;
    match remote.read_authority_proof(state.authority_id, state.authority_epoch, deadline).await? {
        Some(proof)
            if pitr_proof_model::proof_matches_runtime(
                &proof,
                &state,
                &runtime,
                state.authority_epoch,
                expected_nonce,
            ) => {}
        _ => {
            let reason = "external authority epoch proof missing or mismatched in object store";
            latch_fence(pool, reason).await;
            bail!("{reason}");
        }
    }

    let successor = state.authority_epoch.checked_add(1).context("authority epoch overflow")?;
    if remote.authority_proof_exists(state.authority_id, successor, deadline).await? {
        let reason = "external object-store epoch is ahead of database (PITR rollback or split-brain clone detected)";
        latch_fence(pool, reason).await;
        bail!("{reason}");
    }

    Ok(state)
}

pub async fn begin_epoch_advance(
    pool: &Pool,
    data_dir: &Path,
    remote: &RemoteObjectStore,
    operation: &str,
    deadline: Instant,
) -> Result<PendingEpochAdvance> {
    let state = verify_or_attest(pool, data_dir, remote, deadline, operation).await?;
    let runtime = gather_runtime_identity(pool, data_dir, remote.backend_identity()?).await?;
    let next_epoch = state.authority_epoch.checked_add(1).context("authority epoch overflow")?;
    let claim = pitr_markers::new_claim_file(
        state.authority_id,
        next_epoch,
        runtime.deployment_id,
        runtime.volume_id,
        runtime.backend_identity.clone(),
    );
    pitr_markers::write_claim_file(data_dir, &claim)?;
    let next_proof = pitr_proof_model::build_proof(&state, &runtime, next_epoch, claim.proof_nonce, operation);
    match remote.put_authority_proof_if_absent(&next_proof, deadline).await {
        Ok(AuthorityCreateOutcome::Created) => Ok(PendingEpochAdvance {
            authority_id: state.authority_id,
            expected_epoch: state.authority_epoch,
            next_epoch,
            restore_generation: state.restore_generation,
            new_nonce: claim.proof_nonce,
        }),
        Ok(AuthorityCreateOutcome::AlreadyExists(_)) => {
            clear_claim_file_best_effort(data_dir, state.authority_id);
            let reason = "next external authority epoch already claimed (PITR rollback or concurrent clone)";
            latch_fence(pool, reason).await;
            bail!("{reason}");
        }
        Err(error) => {
            clear_claim_file_best_effort(data_dir, state.authority_id);
            Err(error)
        }
    }
}

pub async fn commit_epoch_advance_in_tx<C: GenericClient + Sync>(
    client: &C,
    pending: &PendingEpochAdvance,
) -> Result<AuthorityState> {
    let changed = client
        .execute(
            "UPDATE pando_storage_authorities \
             SET authority_epoch = $1, proof_nonce = $2, rotated_at = clock_timestamp() \
             WHERE singleton AND authority_id = $3 AND authority_epoch = $4 AND NOT remote_delete_fenced",
            &[&pending.next_epoch, &pending.new_nonce, &pending.authority_id, &pending.expected_epoch],
        )
        .await?;
    ensure!(changed == 1, "authority epoch CAS mismatch during commit");
    load_authority_state(client).await
}

pub async fn advance_epoch(
    pool: &Pool,
    data_dir: &Path,
    remote: &RemoteObjectStore,
    operation: &str,
    deadline: Instant,
) -> Result<AuthorityState> {
    let pending = begin_epoch_advance(pool, data_dir, remote, operation, deadline).await?;
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let committed = commit_epoch_advance_in_tx(&tx, &pending).await?;
    tx.commit().await?;
    clear_claim_file_best_effort(data_dir, pending.authority_id);
    Ok(committed)
}

pub async fn isolate_cloned_authority(
    pool: &Pool,
    data_dir: &Path,
    remote: &RemoteObjectStore,
    deadline: Instant,
) -> Result<AuthorityState> {
    let mut client = pool.get().await?;
    let previous = retention::authority(&**client).await?;
    retention::reset_authority(&mut client).await?;
    clear_claim_file_best_effort(data_dir, previous.id);
    drop(client);
    verify_or_attest(pool, data_dir, remote, deadline, "isolate_authority").await
}
