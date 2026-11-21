//! New-incarnation installation onto a freshly restored `schema 151` PostgreSQL 17 database: cluster
//! identity rotation, `authz_floor`/`deleter_epoch` floors, revoked pre-restore authority and the
//! A3/A4 new-realm re-homing of every restored repository (#153).

use std::collections::BTreeSet;

use tokio_postgres::Client;
use uuid::Uuid;

use super::format30_paired::Format30PairedManifest;
use super::format30_realm_rehome::{RestoredRepoCapture, rehome_restored_repositories_realm};
use super::pg_cutpoint::pg_err;
use super::types::{NewIncarnationAuthority, PairedBackupError};

pub(super) async fn install_new_incarnation_on_restored_schema151(
    client: &mut Client,
    manifest: &Format30PairedManifest,
    captured_repos: &[RestoredRepoCapture],
) -> Result<NewIncarnationAuthority, PairedBackupError> {
    let gate_auth_e = manifest.pg_cutpoint.repositories.iter().map(|r| r.authority_epoch).max().unwrap_or(1).max(1);
    let active_grp_e = manifest.pg_cutpoint.repositories.iter().map(|r| r.group_epoch).max().unwrap_or(1).max(1);
    let max_floor = manifest
        .raft_cutpoint
        .close_receipts
        .iter()
        .map(|r| r.authz_floor)
        .max()
        .unwrap_or(1)
        .max(manifest.pg_cutpoint.max_decision_scope_version);
    let new_authz_floor = max_floor.saturating_add(10);
    let requested_deleter_epoch = manifest.freeze.fenced_deleter_epoch.saturating_add(1);
    let deleter_floor_i64 = i64::try_from(requested_deleter_epoch).unwrap_or(i64::MAX);

    let new_cluster_inc = Uuid::new_v4();
    let new_storage_auth = Uuid::new_v4();
    let new_storage_gen = manifest.pg_cutpoint.source_storage_generation.saturating_add(2);
    let new_history_inc = Uuid::new_v4();
    let new_auth_epoch = gate_auth_e.saturating_add(1);
    let max_peer_grp_e = manifest.raft_cutpoint.group_epochs.values().copied().max().unwrap_or(1);
    let new_grp_epoch = active_grp_e.max(max_peer_grp_e).saturating_add(1);

    let tx = client.transaction().await.map_err(pg_err)?;
    tx.batch_execute("SET LOCAL session_replication_role = replica").await.map_err(pg_err)?;
    tx.execute(
        "UPDATE public.cluster_authority SET incarnation = $1, rotated_at = clock_timestamp() WHERE singleton = true",
        &[&new_cluster_inc],
    )
    .await
    .map_err(pg_err)?;
    let srow = tx
        .query_one(
            "UPDATE public.pando_storage_authorities \
             SET authority_id = $1, generation = GREATEST(generation + 1, $2), \
                 restore_generation = GREATEST(restore_generation + 1, $3), \
                 authority_epoch = $4, remote_delete_fenced = true, \
                 remote_delete_fence_reason = 'restore-boot-in-progress', rotated_at = clock_timestamp() \
             WHERE singleton = true \
             RETURNING generation, authority_epoch, restore_generation",
            &[&new_storage_auth, &new_storage_gen, &deleter_floor_i64, &new_auth_epoch],
        )
        .await
        .map_err(pg_err)?;
    let (actual_storage_gen, actual_auth_e): (i64, i64) = (srow.get(0), srow.get(1));
    let new_deleter_epoch = u64::try_from(srow.get::<_, i64>(2)).unwrap_or(requested_deleter_epoch);

    tx.execute("UPDATE public.tokens SET revoked = true WHERE NOT revoked", &[]).await.map_err(pg_err)?;
    tx.execute(
        "UPDATE public.ref_store_publication_decisions \
         SET state = 'CANCELLED', closed_code = 'restored_new_incarnation', \
             cancelled_at = clock_timestamp(), cancel_change_id = $1 \
         WHERE state = 'OPEN'",
        &[&Uuid::new_v4()],
    )
    .await
    .map_err(pg_err)?;

    tx.execute(
        "INSERT INTO public.ref_store_decision_scopes(scope_kind, scope_id, version, state, change_id) \
         VALUES('authority', $1, $2, 'CLOSING', $3) \
         ON CONFLICT (scope_kind, scope_id) DO UPDATE \
         SET state = 'CLOSING', \
             version = GREATEST(public.ref_store_decision_scopes.version, EXCLUDED.version), \
             change_id = COALESCE(public.ref_store_decision_scopes.change_id, EXCLUDED.change_id)",
        &[&manifest.pg_cutpoint.source_storage_authority_id, &new_authz_floor, &Uuid::new_v4()],
    )
    .await
    .map_err(pg_err)?;
    tx.execute(
        "INSERT INTO public.ref_store_decision_scopes(scope_kind, scope_id, version, state, change_id) \
         VALUES('authority', $1, $2, 'OPEN', NULL) \
         ON CONFLICT (scope_kind, scope_id) DO UPDATE \
         SET version = GREATEST(public.ref_store_decision_scopes.version, EXCLUDED.version)",
        &[&new_storage_auth, &new_authz_floor],
    )
    .await
    .map_err(pg_err)?;
    tx.execute(
        "UPDATE public.ref_store_decision_scopes SET version = GREATEST(version, $1) WHERE state = 'OPEN'",
        &[&new_authz_floor],
    )
    .await
    .map_err(pg_err)?;
    for repo in &manifest.pg_cutpoint.repositories {
        for kind in ["repo_access", "repo_lifecycle"] {
            tx.execute(
                "INSERT INTO public.ref_store_decision_scopes(scope_kind, scope_id, version, state, change_id) \
                 VALUES($1, $2, $3, 'OPEN', NULL) \
                 ON CONFLICT (scope_kind, scope_id) DO UPDATE \
                 SET version = GREATEST(public.ref_store_decision_scopes.version, EXCLUDED.version)",
                &[&kind, &repo.repository_id, &new_authz_floor],
            )
            .await
            .map_err(pg_err)?;
        }
    }
    rehome_restored_repositories_realm(&tx, captured_repos, new_history_inc, actual_auth_e, new_grp_epoch).await?;
    tx.batch_execute(
        "SET LOCAL session_replication_role = DEFAULT; \
         DELETE FROM public.ref_store_core_serving_reads; \
         DELETE FROM public.ref_cas_projection_jobs; \
         DELETE FROM public.ref_cas_projected_refs; \
         DELETE FROM public.ref_cas_projected_events; \
         DELETE FROM public.ref_cas_projected_operations;",
    )
    .await
    .map_err(pg_err)?;
    tx.commit().await.map_err(pg_err)?;

    let mut fenced_inc = BTreeSet::from([
        manifest.pg_cutpoint.source_cluster_incarnation,
        manifest.pg_cutpoint.source_storage_authority_id,
    ]);
    for repo in &manifest.pg_cutpoint.repositories {
        fenced_inc.insert(repo.history_incarnation);
    }
    for peer in &manifest.raft_cutpoint.peer_groups {
        for gate in &peer.snapshot.body.gates {
            fenced_inc.insert(gate.history_incarnation);
        }
    }
    let fenced_decisions: BTreeSet<Uuid> =
        manifest.raft_cutpoint.snapshot.body.decisions.iter().map(|d| d.decision_id).collect();
    Ok(NewIncarnationAuthority {
        new_cluster_incarnation: new_cluster_inc,
        new_storage_authority_id: new_storage_auth,
        new_storage_generation: actual_storage_gen,
        new_history_incarnation: new_history_inc,
        new_authority_epoch: actual_auth_e,
        new_group_epoch: new_grp_epoch,
        new_authz_floor,
        new_deleter_epoch,
        fenced_prior_incarnations: fenced_inc,
        fenced_pre_backup_decision_ids: fenced_decisions,
    })
}
