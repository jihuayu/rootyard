//! PostgreSQL 17 consistent cutpoint capture, cursor reconciliation, and clean-room
//! new-incarnation authority persistence (#153).

use std::collections::BTreeMap;

use tokio_postgres::{Client, GenericClient, Transaction};
use uuid::Uuid;

use crate::ref_store::GitObjectFormat;

use super::types::{
    DeleterLeaseTicket, NewIncarnationAuthority, PairedBackupError, PairedBackupManifest, PgCutpointProof,
    PgProjectionCursorCut, PgRepositoryRowProof, WriterGrantTicket, sha256_json_tagged,
};

fn pg_err(err: tokio_postgres::Error) -> PairedBackupError {
    PairedBackupError::Postgres(err.to_string())
}

fn parse_obj_format(raw: &str) -> Result<GitObjectFormat, PairedBackupError> {
    match raw {
        "sha1" => Ok(GitObjectFormat::Sha1),
        "sha256" => Ok(GitObjectFormat::Sha256),
        other => Err(PairedBackupError::Postgres(format!("unsupported object_format in PG: {other}"))),
    }
}

/// Fence physical deletions in PostgreSQL before capturing a paired backup cutpoint.
pub async fn freeze_pg_deleter(client: &impl GenericClient, reason: &str) -> Result<(), PairedBackupError> {
    client
        .execute(
            "UPDATE public.pando_storage_authorities \
             SET remote_delete_fenced = true, remote_delete_fence_reason = $1 \
             WHERE singleton = true",
            &[&reason],
        )
        .await
        .map_err(pg_err)?;
    Ok(())
}

/// Capture an immutable PG 17 repeatable-read cutpoint and reconcile projection cursors
/// & pending decisions/outbox entries to the exact Raft `(group_id, term, index)` cut.
pub async fn capture_pg_cutpoint_in_tx(
    tx: &Transaction<'_>,
    expected_group_id: i64,
    expected_incarnation: Uuid,
    expected_raft_index: u64,
    expected_raft_term: u64,
    expected_event_seq: u64,
) -> Result<PgCutpointProof, PairedBackupError> {
    let pg_ver: String = tx.query_one("SHOW server_version", &[]).await.map_err(pg_err)?.get(0);
    if !pg_ver.starts_with("17.") {
        return Err(PairedBackupError::Postgres(format!("paired backup requires PG 17, got {pg_ver}")));
    }
    let schema_head: i64 = tx
        .query_one("SELECT COALESCE(max(version), 0)::bigint FROM schema_migrations", &[])
        .await
        .map_err(pg_err)?
        .get(0);
    let cut_row =
        tx.query_one("SELECT pg_current_wal_lsn()::text, pg_current_snapshot()::text", &[]).await.map_err(pg_err)?;
    let (wal_lsn, snapshot_tx): (String, String) = (cut_row.get(0), cut_row.get(1));

    let cluster_inc: Uuid = tx
        .query_one("SELECT incarnation FROM cluster_authority WHERE singleton = true", &[])
        .await
        .map_err(pg_err)?
        .get(0);
    let auth_row = tx
        .query_one(
            "SELECT authority_id, generation, remote_delete_fenced \
             FROM pando_storage_authorities WHERE singleton = true",
            &[],
        )
        .await
        .map_err(pg_err)?;
    let (source_storage_authority_id, source_storage_generation, remote_delete_fenced): (Uuid, i64, bool) =
        (auth_row.get(0), auth_row.get(1), auth_row.get(2));
    if !remote_delete_fenced {
        return Err(PairedBackupError::DeleterNotFenced(
            "PG pando_storage_authorities.remote_delete_fenced must be true",
        ));
    }

    let pending_decisions_count: i64 = tx
        .query_one("SELECT count(*)::bigint FROM ref_store_publication_decisions WHERE state = 'OPEN'", &[])
        .await
        .map_err(pg_err)?
        .get(0);
    let pending_outbox_count: i64 = tx
        .query_one(
            "SELECT (SELECT count(*)::bigint FROM git_operations WHERE outcome = 'unknown') \
             + (SELECT count(*)::bigint FROM event_deliveries WHERE state <> 'delivered') \
             + (SELECT count(*)::bigint FROM ref_cas_projection_jobs WHERE state IN ('queued','running','unknown_hold'))",
            &[],
        )
        .await
        .map_err(pg_err)?
        .get(0);
    if pending_decisions_count != 0 || pending_outbox_count != 0 {
        return Err(PairedBackupError::UnknownInFlightOperations(
            (pending_decisions_count + pending_outbox_count) as usize,
        ));
    }

    let cursor_rows = tx
        .query(
            "SELECT group_id, history_incarnation, group_epoch, applied_event_seq, applied_log_index, \
                    applied_log_term, last_event_id, stream_state \
             FROM ref_cas_projection_cursors ORDER BY group_id, history_incarnation",
            &[],
        )
        .await
        .map_err(pg_err)?;
    let mut projection_cursors = Vec::with_capacity(cursor_rows.len());
    for row in cursor_rows {
        projection_cursors.push(PgProjectionCursorCut {
            group_id: row.get(0),
            history_incarnation: row.get(1),
            group_epoch: row.get(2),
            applied_event_seq: row.get(3),
            applied_log_index: row.get(4),
            applied_log_term: row.get(5),
            last_event_id: row.get(6),
            stream_state: row.get(7),
        });
    }
    let matched_cursor = projection_cursors
        .iter()
        .find(|c| c.group_id == expected_group_id && c.history_incarnation == expected_incarnation)
        .ok_or_else(|| {
            PairedBackupError::CutpointSkew(
                "missing PG ref_cas_projection_cursors row for active Raft group/incarnation".into(),
            )
        })?;
    if matched_cursor.stream_state != "active"
        || matched_cursor.applied_log_index as u64 != expected_raft_index
        || matched_cursor.applied_log_term as u64 != expected_raft_term
        || matched_cursor.applied_event_seq as u64 != expected_event_seq
    {
        return Err(PairedBackupError::CutpointSkew(format!(
            "PG projection cursor ({},{},{}) != Raft cut ({expected_raft_term},{expected_raft_index},{expected_event_seq})",
            matched_cursor.applied_log_term, matched_cursor.applied_log_index, matched_cursor.applied_event_seq
        )));
    }

    let repo_rows = tx
        .query(
            "SELECT r.id, r.owner_id, r.name, r.object_format, r.storage_backend, \
                    g.history_incarnation, g.authority_epoch, g.group_epoch, g.revision \
             FROM repositories r \
             JOIN ref_store_core_gates g ON g.repository_id = r.id \
             ORDER BY r.id",
            &[],
        )
        .await
        .map_err(pg_err)?;
    let mut repositories = Vec::with_capacity(repo_rows.len());
    for row in repo_rows {
        let repository_id: Uuid = row.get(0);
        let ref_rows = tx
            .query(
                "SELECT ref_name, oid FROM ref_store_core_refs WHERE repository_id = $1 ORDER BY ref_name",
                &[&repository_id],
            )
            .await
            .map_err(pg_err)?;
        let mut refs = BTreeMap::new();
        for rr in ref_rows {
            refs.insert(rr.get(0), rr.get(1));
        }
        let refs_digest = sha256_json_tagged(b"rootyard-pg-refs-v1", &refs)?;
        repositories.push(PgRepositoryRowProof {
            repository_id,
            tenant_id: row.get(1),
            name: row.get(2),
            object_format: parse_obj_format(row.get::<_, String>(3).as_str())?,
            storage_backend: row.get(4),
            history_incarnation: row.get(5),
            authority_epoch: row.get(6),
            group_epoch: row.get(7),
            gate_revision: row.get(8),
            refs_digest,
            refs,
        });
    }

    PgCutpointProof {
        schema_head_version: schema_head,
        wal_lsn,
        snapshot_tx,
        postgres_major_version: pg_ver,
        source_cluster_incarnation: cluster_inc,
        source_storage_authority_id,
        source_storage_generation,
        remote_delete_fenced,
        pending_decisions_count,
        pending_outbox_count,
        projection_cursors,
        repositories,
        cutpoint_digest: String::new(),
    }
    .seal()
}

/// Restore clean-room PG 17 tables under a strictly new incarnation, rotate authority,
/// fence prior cluster leases/credentials/tokens, and register backup retention roots.
pub async fn install_restored_pg_incarnation(
    client: &mut Client,
    manifest: &PairedBackupManifest,
    inc: &NewIncarnationAuthority,
) -> Result<(), PairedBackupError> {
    let tx = client.transaction().await.map_err(pg_err)?;
    tx.batch_execute(
        "DELETE FROM cluster_transport_nonces;
         UPDATE ci_runs SET state='cancelled', lease_generation=lease_generation+1, lease_expires_unix=0, runner_id=NULL WHERE state IN ('queued','leased');
         UPDATE ci_mirror_nodes SET active=false, ready_oids='[]'::jsonb, heartbeat_unix=0;
         UPDATE forge_webhook_deliveries SET state='pending', lease_generation=lease_generation+1, next_attempt_unix=0 WHERE state='leased';
         UPDATE ref_cas_projection_jobs SET state='queued', claim_generation=claim_generation+1, lease_owner=NULL, lease_until=NULL WHERE state='running';
         UPDATE workspaces SET lease_epoch=lease_epoch+1, lease_until=clock_timestamp()-interval '1 second' WHERE state='ready';
         UPDATE sandbox_jobs SET state='cancelled', pid=NULL, finished_at=clock_timestamp() WHERE state IN ('queued','preparing','running');
         UPDATE tokens SET revoked=true WHERE kind='browser';
         UPDATE web_sessions SET revoked=true;",
    )
    .await
    .map_err(pg_err)?;

    tx.execute(
        "UPDATE cluster_authority SET incarnation = $1, rotated_at = clock_timestamp() WHERE singleton = true",
        &[&inc.new_cluster_incarnation],
    )
    .await
    .map_err(pg_err)?;
    let storage_row = tx
        .query_one(
            "UPDATE pando_storage_authorities \
             SET authority_id = $1, generation = $2, restore_generation = restore_generation + 1, \
                 authority_epoch = $3, remote_delete_fenced = false, remote_delete_fence_reason = NULL, \
                 rotated_at = clock_timestamp() \
             WHERE singleton = true \
             RETURNING restore_generation",
            &[&inc.new_storage_authority_id, &inc.new_storage_generation, &inc.new_authority_epoch],
        )
        .await
        .map_err(pg_err)?;
    let restore_gen: i64 = storage_row.get(0);

    for repo in &manifest.pg_cutpoint.repositories {
        let uname = format!("r{}", &repo.tenant_id.simple().to_string()[..12]);
        tx.execute(
            "INSERT INTO users(id, username) VALUES($1, $2) ON CONFLICT (id) DO NOTHING",
            &[&repo.tenant_id, &uname],
        )
        .await
        .map_err(pg_err)?;
        let fmt_str = repo.object_format.as_str();
        tx.execute(
            "INSERT INTO repositories(id, owner_id, name, state, storage_backend, object_format, transition_state) \
             VALUES($1, $2, $3, 'provisioning', $4, $5, 'stable')",
            &[&repo.repository_id, &repo.tenant_id, &repo.name, &repo.storage_backend, &fmt_str],
        )
        .await
        .map_err(pg_err)?;
        let head_ref = repo
            .refs
            .keys()
            .find(|k| k.as_str() == "refs/heads/main")
            .or_else(|| repo.refs.keys().find(|k| k.starts_with("refs/heads/")))
            .map(String::as_str)
            .unwrap_or("refs/heads/main");
        tx.execute(
            "INSERT INTO ref_store_core_gates(repository_id, tenant_id, object_format, history_incarnation, authority_epoch, group_epoch, head_ref, revision, pack_mode) \
             VALUES($1, $2, $3, $4, $5, $6, $7, $8, 'metadata_only')",
            &[
                &repo.repository_id,
                &repo.tenant_id,
                &fmt_str,
                &inc.new_history_incarnation,
                &inc.new_authority_epoch,
                &inc.new_group_epoch,
                &head_ref,
                &repo.gate_revision,
            ],
        )
        .await
        .map_err(pg_err)?;
        tx.execute(
            "INSERT INTO ref_store_core_protocol_repos(repository_id, tenant_id, object_format, history_incarnation, authority_epoch, group_epoch, decision_required, roots_revision) \
             VALUES($1, $2, $3, $4, $5, $6, TRUE, 1)",
            &[&repo.repository_id, &repo.tenant_id, &fmt_str, &inc.new_history_incarnation, &inc.new_authority_epoch, &inc.new_group_epoch],
        )
        .await
        .map_err(pg_err)?;
        for (ref_name, oid) in &repo.refs {
            tx.execute(
                "INSERT INTO ref_store_core_refs(repository_id, ref_name, oid, revision) VALUES($1, $2, $3, $4)",
                &[&repo.repository_id, ref_name, oid, &repo.gate_revision],
            )
            .await
            .map_err(pg_err)?;
        }
        if repo.storage_backend == "pg_refstore" {
            tx.execute(
                "INSERT INTO ref_store_serving_repositories(repository_id, owner_id, name, object_format, history_incarnation, authority_epoch, group_epoch, backend_identity, state) \
                 VALUES($1, $2, $3, $4, $5, $6, $7, $8, 'pending')",
                &[
                    &repo.repository_id,
                    &repo.tenant_id,
                    &repo.name,
                    &fmt_str,
                    &inc.new_history_incarnation,
                    &inc.new_authority_epoch,
                    &inc.new_group_epoch,
                    &manifest.blob_closure.backend_identity,
                ],
            )
            .await
            .map_err(pg_err)?;
            tx.execute(
                "UPDATE ref_store_serving_repositories SET state = 'ready' WHERE repository_id = $1",
                &[&repo.repository_id],
            )
            .await
            .map_err(pg_err)?;
        }
        tx.execute("UPDATE repositories SET state = 'ready' WHERE id = $1", &[&repo.repository_id])
            .await
            .map_err(pg_err)?;
        tx.execute(
            "INSERT INTO pando_retention_roots(id, authority_id, tenant_id, repository_id, root_kind, state, restore_generation, external_lsn, note) \
             VALUES($1, $2, $3, $4, 'backup_snapshot', 'active', $5, $6, $7)",
            &[
                &Uuid::new_v4(),
                &inc.new_storage_authority_id,
                &repo.tenant_id,
                &repo.repository_id,
                &restore_gen,
                &manifest.pg_cutpoint.wal_lsn,
                &format!("restored-from-backup-{}", manifest.backup_id),
            ],
        )
        .await
        .map_err(pg_err)?;
    }

    for cur in &manifest.pg_cutpoint.projection_cursors {
        tx.execute(
            "INSERT INTO ref_cas_projection_cursors(group_id, history_incarnation, group_epoch, applied_event_seq, applied_log_index, applied_log_term, last_event_id, stream_state) \
             VALUES($1, $2, $3, $4, $5, $6, $7, 'active')",
            &[
                &cur.group_id,
                &inc.new_history_incarnation,
                &inc.new_group_epoch,
                &cur.applied_event_seq,
                &cur.applied_log_index,
                &cur.applied_log_term,
                &cur.last_event_id,
            ],
        )
        .await
        .map_err(pg_err)?;
    }

    tx.commit().await.map_err(pg_err)?;
    Ok(())
}

/// Fail-closed SQL check rejecting pre-backup incarnation credentials or stale deleter leases against PG 17.
pub async fn verify_pg_live_incarnation(
    client: &Client,
    repository_id: Uuid,
    grant: &WriterGrantTicket,
    deleter: Option<&DeleterLeaseTicket>,
) -> Result<(), PairedBackupError> {
    let cluster_inc: Uuid = client
        .query_one("SELECT incarnation FROM cluster_authority WHERE singleton = true", &[])
        .await
        .map_err(pg_err)?
        .get(0);
    if grant.cluster_incarnation != cluster_inc {
        return Err(PairedBackupError::StaleIncarnation {
            field: "cluster_incarnation",
            expected: cluster_inc.to_string(),
            got: grant.cluster_incarnation.to_string(),
        });
    }
    let gate_row = client
        .query_one(
            "SELECT history_incarnation, authority_epoch, group_epoch FROM ref_store_core_gates WHERE repository_id = $1",
            &[&repository_id],
        )
        .await
        .map_err(pg_err)?;
    let (live_hist, live_auth_e, live_grp_e): (Uuid, i64, i64) = (gate_row.get(0), gate_row.get(1), gate_row.get(2));
    if grant.history_incarnation != live_hist || grant.authority_epoch < live_auth_e || grant.group_epoch < live_grp_e {
        return Err(PairedBackupError::StaleGrantRefused("grant incarnation/epoch behind live PG gate"));
    }
    if let Some(del) = deleter {
        let auth_row = client
            .query_one(
                "SELECT authority_id, generation, remote_delete_fenced FROM pando_storage_authorities WHERE singleton = true",
                &[],
            )
            .await
            .map_err(pg_err)?;
        let (aid, auth_gen, fenced): (Uuid, i64, bool) = (auth_row.get(0), auth_row.get(1), auth_row.get(2));
        if fenced
            || del.storage_authority_id != aid
            || del.storage_generation < auth_gen
            || del.cluster_incarnation != cluster_inc
        {
            return Err(PairedBackupError::StaleDeleterRefused(
                "deleter authority/generation/cluster_incarnation rejected by PG",
            ));
        }
    }
    Ok(())
}
