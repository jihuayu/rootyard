//! PostgreSQL 17 clean-room new-incarnation restore persistence, multi-group cursor
//! verification, and restored `authz_epoch` + `deleter_epoch` floor admission (#153).

use std::collections::BTreeMap;

use tokio_postgres::Client;
use uuid::Uuid;

use crate::ref_store::core::state_machine::RefCasSnapshot;

use super::closure_bind::extract_raft_group_realm;
use super::pg_cutpoint::pg_err;
use super::types::{
    DecisionExecutionTicket, DeleterLeaseTicket, NewIncarnationAuthority, PairedBackupError, PairedBackupManifest,
    WriterGrantTicket,
};

/// Restore clean-room PG 17 tables under a strictly new incarnation, rotate authority,
/// persist `ref_store_decision_scopes` `authz_floor` + `deleter_epoch` floor, and align
/// `ref_cas_projection_cursors` across active AND restored peer Raft groups.
pub async fn install_restored_pg_incarnation(
    client: &mut Client,
    manifest: &PairedBackupManifest,
    inc: &NewIncarnationAuthority,
    restored_group_id: i64,
    restored_snap: &RefCasSnapshot,
    restored_peer_snaps: &BTreeMap<i64, RefCasSnapshot>,
) -> Result<(), PairedBackupError> {
    let mut all_restored_snaps = restored_peer_snaps.clone();
    all_restored_snaps.insert(restored_group_id, restored_snap.clone());
    for cur in &manifest.pg_cutpoint.projection_cursors {
        if !all_restored_snaps.contains_key(&cur.group_id) {
            return Err(PairedBackupError::IncompleteCut("missing restored durable Raft snapshot for PG cursor group"));
        }
    }
    let deleter_floor_i64 = i64::try_from(inc.new_deleter_epoch).unwrap_or(i64::MAX);

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
             SET authority_id = $1, generation = $2, \
                 restore_generation = GREATEST(restore_generation + 1, $4), \
                 authority_epoch = $3, remote_delete_fenced = false, remote_delete_fence_reason = NULL, \
                 rotated_at = clock_timestamp() \
             WHERE singleton = true \
             RETURNING restore_generation",
            &[&inc.new_storage_authority_id, &inc.new_storage_generation, &inc.new_authority_epoch, &deleter_floor_i64],
        )
        .await
        .map_err(pg_err)?;
    let restore_gen: i64 = storage_row.get(0);

    tx.execute(
        "INSERT INTO ref_store_decision_scopes(scope_kind, scope_id, version, state, change_id) \
         VALUES('authority', $1, $2, 'CLOSING', $3) \
         ON CONFLICT (scope_kind, scope_id) DO UPDATE \
         SET state = 'CLOSING', \
             version = GREATEST(ref_store_decision_scopes.version, EXCLUDED.version), \
             change_id = COALESCE(ref_store_decision_scopes.change_id, EXCLUDED.change_id)",
        &[&manifest.pg_cutpoint.source_storage_authority_id, &inc.new_authz_floor, &Uuid::new_v4()],
    )
    .await
    .map_err(pg_err)?;
    tx.execute(
        "INSERT INTO ref_store_decision_scopes(scope_kind, scope_id, version, state, change_id) \
         VALUES('authority', $1, $2, 'OPEN', NULL)",
        &[&inc.new_storage_authority_id, &inc.new_authz_floor],
    )
    .await
    .map_err(pg_err)?;

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
        for kind in ["repo_lifecycle", "repo_access"] {
            tx.execute(
                "INSERT INTO ref_store_decision_scopes(scope_kind, scope_id, version, state, change_id) \
                 VALUES($1, $2, $3, 'OPEN', NULL)",
                &[&kind, &repo.repository_id, &inc.new_authz_floor],
            )
            .await
            .map_err(pg_err)?;
        }
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
        let gsnap = all_restored_snaps
            .get(&cur.group_id)
            .ok_or(PairedBackupError::IncompleteCut("missing restored group snapshot"))?;
        let glast = gsnap
            .body
            .last_applied
            .ok_or(PairedBackupError::IncompleteCut("restored group snapshot missing last_applied"))?;
        let gseq = gsnap.body.next_event_seq.saturating_sub(1) as i64;
        let (log_idx, log_term) = (glast.index as i64, glast.term as i64);
        tx.execute(
            "INSERT INTO ref_cas_projection_cursors(group_id, history_incarnation, group_epoch, applied_event_seq, applied_log_index, applied_log_term, last_event_id, stream_state) \
             VALUES($1, $2, $3, $4, $5, $6, NULL, 'active')",
            &[&cur.group_id, &inc.new_history_incarnation, &inc.new_group_epoch, &gseq, &log_idx, &log_term],
        )
        .await
        .map_err(pg_err)?;
    }

    tx.commit().await.map_err(pg_err)?;
    Ok(())
}

/// Verify restored PG `ref_cas_projection_cursors` `(history_incarnation, group_epoch, seq, index, term)`
/// against each group's actual restored durable `RefCasSnapshot`.
pub async fn verify_pg_restored_cursors(
    client: &Client,
    restored_group_id: i64,
    restored_snap: &RefCasSnapshot,
    restored_peer_snaps: &BTreeMap<i64, RefCasSnapshot>,
) -> Result<(), PairedBackupError> {
    let mut expected_snaps = restored_peer_snaps.clone();
    expected_snaps.insert(restored_group_id, restored_snap.clone());
    let rows = client
        .query(
            "SELECT group_id, history_incarnation, group_epoch, applied_event_seq, applied_log_index, applied_log_term, stream_state \
             FROM ref_cas_projection_cursors ORDER BY group_id",
            &[],
        )
        .await
        .map_err(pg_err)?;
    if rows.len() != expected_snaps.len() {
        return Err(PairedBackupError::CutpointSkew("restored PG cursor count mismatches restored Raft groups".into()));
    }
    for row in rows {
        let (gid, hinc, gepoch, seq, idx, term, st): (i64, Uuid, i64, i64, i64, i64, String) =
            (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4), row.get(5), row.get(6));
        let Some(gsnap) = expected_snaps.get(&gid) else {
            return Err(PairedBackupError::CutpointSkew(format!("unexpected restored PG cursor group {gid}")));
        };
        let (raft_inc, raft_grp_epoch) = extract_raft_group_realm(gsnap)?;
        let glast = gsnap
            .body
            .last_applied
            .ok_or(PairedBackupError::IncompleteCut("restored group snapshot missing last_applied"))?;
        let expected_seq = gsnap.body.next_event_seq.saturating_sub(1) as i64;
        if hinc != raft_inc
            || gepoch != raft_grp_epoch
            || seq != expected_seq
            || idx != glast.index as i64
            || term != glast.term as i64
            || st != "active"
        {
            return Err(PairedBackupError::CutpointSkew(format!(
                "restored PG cursor group {gid} (inc={hinc}, grp_epoch={gepoch}, term={term}, idx={idx}, seq={seq}) skewed from restored Raft"
            )));
        }
    }
    Ok(())
}

/// Fail-closed SQL admission check enforcing restored `cluster_incarnation`, `history_incarnation`,
/// `authority_epoch`, `group_epoch`, `ref_store_decision_scopes` `authz_epoch` floor, AND `deleter_epoch` floor.
pub async fn verify_pg_live_incarnation(
    client: &Client,
    repository_id: Uuid,
    grant: &WriterGrantTicket,
    decision: Option<&DecisionExecutionTicket>,
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
    let auth_row = client
        .query_one(
            "SELECT authority_id, generation, restore_generation, authority_epoch, remote_delete_fenced \
             FROM pando_storage_authorities WHERE singleton = true",
            &[],
        )
        .await
        .map_err(pg_err)?;
    let (live_auth_id, auth_gen, restore_gen, storage_auth_e, fenced): (Uuid, i64, i64, i64, bool) =
        (auth_row.get(0), auth_row.get(1), auth_row.get(2), auth_row.get(3), auth_row.get(4));

    let gate_row = client
        .query_one(
            "SELECT history_incarnation, authority_epoch, group_epoch FROM ref_store_core_gates WHERE repository_id = $1",
            &[&repository_id],
        )
        .await
        .map_err(pg_err)?;
    let (live_hist, live_auth_e, live_grp_e): (Uuid, i64, i64) = (gate_row.get(0), gate_row.get(1), gate_row.get(2));
    if grant.history_incarnation != live_hist
        || grant.authority_epoch < live_auth_e.max(storage_auth_e)
        || grant.group_epoch < live_grp_e
    {
        return Err(PairedBackupError::StaleGrantRefused("grant incarnation/epoch behind live PG gate"));
    }

    let scope_rows = client
        .query(
            "SELECT scope_kind, state, version FROM ref_store_decision_scopes \
             WHERE (scope_kind = 'authority' AND scope_id = $1) \
                OR (scope_kind IN ('repo_lifecycle', 'repo_access') AND scope_id = $2)",
            &[&live_auth_id, &repository_id],
        )
        .await
        .map_err(pg_err)?;
    if scope_rows.len() != 3 {
        return Err(PairedBackupError::ScopeNotClosed("missing restored PG ref_store_decision_scopes rows".into()));
    }
    let mut restored_authz_floor = 0i64;
    for sr in scope_rows {
        let (kind, st, ver): (String, String, i64) = (sr.get(0), sr.get(1), sr.get(2));
        if st != "OPEN" || ver <= 0 {
            return Err(PairedBackupError::ScopeNotClosed(format!(
                "PG decision scope {kind} state={st} version={ver} not OPEN"
            )));
        }
        restored_authz_floor = restored_authz_floor.max(ver);
    }
    if grant.authz_epoch < restored_authz_floor {
        return Err(PairedBackupError::StaleGrantRefused("writer grant authz_epoch below restored PG authz_floor"));
    }

    if let Some(dec) = decision {
        if dec.history_incarnation != live_hist
            || dec.authority_epoch < live_auth_e.max(storage_auth_e)
            || dec.group_epoch < live_grp_e
            || dec.authz_epoch < restored_authz_floor
        {
            return Err(PairedBackupError::StaleDecisionRefused(dec.decision_id));
        }
        if let Some(drow) = client
            .query_opt(
                "SELECT history_incarnation, authority_epoch, group_epoch, state \
                 FROM ref_store_publication_decisions WHERE decision_id = $1",
                &[&dec.decision_id],
            )
            .await
            .map_err(pg_err)?
        {
            let (dh, da, dg, dst): (Uuid, i64, i64, String) = (drow.get(0), drow.get(1), drow.get(2), drow.get(3));
            if dh != live_hist || da < live_auth_e || dg < live_grp_e || dst != "OPEN" {
                return Err(PairedBackupError::StaleDecisionRefused(dec.decision_id));
            }
        }
    }

    if let Some(del) = deleter
        && (fenced
            || del.storage_authority_id != live_auth_id
            || del.storage_generation < auth_gen
            || restore_gen <= 0
            || del.deleter_epoch < restore_gen as u64
            || del.cluster_incarnation != cluster_inc)
    {
        return Err(PairedBackupError::StaleDeleterRefused(
            "deleter authority/generation/deleter_epoch/cluster_incarnation rejected by PG",
        ));
    }
    Ok(())
}
