//! PostgreSQL 17 consistent cutpoint capture and cursor `group_epoch` reconciliation (#153).

use std::collections::{BTreeMap, BTreeSet};

use tokio_postgres::{GenericClient, Transaction};
use uuid::Uuid;

use crate::ref_store::GitObjectFormat;

use super::types::{
    PairedBackupError, PgCutpointProof, PgProjectionCursorCut, PgRepositoryRowProof, sha256_json_tagged,
};

#[derive(Clone, Debug)]
pub struct ExpectedRaftCut {
    pub group_id: i64,
    pub history_incarnation: Uuid,
    pub group_epoch: i64,
    pub peer_group_epochs: BTreeMap<i64, i64>,
    pub applied_index: u64,
    pub applied_term: u64,
    pub applied_event_seq: u64,
}

impl ExpectedRaftCut {
    pub fn all_group_epochs(&self) -> BTreeMap<i64, i64> {
        let mut all = self.peer_group_epochs.clone();
        all.insert(self.group_id, self.group_epoch);
        all
    }
}

pub(super) fn pg_err(err: tokio_postgres::Error) -> PairedBackupError {
    let detail = err
        .as_db_error()
        .map_or_else(|| err.to_string(), |db| format!("{}: {} ({:?})", db.severity(), db.message(), db.detail()));
    PairedBackupError::Postgres(detail)
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
    let updated = client
        .execute(
            "UPDATE pando_storage_authorities \
             SET remote_delete_fenced = true, remote_delete_fence_reason = $1 \
             WHERE singleton = true",
            &[&reason],
        )
        .await
        .map_err(pg_err)?;
    if updated != 1 {
        return Err(PairedBackupError::DeleterNotFenced("singleton pando_storage_authorities row missing"));
    }
    Ok(())
}

/// Capture an immutable PG 17 repeatable-read cutpoint and reconcile projection cursors
/// (`group_epoch` across all Raft groups + log index/term/seq) and pending decisions/outbox.
pub async fn capture_pg_cutpoint_in_tx(
    tx: &Transaction<'_>,
    expected: &ExpectedRaftCut,
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
    let max_decision_scope_version: i64 = tx
        .query_one("SELECT COALESCE(max(version), 0)::bigint FROM ref_store_decision_scopes", &[])
        .await
        .map_err(pg_err)?
        .get(0);

    let pending_decisions_count: i64 = tx
        .query_one("SELECT count(*)::bigint FROM ref_store_publication_decisions WHERE state = 'OPEN'", &[])
        .await
        .map_err(pg_err)?
        .get(0);
    let pending_outbox_val: i64 = tx
        .query_one(
            "SELECT (SELECT count(*)::bigint FROM git_operations WHERE outcome = 'unknown') \
             + (SELECT count(*)::bigint FROM event_deliveries WHERE state <> 'delivered') \
             + (SELECT count(*)::bigint FROM ref_cas_projection_jobs WHERE state IN ('queued','running','unknown_hold'))",
            &[],
        )
        .await
        .map_err(pg_err)?
        .get(0);
    if pending_decisions_count != 0 || pending_outbox_val != 0 {
        return Err(PairedBackupError::UnknownInFlightOperations(
            (pending_decisions_count + pending_outbox_val) as usize,
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

    let expected_epochs = expected.all_group_epochs();
    if projection_cursors.len() != expected_epochs.len() {
        return Err(PairedBackupError::CutpointSkew(format!(
            "PG projection_cursors count ({}) != expected Raft group count ({})",
            projection_cursors.len(),
            expected_epochs.len()
        )));
    }
    let mut seen_groups = BTreeSet::new();
    for cur in &projection_cursors {
        if !seen_groups.insert(cur.group_id)
            || cur.group_epoch <= 0
            || cur.history_incarnation.is_nil()
            || cur.stream_state != "active"
        {
            return Err(PairedBackupError::CutpointSkew(format!(
                "PG cursor group {} duplicate, invalid group_epoch {}, or stream_state {}",
                cur.group_id, cur.group_epoch, cur.stream_state
            )));
        }
        let Some(&exp_epoch) = expected_epochs.get(&cur.group_id) else {
            return Err(PairedBackupError::CutpointSkew(format!("unbound PG cursor for group {}", cur.group_id)));
        };
        if cur.group_epoch != exp_epoch {
            return Err(PairedBackupError::CutpointSkew(format!(
                "PG cursor group {} group_epoch {} != Raft group_epoch {}",
                cur.group_id, cur.group_epoch, exp_epoch
            )));
        }
    }

    let matched_cursor = projection_cursors
        .iter()
        .find(|c| c.group_id == expected.group_id && c.history_incarnation == expected.history_incarnation)
        .ok_or_else(|| {
            PairedBackupError::CutpointSkew(
                "missing PG ref_cas_projection_cursors row for active Raft group/incarnation".into(),
            )
        })?;
    if matched_cursor.group_epoch != expected.group_epoch
        || matched_cursor.applied_log_index as u64 != expected.applied_index
        || matched_cursor.applied_log_term as u64 != expected.applied_term
        || matched_cursor.applied_event_seq as u64 != expected.applied_event_seq
    {
        return Err(PairedBackupError::CutpointSkew(format!(
            "PG projection cursor (grp_epoch={},{},{},{}) != Raft cut (grp_epoch={},{},{},{})",
            matched_cursor.group_epoch,
            matched_cursor.applied_log_term,
            matched_cursor.applied_log_index,
            matched_cursor.applied_event_seq,
            expected.group_epoch,
            expected.applied_term,
            expected.applied_index,
            expected.applied_event_seq,
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
        let history_incarnation: Uuid = row.get(5);
        let group_epoch: i64 = row.get(7);
        if history_incarnation != expected.history_incarnation || group_epoch != expected.group_epoch {
            return Err(PairedBackupError::CutpointSkew(format!(
                "PG repository {repository_id} (inc={history_incarnation}, group_epoch={group_epoch}) != Raft cut",
            )));
        }
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
            history_incarnation,
            authority_epoch: row.get(6),
            group_epoch,
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
        max_decision_scope_version,
        pending_decisions_count,
        pending_outbox_count: pending_outbox_val,
        projection_cursors,
        repositories,
        cutpoint_digest: String::new(),
    }
    .seal()
}
