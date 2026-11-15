//! Single-transaction PostgreSQL Ref-CAS event projection, durable cursor replay,
//! truncation closure reconciliation, and historical non-authorization checks (#117).

use super::jobs::{enqueue_push_webhooks_in_tx, insert_jobs_in_tx};
use super::replay::{
    CursorTransition, assert_projection_cannot_authorize_write, check_stream_continuity, complete_cursor_resync,
    plan_operation_projection, reconcile_cutoff_on_cursor, validate_cursor_step,
};
use super::types::{
    ProjectionCursor, ProjectionError, ProjectionRealm, ProjectionStreamState, RefCasEventEnvelope, RefCasEventPage,
    ReplayBatchOutcome, SingleEventOutcome, TruncationCutoff,
};
use deadpool_postgres::{Pool, Transaction};
use tokio_postgres::GenericClient;
use uuid::Uuid;

pub(crate) fn pg_err(err: tokio_postgres::Error) -> ProjectionError {
    ProjectionError::Database(err.to_string())
}

pub(crate) fn to_pg_i64(value: u64, field: &str) -> Result<i64, ProjectionError> {
    i64::try_from(value)
        .map_err(|_| ProjectionError::InvalidInput(format!("{field} overflows PostgreSQL BIGINT: {value}")))
}

pub(crate) fn from_pg_u64(value: i64, field: &str) -> Result<u64, ProjectionError> {
    u64::try_from(value)
        .map_err(|_| ProjectionError::Decode(format!("negative {field} in PostgreSQL projection row: {value}")))
}

/// Checks whether the migration-149 Ref-CAS projection tables exist in the active schema.
pub async fn projection_tables_present<C: GenericClient + Sync>(client: &C) -> Result<bool, ProjectionError> {
    let row =
        client.query_one("SELECT to_regclass('ref_cas_projection_cursors') IS NOT NULL", &[]).await.map_err(pg_err)?;
    Ok(row.get(0))
}

/// Reads the authoritative durable cursor from `ref_cas_projection_cursors`.
/// Never derives the frontier from `MAX(id)` or `MAX(sequence)` of event/delivery tables.
pub async fn load_cursor<C: GenericClient + Sync>(
    client: &C,
    group_id: i64,
    history_incarnation: Uuid,
) -> Result<Option<ProjectionCursor>, ProjectionError> {
    let row = client
        .query_opt(
            "SELECT history_incarnation, group_id, group_epoch, applied_event_seq, applied_log_index, \
                    applied_log_term, last_event_id, truncation_cutoff_log_index, \
                    truncation_cutoff_event_seq, truncation_cutoff_log_term, \
                    truncation_closure_digest, truncation_archive_uri, stream_state \
             FROM ref_cas_projection_cursors \
             WHERE group_id = $1 AND history_incarnation = $2",
            &[&group_id, &history_incarnation],
        )
        .await
        .map_err(pg_err)?;
    row.as_ref().map(decode_cursor_row).transpose()
}

pub async fn load_or_init_cursor_for_update(
    tx: &Transaction<'_>,
    realm: ProjectionRealm,
) -> Result<ProjectionCursor, ProjectionError> {
    realm.validate()?;
    tx.execute(
        "INSERT INTO ref_cas_projection_cursors \
         (group_id, history_incarnation, group_epoch, applied_event_seq, applied_log_index, \
          applied_log_term, stream_state) \
         VALUES ($1, $2, $3, 0, 0, 0, 'active') \
         ON CONFLICT (group_id, history_incarnation) DO NOTHING",
        &[&realm.group_id, &realm.history_incarnation, &realm.group_epoch],
    )
    .await
    .map_err(pg_err)?;
    let row = tx
        .query_one(
            "SELECT history_incarnation, group_id, group_epoch, applied_event_seq, applied_log_index, \
                    applied_log_term, last_event_id, truncation_cutoff_log_index, \
                    truncation_cutoff_event_seq, truncation_cutoff_log_term, \
                    truncation_closure_digest, truncation_archive_uri, stream_state \
             FROM ref_cas_projection_cursors \
             WHERE group_id = $1 AND history_incarnation = $2 FOR UPDATE",
            &[&realm.group_id, &realm.history_incarnation],
        )
        .await
        .map_err(pg_err)?;
    decode_cursor_row(&row)
}

/// Projects one committed/rejected Ref-CAS terminal event + its ref deltas + signed webhooks +
/// reliable jobs + durable cursor advancement atomically inside the caller's PostgreSQL transaction.
pub async fn project_event_in_tx(
    tx: &Transaction<'_>,
    envelope: &RefCasEventEnvelope,
    cutoff_hint: Option<&TruncationCutoff>,
) -> Result<SingleEventOutcome, ProjectionError> {
    let mut cursor = load_or_init_cursor_for_update(tx, envelope.realm).await?;
    if let Some(cutoff) = cutoff_hint {
        reconcile_cutoff_on_cursor(&mut cursor, cutoff)?;
    }

    let transition = validate_cursor_step(&cursor, envelope)?;
    let plan = plan_operation_projection(envelope)?;
    assert_projection_cannot_authorize_write(&plan.operation)?;

    let existing = tx
        .query_opt(
            "SELECT terminal_digest FROM ref_cas_projected_operations WHERE op_event_id = $1",
            &[&plan.operation.op_event_id],
        )
        .await
        .map_err(pg_err)?;
    if let Some(row) = existing {
        let stored_digest: String = row.get(0);
        if stored_digest != plan.operation.terminal_digest {
            return Err(ProjectionError::Equivocation {
                op_event_id: plan.operation.op_event_id,
                expected_digest: stored_digest,
                actual_digest: plan.operation.terminal_digest,
            });
        }
        return Ok(SingleEventOutcome::DuplicateSkipped { op_event_id: plan.operation.op_event_id, cursor });
    }
    if transition == CursorTransition::HistoricalOrDuplicate {
        return Err(ProjectionError::StreamRegression(format!(
            "cursor at {} already passed event_seq {} but operation {} is missing",
            cursor.applied_event_seq, envelope.event_seq, plan.operation.op_event_id
        )));
    }

    // Lock only the immutable repository identity (FOR SHARE) without touching `tokens` or
    // membership tables so revoked-token/removed-member committed facts still project reliably.
    let repo_row = tx
        .query_opt("SELECT owner_id FROM repositories WHERE id = $1 FOR SHARE", &[&envelope.repository_id])
        .await
        .map_err(pg_err)?
        .ok_or_else(|| ProjectionError::InvalidInput(format!("repository {} not found", envelope.repository_id)))?;
    let tenant_id: Uuid = repo_row.get(0);
    if let Some(expected_tenant) = envelope.tenant_id
        && expected_tenant != tenant_id
    {
        return Err(ProjectionError::InvalidInput("envelope tenant_id mismatches repository owner_id".into()));
    }

    let log_index = to_pg_i64(envelope.log_index, "log_index")?;
    let log_term = to_pg_i64(envelope.log_term, "log_term")?;
    let event_seq = to_pg_i64(envelope.event_seq, "event_seq")?;
    let applied_ref_count = i32::try_from(plan.operation.applied_ref_count)
        .map_err(|_| ProjectionError::InvalidInput("applied_ref_count overflow".into()))?;

    tx.execute(
        "INSERT INTO ref_cas_projected_operations \
         (op_event_id, history_incarnation, group_id, group_epoch, log_index, log_term, event_seq, \
          repository_id, tenant_id, operation_id, revision, outcome, head_ref, actor_id, token_id, \
          applied_ref_count, terminal_digest, terminal_payload, can_authorize_write) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,FALSE)",
        &[
            &plan.operation.op_event_id,
            &envelope.realm.history_incarnation,
            &envelope.realm.group_id,
            &envelope.realm.group_epoch,
            &log_index,
            &log_term,
            &event_seq,
            &envelope.repository_id,
            &tenant_id,
            &envelope.operation_id,
            &envelope.revision,
            &plan.operation.outcome,
            &plan.operation.head_ref,
            &envelope.actor_id,
            &envelope.token_id,
            &applied_ref_count,
            &plan.operation.terminal_digest,
            &envelope.payload,
        ],
    )
    .await
    .map_err(pg_err)?;

    let mut enqueued_webhooks = 0usize;
    for delta in &plan.deltas {
        tx.execute(
            "INSERT INTO ref_cas_projected_events \
             (event_id, op_event_id, repository_id, tenant_id, history_incarnation, group_id, \
              group_epoch, log_index, log_term, event_seq, operation_id, revision, ref_sequence, \
              ref_name, old_oid, new_oid, deleted) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) \
             ON CONFLICT (event_id) DO NOTHING",
            &[
                &delta.event_id,
                &plan.operation.op_event_id,
                &envelope.repository_id,
                &tenant_id,
                &envelope.realm.history_incarnation,
                &envelope.realm.group_id,
                &envelope.realm.group_epoch,
                &log_index,
                &log_term,
                &event_seq,
                &envelope.operation_id,
                &envelope.revision,
                &delta.ref_sequence,
                &delta.ref_name,
                &delta.old_oid,
                &delta.new_oid,
                &delta.deleted,
            ],
        )
        .await
        .map_err(pg_err)?;

        tx.execute(
            "INSERT INTO ref_cas_projected_refs \
             (repository_id, ref_name, oid, deleted, revision, history_incarnation, group_id, \
              group_epoch, log_index, log_term, event_seq, op_event_id, can_authorize_write) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,FALSE) \
             ON CONFLICT (repository_id, ref_name) DO UPDATE SET \
               oid = EXCLUDED.oid, deleted = EXCLUDED.deleted, revision = EXCLUDED.revision, \
               history_incarnation = EXCLUDED.history_incarnation, group_id = EXCLUDED.group_id, \
               group_epoch = EXCLUDED.group_epoch, log_index = EXCLUDED.log_index, \
               log_term = EXCLUDED.log_term, event_seq = EXCLUDED.event_seq, \
               op_event_id = EXCLUDED.op_event_id, can_authorize_write = FALSE, \
               updated_at = clock_timestamp() \
             WHERE (ref_cas_projected_refs.group_epoch, ref_cas_projected_refs.log_index, \
                    ref_cas_projected_refs.event_seq) \
                   < (EXCLUDED.group_epoch, EXCLUDED.log_index, EXCLUDED.event_seq)",
            &[
                &envelope.repository_id,
                &delta.ref_name,
                &delta.new_oid,
                &delta.deleted,
                &envelope.revision,
                &envelope.realm.history_incarnation,
                &envelope.realm.group_id,
                &envelope.realm.group_epoch,
                &log_index,
                &log_term,
                &event_seq,
                &plan.operation.op_event_id,
            ],
        )
        .await
        .map_err(pg_err)?;

        enqueued_webhooks +=
            enqueue_push_webhooks_in_tx(tx, tenant_id, envelope, &plan.operation.op_event_id, delta).await?;
    }

    let enqueued_jobs = insert_jobs_in_tx(tx, tenant_id, &plan.jobs).await?;

    cursor.realm.group_epoch = envelope.realm.group_epoch;
    cursor.applied_event_seq = envelope.event_seq;
    cursor.applied_log_index = envelope.log_index;
    cursor.applied_log_term = envelope.log_term;
    cursor.last_event_id = Some(plan.operation.op_event_id.clone());
    persist_cursor_in_tx(tx, &cursor).await?;

    Ok(SingleEventOutcome::Applied {
        op_event_id: plan.operation.op_event_id,
        projected_refs: plan.deltas.len(),
        enqueued_webhooks,
        enqueued_jobs,
        cursor,
    })
}

/// Replays one bounded event page in a single atomic PG transaction, recording any stream
/// truncation gap durably onto the cursor before returning `TruncatedBeforeCursor`.
pub async fn replay_page_to_pg(pool: &Pool, page: &RefCasEventPage) -> Result<ReplayBatchOutcome, ProjectionError> {
    let mut client = pool.get().await.map_err(|e| ProjectionError::Database(e.to_string()))?;
    let tx = client.transaction().await.map_err(pg_err)?;
    let mut cursor = load_or_init_cursor_for_update(&tx, page.realm).await?;
    if let Err(err) = check_stream_continuity(&mut cursor, page) {
        persist_cursor_in_tx(&tx, &cursor).await?;
        tx.commit().await.map_err(pg_err)?;
        return Err(err);
    }
    persist_cursor_in_tx(&tx, &cursor).await?;

    let mut summary = ReplayBatchOutcome {
        applied_events: 0,
        duplicate_skipped: 0,
        projected_refs: 0,
        enqueued_webhooks: 0,
        enqueued_jobs: 0,
        batches: usize::from(!page.events.is_empty()),
        cursor,
    };

    for env in &page.events {
        match project_event_in_tx(&tx, env, page.truncation_cutoff.as_ref()).await? {
            SingleEventOutcome::Applied { projected_refs, enqueued_webhooks, enqueued_jobs, cursor, .. } => {
                summary.applied_events += 1;
                summary.projected_refs += projected_refs;
                summary.enqueued_webhooks += enqueued_webhooks;
                summary.enqueued_jobs += enqueued_jobs;
                summary.cursor = cursor;
            }
            SingleEventOutcome::DuplicateSkipped { cursor, .. } => {
                summary.duplicate_skipped += 1;
                summary.cursor = cursor;
            }
            SingleEventOutcome::ResyncRequired { cursor } => {
                summary.cursor = cursor;
                tx.commit().await.map_err(pg_err)?;
                return Err(ProjectionError::ResyncRequired("projection stream paused for resync".into()));
            }
        }
    }

    tx.commit().await.map_err(pg_err)?;
    Ok(summary)
}

pub async fn record_truncation_cutoff_in_tx(
    tx: &Transaction<'_>,
    realm: ProjectionRealm,
    cutoff: &TruncationCutoff,
) -> Result<ProjectionCursor, ProjectionError> {
    let mut cursor = load_or_init_cursor_for_update(tx, realm).await?;
    reconcile_cutoff_on_cursor(&mut cursor, cutoff)?;
    persist_cursor_in_tx(tx, &cursor).await?;
    Ok(cursor)
}

pub async fn complete_cursor_resync_in_tx(
    tx: &Transaction<'_>,
    realm: ProjectionRealm,
    cutoff: TruncationCutoff,
    verified_last_event_id: Option<String>,
) -> Result<ProjectionCursor, ProjectionError> {
    let mut cursor = load_or_init_cursor_for_update(tx, realm).await?;
    complete_cursor_resync(&mut cursor, cutoff, verified_last_event_id)?;
    persist_cursor_in_tx(tx, &cursor).await?;
    Ok(cursor)
}

/// Proves that a projected operation record exists with `can_authorize_write = false` and
/// does not grant entries in `ref_admissions`, `git_ref_admissions`, or `ref_store_publication_decisions`.
pub async fn verify_projected_operation_non_authorizing<C: GenericClient + Sync>(
    client: &C,
    op_event_id: &str,
) -> Result<bool, ProjectionError> {
    let row = client
        .query_opt(
            "SELECT o.can_authorize_write, \
                    EXISTS(SELECT 1 FROM ref_cas_projected_refs r \
                           WHERE r.op_event_id = o.op_event_id AND r.can_authorize_write) AS writable_ref \
             FROM ref_cas_projected_operations o WHERE o.op_event_id = $1",
            &[&op_event_id],
        )
        .await
        .map_err(pg_err)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let can_authorize: bool = row.get("can_authorize_write");
    let writable_ref: bool = row.get("writable_ref");
    if can_authorize || writable_ref {
        return Err(ProjectionError::AuthorityViolation("projected row illegally flagged writable"));
    }
    Ok(true)
}

async fn persist_cursor_in_tx(tx: &Transaction<'_>, cursor: &ProjectionCursor) -> Result<(), ProjectionError> {
    let applied_seq = to_pg_i64(cursor.applied_event_seq, "applied_event_seq")?;
    let applied_log_index = to_pg_i64(cursor.applied_log_index, "applied_log_index")?;
    let applied_log_term = to_pg_i64(cursor.applied_log_term, "applied_log_term")?;
    let (cutoff_log, cutoff_seq, cutoff_term, cutoff_digest, cutoff_uri) = match &cursor.truncation_cutoff {
        Some(c) => (
            Some(to_pg_i64(c.log_index, "truncation_cutoff_log_index")?),
            Some(to_pg_i64(c.event_seq, "truncation_cutoff_event_seq")?),
            Some(to_pg_i64(c.log_term, "truncation_cutoff_log_term")?),
            Some(c.closure_digest.as_str()),
            c.archive_uri.as_deref(),
        ),
        None => (None, None, None, None, None),
    };
    tx.execute(
        "UPDATE ref_cas_projection_cursors \
         SET group_epoch = $3, applied_event_seq = $4, applied_log_index = $5, \
             applied_log_term = $6, last_event_id = $7, truncation_cutoff_log_index = $8, \
             truncation_cutoff_event_seq = $9, truncation_cutoff_log_term = $10, \
             truncation_closure_digest = $11, truncation_archive_uri = $12, \
             stream_state = $13, updated_at = clock_timestamp() \
         WHERE group_id = $1 AND history_incarnation = $2",
        &[
            &cursor.realm.group_id,
            &cursor.realm.history_incarnation,
            &cursor.realm.group_epoch,
            &applied_seq,
            &applied_log_index,
            &applied_log_term,
            &cursor.last_event_id,
            &cutoff_log,
            &cutoff_seq,
            &cutoff_term,
            &cutoff_digest,
            &cutoff_uri,
            &cursor.stream_state.as_str(),
        ],
    )
    .await
    .map_err(pg_err)?;
    Ok(())
}

fn decode_cursor_row(row: &tokio_postgres::Row) -> Result<ProjectionCursor, ProjectionError> {
    let realm = ProjectionRealm::new(row.get("history_incarnation"), row.get("group_id"), row.get("group_epoch"))?;
    let applied_event_seq = from_pg_u64(row.get("applied_event_seq"), "applied_event_seq")?;
    let applied_log_index = from_pg_u64(row.get("applied_log_index"), "applied_log_index")?;
    let applied_log_term = from_pg_u64(row.get("applied_log_term"), "applied_log_term")?;
    let cutoff_log: Option<i64> = row.get("truncation_cutoff_log_index");
    let cutoff_seq: Option<i64> = row.get("truncation_cutoff_event_seq");
    let cutoff_term: Option<i64> = row.get("truncation_cutoff_log_term");
    let cutoff_digest: Option<String> = row.get("truncation_closure_digest");
    let cutoff_uri: Option<String> = row.get("truncation_archive_uri");
    let truncation_cutoff = match (cutoff_log, cutoff_seq, cutoff_term, cutoff_digest) {
        (Some(log_idx), Some(seq), Some(term), Some(digest)) => {
            let cutoff = TruncationCutoff {
                log_index: from_pg_u64(log_idx, "truncation_cutoff_log_index")?,
                event_seq: from_pg_u64(seq, "truncation_cutoff_event_seq")?,
                log_term: from_pg_u64(term, "truncation_cutoff_log_term")?,
                closure_digest: digest,
                archive_uri: cutoff_uri,
            };
            cutoff.validate()?;
            Some(cutoff)
        }
        (None, None, None, None) => None,
        _ => {
            return Err(ProjectionError::Decode(
                "incomplete truncation cutoff columns in ref_cas_projection_cursors".into(),
            ));
        }
    };
    Ok(ProjectionCursor {
        realm,
        applied_event_seq,
        applied_log_index,
        applied_log_term,
        last_event_id: row.get("last_event_id"),
        truncation_cutoff,
        stream_state: ProjectionStreamState::parse(row.get("stream_state"))?,
    })
}
