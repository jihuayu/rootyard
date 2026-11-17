//! PostgreSQL 17 monotonic projection store for remote-authz PR merge attempts (`Refs #156`).
//!
//! Creates test/ephemeral tables via [`init_remote_merge_tables`] without modifying `migrations/`
//! or `schema/`, enforces one-way `committed_merge` immutability triggers in SQL, and synchronizes
//! `forge_pulls` only after confirming an authoritative Ref-CAS receipt.

use deadpool_postgres::Pool;
use tokio_postgres::Row;
use uuid::Uuid;

use super::projector::{BoxFuture, MergeReceiptStore};
use super::types::{
    CommittedMergeReceipt, MergeStrategy, PendingMergeRecord, ProjectionOutcome, PullMergeState, RejectedMergeReceipt,
    RemoteMergeError,
};

const ATTEMPT_SELECT: &str = "attempt_id, operation_id, decision_id, tenant_id, repository_id, pull_number, \
    base_ref, expected_head_oid, expected_base_oid, candidate_target_oid, expected_version, \
    expected_storage_generation, strategy, authz_epoch, pack_sha256, facts_digest, state, \
    commit_log_index, commit_log_term, merged_oid, terminal_digest, reject_reason";

/// Creates ephemeral/test attempt tracking tables + immutability triggers inside the caller's schema.
pub async fn init_remote_merge_tables(pool: &Pool) -> Result<(), RemoteMergeError> {
    let client = pool.get().await.map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS pull_remote_merge_attempts (
                repository_id UUID NOT NULL,
                operation_id UUID NOT NULL,
                attempt_id UUID NOT NULL,
                decision_id UUID NOT NULL,
                tenant_id UUID NOT NULL,
                pull_number BIGINT NOT NULL CHECK (pull_number > 0),
                base_ref TEXT NOT NULL CHECK (base_ref LIKE 'refs/heads/%'),
                expected_head_oid TEXT NOT NULL CHECK (expected_head_oid ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
                expected_base_oid TEXT NOT NULL CHECK (expected_base_oid ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
                candidate_target_oid TEXT NOT NULL CHECK (candidate_target_oid ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
                expected_version BIGINT NOT NULL CHECK (expected_version > 0),
                expected_storage_generation BIGINT NOT NULL CHECK (expected_storage_generation > 0),
                strategy TEXT NOT NULL CHECK (strategy IN ('fast_forward', 'merge_commit')),
                authz_epoch BIGINT NOT NULL CHECK (authz_epoch >= 0),
                pack_sha256 TEXT NOT NULL CHECK (pack_sha256 ~ '^[0-9a-f]{64}$'),
                facts_digest TEXT NOT NULL CHECK (facts_digest ~ '^[0-9a-f]{64}$'),
                state TEXT NOT NULL CHECK (state IN ('pending_merge', 'committed_merge', 'rejected_merge', 'aborted_before_cas')),
                commit_log_index BIGINT CHECK (commit_log_index IS NULL OR commit_log_index > 0),
                commit_log_term BIGINT CHECK (commit_log_term IS NULL OR commit_log_term >= 0),
                merged_oid TEXT CHECK (merged_oid IS NULL OR merged_oid ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
                terminal_digest TEXT CHECK (terminal_digest IS NULL OR terminal_digest ~ '^[0-9a-f]{64}$'),
                reject_reason TEXT,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
                PRIMARY KEY (repository_id, operation_id),
                CHECK (
                    (state = 'committed_merge' AND commit_log_index IS NOT NULL AND merged_oid IS NOT NULL AND terminal_digest IS NOT NULL)
                    OR state <> 'committed_merge'
                )
            );
            CREATE OR REPLACE FUNCTION pull_remote_merge_monotonic_guard() RETURNS trigger AS $$
            BEGIN
                IF TG_OP = 'DELETE' THEN
                    RAISE EXCEPTION 'pull_remote_merge_attempts rows cannot be deleted';
                END IF;
                IF OLD.state = 'committed_merge' AND (
                    NEW.state <> 'committed_merge'
                    OR NEW.merged_oid IS DISTINCT FROM OLD.merged_oid
                    OR NEW.commit_log_index IS DISTINCT FROM OLD.commit_log_index
                    OR NEW.terminal_digest IS DISTINCT FROM OLD.terminal_digest
                    OR NEW.pack_sha256 IS DISTINCT FROM OLD.pack_sha256
                    OR NEW.facts_digest IS DISTINCT FROM OLD.facts_digest
                ) THEN
                    RAISE EXCEPTION 'committed_merge receipt is immutable and cannot regress or equivocate';
                END IF;
                IF OLD.state IN ('rejected_merge', 'aborted_before_cas') AND NEW.state <> OLD.state THEN
                    RAISE EXCEPTION 'terminal non-committed state % cannot transition to %', OLD.state, NEW.state;
                END IF;
                NEW.updated_at := clock_timestamp();
                RETURN NEW;
            END $$ LANGUAGE plpgsql;
            DROP TRIGGER IF EXISTS pull_remote_merge_monotonic_trig ON pull_remote_merge_attempts;
            CREATE TRIGGER pull_remote_merge_monotonic_trig
                BEFORE UPDATE OR DELETE ON pull_remote_merge_attempts
                FOR EACH ROW EXECUTE FUNCTION pull_remote_merge_monotonic_guard();",
        )
        .await
        .map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
    Ok(())
}

#[derive(Clone)]
pub struct PgMergeStore {
    pool: Pool,
}

impl PgMergeStore {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    fn decode_row(row: &Row) -> Result<PendingMergeRecord, RemoteMergeError> {
        let strategy_raw: String = row.get(12);
        let strategy = match strategy_raw.as_str() {
            "fast_forward" => MergeStrategy::FastForward,
            "merge_commit" => MergeStrategy::MergeCommit,
            other => return Err(RemoteMergeError::InvalidInput(format!("bad strategy `{other}`"))),
        };
        let state_raw: String = row.get(16);
        let state = PullMergeState::parse(&state_raw)?;
        let log_idx_opt: Option<i64> = row.get(17);
        let log_term_opt: Option<i64> = row.get(18);
        Ok(PendingMergeRecord {
            attempt_id: row.get(0),
            operation_id: row.get(1),
            decision_id: row.get(2),
            tenant_id: row.get(3),
            repository_id: row.get(4),
            pull_number: row.get(5),
            base_ref: row.get(6),
            expected_head_oid: row.get(7),
            expected_base_oid: row.get(8),
            candidate_target_oid: row.get(9),
            expected_version: row.get(10),
            expected_storage_generation: row.get(11),
            strategy,
            authz_epoch: row.get(13),
            pack_sha256: row.get(14),
            facts_digest: row.get(15),
            state,
            commit_log_index: log_idx_opt.map(|v| v as u64),
            commit_log_term: log_term_opt.map(|v| v as u64),
            merged_oid: row.get(19),
            terminal_digest: row.get(20),
            reject_reason: row.get(21),
        })
    }
}

impl MergeReceiptStore for PgMergeStore {
    fn insert_pending<'a>(&'a self, record: &'a PendingMergeRecord) -> BoxFuture<'a, Result<(), RemoteMergeError>> {
        Box::pin(async move {
            let mut client = self.pool.get().await.map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
            let tx = client.transaction().await.map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
            tx.batch_execute("SET LOCAL synchronous_commit = 'on'")
                .await
                .map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;

            if let Some(winner) = tx
                .query_opt(
                    "SELECT pull_number, merged_oid, commit_log_index FROM pull_remote_merge_attempts
                     WHERE repository_id = $1 AND pull_number = $2 AND state = 'committed_merge'
                       AND operation_id <> $3 FOR UPDATE",
                    &[&record.repository_id, &record.pull_number, &record.operation_id],
                )
                .await
                .map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?
            {
                let oid: Option<String> = winner.get(1);
                let idx: Option<i64> = winner.get(2);
                return Err(RemoteMergeError::AlreadyMerged {
                    pull_number: winner.get(0),
                    committed_oid: oid.unwrap_or_default(),
                    commit_log_index: idx.unwrap_or(0) as u64,
                });
            }

            if let Some(row) = tx
                .query_opt(
                    &format!("SELECT {ATTEMPT_SELECT} FROM pull_remote_merge_attempts WHERE repository_id=$1 AND operation_id=$2 FOR UPDATE"),
                    &[&record.repository_id, &record.operation_id],
                )
                .await
                .map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?
            {
                let existing = Self::decode_row(&row)?;
                if existing.state == PullMergeState::CommittedMerge {
                    return Err(RemoteMergeError::ReceiptRegression(
                        "cannot re-insert PendingMerge over CommittedMerge".into(),
                    ));
                }
                if &existing == record {
                    tx.commit().await.map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
                    return Ok(());
                }
                return Err(RemoteMergeError::Equivocation("conflicting PG PendingMergeRecord".into()));
            }

            tx.execute(
                "INSERT INTO pull_remote_merge_attempts (
                    attempt_id, operation_id, decision_id, tenant_id, repository_id, pull_number,
                    base_ref, expected_head_oid, expected_base_oid, candidate_target_oid,
                    expected_version, expected_storage_generation, strategy, authz_epoch, pack_sha256,
                    facts_digest, state
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,'pending_merge')",
                &[
                    &record.attempt_id,
                    &record.operation_id,
                    &record.decision_id,
                    &record.tenant_id,
                    &record.repository_id,
                    &record.pull_number,
                    &record.base_ref,
                    &record.expected_head_oid,
                    &record.expected_base_oid,
                    &record.candidate_target_oid,
                    &record.expected_version,
                    &record.expected_storage_generation,
                    &record.strategy.as_str(),
                    &record.authz_epoch,
                    &record.pack_sha256,
                    &record.facts_digest,
                ],
            )
            .await
            .map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
            tx.commit().await.map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
            Ok(())
        })
    }

    fn project_committed<'a>(
        &'a self,
        receipt: &'a CommittedMergeReceipt,
        storage_generation: i64,
        expected_version: i64,
        update_forge_pulls: bool,
    ) -> BoxFuture<'a, Result<ProjectionOutcome, RemoteMergeError>> {
        Box::pin(async move {
            let log_idx = i64::try_from(receipt.commit_log_index)
                .map_err(|_| RemoteMergeError::InvalidInput("commit_log_index overflows i64".into()))?;
            let log_term = i64::try_from(receipt.commit_log_term)
                .map_err(|_| RemoteMergeError::InvalidInput("commit_log_term overflows i64".into()))?;
            let mut client = self.pool.get().await.map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
            let tx = client.transaction().await.map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
            tx.batch_execute("SET LOCAL synchronous_commit = 'on'")
                .await
                .map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;

            if let Some(other) = tx
                .query_opt(
                    "SELECT pull_number, merged_oid, commit_log_index FROM pull_remote_merge_attempts
                     WHERE repository_id=$1 AND pull_number=$2 AND state='committed_merge' AND operation_id<>$3 FOR UPDATE",
                    &[&receipt.repository_id, &receipt.pull_number, &receipt.operation_id],
                )
                .await
                .map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?
            {
                let oid: Option<String> = other.get(1);
                let idx: Option<i64> = other.get(2);
                return Err(RemoteMergeError::AlreadyMerged {
                    pull_number: other.get(0),
                    committed_oid: oid.unwrap_or_default(),
                    commit_log_index: idx.unwrap_or(0) as u64,
                });
            }

            let row = tx
                .query_opt(
                    &format!("SELECT {ATTEMPT_SELECT} FROM pull_remote_merge_attempts WHERE repository_id=$1 AND operation_id=$2 FOR UPDATE"),
                    &[&receipt.repository_id, &receipt.operation_id],
                )
                .await
                .map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?
                .ok_or_else(|| RemoteMergeError::InvalidInput("PG attempt row missing".into()))?;
            let existing = Self::decode_row(&row)?;
            let replayed = match existing.state {
                PullMergeState::CommittedMerge => {
                    if existing.merged_oid.as_deref() != Some(receipt.merged_oid.as_str())
                        || existing.commit_log_index != Some(receipt.commit_log_index)
                        || existing.terminal_digest.as_deref() != Some(receipt.terminal_digest.as_str())
                    {
                        return Err(RemoteMergeError::Equivocation("PG CommittedMerge receipt differs".into()));
                    }
                    true
                }
                PullMergeState::RejectedMerge | PullMergeState::AbortedBeforeCas => {
                    return Err(RemoteMergeError::ReceiptRegression(
                        "cannot promote PG Rejected/Aborted attempt to CommittedMerge".into(),
                    ));
                }
                PullMergeState::PendingMerge => {
                    tx.execute(
                        "UPDATE pull_remote_merge_attempts
                         SET state='committed_merge', commit_log_index=$3, commit_log_term=$4,
                             merged_oid=$5, terminal_digest=$6
                         WHERE repository_id=$1 AND operation_id=$2",
                        &[
                            &receipt.repository_id,
                            &receipt.operation_id,
                            &log_idx,
                            &log_term,
                            &receipt.merged_oid,
                            &receipt.terminal_digest,
                        ],
                    )
                    .await
                    .map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
                    false
                }
            };

            if update_forge_pulls {
                let pull_row = tx
                    .query_opt(
                        "SELECT state, merge_commit_oid, version FROM forge_pulls
                         WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 FOR UPDATE",
                        &[&receipt.tenant_id, &receipt.repository_id, &receipt.pull_number],
                    )
                    .await
                    .map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?
                    .ok_or_else(|| RemoteMergeError::InvalidInput("forge_pulls row not found".into()))?;
                let pr_state: String = pull_row.get(0);
                let pr_oid: Option<String> = pull_row.get(1);
                let pr_ver: i64 = pull_row.get(2);
                if pr_state == "merged" {
                    if pr_oid.as_deref() != Some(receipt.merged_oid.as_str()) {
                        return Err(RemoteMergeError::Equivocation(
                            "forge_pulls already merged with different OID".into(),
                        ));
                    }
                } else if pr_state == "open" && pr_ver == expected_version {
                    tx.execute(
                        "UPDATE forge_pulls
                         SET state='merged', merge_commit_oid=$4, merged_storage_generation=$5,
                             version=version+1, updated_at=clock_timestamp()
                         WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 AND version=$6 AND state='open'",
                        &[
                            &receipt.tenant_id,
                            &receipt.repository_id,
                            &receipt.pull_number,
                            &receipt.merged_oid,
                            &storage_generation,
                            &expected_version,
                        ],
                    )
                    .await
                    .map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
                } else {
                    return Err(RemoteMergeError::Equivocation(
                        "forge_pulls state/version diverged from receipt".into(),
                    ));
                }
            }

            tx.commit().await.map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
            Ok(ProjectionOutcome::ProjectedCommitted { replayed })
        })
    }

    fn project_rejected<'a>(
        &'a self,
        receipt: &'a RejectedMergeReceipt,
    ) -> BoxFuture<'a, Result<ProjectionOutcome, RemoteMergeError>> {
        Box::pin(async move {
            let log_idx = receipt.commit_log_index.map(|v| v as i64);
            let log_term = receipt.commit_log_term.map(|v| v as i64);
            let mut client = self.pool.get().await.map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
            let tx = client.transaction().await.map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
            tx.batch_execute("SET LOCAL synchronous_commit = 'on'")
                .await
                .map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
            let row = tx
                .query_opt(
                    &format!("SELECT {ATTEMPT_SELECT} FROM pull_remote_merge_attempts WHERE repository_id=$1 AND operation_id=$2 FOR UPDATE"),
                    &[&receipt.repository_id, &receipt.operation_id],
                )
                .await
                .map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?
                .ok_or_else(|| RemoteMergeError::InvalidInput("PG attempt row missing".into()))?;
            let existing = Self::decode_row(&row)?;
            let replayed = match existing.state {
                PullMergeState::CommittedMerge => {
                    return Err(RemoteMergeError::ReceiptRegression(
                        "cannot downgrade PG CommittedMerge to RejectedMerge".into(),
                    ));
                }
                PullMergeState::AbortedBeforeCas => {
                    return Err(RemoteMergeError::ReceiptRegression(
                        "cannot transition PG AbortedBeforeCas to RejectedMerge".into(),
                    ));
                }
                PullMergeState::RejectedMerge => true,
                PullMergeState::PendingMerge => {
                    tx.execute(
                        "UPDATE pull_remote_merge_attempts
                         SET state='rejected_merge', commit_log_index=$3, commit_log_term=$4,
                             terminal_digest=$5, reject_reason=$6
                         WHERE repository_id=$1 AND operation_id=$2",
                        &[
                            &receipt.repository_id,
                            &receipt.operation_id,
                            &log_idx,
                            &log_term,
                            &receipt.terminal_digest,
                            &receipt.reason,
                        ],
                    )
                    .await
                    .map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
                    false
                }
            };
            tx.commit().await.map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
            Ok(ProjectionOutcome::ProjectedRejected { replayed })
        })
    }

    fn project_aborted_before_cas<'a>(
        &'a self,
        repository_id: Uuid,
        operation_id: Uuid,
        reason: &'a str,
    ) -> BoxFuture<'a, Result<ProjectionOutcome, RemoteMergeError>> {
        Box::pin(async move {
            let mut client = self.pool.get().await.map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
            let tx = client.transaction().await.map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
            tx.batch_execute("SET LOCAL synchronous_commit = 'on'")
                .await
                .map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
            let row = tx
                .query_opt(
                    &format!("SELECT {ATTEMPT_SELECT} FROM pull_remote_merge_attempts WHERE repository_id=$1 AND operation_id=$2 FOR UPDATE"),
                    &[&repository_id, &operation_id],
                )
                .await
                .map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?
                .ok_or_else(|| RemoteMergeError::InvalidInput("PG attempt row missing".into()))?;
            let existing = Self::decode_row(&row)?;
            let replayed = match existing.state {
                PullMergeState::CommittedMerge => {
                    return Err(RemoteMergeError::ReceiptRegression(
                        "cannot downgrade PG CommittedMerge to AbortedBeforeCas".into(),
                    ));
                }
                PullMergeState::RejectedMerge => {
                    return Err(RemoteMergeError::ReceiptRegression(
                        "cannot transition PG RejectedMerge to AbortedBeforeCas".into(),
                    ));
                }
                PullMergeState::AbortedBeforeCas => true,
                PullMergeState::PendingMerge => {
                    tx.execute(
                        "UPDATE pull_remote_merge_attempts SET state='aborted_before_cas', reject_reason=$3
                         WHERE repository_id=$1 AND operation_id=$2",
                        &[&repository_id, &operation_id, &reason],
                    )
                    .await
                    .map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
                    false
                }
            };
            tx.commit().await.map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
            Ok(ProjectionOutcome::ProjectedAborted { replayed })
        })
    }

    fn list_pending<'a>(
        &'a self,
        repository_id: Uuid,
    ) -> BoxFuture<'a, Result<Vec<PendingMergeRecord>, RemoteMergeError>> {
        Box::pin(async move {
            let client = self.pool.get().await.map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
            let rows = client
                .query(
                    &format!("SELECT {ATTEMPT_SELECT} FROM pull_remote_merge_attempts WHERE repository_id=$1 AND state='pending_merge' ORDER BY pull_number ASC, operation_id ASC"),
                    &[&repository_id],
                )
                .await
                .map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
            rows.iter().map(Self::decode_row).collect()
        })
    }

    fn load_attempt<'a>(
        &'a self,
        repository_id: Uuid,
        operation_id: Uuid,
    ) -> BoxFuture<'a, Result<Option<PendingMergeRecord>, RemoteMergeError>> {
        Box::pin(async move {
            let client = self.pool.get().await.map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
            let row = client
                .query_opt(
                    &format!("SELECT {ATTEMPT_SELECT} FROM pull_remote_merge_attempts WHERE repository_id=$1 AND operation_id=$2"),
                    &[&repository_id, &operation_id],
                )
                .await
                .map_err(|e| RemoteMergeError::PgDatabase(e.to_string()))?;
            row.as_ref().map(Self::decode_row).transpose()
        })
    }
}
