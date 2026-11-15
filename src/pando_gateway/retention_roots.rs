//! Durable backup and PITR retention roots for Pando remote artifacts (#77).
//!
//! Retention roots record manifests reachable at a backup snapshot, PITR
//! recovery point, or explicit operator pin under `pando_retention_roots` and
//! `pando_retention_root_manifests`. While an active root exists (and has not
//! passed `retain_until`), Pando GC refuses to retire or delete any linked
//! ciphertext or envelope object under the active authority.
use crate::pando_gateway::{pitr_fence, retention};
use crate::storage::remote_objects::RemoteObjectStore;
use anyhow::{Context, Result, ensure};
use deadpool_postgres::Pool;
use serde::Serialize;
use std::path::Path;
use tokio::time::Instant;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionRootKind {
    BackupSnapshot,
    PitrRecoveryPoint,
    ManualPin,
}

impl RetentionRootKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BackupSnapshot => "backup_snapshot",
            Self::PitrRecoveryPoint => "pitr_recovery_point",
            Self::ManualPin => "manual_pin",
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "backup_snapshot" => Ok(Self::BackupSnapshot),
            "pitr_recovery_point" => Ok(Self::PitrRecoveryPoint),
            "manual_pin" => Ok(Self::ManualPin),
            _ => anyhow::bail!("retention root kind must be backup_snapshot, pitr_recovery_point or manual_pin"),
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RetentionRootSummary {
    pub id: Uuid,
    pub authority_id: Uuid,
    pub tenant_id: Uuid,
    pub repository_id: Option<Uuid>,
    pub root_kind: String,
    pub state: String,
    pub restore_generation: i64,
    pub external_lsn: Option<String>,
    pub note: Option<String>,
    pub manifest_count: usize,
}

/// Collect currently reachable or active Pando pack manifests for a tenant (and
/// optional repository), pin them under a durable retention root, and advance the
/// external bucket epoch proof so any future PITR rollback fails closed against
/// deleting objects required by this recovery point.
#[allow(clippy::too_many_arguments)]
pub async fn pin_recovery_root(
    pool: &Pool,
    data_dir: &Path,
    remote: &RemoteObjectStore,
    tenant_id: Uuid,
    repository_id: Option<Uuid>,
    kind: RetentionRootKind,
    note: Option<&str>,
    retain_until_secs: Option<i64>,
    explicit_manifests: &[Uuid],
    deadline: Instant,
) -> Result<RetentionRootSummary> {
    if let Some(note_text) = note {
        ensure!(note_text.len() <= 512, "retention root note exceeds 512 bytes");
    }
    if let Some(secs) = retain_until_secs {
        ensure!(secs > 0 && secs <= 10 * 365 * 86_400, "retain_until_secs out of valid range");
    }

    let prepared = pitr_fence::begin_epoch_advance(pool, data_dir, remote, "pin_recovery_root", deadline).await?;
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let committed = pitr_fence::commit_epoch_advance_in_tx(&*tx, &prepared).await?;

    let external_lsn: String = tx
        .query_one(
            "SELECT CASE WHEN pg_is_in_recovery() THEN pg_last_wal_replay_lsn()::text \
             ELSE pg_current_wal_lsn()::text END",
            &[],
        )
        .await?
        .get(0);

    let root_id = Uuid::new_v4();
    let retain_until_secs_f = retain_until_secs.map(|s| s as f64);
    let note_owned = note.map(str::to_owned);
    tx.execute(
        "INSERT INTO pando_retention_roots \
         (id, authority_id, tenant_id, repository_id, root_kind, state, restore_generation, \
          external_lsn, note, retain_until) \
         VALUES ($1, $2, $3, $4, $5, 'active', $6, $7, $8, \
                 CASE WHEN $9::double precision IS NULL THEN NULL \
                 ELSE clock_timestamp() + make_interval(secs => $9::double precision) END)",
        &[
            &root_id,
            &committed.authority_id,
            &tenant_id,
            &repository_id,
            &kind.as_str(),
            &committed.restore_generation,
            &external_lsn,
            &note_owned,
            &retain_until_secs_f,
        ],
    )
    .await
    .context("insert Pando retention root")?;

    let mut linked_manifests: Vec<(Uuid, Uuid)> = if explicit_manifests.is_empty() {
        let rows = tx
            .query(
                "SELECT DISTINCT m.id, m.repository_id \
                 FROM pando_pack_manifests m \
                 WHERE m.tenant_id = $1 \
                   AND ($2::uuid IS NULL OR m.repository_id = $2) \
                   AND ( \
                     EXISTS ( \
                       SELECT 1 FROM pando_repository_states s \
                       WHERE s.repository_id = m.repository_id AND m.id = ANY(s.pack_ids) \
                     ) \
                     OR EXISTS ( \
                       SELECT 1 FROM pando_publication_fences f \
                       WHERE f.manifest_id = m.id AND f.authority_id = $3 \
                         AND f.lease_until > clock_timestamp() \
                     ) \
                   )",
                &[&tenant_id, &repository_id, &committed.authority_id],
            )
            .await?;
        rows.into_iter().map(|r| (r.get(0), r.get(1))).collect()
    } else {
        let rows = tx
            .query(
                "SELECT id, repository_id FROM pando_pack_manifests \
                 WHERE tenant_id = $1 AND ($2::uuid IS NULL OR repository_id = $2) \
                   AND id = ANY($3::uuid[])",
                &[&tenant_id, &repository_id, &explicit_manifests],
            )
            .await?;
        ensure!(rows.len() == explicit_manifests.len(), "one or more explicit retention manifests were not found");
        rows.into_iter().map(|r| (r.get(0), r.get(1))).collect()
    };

    linked_manifests.sort();
    linked_manifests.dedup();
    for (manifest_id, repo_id) in &linked_manifests {
        tx.execute(
            "INSERT INTO pando_retention_root_manifests \
             (root_id, authority_id, tenant_id, repository_id, manifest_id) \
             VALUES ($1, $2, $3, $4, $5)",
            &[&root_id, &committed.authority_id, &tenant_id, repo_id, manifest_id],
        )
        .await
        .context("link manifest to Pando retention root")?;
    }

    tx.commit().await?;
    pitr_fence::clear_claim_file_best_effort(data_dir, committed.authority_id);

    Ok(RetentionRootSummary {
        id: root_id,
        authority_id: committed.authority_id,
        tenant_id,
        repository_id,
        root_kind: kind.as_str().into(),
        state: "active".into(),
        restore_generation: committed.restore_generation,
        external_lsn: Some(external_lsn),
        note: note_owned,
        manifest_count: linked_manifests.len(),
    })
}

pub async fn release_recovery_root(pool: &Pool, root_id: Uuid) -> Result<bool> {
    let client = pool.get().await?;
    let changed = client
        .execute(
            "UPDATE pando_retention_roots \
             SET state = 'released', released_at = clock_timestamp() \
             WHERE id = $1 AND state = 'active'",
            &[&root_id],
        )
        .await?;
    Ok(changed == 1)
}

pub async fn list_active_roots(pool: &Pool, tenant_id: Option<Uuid>) -> Result<Vec<RetentionRootSummary>> {
    let client = pool.get().await?;
    let authority = retention::authority(&**client).await?;
    let rows = client
        .query(
            "SELECT r.id, r.authority_id, r.tenant_id, r.repository_id, r.root_kind, r.state, \
                    r.restore_generation, r.external_lsn, r.note, \
                    (SELECT count(*)::bigint FROM pando_retention_root_manifests rm WHERE rm.root_id = r.id) \
             FROM pando_retention_roots r \
             WHERE r.authority_id = $1 AND r.state = 'active' \
               AND (r.retain_until IS NULL OR r.retain_until > clock_timestamp()) \
               AND ($2::uuid IS NULL OR r.tenant_id = $2) \
             ORDER BY r.created_at, r.id",
            &[&authority.id, &tenant_id],
        )
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| RetentionRootSummary {
            id: row.get(0),
            authority_id: row.get(1),
            tenant_id: row.get(2),
            repository_id: row.get(3),
            root_kind: row.get(4),
            state: row.get(5),
            restore_generation: row.get(6),
            external_lsn: row.get(7),
            note: row.get(8),
            manifest_count: row.get::<_, i64>(9).max(0) as usize,
        })
        .collect())
}
