use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackReport {
    pub migration_id: Uuid,
    pub repo: Uuid,
    pub direction: String,
    pub state: String,
    pub storage_backend: String,
    pub migration_state: String,
    pub write_paused: bool,
    pub gitfs_write_paused: bool,
    pub gitfs_path: String,
    pub generation: i64,
    pub old_storage_generation: i64,
    pub new_storage_generation: i64,
    pub packs_synced: usize,
    pub objects_verified: usize,
    pub ref_count: usize,
    pub post_switchover_commits: u64,
    pub deleted_refs_reconciled: usize,
    pub gitfs_fsck_ok: bool,
    pub diff_report: export::DiffExportReport,
}

/// Safely rolls a repository's write authority back from `pando` to `gitfs`,
/// reverse-synchronizing all post-switchover commits, packs, and ref mutations
/// into the GitFS bare repository before verifying dual-operator parity,
/// bumping `storage_generation`, and unfencing GitFS writes.
pub(super) async fn rollback(
    config: &Config,
    repo: Uuid,
    gitfs_path: &Path,
) -> Result<RollbackReport> {
    let gitfs_abs = std::fs::canonicalize(gitfs_path)?;
    let gitfs_str = gitfs_abs.to_string_lossy().into_owned();
    migration::validate_gitfs_bare_repo(config, &gitfs_abs).await?;
    migration::ensure_no_gitfs_locks(&gitfs_abs)?;

    let mut c = config.db().await?;
    let (mig_id, old_storage_gen) = {
        let t = c.transaction().await?;
        let row = t
            .query_one(
                "SELECT storage_generation, storage_backend, migration_state \
                 FROM pando_lab.repositories WHERE id=$1 FOR UPDATE",
                &[&repo],
            )
            .await?;
        let sgen: i64 = row.get(0);
        let backend: String = row.get(1);
        let mstate: String = row.get(2);
        ensure!(
            backend == "pando" || mstate == "rolling_back",
            "rollback requires storage_backend='pando' (got backend={backend}, state={mstate})"
        );

        t.execute(
            "UPDATE pando_lab.repositories \
             SET write_paused=true, migration_state='rolling_back', gitfs_path=$2 \
             WHERE id=$1",
            &[&repo, &gitfs_str],
        )
        .await?;
        t.execute(
            "UPDATE pando_lab.operations \
             SET state='ABORTED', result=jsonb_build_object('error','aborted by rollback drain') \
             WHERE repo=$1 AND state NOT IN ('COMMITTED','REJECTED','ABORTED')",
            &[&repo],
        )
        .await?;

        let id = Uuid::new_v4();
        t.execute(
            "INSERT INTO pando_lab.migrations(id,repo,direction,state,gitfs_path,old_storage_generation) \
             VALUES($1,$2,'pando_to_gitfs','ROLLING_BACK',$3,$4)",
            &[&id, &repo, &gitfs_str, &sgen],
        )
        .await?;
        t.commit().await?;
        (id, sgen)
    };

    // Keep GitFS write-paused while reverse-syncing packs and refs.
    migration::configure_gitfs_fence(config, &gitfs_abs, true, "pando", old_storage_gen).await?;

    let snapshot = store::snapshot(config, repo).await?;
    let gitfs_before_refs = migration::read_gitfs_refs(config, &gitfs_abs).await?;

    let mut obj_store = graph::ObjectStore::default();
    for pack in &snapshot.packs {
        let prefix = config
            .root
            .join("objects")
            .join(repo.to_string())
            .join(pack.id.to_string());
        let pack_bytes = std::fs::read(prefix.with_extension("pack"))?;
        let idx_bytes = std::fs::read(prefix.with_extension("idx"))?;
        ensure!(
            delta::sha256_hex(&pack_bytes) == pack.pack_sha256
                && delta::sha256_hex(&idx_bytes) == pack.idx_sha256,
            "committed pack checksum mismatch during rollback reverse-sync"
        );
        let report = delta::verify_pack(&pack_bytes, &delta::Limits::default())?;
        obj_store.insert_pack(&report);
        config
            .git(
                &gitfs_abs,
                &["index-pack", "--stdin", "--strict"],
                &pack_bytes,
            )
            .await?;
    }

    let wants: Vec<String> = snapshot
        .refs
        .values()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let haves: Vec<String> = gitfs_before_refs
        .values()
        .filter(|oid| obj_store.objects.contains_key(*oid))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let inc_walk = graph::walk_reachable(&obj_store, &wants, &haves)?;
    let post_switchover_commits = inc_walk.commits as u64;

    for (name, oid) in &snapshot.refs {
        config
            .git(
                &gitfs_abs,
                &["-c", "core.hooksPath=/dev/null", "update-ref", name, oid],
                b"",
            )
            .await?;
    }
    let mut deleted_refs_reconciled = 0usize;
    for old_name in gitfs_before_refs.keys() {
        if !snapshot.refs.contains_key(old_name) {
            config
                .git(
                    &gitfs_abs,
                    &[
                        "-c",
                        "core.hooksPath=/dev/null",
                        "update-ref",
                        "-d",
                        old_name,
                    ],
                    b"",
                )
                .await?;
            deleted_refs_reconciled += 1;
        }
    }

    config
        .git(
            &gitfs_abs,
            &["fsck", "--full", "--strict", "--no-reflogs"],
            b"",
        )
        .await?;
    let diff_report = migration::verify_parity_against_gitfs(config, repo, &gitfs_abs).await?;

    let t = c.transaction().await?;
    let row = t
        .query_one(
            "SELECT generation, storage_generation FROM pando_lab.repositories WHERE id=$1 FOR UPDATE",
            &[&repo],
        )
        .await?;
    let generation: i64 = row.get(0);
    let cur_storage_gen: i64 = row.get(1);
    let new_gen = generation.checked_add(1).context("generation exhausted")?;
    let new_storage_gen = cur_storage_gen
        .checked_add(1)
        .context("storage_generation exhausted")?;

    t.execute(
        "UPDATE pando_lab.repositories \
         SET generation=$2, storage_generation=$3, storage_backend='gitfs', \
             migration_state='rolled_back', write_paused=true, gitfs_path=$4 \
         WHERE id=$1",
        &[&repo, &new_gen, &new_storage_gen, &gitfs_str],
    )
    .await?;
    t.execute(
        "DELETE FROM pando_lab.snapshots WHERE repo=$1 AND storage_generation < $2",
        &[&repo, &new_storage_gen],
    )
    .await?;
    t.execute(
        "UPDATE pando_lab.operations \
         SET state='ABORTED', result=jsonb_build_object('error','fenced by rollback switchover') \
         WHERE repo=$1 AND state NOT IN ('COMMITTED','REJECTED','ABORTED')",
        &[&repo],
    )
    .await?;
    let packs_synced = snapshot.packs.len();
    let objects_verified = diff_report.reachable_objects;
    t.execute(
        "UPDATE pando_lab.migrations \
         SET state='ROLLED_BACK', new_storage_generation=$2, copied_packs=$3, copied_objects=$4, \
             post_switchover_commits=$5, diff_report=$6, updated_at=clock_timestamp() \
         WHERE id=$1",
        &[
            &mig_id,
            &new_storage_gen,
            &(packs_synced as i64),
            &(objects_verified as i64),
            &(post_switchover_commits as i64),
            &serde_json::to_value(&diff_report)?,
        ],
    )
    .await?;
    t.commit().await?;

    // Unfence GitFS so native GitFS pushes succeed again under the new storage_generation.
    migration::configure_gitfs_fence(config, &gitfs_abs, false, "gitfs", new_storage_gen).await?;

    Ok(RollbackReport {
        migration_id: mig_id,
        repo,
        direction: "pando_to_gitfs".to_owned(),
        state: "ROLLED_BACK".to_owned(),
        storage_backend: "gitfs".to_owned(),
        migration_state: "rolled_back".to_owned(),
        write_paused: true,
        gitfs_write_paused: false,
        gitfs_path: gitfs_str,
        generation: new_gen,
        old_storage_generation: old_storage_gen,
        new_storage_generation: new_storage_gen,
        packs_synced,
        objects_verified,
        ref_count: snapshot.refs.len(),
        post_switchover_commits,
        deleted_refs_reconciled,
        gitfs_fsck_ok: true,
        diff_report,
    })
}
