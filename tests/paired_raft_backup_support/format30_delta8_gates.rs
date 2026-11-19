//! Gate 8: a restored repository that legitimately holds active packs but zero refs must rebind
//! through the ephemeral adopt tag and finish with zero refs, and a restore that cannot publish
//! must leave the target volume unpublished behind an armed crash-persistent guard (#153).
use std::collections::BTreeMap;
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow, ensure};
use serde_json::json;
use tempfile::TempDir;
use uuid::Uuid;

use rootyard::db;
use rootyard::maintenance::paired_raft_backup::install_paired_write_raft_binding as bind_paired_write;
use rootyard::maintenance::paired_raft_backup::{
    DurableFreezeRequest, DurableRaftBackend, Format30PairedBackupRequest, MtlsLiveRaftBackend,
    create_format30_paired_raft_backup, enter_durable_pg_raft_freeze, load_pg_repo_backup_specs,
    read_pg_database_freeze_marker, read_pg_database_read_only, restore_and_boot_format30_new_incarnation,
};
use rootyard::ref_store::core::decision_commit::{PgDecisionProtocol, RealmExpectation};
use rootyard::ref_store::serving::lookup;

use super::fixture::LoopbackS3;
use super::format30_helpers::{
    find_git_bin, init_volume_dir, make_actor, make_backup_config, replace_db_in_url, run_git_cli, start_gateway,
};
use super::mtls_cluster::LiveMtlsRaftGroup;

fn guard_of(data_dir: &std::path::Path) -> std::path::PathBuf {
    let name = data_dir.file_name().expect("volume name").to_string_lossy().to_string();
    data_dir.parent().expect("volume parent").join(format!(".{name}.rootyard-restoring"))
}

/// `SELECT count(*)` for a single bound repository.
async fn repo_count(client: &tokio_postgres::Client, sql: &str, repo_id: Uuid) -> Result<i64> {
    Ok(client.query_one(sql, &[&repo_id]).await?.get(0))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires live PostgreSQL 17 + built raft-node and rootyard-peer-attestor binaries"]
async fn gate8_refless_active_packs_rebind_and_failed_restore_stays_unpublished() -> Result<()> {
    let base_url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let admin = db::pool(&base_url)?;
    let suffix = &Uuid::new_v4().simple().to_string()[..12];
    let (db_name, dst_db) = (format!("gate8_db_{suffix}"), format!("gate8_dst_{suffix}"));
    let published_db = format!("gate8_dst2_{suffix}");
    for name in [&db_name, &dst_db, &published_db] {
        admin.get().await?.batch_execute(&format!("CREATE DATABASE {name}")).await?;
    }
    let url = replace_db_in_url(&base_url, &db_name)?;
    let result: Result<()> = async {
        let git = find_git_bin()?;
        let dir = TempDir::new()?;
        let s3 = LoopbackS3::new();
        let store = s3.open_store("paired-fmt30-delta8")?;
        let group = LiveMtlsRaftGroup::start_three(31)?;
        let mut raft = group.connect_backend(1)?;
        let pool = db::pool(&url)?;
        db::migrate(&pool).await?;
        let _write_binding = bind_paired_write(Arc::new(Mutex::new(group.connect_backend(1)?)), &url)?;
        let owner = make_actor(&pool, "gate8owner", true).await?;
        let (gw_addr, gw_jh) =
            start_gateway(pool.clone(), store.clone(), git.clone(), dir.path().join("gate8-gw")).await?;
        let created = reqwest::Client::new()
            .post(format!("http://{gw_addr}/api/repos"))
            .bearer_auth(&owner.token)
            .json(&json!({ "name": "gate8-repo", "object_format": "sha256" }))
            .send()
            .await?;
        ensure!(created.status().is_success(), "POST /api/repos failed");
        let serving = lookup(
            &pool,
            &owner.identity,
            &owner.username,
            "gate8-repo",
            true,
            store.backend_identity(),
            tokio::time::Instant::now() + Duration::from_secs(30),
        )
        .await
        .map_err(|e| anyhow!("lookup: {}", e.1))?;
        let gate = serving.gate;
        let repo_id = gate.repository_id();
        {
            let mut c = pool.get().await?;
            let exp = RealmExpectation::new(
                repo_id,
                gate.tenant_id(),
                gate.object_format(),
                gate.history_incarnation(),
                gate.authority_epoch(),
                gate.group_epoch(),
            )?;
            PgDecisionProtocol.provision(&mut c, &exp, tokio::time::Instant::now() + Duration::from_secs(30)).await?;
        }
        let owner_path = &owner.username;
        let git_url = format!("http://{owner_path}:{}@{gw_addr}/git/{owner_path}/gate8-repo.git", owner.token);
        ensure!(run_git_cli(&git, dir.path(), &["clone", &git_url, "gate8-clone"]).status.success(), "clone");
        let clone = dir.path().join("gate8-clone");
        fs::write(clone.join("f.txt"), "gate8\n")?;
        ensure!(run_git_cli(&git, &clone, &["add", "."]).status.success());
        ensure!(run_git_cli(&git, &clone, &["commit", "-q", "-m", "gate8"]).status.success());
        // An ephemeral tag keeps the pack membership but is legally deleted again through the
        // Smart-HTTP ref protocol, leaving the repository with real packs and zero refs. A tag must be
        // used here, not a `refs/heads/*` branch: pushing the first branch into an unborn repository
        // retargets HEAD (`publish.rs`), so deleting it would trip `rejected:head_dependency`.
        let pushed = run_git_cli(&git, &clone, &["push", "origin", "HEAD:refs/tags/scratch"]);
        ensure!(pushed.status.success(), "push failed: {}", String::from_utf8_lossy(&pushed.stderr));
        let deleted = run_git_cli(&git, &clone, &["push", "origin", ":refs/tags/scratch"]);
        ensure!(deleted.status.success(), "tag delete failed: {}", String::from_utf8_lossy(&deleted.stderr));
        {
            let c = pool.get().await?;
            let refs =
                repo_count(&c, "SELECT count(*) FROM public.ref_store_core_refs WHERE repository_id = $1", repo_id)
                    .await?;
            ensure!(refs == 0i64, "the ephemeral tag must be gone again");
            let memberships = repo_count(
                &c,
                "SELECT count(*) FROM public.ref_store_core_pack_memberships WHERE repository_id = $1",
                repo_id,
            )
            .await?;
            ensure!(memberships == 1i64, "the pushed pack must stay an active membership");
        }
        gw_jh.abort();
        let _ = gw_jh.await;
        let (raft_snap, _) = raft.durable_state()?;
        let raft_refs =
            raft_snap.body.refs.iter().find(|r| r.repository_id == repo_id).map(|r| r.refs.clone()).unwrap_or_default();
        ensure!(
            raft_snap.body.gates.iter().any(|g| g.repository_id == repo_id) && raft_refs.is_empty(),
            "the mirrored create+delete pushes must leave the live Raft gate with exactly zero refs"
        );
        let specs = load_pg_repo_backup_specs(&**pool.get().await?).await?;
        ensure!(
            specs.len() == 1 && !specs[0].expected_packs.is_empty(),
            "a ref-less repository must keep its active pack closure"
        );
        let data_dir = dir.path().join("gate8-vol");
        init_volume_dir(&data_dir)?;
        let cfg = make_backup_config(url.clone(), data_dir, git.clone());
        let freeze = {
            let mut c = pool.get().await?;
            let req = DurableFreezeRequest {
                fenced_deleter_epoch: 11,
                app_fence_seq: 3,
                scope_authz_floor: 25,
                repos: &specs,
                peer_repos_by_group: BTreeMap::new(),
                fence_database_url: url.as_str(),
            };
            enter_durable_pg_raft_freeze(&mut c, &mut raft, &mut BTreeMap::new(), &req).await?
        };
        let s3_env = s3.apply_env("paired-fmt30-delta8");
        let archive_dir = dir.path().join("gate8-archive");
        let (_manifest, _receipt) = create_format30_paired_raft_backup(Format30PairedBackupRequest {
            backup_id: Uuid::new_v4(),
            src_config: &cfg,
            freeze_handle: &freeze,
            raft: &raft,
            peer_groups: Vec::new(),
            store: &store,
            staging_dir: dir.path(),
            destination: &archive_dir,
        })
        .await?;
        drop(s3_env);

        // A mid-flight failure AFTER `backup::restore` (here: the new incarnation cannot commit
        // its Raft boot on a partitioned quorum) must never publish the staged volume, while the
        // crash-persistent guard and the PostgreSQL freeze/read-only fences stay armed.
        let dst_url = replace_db_in_url(&base_url, &dst_db)?;
        let blocked_vol = dir.path().join("gate8-dst-blocked");
        ensure!(!blocked_vol.exists(), "the blocked target volume must start absent");
        let blocked_cfg = make_backup_config(dst_url.clone(), blocked_vol.clone(), git.clone());
        let blocked_guard = guard_of(&blocked_vol);
        let blocked_group = LiveMtlsRaftGroup::start_three(32)?;
        let mut blocked_raft = blocked_group.connect_backend(1)?;
        let mut blocked_peers: BTreeMap<i64, MtlsLiveRaftBackend> = BTreeMap::new();
        // Every voter is mutually partitioned `{1} | {2} | {3}` so no pair retains a 2-of-3 quorum,
        // while direct pristine probes from the test client still reach all three voters.
        blocked_group.partition_all_nodes()?;
        let restore_env = s3.apply_env("paired-fmt30-delta8");
        let rejected = restore_and_boot_format30_new_incarnation(
            &archive_dir,
            &dir.path().join("gate8-work-blocked"),
            &blocked_cfg,
            &store,
            &mut blocked_raft,
            &mut blocked_peers,
        )
        .await;
        drop(restore_env);
        ensure!(
            matches!(&rejected, Err(rootyard::maintenance::paired_raft_backup::PairedBackupError::FreezeNotHeld(_))),
            "a restore whose Raft boot loses quorum must fail closed on FreezeNotHeld, got {rejected:?}"
        );
        ensure!(!blocked_vol.exists(), "a failed restore must never publish the target volume");
        ensure!(blocked_guard.is_file(), "a failed restore must leave the crash-persistent guard armed");
        ensure!(
            rootyard::backup::ensure_not_restoring(&blocked_vol).is_err(),
            "the armed guard must block startup admission of the target volume"
        );
        let blocked_pg = db::connect_url(&dst_url).await?;
        ensure!(
            read_pg_database_freeze_marker(&blocked_pg).await?.is_some(),
            "the durable PG freeze marker must stay armed after a mid-flight failure"
        );
        ensure!(
            read_pg_database_read_only(&blocked_pg).await?,
            "the restored target database must stay READ ONLY after a mid-flight failure"
        );
        let rip: Option<String> = blocked_pg
            .query_one("SELECT NULLIF(current_setting('rootyard.restore_in_progress', true), '')", &[])
            .await?
            .get(0);
        ensure!(rip.is_some(), "rootyard.restore_in_progress must stay armed after a mid-flight failure");

        // The same archive restores, publishes and disarms the guard on a pristine target.
        let published_vol = dir.path().join("gate8-dst-published");
        let published_cfg =
            make_backup_config(replace_db_in_url(&base_url, &published_db)?, published_vol.clone(), git.clone());
        let published_guard = guard_of(&published_vol);
        let published_group = LiveMtlsRaftGroup::start_three(33)?;
        let mut published_raft = published_group.connect_backend(1)?;
        let mut published_peers: BTreeMap<i64, MtlsLiveRaftBackend> = BTreeMap::new();
        let restore_env = s3.apply_env("paired-fmt30-delta8");
        let (outcome, _admission) = restore_and_boot_format30_new_incarnation(
            &archive_dir,
            &dir.path().join("gate8-work-published"),
            &published_cfg,
            &store,
            &mut published_raft,
            &mut published_peers,
        )
        .await?;
        drop(restore_env);
        ensure!(outcome.restored_repos == 1, "the ref-less repository must be restored and rebound");
        ensure!(published_vol.is_dir(), "a committed restore must publish the staged volume");
        ensure!(!published_guard.exists(), "a committed restore must remove the restore guard");
        // The ephemeral adopt tag is gone, the active pack is rebound, and the new-realm A4
        // publication exists alongside the untouched source-realm ledger rows.
        let published_pool = db::pool(&published_cfg.database_url)?;
        {
            let c = published_pool.get().await?;
            let refs =
                repo_count(&c, "SELECT count(*) FROM public.ref_store_core_refs WHERE repository_id = $1", repo_id)
                    .await?;
            ensure!(refs == 0i64, "the ephemeral rebind tag must be deleted again");
            let memberships = repo_count(
                &c,
                "SELECT count(*) FROM public.ref_store_core_pack_memberships WHERE repository_id = $1",
                repo_id,
            )
            .await?;
            ensure!(memberships == 1i64, "the active pack must be rebound in the new realm");
            let publications: i64 = c
                .query_one(
                    "SELECT count(*) FROM public.ref_store_core_pack_publications \
                     WHERE repository_id = $1 AND history_incarnation = $2",
                    &[&repo_id, &outcome.incarnation.new_history_incarnation],
                )
                .await?
                .get(0);
            ensure!(publications == 1i64, "the new-realm A4 publication must exist");
        }
        Ok(())
    }
    .await;
    if let Ok(c) = admin.get().await {
        for name in [&db_name, &dst_db, &published_db] {
            let _ = c.batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)")).await;
        }
    }
    result
}
