//! Gate 10: a restored archive holding more refs than one A4 plan admits must rebind through several
//! canonical plans, and a thaw that cannot reach quorum must leave the staged volume unpublished (#153).
use std::collections::BTreeMap;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow, ensure};
use serde_json::json;
use tempfile::TempDir;
use uuid::Uuid;

use rootyard::db;
use rootyard::maintenance::paired_raft_backup::format30_boot::restore_and_boot_format30_with_pre_publish_hook;
use rootyard::maintenance::paired_raft_backup::install_paired_write_raft_binding as bind_paired_write;
use rootyard::maintenance::paired_raft_backup::{
    DurableFreezeRequest, DurableRaftBackend, DurableRaftFreezeRecord, Format30PairedBackupRequest,
    MtlsLiveRaftBackend, PairedBackupError, create_format30_paired_raft_backup, enter_durable_pg_raft_freeze,
    load_pg_repo_backup_specs, read_pg_database_freeze_marker, read_pg_database_read_only,
    restore_and_boot_format30_new_incarnation, restore_and_boot_format30_with_pre_thaw_hook,
};
use rootyard::ref_store::core::decision_commit::{PgDecisionProtocol, RealmExpectation};
use rootyard::ref_store::serving::lookup;

use super::fixture::LoopbackS3;
use super::format30_helpers::{
    find_git_bin, init_volume_dir, make_actor, make_backup_config, replace_db_in_url, run_git_cli, start_gateway,
};
use super::mtls_cluster::LiveMtlsRaftGroup;

const REF_COUNT: i64 = 136;

fn guard_of(data_dir: &std::path::Path) -> std::path::PathBuf {
    let name = data_dir.file_name().expect("volume name").to_string_lossy().to_string();
    data_dir.parent().expect("volume parent").join(format!(".{name}.rootyard-restoring"))
}

/// `SELECT count(*)` for a single bound repository.
async fn repo_count(client: &tokio_postgres::Client, sql: &str, repo_id: Uuid) -> Result<i64> {
    Ok(client.query_one(sql, &[&repo_id]).await?.get(0))
}

/// Prove the four durable PostgreSQL fences are still continuously armed: the freeze marker, the
/// `default_transaction_read_only` setting, the `restore_in_progress` GUC and the delete fence.
async fn assert_pg_fully_fenced(client: &tokio_postgres::Client) -> Result<()> {
    ensure!(read_pg_database_freeze_marker(client).await?.is_some(), "the durable PG freeze marker must stay armed");
    ensure!(read_pg_database_read_only(client).await?, "the restored target database must stay READ ONLY");
    let rip: Option<String> =
        client.query_one("SELECT NULLIF(current_setting('rootyard.restore_in_progress', true), '')", &[]).await?.get(0);
    ensure!(rip.is_some(), "rootyard.restore_in_progress must stay armed");
    let fenced: bool = client
        .query_one("SELECT remote_delete_fenced FROM public.pando_storage_authorities WHERE singleton = true", &[])
        .await?
        .get(0);
    ensure!(fenced, "remote_delete_fenced must stay true");
    Ok(())
}

/// Push `REF_COUNT` refs while never exceeding the 51-ref `ensure_pack_terminal_budget` ceiling of a
/// single Smart-HTTP push: `ensure_pack_terminal_budget` pads every ref name to `1024` bytes against
/// the 64 KiB `TerminalResult` bound, so one `PackCommitPlan` admits at most 51 refs. The pushes
/// therefore accumulate `REF_COUNT = 136 > MAX_PLAN_REFS = 128` refs *in the repository* while each
/// batch stays at 45. Those 136 refs then rebind across the three canonical A4 plans of the restore.
fn push_many_refs(git: &std::path::Path, clone: &std::path::Path) -> Result<()> {
    let main = run_git_cli(git, clone, &["push", "origin", "HEAD:refs/heads/main"]);
    ensure!(main.status.success(), "main ref push failed: {}", String::from_utf8_lossy(&main.stderr));
    let bulk: Vec<String> = (0..REF_COUNT - 1).map(|index| format!("HEAD:refs/tags/bulk-{index:03}")).collect();
    for window in bulk.chunks(45) {
        let mut args: Vec<&str> = vec!["push", "origin"];
        args.extend(window.iter().map(String::as_str));
        let out = run_git_cli(git, clone, &args);
        ensure!(out.status.success(), "bulk ref push failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires live PostgreSQL 17 + built raft-node and rootyard-peer-attestor binaries"]
async fn gate10_multi_plan_135_refs_rebind_and_thaw_failure_blocks_publish() -> Result<()> {
    let base_url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let admin = db::pool(&base_url)?;
    let suffix = &Uuid::new_v4().simple().to_string()[..12];
    let (db_name, blocked_db) = (format!("gate10_db_{suffix}"), format!("gate10_blocked_{suffix}"));
    let pub_fail_db = format!("gate10_pub_fail_{suffix}");
    let published_db = format!("gate10_published_{suffix}");
    for name in [&db_name, &blocked_db, &pub_fail_db, &published_db] {
        admin.get().await?.batch_execute(&format!("CREATE DATABASE {name}")).await?;
    }
    let url = replace_db_in_url(&base_url, &db_name)?;
    let result: Result<()> = async {
        let git = find_git_bin()?;
        let dir = TempDir::new()?;
        let s3 = LoopbackS3::new();
        let store = s3.open_store("paired-fmt30-delta10")?;
        let group = LiveMtlsRaftGroup::start_three(41)?;
        let mut raft = group.connect_backend(1)?;
        let pool = db::pool(&url)?;
        db::migrate(&pool).await?;
        let write_binding = bind_paired_write(Arc::new(Mutex::new(group.connect_backend(1)?)), &url)?;
        let owner = make_actor(&pool, "gate10owner", true).await?;
        let (gw_addr, gw_jh) =
            start_gateway(pool.clone(), store.clone(), git.clone(), dir.path().join("gate10-gw")).await?;
        let created = reqwest::Client::new()
            .post(format!("http://{gw_addr}/api/repos"))
            .bearer_auth(&owner.token)
            .json(&json!({ "name": "gate10-repo", "object_format": "sha256" }))
            .send()
            .await?;
        ensure!(created.status().is_success(), "POST /api/repos failed");
        let serving = lookup(
            &pool,
            &owner.identity,
            &owner.username,
            "gate10-repo",
            true,
            store.backend_identity(),
            tokio::time::Instant::now() + Duration::from_secs(60),
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
        let git_url = format!("http://{owner_path}:{}@{gw_addr}/git/{owner_path}/gate10-repo.git", owner.token);
        ensure!(run_git_cli(&git, dir.path(), &["clone", &git_url, "gate10-clone"]).status.success(), "clone");
        let clone = dir.path().join("gate10-clone");
        fs::write(clone.join("f.txt"), "gate10\n")?;
        ensure!(run_git_cli(&git, &clone, &["add", "."]).status.success());
        ensure!(run_git_cli(&git, &clone, &["commit", "-q", "-m", "gate10"]).status.success());
        push_many_refs(&git, &clone)?;
        {
            let c = pool.get().await?;
            let refs =
                repo_count(&c, "SELECT count(*) FROM public.ref_store_core_refs WHERE repository_id = $1", repo_id)
                    .await?;
            ensure!(refs == REF_COUNT, "the source must own more refs than one A4 plan admits, got {refs}");
        }
        // Drain the gateway task and its binding before the freeze, then prove the normal receive path
        // already mirrored every pushed ref into the source three-voter mTLS cluster.
        gw_jh.abort();
        let _ = gw_jh.await;
        drop(write_binding);
        let (src_snap, _) = raft.durable_state()?;
        let src_refs =
            src_snap.body.refs.iter().find(|r| r.repository_id == repo_id).map(|r| r.refs.len()).unwrap_or(0);
        ensure!(src_refs as i64 == REF_COUNT, "receive.rs must mirror every pushed ref into the source Raft cluster");
        let specs = load_pg_repo_backup_specs(&**pool.get().await?).await?;
        ensure!(specs.len() == 1 && !specs[0].expected_packs.is_empty(), "the source must own one pack closure");
        let data_dir = dir.path().join("gate10-vol");
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
        let s3_env = s3.apply_env("paired-fmt30-delta10");
        let archive_dir = dir.path().join("gate10-archive");
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

        // A thaw that loses quorum *inside* the hook happens after the frozen boot record has
        // committed, so `boot_thaw` must be refused while the staged volume stays unpublished.
        let blocked_url = replace_db_in_url(&base_url, &blocked_db)?;
        let blocked_vol = dir.path().join("gate10-blocked-vol");
        ensure!(!blocked_vol.exists(), "the blocked target volume must start absent");
        let blocked_cfg = make_backup_config(blocked_url.clone(), blocked_vol.clone(), git.clone());
        let blocked_guard = guard_of(&blocked_vol);
        let thaw_fail_grp = LiveMtlsRaftGroup::start_three(42)?;
        let mut blocked_raft = thaw_fail_grp.connect_backend(1)?;
        let mut blocked_peers: BTreeMap<i64, MtlsLiveRaftBackend> = BTreeMap::new();
        let pre_thaw_hook_ran = Arc::new(AtomicBool::new(false));
        let thaw_flag = pre_thaw_hook_ran.clone();
        let restore_env = s3.apply_env("paired-fmt30-delta10");
        let rejected = restore_and_boot_format30_with_pre_thaw_hook(
            &archive_dir,
            &dir.path().join("gate10-work-blocked"),
            &blocked_cfg,
            &store,
            &mut blocked_raft,
            &mut blocked_peers,
            || {
                thaw_flag.store(true, Ordering::SeqCst);
                thaw_fail_grp.nodes[&2].kill_hard();
                thaw_fail_grp.nodes[&3].kill_hard();
            },
        )
        .await;
        drop(restore_env);
        ensure!(
            pre_thaw_hook_ran.load(Ordering::SeqCst),
            "pre-thaw hook must have run after rebind and cursor verification"
        );
        ensure!(
            matches!(&rejected, Err(PairedBackupError::BootThawRefused(_))),
            "expected BootThawRefused when quorum dies before thaw, got {rejected:?}"
        );
        ensure!(!blocked_vol.exists(), "a failed thaw must never publish the target volume");
        ensure!(blocked_guard.is_file(), "a failed thaw must leave the crash-persistent guard armed");
        // Voter #1 survived: it must hold the committed frozen `boot_freeze`, never the thawed record.
        let kv = thaw_fail_grp.nodes[&1].rpc(&json!({ "InspectReplicaKv": { "key": "refcas/paired_freeze" } }))?;
        let raw = kv
            .pointer("/KvValue/value")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow!("missing freeze KV"))?;
        let record: DurableRaftFreezeRecord = serde_json::from_str(raw)?;
        ensure!(record.frozen, "boot_freeze must have committed before the pre-thaw hook");
        ensure!(record.seal_receipt_digest.is_none(), "boot_thaw must not commit when quorum dies before thaw");
        let blocked_pg = db::connect_url(&blocked_url).await?;
        assert_pg_fully_fenced(&blocked_pg).await?;

        // Item 3 witness: a target that appears after every Raft/PG step but before the single
        // RENAME_NOREPLACE must keep its contents and leave every PostgreSQL fence armed.
        let pub_fail_url = replace_db_in_url(&base_url, &pub_fail_db)?;
        let pub_fail_vol = dir.path().join("gate10-pub-fail-vol");
        ensure!(!pub_fail_vol.exists(), "the pre-publish target volume must start absent");
        let pub_fail_cfg = make_backup_config(pub_fail_url.clone(), pub_fail_vol.clone(), git.clone());
        let pub_fail_guard = guard_of(&pub_fail_vol);
        let pub_fail_grp = LiveMtlsRaftGroup::start_three(44)?;
        let mut pub_fail_raft = pub_fail_grp.connect_backend(1)?;
        let mut pub_fail_peers: BTreeMap<i64, MtlsLiveRaftBackend> = BTreeMap::new();
        let pre_publish_hook_ran = Arc::new(AtomicBool::new(false));
        let publish_flag = pre_publish_hook_ran.clone();
        let restore_env = s3.apply_env("paired-fmt30-delta10");
        let pub_rejected = restore_and_boot_format30_with_pre_publish_hook(
            &archive_dir,
            &dir.path().join("gate10-work-pub-fail"),
            &pub_fail_cfg,
            &store,
            &mut pub_fail_raft,
            &mut pub_fail_peers,
            || {
                publish_flag.store(true, Ordering::SeqCst);
                fs::create_dir_all(&pub_fail_vol).expect("create colliding target");
                fs::write(pub_fail_vol.join("live.txt"), "keep-live").expect("write colliding target");
            },
        )
        .await;
        drop(restore_env);
        ensure!(
            pre_publish_hook_ran.load(Ordering::SeqCst),
            "pre-publish hook must have run immediately before the atomic rename"
        );
        ensure!(
            matches!(&pub_rejected, Err(PairedBackupError::FreezeNotHeld(_))),
            "a colliding target must fail closed on FreezeNotHeld, got {pub_rejected:?}"
        );
        ensure!(
            fs::read_to_string(pub_fail_vol.join("live.txt"))? == "keep-live",
            "a rejected publish must never clobber the live target"
        );
        ensure!(pub_fail_guard.is_file(), "a rejected publish must leave the crash-persistent guard armed");
        let pub_fail_pg = db::connect_url(&pub_fail_url).await?;
        assert_pg_fully_fenced(&pub_fail_pg).await?;

        // The same archive restores on a pristine target and rebinds through more than one A4 plan.
        let published_vol = dir.path().join("gate10-published-vol");
        let published_cfg =
            make_backup_config(replace_db_in_url(&base_url, &published_db)?, published_vol.clone(), git.clone());
        let published_guard = guard_of(&published_vol);
        let published_group = LiveMtlsRaftGroup::start_three(43)?;
        let mut published_raft = published_group.connect_backend(1)?;
        let mut published_peers: BTreeMap<i64, MtlsLiveRaftBackend> = BTreeMap::new();
        let restore_env = s3.apply_env("paired-fmt30-delta10");
        let (outcome, _admission) = restore_and_boot_format30_new_incarnation(
            &archive_dir,
            &dir.path().join("gate10-work-published"),
            &published_cfg,
            &store,
            &mut published_raft,
            &mut published_peers,
        )
        .await?;
        drop(restore_env);
        ensure!(outcome.restored_repos == 1, "the multi-ref repository must be restored and rebound");
        ensure!(published_vol.is_dir(), "a committed restore must publish the staged volume");
        ensure!(!published_guard.exists(), "a committed restore must remove the restore guard");
        let published_pool = db::pool(&published_cfg.database_url)?;
        {
            let c = published_pool.get().await?;
            let refs =
                repo_count(&c, "SELECT count(*) FROM public.ref_store_core_refs WHERE repository_id = $1", repo_id)
                    .await?;
            ensure!(refs == REF_COUNT, "every restored ref must survive the multi-plan rebind, got {refs}");
            let plans: i64 = c
                .query_one(
                    "SELECT count(*) FROM public.ref_store_operations WHERE repository_id = $1 \
                     AND issuer_id = $2 AND lane = 'paired-restore-rebind' AND state = 'committed'",
                    &[&repo_id, &outcome.incarnation.new_history_incarnation],
                )
                .await?
                .get(0);
            ensure!(plans >= 2, "a rebind above one plan's ref limit must commit several plans, got {plans}");
        }
        let (booted_snap, _) = published_raft.durable_state()?;
        let raft_refs =
            booted_snap.body.refs.iter().find(|r| r.repository_id == repo_id).map(|r| r.refs.len()).unwrap_or(0);
        ensure!(raft_refs as i64 == REF_COUNT, "chunked Raft replay must carry every restored ref, got {raft_refs}");
        Ok(())
    }
    .await;
    if let Ok(c) = admin.get().await {
        for name in [&db_name, &blocked_db, &pub_fail_db, &published_db] {
            let _ = c.batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)")).await;
        }
    }
    result
}
