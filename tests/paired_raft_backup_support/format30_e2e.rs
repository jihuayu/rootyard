//! Live 3-voter mTLS `raft-node` + standard `schema 151` / `format 30` (`pg_dump`/`pg_restore`)
//! + Smart-HTTP `BlobGitState` + OpenDAL S3 E2E qualification for Issue #153.

use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;

use anyhow::{Result, anyhow, ensure};
use serde_json::json;
use tempfile::TempDir;
use uuid::Uuid;

use rootyard::db;
use rootyard::maintenance::paired_raft_backup::{
    DurableFreezeRequest, DurableRaftBackend, Format30PairedBackupRequest, PairedBackupError, PeerGroupBackupInput,
    STANDARD_PAIRED_PG_FORMAT, STANDARD_SCHEMA_HEAD, create_format30_paired_raft_backup, enter_durable_pg_raft_freeze,
    execute_deleter_guarded, load_pg_repo_backup_specs, propose_raft_hold_guarded, propose_raft_ref_write_guarded,
    restore_and_boot_format30_new_incarnation, thaw_durable_pg_raft_freeze, upsert_repo_access_collaborator_guarded,
    verify_pg_live_incarnation,
};
use rootyard::ref_store::core::decision_commit::{PgDecisionProtocol, RealmExpectation};
use rootyard::ref_store::core::state_machine::{
    AcquireHoldBatchCommand, CommitRefsCommand, RefCasCommand, WireCommitRefsRequest, WireHoldArtifactSpec,
};
use rootyard::ref_store::{
    CommitMode, CommitRefsRequest, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, RefName, RefPrecondition,
    RefTarget, RefUpdate, serving::lookup,
};

use super::fixture::{LoopbackS3, dticket, wticket};
use super::format30_helpers::{
    find_git_bin, init_volume_dir, make_actor, make_backup_config, replace_db_in_url, run_git_cli,
    seed_gate_and_commit, start_gateway, verify_mtls_auth_and_quorum_faults,
};
use super::mtls_cluster::LiveMtlsRaftGroup;

pub async fn run_live_mtls_quorum_freeze_format30_and_new_incarnation_boot() -> Result<()> {
    verify_mtls_auth_and_quorum_faults()?;

    let base_url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let admin = db::pool(&base_url)?;
    let (src_db, dst_db) = (
        format!("paired153_src_{}", &Uuid::new_v4().simple().to_string()[..12]),
        format!("paired153_dst_{}", &Uuid::new_v4().simple().to_string()[..12]),
    );
    {
        let c = admin.get().await?;
        c.batch_execute(&format!("CREATE DATABASE {src_db}")).await?;
        c.batch_execute(&format!("CREATE DATABASE {dst_db}")).await?;
    }
    let (src_url, dst_url) = (replace_db_in_url(&base_url, &src_db)?, replace_db_in_url(&base_url, &dst_db)?);

    let outcome: Result<()> = async {
        let git = find_git_bin()?;
        let dir = TempDir::new()?;
        let s3 = LoopbackS3::new();
        let store = s3.open_store("paired-fmt30-s3")?;

        let mut g1 = LiveMtlsRaftGroup::start_three(1)?;
        let g2 = LiveMtlsRaftGroup::start_three(2)?;
        let mut raft1 = g1.connect_backend(1)?;
        let mut raft2 = g2.connect_backend(1)?;
        let (peer_repo, peer_tenant, peer_hist) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        seed_gate_and_commit(&mut raft2, (peer_repo, peer_tenant, peer_hist, 2, 4), &["b".repeat(64)])?;

        // 1. Migrate full standard `schema 151` & seed via Smart-HTTP `BlobGitState` + stock `git push`!
        let src_pool = db::pool(&src_url)?;
        db::migrate(&src_pool).await?;
        let owner = make_actor(&src_pool, "fmtowner", true).await?;
        let collab = make_actor(&src_pool, "fmtcollab", true).await?;
        let stranger = make_actor(&src_pool, "fmtstranger", true).await?;

        let (gw_addr, gw_jh) =
            start_gateway(src_pool.clone(), store.clone(), git.clone(), dir.path().join("src-gw-scratch")).await?;
        let create_resp = reqwest::Client::new()
            .post(format!("http://{gw_addr}/api/repos"))
            .bearer_auth(&owner.token)
            .json(&json!({ "name": "paired-fmt30", "object_format": "sha256" }))
            .send()
            .await?;
        ensure!(create_resp.status().is_success(), "POST /api/repos failed");

        let serving = lookup(
            &src_pool,
            &owner.identity,
            &owner.username,
            "paired-fmt30",
            true,
            store.backend_identity(),
            tokio::time::Instant::now() + Duration::from_secs(30),
        )
        .await
        .map_err(|e| anyhow!("lookup: {}", e.1))?;
        let gate = serving.gate;
        let repo_id = gate.repository_id();
        {
            let mut c = src_pool.get().await?;
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
        let ver_before =
            upsert_repo_access_collaborator_guarded(&src_pool, &raft1, repo_id, collab.id, "write").await?;
        ensure!(ver_before >= 1);

        let stranger_url = format!(
            "http://{}:{}@{gw_addr}/git/{}/paired-fmt30.git",
            stranger.username, stranger.token, owner.username
        );
        ensure!(
            !run_git_cli(&git, dir.path(), &["clone", &stranger_url, "denied-src"]).status.success(),
            "stranger must be denied repo_access"
        );

        let collab_url =
            format!("http://{}:{}@{gw_addr}/git/{}/paired-fmt30.git", collab.username, collab.token, owner.username);
        let work_clone = dir.path().join("src-clone");
        ensure!(run_git_cli(&git, dir.path(), &["clone", &collab_url, "src-clone"]).status.success(), "collab clone");
        let mut pushed_oids = Vec::new();
        for (fname, body) in [("f1.txt", "commit-one\n"), ("f2.txt", "commit-two\n")] {
            fs::write(work_clone.join(fname), body)?;
            ensure!(run_git_cli(&git, &work_clone, &["add", "."]).status.success());
            ensure!(run_git_cli(&git, &work_clone, &["commit", "-q", "-m", fname]).status.success());
            let head =
                String::from_utf8(run_git_cli(&git, &work_clone, &["rev-parse", "HEAD"]).stdout)?.trim().to_owned();
            let push_out = run_git_cli(&git, &work_clone, &["push", "origin", "HEAD:refs/heads/main"]);
            ensure!(push_out.status.success(), "git push failed: {}", String::from_utf8_lossy(&push_out.stderr));
            pushed_oids.push(head);
        }

        seed_gate_and_commit(
            &mut raft1,
            (repo_id, gate.tenant_id(), gate.history_incarnation(), gate.authority_epoch(), gate.group_epoch()),
            &pushed_oids,
        )?;

        let specs = {
            let c = src_pool.get().await?;
            load_pg_repo_backup_specs(&**c).await?
        };
        ensure!(specs.len() == 1 && specs[0].expected_packs.len() == 2);
        let src_authority_id = specs[0].authority_id;

        // 2. Enter durable PG + 3-voter mTLS Raft freeze & verify engine-level + restart survival!
        let mut peer_rafts = BTreeMap::from([(2i64, raft2)]);
        let freeze_handle = {
            let mut c = src_pool.get().await?;
            let req = DurableFreezeRequest {
                fenced_deleter_epoch: 11,
                app_fence_seq: 3,
                scope_authz_floor: 25,
                repos: &specs,
                peer_repos_by_group: BTreeMap::from([(2i64, vec![(peer_repo, peer_tenant, src_authority_id)])]),
            };
            enter_durable_pg_raft_freeze(&mut c, &mut raft1, &mut peer_rafts, &req).await?
        };

        // Direct unmodified Smart-HTTP gateway (`POST /api/repos` + stock `git push`) MUST fail while frozen!
        let frozen_api = reqwest::Client::new()
            .post(format!("http://{gw_addr}/api/repos"))
            .bearer_auth(&owner.token)
            .json(&json!({ "name": "blocked-while-frozen", "object_format": "sha256" }))
            .send()
            .await?;
        ensure!(!frozen_api.status().is_success(), "production POST /api/repos must fail during PG freeze");
        fs::write(work_clone.join("frozen.txt"), "must-not-land\n")?;
        ensure!(run_git_cli(&git, &work_clone, &["add", "."]).status.success());
        ensure!(run_git_cli(&git, &work_clone, &["commit", "-q", "-m", "frozen"]).status.success());
        ensure!(
            !run_git_cli(&git, &work_clone, &["push", "origin", "HEAD:refs/heads/main"]).status.success(),
            "production Smart-HTTP git push must fail during PG freeze"
        );
        gw_jh.abort();
        let _ = gw_jh.await;

        g1.kill_and_restart_node(2)?;
        raft1.update_endpoints(g1.endpoints())?;
        let fresh_src_pool = db::pool(&src_url)?;
        // Direct unguarded SQL write to `public.repository_collaborators` (`repo_access`) MUST fail in PG 17!
        ensure!(
            fresh_src_pool
                .get()
                .await?
                .execute(
                    "INSERT INTO public.repository_collaborators(repository_id, tenant_id, user_id, role) \
                     VALUES($1, $2, $3, 'read')",
                    &[&repo_id, &gate.tenant_id(), &stranger.id],
                )
                .await
                .is_err(),
            "raw SQL INSERT into repository_collaborators must be blocked by durable PG read-only freeze"
        );
        assert!(matches!(
            upsert_repo_access_collaborator_guarded(&fresh_src_pool, &raft1, repo_id, stranger.id, "read")
                .await
                .unwrap_err(),
            PairedBackupError::FreezeNotHeld(_)
        ));
        let dummy_hold = AcquireHoldBatchCommand {
            request_id: Uuid::new_v4(),
            consume_request_id: Uuid::new_v4(),
            operation_id: Uuid::new_v4(),
            repository_id: repo_id,
            tenant_id: gate.tenant_id(),
            owner_id: gate.tenant_id(),
            authority_id: src_authority_id,
            authority_generation: 1,
            purpose: "ref_publication".into(),
            backend_identity: store.backend_identity().as_hex().into(),
            expected_gate_digest: "a".repeat(64),
            artifacts: vec![WireHoldArtifactSpec {
                hold_id: Uuid::new_v4(),
                slot: 0,
                artifact_digest: "b".repeat(64),
                declared_bytes: 128,
                logical_bytes: 128,
            }],
        };
        assert!(matches!(
            propose_raft_hold_guarded(&fresh_src_pool, &mut raft1, dummy_hold.clone()).await.unwrap_err(),
            PairedBackupError::FreezeNotHeld(_)
        ));
        assert!(matches!(
            propose_raft_ref_write_guarded(
                &fresh_src_pool,
                &mut raft1,
                repo_id,
                30,
                RefCasCommand::AcquireHoldBatch(dummy_hold),
            )
            .await
            .unwrap_err(),
            PairedBackupError::FreezeNotHeld(_)
        ));
        assert!(matches!(
            execute_deleter_guarded(&fresh_src_pool, &raft1, &dticket(Uuid::new_v4(), src_authority_id, 1, 11))
                .await
                .unwrap_err(),
            PairedBackupError::DeleterNotFenced(_)
        ));
        drop(fresh_src_pool);
        drop(src_pool);

        // 3. Capture standard `format 30` / `schema 151` paired backup (`crate::backup::create`) + thaw!
        let src_data_dir = dir.path().join("src-vol");
        init_volume_dir(&src_data_dir)?;
        let src_cfg = make_backup_config(src_url.clone(), src_data_dir, git.clone());
        let archive_dir = dir.path().join("fmt30-paired-archive");
        let peer_inputs = vec![PeerGroupBackupInput {
            group_id: 2,
            freeze_barrier: &freeze_handle.peer_barriers[&2],
            raft: &peer_rafts[&2],
        }];
        let (manifest, seal_receipt) = {
            let _s3_env = s3.apply_env("paired-fmt30-s3");
            create_format30_paired_raft_backup(Format30PairedBackupRequest {
                backup_id: Uuid::new_v4(),
                src_config: &src_cfg,
                freeze_handle: &freeze_handle,
                raft: &raft1,
                peer_groups: peer_inputs,
                store: &store,
                staging_dir: dir.path(),
                destination: &archive_dir,
            })
            .await?
        };
        ensure!(manifest.format30_pg.format == STANDARD_PAIRED_PG_FORMAT);
        ensure!(manifest.format30_pg.schema_head == STANDARD_SCHEMA_HEAD);
        ensure!(manifest.blob_closure.total_artifacts == 4);
        ensure!(manifest.raft_cutpoint.peer_groups.len() == 1);

        let thawed_pool = db::pool(&src_url)?;
        {
            let mut tc = thawed_pool.get().await?;
            let mut forged = seal_receipt.clone();
            forged.receipt_seal = "0".repeat(64);
            ensure!(
                thaw_durable_pg_raft_freeze(&mut tc, &raft1, &peer_rafts, &freeze_handle, &archive_dir, &forged)
                    .await
                    .is_err(),
                "forged seal_receipt must not thaw PG or 3-voter mTLS Raft"
            );
            ensure!(
                tc.execute(
                    "INSERT INTO public.repository_collaborators(repository_id, tenant_id, user_id, role) \
                     VALUES($1, $2, $3, 'read')",
                    &[&repo_id, &gate.tenant_id(), &stranger.id],
                )
                .await
                .is_err(),
                "PG read-only freeze must remain active after backup::create until verified thaw"
            );
            let post_floor =
                thaw_durable_pg_raft_freeze(&mut tc, &raft1, &peer_rafts, &freeze_handle, &archive_dir, &seal_receipt)
                    .await?;
            ensure!(post_floor >= 26);
        }
        let ver_after_thaw =
            upsert_repo_access_collaborator_guarded(&thawed_pool, &raft1, repo_id, collab.id, "admin").await?;
        ensure!(ver_after_thaw >= 27);
        drop(thawed_pool);

        // 4. Wipe S3 bytes & boot fresh incarnation on empty PG17 `dst_db` + fresh 3-voter mTLS Raft clusters!
        s3.state.objects.lock().unwrap().clear();
        ensure!(s3.state.objects.lock().unwrap().is_empty());
        let mut dst_g1 = LiveMtlsRaftGroup::start_three(1)?;
        let dst_g2 = LiveMtlsRaftGroup::start_three(2)?;
        let mut booted_raft1 = dst_g1.connect_backend(1)?;
        let booted_raft2 = dst_g2.connect_backend(1)?;
        let mut booted_peers = BTreeMap::from([(2i64, booted_raft2)]);

        let dst_cfg = make_backup_config(dst_url.clone(), dir.path().join("dst-vol"), git.clone());
        let (restore_out, _guard) = {
            let _s3_env = s3.apply_env("paired-fmt30-s3");
            restore_and_boot_format30_new_incarnation(
                &archive_dir,
                &dir.path().join("restore-work"),
                &dst_cfg,
                &store,
                &mut booted_raft1,
                &mut booted_peers,
            )
            .await?
        };
        let inc = &restore_out.incarnation;
        ensure!(inc.new_cluster_incarnation != manifest.pg_cutpoint.source_cluster_incarnation);
        ensure!(s3.state.objects.lock().unwrap().len() == 4, "all 4 Blob objects rebuilt from format 30 archive");
        ensure!(booted_raft1.read_incarnation_record()?.as_ref() == Some(inc));

        // 5. Boot live Smart-HTTP `BlobGitState` on restored `schema 151` DB & verify post-restore behavior!
        let dst_pool = db::pool(&dst_url)?;
        {
            let dc = dst_pool.get().await?;
            let g_ok = wticket(
                inc.new_cluster_incarnation,
                inc.new_history_incarnation,
                inc.new_authority_epoch,
                inc.new_group_epoch,
                inc.new_authz_floor,
            );
            let d_ok = dticket(
                inc.new_cluster_incarnation,
                inc.new_storage_authority_id,
                inc.new_storage_generation,
                inc.new_deleter_epoch,
            );
            verify_pg_live_incarnation(&dc, repo_id, &g_ok, None, Some(&d_ok)).await?;
            let mut g_stale = g_ok.clone();
            g_stale.authz_epoch = inc.new_authz_floor - 1;
            assert!(matches!(
                verify_pg_live_incarnation(&dc, repo_id, &g_stale, None, None).await.unwrap_err(),
                PairedBackupError::StaleGrantRefused(_)
            ));
            let mut d_stale = d_ok.clone();
            d_stale.deleter_epoch = inc.new_deleter_epoch - 1;
            assert!(matches!(
                verify_pg_live_incarnation(&dc, repo_id, &g_ok, None, Some(&d_stale)).await.unwrap_err(),
                PairedBackupError::StaleDeleterRefused(_)
            ));
        }

        let (dst_gw_addr, dst_gw_jh) =
            start_gateway(dst_pool.clone(), store.clone(), git.clone(), dir.path().join("dst-gw-scratch")).await?;
        let old_collab_url = format!(
            "http://{}:{}@{dst_gw_addr}/git/{}/paired-fmt30.git",
            collab.username, collab.token, owner.username
        );
        ensure!(
            !run_git_cli(&git, dir.path(), &["clone", &old_collab_url, "old-tok-denied"]).status.success(),
            "pre-restore token must be revoked on new incarnation"
        );

        let new_collab = make_actor(&dst_pool, &collab.username, false).await?;
        let new_stranger = make_actor(&dst_pool, &stranger.username, false).await?;
        let dst_stranger_url = format!(
            "http://{}:{}@{dst_gw_addr}/git/{}/paired-fmt30.git",
            new_stranger.username, new_stranger.token, owner.username
        );
        ensure!(
            !run_git_cli(&git, dir.path(), &["clone", &dst_stranger_url, "dst-stranger-denied"]).status.success(),
            "stranger must still be denied repo_access after format 30 restore"
        );

        let dst_collab_url = format!(
            "http://{}:{}@{dst_gw_addr}/git/{}/paired-fmt30.git",
            new_collab.username, new_collab.token, owner.username
        );
        let dst_clone = dir.path().join("dst-collab-clone");
        ensure!(
            run_git_cli(&git, dir.path(), &["clone", &dst_collab_url, "dst-collab-clone"]).status.success(),
            "restored collaborator repo_access must permit clone from rebuilt BlobStore"
        );
        ensure!(run_git_cli(&git, &dst_clone, &["fsck", "--full", "--strict"]).status.success());
        let cloned_head =
            String::from_utf8(run_git_cli(&git, &dst_clone, &["rev-parse", "HEAD"]).stdout)?.trim().to_owned();
        ensure!(cloned_head == pushed_oids[1]);

        fs::write(dst_clone.join("post_restore.txt"), "new-incarnation-commit\n")?;
        ensure!(run_git_cli(&git, &dst_clone, &["add", "."]).status.success());
        ensure!(run_git_cli(&git, &dst_clone, &["commit", "-q", "-m", "post-restore"]).status.success());
        let post_oid =
            String::from_utf8(run_git_cli(&git, &dst_clone, &["rev-parse", "HEAD"]).stdout)?.trim().to_owned();
        ensure!(run_git_cli(&git, &dst_clone, &["push", "origin", "HEAD:refs/heads/main"]).status.success());
        dst_gw_jh.abort();
        let _ = dst_gw_jh.await;

        // Live Ref-CAS quorum write on booted 3-voter mTLS Raft cluster enforced at `new_authz_floor`!
        let (cur_snap, _) = booted_raft1.durable_state()?;
        let cur_rev = cur_snap.body.gates[0].revision;
        let old_oid = GitOid::parse(GitObjectFormat::Sha256, &pushed_oids[1])?;
        let next_oid = GitOid::parse(GitObjectFormat::Sha256, &post_oid)?;
        let raft_upd = RefUpdate::new(
            RefName::new("refs/heads/main")?,
            RefPrecondition::Present(old_oid),
            RefTarget::Oid(next_oid),
        );
        let raft_req = CommitRefsRequest::new(
            repo_id,
            gate.tenant_id(),
            Uuid::new_v4(),
            IssuerLane::new("post-restore-quorum")?,
            1,
            Uuid::new_v4(),
            GitObjectFormat::Sha256,
            inc.new_history_incarnation,
            inc.new_authority_epoch,
            inc.new_group_epoch,
            cur_rev,
            HeadUpdate::Keep,
            CommitMode::Atomic,
            vec![raft_upd],
        )?;
        let raft_cmd = RefCasCommand::CommitRefs(CommitRefsCommand {
            request: WireCommitRefsRequest::from(&raft_req),
            decision_id: None,
            required_holds: Vec::new(),
            policy_rejects: BTreeMap::new(),
            logical_tick: (inc.new_authz_floor + 5) as u64,
        });
        assert!(matches!(
            propose_raft_ref_write_guarded(
                &dst_pool,
                &mut booted_raft1,
                repo_id,
                inc.new_authz_floor - 1,
                raft_cmd.clone(),
            )
            .await
            .unwrap_err(),
            PairedBackupError::StaleGrantRefused(_)
        ));
        let dst_lid = dst_g1.wait_leader()?;
        dst_g1.kill_and_restart_node(dst_lid)?;
        booted_raft1.update_endpoints(dst_g1.endpoints())?;
        propose_raft_ref_write_guarded(&dst_pool, &mut booted_raft1, repo_id, inc.new_authz_floor, raft_cmd).await?;
        let post_snap = booted_raft1.durable_state()?.0;
        ensure!(post_snap.body.last_applied.unwrap().term >= 2, "leader failover must advance durable consensus term");
        ensure!(
            post_snap.body.refs[0].refs.get("refs/heads/main") == Some(&post_oid),
            "3-voter mTLS Raft cluster committed post-restore ref advance"
        );
        drop(dst_pool);
        Ok(())
    }
    .await;

    if let Ok(c) = admin.get().await {
        let _ = c.batch_execute(&format!("DROP DATABASE IF EXISTS {src_db} WITH (FORCE)")).await;
        let _ = c.batch_execute(&format!("DROP DATABASE IF EXISTS {dst_db} WITH (FORCE)")).await;
    }
    outcome
}
