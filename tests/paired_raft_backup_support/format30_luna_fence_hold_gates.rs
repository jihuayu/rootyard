//! Gate 7: the PostgreSQL SHARE table write fence and every Raft freeze barrier must survive archive
//! capture *and* receipt publication. A fence dropped at any publication boundary fails the whole
//! paired backup closed and must never leave a published archive or a thawable barrier (#153).
use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;

use anyhow::{Result, anyhow, ensure};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::json;
use tempfile::TempDir;
use uuid::Uuid;

use rootyard::db;
use rootyard::maintenance::paired_raft_backup::{
    DurableFreezeRequest, Format30PairedBackupRequest, MtlsLiveRaftBackend, PairedBackupError, PeerDurableAttestation,
    PeerDurableAttestationClaims, SealedArchiveReceipt, compute_group_membership_digest,
    create_format30_paired_raft_backup, derive_voter_uuid_bound, enter_durable_pg_raft_freeze,
    load_pg_repo_backup_specs, replicate_pg_repo_to_raft_guarded, thaw_durable_pg_raft_freeze,
    verify_cutpoint_attestations,
};
use rootyard::ref_store::core::decision_commit::{PgDecisionProtocol, RealmExpectation};
use rootyard::ref_store::core::state_machine::AppliedLogId;
use rootyard::ref_store::serving::lookup;

use super::fixture::LoopbackS3;
use super::format30_helpers::{
    find_git_bin, init_volume_dir, make_actor, make_backup_config, replace_db_in_url, run_git_cli, start_gateway,
};
use super::mtls_cluster::LiveMtlsRaftGroup;

/// Requirement 2: a missing durable WAL digest is refused before any realm/fence logic accepts it.
#[test]
fn durable_attestation_without_wal_digest_is_refused() -> Result<()> {
    let rng = ring::rand::SystemRandom::new();
    let voters: Vec<_> = (1..=3u64)
        .map(|node_id| -> Result<_> {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| anyhow!("generate ed25519 pkcs8"))?;
            let keypair =
                Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|e| anyhow!("parse ed25519 pkcs8: {e}"))?;
            let cert = format!("{node_id:064x}");
            let pubkey = hex::encode(KeyPair::public_key(&keypair).as_ref());
            let voter_id = derive_voter_uuid_bound(1, node_id, &cert, &pubkey);
            Ok((node_id, keypair, cert, voter_id, pubkey))
        })
        .collect::<Result<Vec<_>>>()?;
    let voter_ids: Vec<Uuid> = voters.iter().map(|voter| voter.3).collect();
    let membership = compute_group_membership_digest(&voter_ids)?;
    let applied = AppliedLogId { term: 1, index: 5 };
    let attest = |raft_committed_index: u64| -> Result<Vec<PeerDurableAttestation>, PairedBackupError> {
        voters
            .iter()
            .map(|(node_id, keypair, cert, voter_id, pubkey)| {
                PeerDurableAttestation::sign(
                    PeerDurableAttestationClaims {
                        kind: "cutpoint".to_owned(),
                        group_id: 1,
                        group_epoch: 1,
                        node_id: *node_id,
                        voter_id: *voter_id,
                        peer_cert_sha256: cert.clone(),
                        ed25519_pubkey_hex: pubkey.clone(),
                        raft_term: 1,
                        raft_committed_index,
                        refcas_seq: 5,
                        subject_digest: "c".repeat(64),
                        secondary_digest: "d".repeat(64),
                        durable_sqlite_sha256: "e".repeat(64),
                    },
                    keypair,
                )
            })
            .collect()
    };
    let mut zeroed = attest(1)?[0].clone();
    zeroed.claims.durable_sqlite_sha256 = "0".repeat(64);
    ensure!(
        matches!(zeroed.verify(), Err(PairedBackupError::FreezeNotHeld(_))),
        "an all-zero durable_sqlite_sha256 must fail the attestation closed"
    );
    for (raft_committed_index, expected_ok) in [(11u64, false), (12u64, true)] {
        let attestations = attest(raft_committed_index)?;
        ensure!(attestations.iter().all(|attestation| attestation.verify().is_ok()), "signed cutpoints must verify");
        let outcome = verify_cutpoint_attestations(
            (1, 1),
            &voter_ids,
            &membership,
            (applied, 12),
            (&"c".repeat(64), &"d".repeat(64)),
            &attestations,
        );
        ensure!(outcome.is_ok() == expected_ok, "cutpoint reach outcome mismatch");
        if !expected_ok {
            ensure!(matches!(outcome, Err(PairedBackupError::FreezeNotHeld(_))), "lagging cutpoint must fail");
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires live PostgreSQL 17 + built raft-node and rootyard-peer-attestor binaries"]
async fn gate7_fence_drop_at_each_publication_boundary_fails_closed() -> Result<()> {
    let base_url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let admin = db::pool(&base_url)?;
    let db_name = format!("gate7_db_{}", &Uuid::new_v4().simple().to_string()[..12]);
    admin.get().await?.batch_execute(&format!("CREATE DATABASE {db_name}")).await?;
    let url = replace_db_in_url(&base_url, &db_name)?;
    let outcome: Result<()> = async {
        let git = find_git_bin()?;
        let dir = TempDir::new()?;
        let s3 = LoopbackS3::new();
        let store = s3.open_store("paired-fmt30-fence-hold")?;
        let group = LiveMtlsRaftGroup::start_three(7)?;
        let mut raft = group.connect_backend(1)?;
        let pool = db::pool(&url)?;
        db::migrate(&pool).await?;
        let owner = make_actor(&pool, "gate7owner", true).await?;
        let (gw_addr, _gw_jh) =
            start_gateway(pool.clone(), store.clone(), git.clone(), dir.path().join("gate7-gw")).await?;
        let created = reqwest::Client::new()
            .post(format!("http://{gw_addr}/api/repos"))
            .bearer_auth(&owner.token)
            .json(&json!({ "name": "gate7-repo", "object_format": "sha256" }))
            .send()
            .await?;
        ensure!(created.status().is_success(), "POST /api/repos failed");
        let serving = lookup(
            &pool,
            &owner.identity,
            &owner.username,
            "gate7-repo",
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
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            PgDecisionProtocol.provision(&mut c, &exp, deadline).await?;
        }
        let owner_path = &owner.username;
        let git_url = format!("http://{owner_path}:{}@{gw_addr}/git/{owner_path}/gate7-repo.git", owner.token);
        ensure!(run_git_cli(&git, dir.path(), &["clone", &git_url, "gate7-clone"]).status.success(), "clone");
        let clone = dir.path().join("gate7-clone");
        fs::write(clone.join("f.txt"), "gate7\n")?;
        ensure!(run_git_cli(&git, &clone, &["add", "."]).status.success());
        ensure!(run_git_cli(&git, &clone, &["commit", "-q", "-m", "gate7"]).status.success());
        let pushed = run_git_cli(&git, &clone, &["push", "origin", "HEAD:refs/heads/main"]);
        ensure!(pushed.status.success(), "push failed: {}", String::from_utf8_lossy(&pushed.stderr));
        replicate_pg_repo_to_raft_guarded(&pool, &mut raft, repo_id).await?;
        let specs = load_pg_repo_backup_specs(&**pool.get().await?).await?;
        ensure!(specs.len() == 1, "the source repository must yield exactly one backup spec");
        let data_dir = dir.path().join("gate7-vol");
        init_volume_dir(&data_dir)?;
        let cfg = make_backup_config(url.clone(), data_dir, git.clone());
        let peers: BTreeMap<i64, MtlsLiveRaftBackend> = BTreeMap::new();
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
        let s3_env = s3.apply_env("paired-fmt30-fence-hold");
        // Drop the SHARE fence *after* the archive is verified but before `SealedArchiveReceipt::mint`:
        // the published archive must be retracted and the receipt never sealed.
        freeze.set_fault_drop_fence_stage_for_test(3);
        let dest_c = dir.path().join("fmt30-fence-hold-c");
        let archived = create_format30_paired_raft_backup(Format30PairedBackupRequest {
            backup_id: Uuid::new_v4(),
            src_config: &cfg,
            freeze_handle: &freeze,
            raft: &raft,
            peer_groups: Vec::new(),
            store: &store,
            staging_dir: dir.path(),
            destination: &dest_c,
        })
        .await;
        ensure!(
            matches!(archived, Err(PairedBackupError::FreezeNotHeld(_))),
            "a fence dropped after archive verification must fail receipt publication closed"
        );
        ensure!(!dest_c.exists(), "a pre-receipt fence drop must remove the published destination archive");
        // With the fence gone, no later attempt may publish an archive at all.
        let dest_d = dir.path().join("fmt30-fence-hold-d");
        let archived = create_format30_paired_raft_backup(Format30PairedBackupRequest {
            backup_id: Uuid::new_v4(),
            src_config: &cfg,
            freeze_handle: &freeze,
            raft: &raft,
            peer_groups: Vec::new(),
            store: &store,
            staging_dir: dir.path(),
            destination: &dest_d,
        })
        .await;
        drop(s3_env);
        ensure!(
            matches!(archived, Err(PairedBackupError::FreezeNotHeld(_))),
            "a lost SHARE fence must refuse every later paired backup"
        );
        ensure!(!dest_d.exists(), "a lost SHARE fence must never publish an archive");
        let log_id = serde_json::to_value(freeze.active_barrier.barrier_log_id)?;
        let receipt: SealedArchiveReceipt = serde_json::from_value(json!({
            "backup_id": Uuid::new_v4(),
            "barrier_id": freeze.active_barrier.barrier_id,
            "fenced_deleter_epoch": 11u64,
            "app_fence_seq": 3u64,
            "barrier_log_id": log_id,
            "barrier_state_digest": "a".repeat(64),
            "paired_cut_digest": "b".repeat(64),
            "complete_marker_sha256": "c".repeat(64),
            "root_ids": [Uuid::new_v4()],
            "hold_ids": [Uuid::new_v4()],
            "receipt_seal": "d".repeat(64),
        }))?;
        let mut thaw_client = pool.get().await?;
        let thawed = thaw_durable_pg_raft_freeze(&mut thaw_client, &raft, &peers, &freeze, &dest_c, &receipt).await;
        ensure!(
            matches!(thawed, Err(PairedBackupError::FreezeNotHeld(_))),
            "thaw must refuse once the SHARE table write fence is gone"
        );
        Ok(())
    }
    .await;
    if let Ok(c) = admin.get().await {
        let _ = c.batch_execute(&format!("DROP DATABASE IF EXISTS {db_name} WITH (FORCE)")).await;
    }
    outcome
}
