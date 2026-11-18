//! Issue #153 merge gates: PG pooled-session reset + verified writer exit, server-side Ed25519
//! peer attestations, pristine target incarnation, and production freeze/epoch guards.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use uuid::Uuid;

use rootyard::db;
use rootyard::maintenance::paired_raft_backup::{
    DecisionExecutionTicket, DeleterLeaseTicket, DurableFreezeRequest, DurableRaftBackend, IncarnationAdmissionGuard,
    NewIncarnationAuthority, PairedBackupError, PairedProductionRuntimeGuard, RepoBackupRegistrationSpec,
    WalSyncedRaftBackend, WorkerProjectionTicket, WriterGrantTicket, compute_group_membership_digest,
    enter_durable_pg_raft_freeze, read_pg_database_read_only, terminate_and_await_other_pg_sessions,
    verify_cutpoint_attestations, verify_no_active_pg_writers,
};
use rootyard::ref_store::core::state_machine::{
    CloseAuthScopeCommand, InitializeGateCommand, RefCasCommand, RepositoryLane, ScopeLifecycle, SmPackMode,
    WireGateInit,
};
use rootyard::ref_store::{CoreGateInit, GitObjectFormat, RefName};

use super::mtls_cluster::LiveMtlsRaftGroup;

fn pg(e: PairedBackupError) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}

fn live_authority() -> NewIncarnationAuthority {
    NewIncarnationAuthority {
        new_cluster_incarnation: Uuid::new_v4(),
        new_storage_authority_id: Uuid::new_v4(),
        new_storage_generation: 2,
        new_history_incarnation: Uuid::new_v4(),
        new_authority_epoch: 3,
        new_group_epoch: 4,
        new_authz_floor: 30,
        new_deleter_epoch: 5,
        fenced_prior_incarnations: BTreeSet::new(),
        fenced_pre_backup_decision_ids: BTreeSet::new(),
    }
}

fn writer_ticket(live: &NewIncarnationAuthority) -> WriterGrantTicket {
    WriterGrantTicket {
        cluster_incarnation: live.new_cluster_incarnation,
        history_incarnation: live.new_history_incarnation,
        authority_epoch: live.new_authority_epoch,
        group_epoch: live.new_group_epoch,
        authz_epoch: live.new_authz_floor,
    }
}

/// Gate 1: the freeze gate must reset the pooled session to `READ ONLY` and must prove that
/// every other client backend actually exited (no fire-and-forget `pg_terminate_backend`).
#[tokio::test]
#[ignore = "requires live PostgreSQL 17 via ROOTYARD_TEST_DATABASE_URL"]
async fn gate1_pooled_pg_session_read_only_reset_and_verified_writer_exit() -> Result<()> {
    let base_url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let admin = db::pool(&base_url)?;
    let suffix = Uuid::new_v4().simple().to_string();
    let suffix = &suffix[..12];
    let (gate1_db, unpriv) = (format!("gate1_db_{suffix}"), format!("unpriv_gate1_{suffix}"));
    let outcome: Result<()> = async {
        {
            let c = admin.get().await?;
            c.batch_execute(&format!("CREATE DATABASE {gate1_db}")).await?;
            c.batch_execute(&format!("CREATE ROLE {unpriv} LOGIN PASSWORD 'gate1-unpriv-pw'")).await?;
        }
        let url = super::format30_helpers::replace_db_in_url(&base_url, &gate1_db)?;
        let pool = db::pool(&url)?;
        let survivor = pool.get().await?;
        let survivor_pg: &tokio_postgres::Client = &survivor;
        // The exact statements `enter_durable_pg_raft_freeze` uses around the freeze transaction.
        survivor_pg.batch_execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE").await?;
        let read_write: String = survivor_pg.query_one("SHOW transaction_read_only", &[]).await?.get(0);
        ensure!(read_write == "off", "READ WRITE session must report transaction_read_only=off");
        survivor_pg.batch_execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY").await?;
        let read_only: String = survivor_pg.query_one("SHOW transaction_read_only", &[]).await?.get(0);
        ensure!(read_only == "on", "pooled session must be reset to READ ONLY on both Ok and Err paths");

        // A genuinely concurrent writer must be terminated AND observed to be gone.
        let doomed = pool.get().await?;
        doomed.batch_execute("BEGIN; SELECT 1").await?;
        let terminated =
            terminate_and_await_other_pg_sessions(survivor_pg, Duration::from_secs(5)).await.map_err(pg)?;
        ensure!(terminated >= 1, "at least the concurrent in-transaction session must be terminated");
        verify_no_active_pg_writers(survivor_pg).await.map_err(pg)?;
        ensure!(doomed.batch_execute("SELECT 1").await.is_err(), "terminated backend must no longer serve queries");
        drop(doomed);

        // The database-wide fence itself is untouched by a session-level reset.
        ensure!(
            !read_pg_database_read_only(survivor_pg).await.map_err(pg)?,
            "no database-wide READ ONLY fence expected"
        );

        // A non-superuser must fail closed when pg_terminate_backend refuses a superuser writer.
        let holder = pool.get().await?;
        holder.batch_execute("BEGIN; SELECT txid_current()").await?;
        let mut ucfg: tokio_postgres::Config = url.parse()?;
        ucfg.user(&unpriv).password("gate1-unpriv-pw").dbname(&gate1_db);
        let mut unpriv_client = db::connect_config(ucfg).await?;
        let refused = terminate_and_await_other_pg_sessions(&unpriv_client, Duration::from_millis(400)).await;
        ensure!(
            matches!(refused, Err(PairedBackupError::FreezeNotHeld(_))),
            "non-superuser termination against a superuser writer must fail closed"
        );
        let _ = holder.batch_execute("ROLLBACK").await;
        drop(holder);

        // Early `Err` before `set_pg_database_read_only(true)`: `ALTER DATABASE` is refused for a
        // non-owner role, and the still-unfrozen session must keep its original characteristic.
        let grp = LiveMtlsRaftGroup::start_three(19)?;
        let mut raft = grp.connect_backend(1)?;
        let repos = [RepoBackupRegistrationSpec {
            repository_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            owner_id: Uuid::new_v4(),
            object_format: GitObjectFormat::Sha256,
            history_incarnation: Uuid::new_v4(),
            authority_epoch: 2,
            group_epoch: 3,
            authority_id: Uuid::new_v4(),
            authority_generation: 1,
            backend_identity: "gate1-unpriv-freeze".to_owned(),
            expected_packs: Vec::new(),
        }];
        let freeze_req = DurableFreezeRequest {
            fenced_deleter_epoch: 5,
            app_fence_seq: 6,
            scope_authz_floor: 7,
            repos: &repos,
            peer_repos_by_group: BTreeMap::new(),
            fence_database_url: url.as_str(),
        };
        let early =
            enter_durable_pg_raft_freeze(&mut unpriv_client, &mut raft, &mut BTreeMap::new(), &freeze_req).await;
        ensure!(early.is_err(), "ALTER DATABASE from a non-owner role must fail the freeze");
        ensure!(
            !read_pg_database_read_only(&unpriv_client).await.map_err(pg)?,
            "an early freeze failure must not latch the database-wide READ ONLY fence"
        );
        let still_rw: String = unpriv_client.query_one("SHOW transaction_read_only", &[]).await?.get(0);
        ensure!(still_rw == "off", "an early freeze error must leave the unfrozen session READ WRITE");

        // Late `Err` after `set_pg_database_read_only(true)`: `gate1_db` has no repository /
        // `ref_store_decision_scopes` schema, so the freeze fails only once the fence is latched
        // and the pooled session must come back READ ONLY.
        drop(unpriv_client);
        drop(survivor);
        let mut pooled = pool.get().await?;
        let late = enter_durable_pg_raft_freeze(&mut pooled, &mut raft, &mut BTreeMap::new(), &freeze_req).await;
        ensure!(late.is_err(), "a freeze that fails after the READ ONLY fence must return an error");
        let pooled_pg: &tokio_postgres::Client = &pooled;
        ensure!(
            read_pg_database_read_only(pooled_pg).await.map_err(pg)?,
            "a late freeze error must leave the database-wide READ ONLY fence latched"
        );
        drop(pooled);
        let recycled = pool.get().await?;
        let recycled_ro: String = recycled.query_one("SHOW transaction_read_only", &[]).await?.get(0);
        ensure!(recycled_ro == "on", "a failed freeze must return its pooled session READ ONLY");
        drop(recycled);
        let thaw_conn = db::connect_url(&url).await?;
        thaw_conn.batch_execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE").await?;
        thaw_conn
            .batch_execute(&format!(
                "ALTER DATABASE \"{gate1_db}\" RESET default_transaction_read_only; \
                 ALTER DATABASE \"{gate1_db}\" RESET rootyard.paired_backup_freeze"
            ))
            .await?;
        terminate_and_await_other_pg_sessions(&thaw_conn, Duration::from_secs(5)).await.map_err(pg)?;
        let writer = pool.get().await?;
        writer.batch_execute("CREATE TEMP TABLE thaw_probe(v int); INSERT INTO thaw_probe VALUES (1);").await?;
        let writer_ro: String = writer.query_one("SHOW transaction_read_only", &[]).await?.get(0);
        ensure!(writer_ro == "off", "cross-connection thaw must restore READ WRITE on the original pool");
        drop(writer);
        drop(thaw_conn);
        drop(pool);
        Ok(())
    }
    .await;
    if let Ok(c) = admin.get().await {
        let _ = c.batch_execute(&format!("DROP DATABASE IF EXISTS {gate1_db} WITH (FORCE)")).await;
        let _ = c.batch_execute(&format!("DROP ROLE IF EXISTS {unpriv}")).await;
    }
    outcome
}

/// Gate 2: a `QuorumCommitReceipt` is only valid when every `VoterWalAck` carries a verified
/// server-side Ed25519 `"commit"` attestation, and cutpoint proofs need a real majority.
#[test]
fn gate2_forged_voter_acks_and_minority_cutpoint_attestations_are_rejected() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut raft = WalSyncedRaftBackend::open_group(dir.path().join("gate2.wal"), 1, 1)?;
    let (repo, tenant, history) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let init =
        CoreGateInit::new(repo, tenant, GitObjectFormat::Sha256, history, 1, 2, RefName::branch("refs/heads/main")?)?;
    raft.commit_and_apply(RefCasCommand::InitializeGate(InitializeGateCommand {
        gate: WireGateInit::from(&init),
        pack_mode: SmPackMode::MetadataOnly,
        lane: RepositoryLane::ServingRefStore,
        authz_floor: 1,
    }))
    .map_err(pg)?;
    let (snapshot, state_digest) = raft.durable_state().map_err(pg)?;
    let applied = snapshot.body.last_applied.context("applied entry")?;
    let voter_ids = raft.voter_ids();
    let membership = compute_group_membership_digest(&voter_ids).map_err(pg)?;

    let cutpoint = raft.attest_group_cutpoint(2, &snapshot, &state_digest).map_err(pg)?;
    ensure!(cutpoint.len() > voter_ids.len() / 2, "majority of voters must attest the cutpoint");
    verify_cutpoint_attestations(1, 2, &voter_ids, &membership, applied, &state_digest, &snapshot.checksum, &cutpoint)
        .map_err(pg)?;
    ensure!(
        verify_cutpoint_attestations(
            1,
            2,
            &voter_ids,
            &membership,
            applied,
            &state_digest,
            &snapshot.checksum,
            &cutpoint[..1],
        )
        .is_err(),
        "a single attestation must never satisfy a 3-voter majority"
    );
    let mut skewed = cutpoint.clone();
    skewed[0].claims.subject_digest = "11".repeat(32);
    ensure!(
        verify_cutpoint_attestations(
            1,
            2,
            &voter_ids,
            &membership,
            applied,
            &state_digest,
            &snapshot.checksum,
            &skewed,
        )
        .is_err(),
        "a cutpoint attestation bound to another state_digest must be rejected"
    );

    let cmd = RefCasCommand::CloseAuthScope(CloseAuthScopeCommand {
        scope_kind: "repo_lifecycle".into(),
        scope_id: repo,
        repository_id: Some(repo),
        tenant_id: Some(tenant),
        lifecycle: ScopeLifecycle::Closed,
        authz_floor: 31,
        change_id: Uuid::new_v4(),
        logical_tick: 20,
    });
    let receipt = raft.commit_quorum_only(&cmd).map_err(pg)?;
    receipt.verify().map_err(pg)?;

    let mut forged_digest = receipt.clone();
    forged_digest.voter_acks[0].wal_record_digest = "22".repeat(32);
    ensure!(forged_digest.verify().is_err(), "a WAL digest with no matching server attestation must be rejected");

    let mut forged_attestation = receipt.clone();
    forged_attestation.voter_acks[0].peer_attestation.claims.node_id += 1;
    ensure!(forged_attestation.verify().is_err(), "attestation claims re-bound to another node must be rejected");

    let mut duplicated = receipt.clone();
    duplicated.voter_acks[1].voter_id = duplicated.voter_acks[0].voter_id;
    duplicated.voter_acks[1].peer_attestation = duplicated.voter_acks[0].peer_attestation.clone();
    ensure!(duplicated.verify().is_err(), "duplicate voter attestations must never reach a majority");
    Ok(())
}

/// Gate 3: restore must refuse a target Raft cluster that ever hosted the source incarnation.
#[test]
#[ignore = "requires built crates/refcas-log raft-node binary + openssl"]
fn gate3_pristine_target_rejects_reused_source_incarnation() -> Result<()> {
    let grp = LiveMtlsRaftGroup::start_three(11)?;
    let mut raft = grp.connect_backend(1)?;
    let forbidden = BTreeSet::from([Uuid::new_v4(), Uuid::new_v4()]);
    let source_membership = raft.group_membership_digest();
    let reused = raft.verify_pristine_new_incarnation_target(&source_membership, &forbidden);
    ensure!(
        matches!(reused, Err(PairedBackupError::StaleIncarnation { .. })),
        "restoring into the source cluster membership must be refused"
    );
    raft.verify_pristine_new_incarnation_target(&"00".repeat(32), &forbidden).map_err(pg)?;
    super::format30_helpers::seed_gate_and_commit(
        &mut raft,
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), 1, 2),
        &["d".repeat(64)],
    )?;
    ensure!(
        matches!(
            raft.verify_pristine_new_incarnation_target(&"00".repeat(32), &forbidden),
            Err(PairedBackupError::StaleIncarnation { .. })
        ),
        "a dirty non-empty target Raft state machine must be refused"
    );
    Ok(())
}

/// Gate 4: production ref writes, projection-worker steps, decisions, and pack deletes all
/// re-check the freeze marker, the restored incarnation, and the durable deleter epoch.
#[test]
fn gate4_production_guards_refuse_frozen_stale_and_superseded_paths() -> Result<()> {
    let live = live_authority();
    let ok = writer_ticket(&live);
    let guard =
        PairedProductionRuntimeGuard::from_live_authority(IncarnationAdmissionGuard { live: live.clone() }, false);
    guard.commit_ref_write(&ok).map_err(pg)?;

    let mut wrong_cluster = ok.clone();
    wrong_cluster.cluster_incarnation = Uuid::new_v4();
    ensure!(
        matches!(guard.commit_ref_write(&wrong_cluster), Err(PairedBackupError::StaleIncarnation { .. })),
        "pre-backup cluster incarnation must be refused"
    );
    let mut low_authz = ok.clone();
    low_authz.authz_epoch = live.new_authz_floor - 1;
    ensure!(
        matches!(guard.commit_ref_write(&low_authz), Err(PairedBackupError::StaleGrantRefused(_))),
        "authz epoch below the restored floor must be refused"
    );

    let frozen =
        PairedProductionRuntimeGuard::from_live_authority(IncarnationAdmissionGuard { live: live.clone() }, true);
    ensure!(matches!(frozen.commit_ref_write(&ok), Err(PairedBackupError::FreezeNotHeld(_))));
    let worker = WorkerProjectionTicket {
        job_key: format!("job-{}", Uuid::new_v4()),
        cluster_incarnation: live.new_cluster_incarnation,
        history_incarnation: live.new_history_incarnation,
        group_id: 1,
        group_epoch: live.new_group_epoch,
        authz_epoch: live.new_authz_floor,
        applied_event_seq: 3,
    };
    ensure!(matches!(frozen.run_projection_worker_step(&worker), Err(PairedBackupError::FreezeNotHeld(_))));
    guard.run_projection_worker_step(&worker).map_err(pg)?;

    let mut stale_worker = worker.clone();
    stale_worker.group_epoch = live.new_group_epoch - 1;
    ensure!(
        matches!(guard.run_projection_worker_step(&stale_worker), Err(PairedBackupError::StaleGrantRefused(_))),
        "projection worker step racing a superseded group epoch must be refused"
    );
    let mut nil_worker = worker.clone();
    nil_worker.history_incarnation = Uuid::nil();
    ensure!(nil_worker.validate().is_err(), "nil restored incarnation must never be admitted");

    let good_decision = DecisionExecutionTicket {
        decision_id: Uuid::new_v4(),
        history_incarnation: live.new_history_incarnation,
        authority_epoch: live.new_authority_epoch,
        group_epoch: live.new_group_epoch,
        authz_epoch: live.new_authz_floor,
    };
    guard.execute_decision(&good_decision).map_err(pg)?;

    let good_deleter = DeleterLeaseTicket {
        cluster_incarnation: live.new_cluster_incarnation,
        storage_authority_id: live.new_storage_authority_id,
        storage_generation: live.new_storage_generation,
        deleter_epoch: live.new_deleter_epoch,
    };
    guard.admission().verify_deleter_lease(&good_deleter).map_err(pg)?;
    let mut superseded = good_deleter.clone();
    superseded.deleter_epoch = live.new_deleter_epoch - 1;
    ensure!(
        matches!(guard.admission().verify_deleter_lease(&superseded), Err(PairedBackupError::StaleDeleterRefused(_))),
        "deleter epoch superseded by the restore must be refused"
    );
    Ok(())
}
