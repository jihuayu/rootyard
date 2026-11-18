//! Gate 5: production serving startup guard installation, freeze fail-closed drain, and
//! exclusive freeze-barrier vs shared journal-retirement lock serialization (#153).
//! Gate 6: co-located peer attestor startup, signed local `group_epoch` agreement, cutpoint
//! commit-index reach, and X.509 caller authorization (#153).

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde_json::json;
use uuid::Uuid;

use rootyard::db;
use rootyard::maintenance::paired_raft_backup::{
    DurableRaftBackend, MtlsRaftClusterConfig, PAIRED_FREEZE_JOURNAL_LOCK_KEY, PairedBackupError,
    PeerDurableAttestation, ensure_serving_database_unfrozen, install_production_serving_guard,
    install_production_serving_guard_with_attestor, installed_peer_attestation_daemon_addr,
    installed_production_runtime_guard, mtls_wire::build_mtls_client_config, mtls_wire::mtls_rpc_call,
    set_installed_production_runtime_guard, shutdown_installed_peer_attestation_daemon,
};

use super::format30_helpers::seed_gate_and_commit;
use super::mtls_cluster::LiveMtlsRaftGroup;

#[tokio::test]
#[ignore = "requires live PostgreSQL 17 via ROOTYARD_TEST_DATABASE_URL"]
async fn gate5_startup_serving_guard_and_journal_lock_serialization() -> Result<()> {
    let base_url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let admin = db::pool(&base_url)?;
    let suffix = &Uuid::new_v4().simple().to_string()[..12];
    let gate5_db = format!("gate5_db_{suffix}");
    let outcome: Result<()> = async {
        {
            let c = admin.get().await?;
            c.batch_execute(&format!("CREATE DATABASE {gate5_db}")).await?;
        }
        let url = super::format30_helpers::replace_db_in_url(&base_url, &gate5_db)?;
        let pool = db::pool(&url)?;
        db::migrate(&pool).await?;
        let barrier_client = db::connect_url(&url).await?;

        let installed = install_production_serving_guard(&barrier_client).await?;
        ensure!(installed.is_some(), "clean schema 151 must install a serving guard");
        ensure!(installed_production_runtime_guard().is_some(), "guard must be process-wide installed");
        ensure_serving_database_unfrozen(&barrier_client).await?;

        barrier_client
            .batch_execute(&format!("ALTER DATABASE \"{gate5_db}\" SET rootyard.paired_backup_freeze = 'test:1'"))
            .await?;
        ensure!(ensure_serving_database_unfrozen(&barrier_client).await.is_err(), "freeze marker must drain serving");
        ensure!(
            installed_production_runtime_guard().is_some_and(|g| g.is_frozen()),
            "freeze marker must latch the installed guard frozen"
        );
        ensure!(
            matches!(install_production_serving_guard(&barrier_client).await, Err(PairedBackupError::FreezeNotHeld(_))),
            "freeze marker must fail serving startup closed"
        );
        barrier_client
            .batch_execute(&format!(
                "ALTER DATABASE \"{gate5_db}\" RESET rootyard.paired_backup_freeze; \
                 ALTER DATABASE \"{gate5_db}\" RESET default_transaction_read_only"
            ))
            .await?;
        set_installed_production_runtime_guard(None);

        // Co-located startup: the same process spawns the voter's mTLS Ed25519 attestor from
        // `ROOTYARD_PAIRED_RAFT_ATTESTOR_JSON` and serves `Identity` on an ephemeral port.
        let grp = LiveMtlsRaftGroup::start_three(23)?;
        let (cert, key) = grp.pki.node_cert_key(1).context("node PKI")?;
        let attestor_json = json!({
            "node_id": 1,
            "group_id": grp.group_id,
            "data_dir": grp.nodes[&1].data_dir.clone(),
            "raft_node_addr": grp.nodes[&1].addr.clone(),
            "ca_cert_pem": grp.pki.ca_cert.clone(),
            "node_cert_pem": cert,
            "node_key_pem": key,
            "raft_client_cert_pem": grp.pki.client_cert.clone(),
            "raft_client_key_pem": grp.pki.client_key.clone(),
            "rpc_timeout_ms": 4_000,
        })
        .to_string();
        drop(install_production_serving_guard_with_attestor(&barrier_client, Some(attestor_json.as_str())).await?);
        let attestor_addr = installed_peer_attestation_daemon_addr().context("installed peer attestor addr")?;
        let (identity, _) =
            mtls_rpc_call(&grp.tls_config(), &attestor_addr, 1, &json!({ "Identity": {} }), Duration::from_secs(5))?;
        ensure!(identity.get("Identity").is_some(), "installed attestor must answer mTLS Identity probes");
        shutdown_installed_peer_attestation_daemon();
        ensure!(
            installed_peer_attestation_daemon_addr().is_none(),
            "attestor shutdown must clear the process-wide slot"
        );

        let freeze_client = db::connect_url(&url).await?;
        let held: bool = freeze_client
            .query_one("SELECT pg_try_advisory_lock($1)", &[&PAIRED_FREEZE_JOURNAL_LOCK_KEY])
            .await?
            .get(0);
        ensure!(held, "freeze barrier must acquire the exclusive journal lock");
        let blocked: bool = barrier_client
            .query_one("SELECT pg_try_advisory_lock_shared($1)", &[&PAIRED_FREEZE_JOURNAL_LOCK_KEY])
            .await?
            .get(0);
        ensure!(!blocked, "journal retirement shared lock must not overlap an exclusive freeze barrier");
        let unlocked: bool =
            freeze_client.query_one("SELECT pg_advisory_unlock($1)", &[&PAIRED_FREEZE_JOURNAL_LOCK_KEY]).await?.get(0);
        ensure!(unlocked, "freeze barrier must release its exclusive journal lock");
        let shared: bool = barrier_client
            .query_one("SELECT pg_try_advisory_lock_shared($1)", &[&PAIRED_FREEZE_JOURNAL_LOCK_KEY])
            .await?
            .get(0);
        ensure!(shared, "journal retirement shared lock must proceed once the freeze barrier releases");
        let _ = barrier_client
            .query_one("SELECT pg_advisory_unlock_shared($1)", &[&PAIRED_FREEZE_JOURNAL_LOCK_KEY])
            .await?;
        Ok(())
    }
    .await;
    if let Ok(c) = admin.get().await {
        let _ = c.batch_execute(&format!("DROP DATABASE IF EXISTS {gate5_db} WITH (FORCE)")).await;
    }
    outcome
}

#[tokio::test]
#[ignore = "requires live PostgreSQL 17 + built raft-node and rootyard-peer-attestor binaries"]
async fn gate6_peer_attestor_rejects_mismatched_local_group_epoch() -> Result<()> {
    let grp = LiveMtlsRaftGroup::start_three(29)?;
    let mut raft = grp.connect_backend(1)?;
    let (repo, tenant, hist) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    seed_gate_and_commit(&mut raft, (repo, tenant, hist, 2, 3), &["e".repeat(64)])?;
    let (snapshot, state_digest) = raft.durable_state()?;
    let applied = snapshot.body.last_applied.context("durable applied index")?;
    let local_epoch = snapshot.body.gates[0].group_epoch;
    let endpoint = grp.attestor_endpoints()[&1].clone();
    let tls = grp.tls_config();
    let call = |epoch: i64, min_committed_index: u64| {
        mtls_rpc_call(
            &tls,
            &endpoint,
            1,
            &json!({ "AttestCutpoint": {
                "group_id": grp.group_id,
                "group_epoch": epoch,
                "expected_seq": applied.index,
                "min_committed_index": min_committed_index,
                "expected_state_digest": state_digest.as_str(),
                "expected_snapshot_checksum": snapshot.checksum.as_str(),
            }}),
            Duration::from_secs(6),
        )
    };
    let mut accepted = None;
    for _ in 0..20 {
        if let Ok((response, _)) = call(local_epoch, applied.index)
            && response.get("Attestation").is_some()
        {
            accepted = Some(response);
            break;
        }
        tokio::time::sleep(Duration::from_millis(80)).await;
    }
    let response = accepted.context("matching local group_epoch must be attested")?;
    let attestation: PeerDurableAttestation =
        serde_json::from_value(response["Attestation"].clone()).context("attestation json")?;
    attestation.verify()?;
    ensure!(attestation.claims.group_epoch == local_epoch, "peer signs only its own local group_epoch");
    ensure!(
        attestation.claims.raft_committed_index >= applied.index,
        "attested raft_committed_index must reach the attested cutpoint"
    );
    ensure!(
        attestation.claims.durable_sqlite_sha256.len() == 64
            && !attestation.claims.durable_sqlite_sha256.bytes().all(|b| b == b'0'),
        "attested cutpoint must bind a real durable WAL digest"
    );
    let (rejected, _) = call(local_epoch + 1, applied.index)?;
    ensure!(rejected.get("Attestation").is_none(), "mismatched group_epoch must not be signed");
    ensure!(rejected.get("Error").is_some(), "mismatched group_epoch must surface an Error");
    let (lagged, _) = call(local_epoch, applied.index + 10_000)?;
    ensure!(
        lagged.get("Attestation").is_none() && lagged.get("Error").is_some(),
        "a min_committed_index beyond the applied index must be refused"
    );

    // Requirement 4: only a leaf whose pinned digest *and* `raft-client` SAN both match may
    // drive the daemon; a wrong-SAN leaf or an extra-CA-signed leaf is refused.
    let probe = json!({ "AttestCutpoint": {
        "group_id": grp.group_id,
        "group_epoch": local_epoch,
        "expected_seq": applied.index,
        "min_committed_index": applied.index,
        "expected_state_digest": state_digest.as_str(),
        "expected_snapshot_checksum": snapshot.checksum.as_str(),
    }});
    let caller_base = |cert: std::path::PathBuf, key: std::path::PathBuf| MtlsRaftClusterConfig {
        group_id: grp.group_id,
        local_node_id: 1,
        voter_endpoints: BTreeMap::new(),
        attestor_endpoints: BTreeMap::new(),
        ca_cert_pem: grp.pki.ca_cert.clone(),
        client_cert_pem: cert,
        client_key_pem: key,
        rpc_timeout: Duration::from_secs(4),
    };
    let wrong_san = caller_base(grp.pki.wrong_san_cert.clone(), grp.pki.wrong_san_key.clone());
    let wrong_san = build_mtls_client_config(&wrong_san)?;
    let attest_commit = json!({ "AttestCommit": {
        "group_id": grp.group_id,
        "group_epoch": local_epoch,
        "seq": 1u64,
        "min_raft_index": 1u64,
        "command_sha256": "a".repeat(64),
    }});
    for request in [json!({ "Identity": {} }), attest_commit, probe.clone()] {
        let (refused, _) = mtls_rpc_call(&wrong_san, &endpoint, 1, &request, Duration::from_secs(6))?;
        ensure!(
            refused.get("Identity").is_none() && refused.get("Attestation").is_none() && refused.get("Error").is_some(),
            "a wrong caller SAN must be refused for every RPC verb"
        );
    }
    let rogue_ca = caller_base(grp.pki.rogue_client_cert.clone(), grp.pki.rogue_client_key.clone());
    let rogue_ca = build_mtls_client_config(&rogue_ca)?;
    ensure!(
        mtls_rpc_call(&rogue_ca, &endpoint, 1, &probe, Duration::from_secs(6)).is_err(),
        "an extra-CA-signed raft-client leaf must be rejected during the mTLS handshake"
    );
    Ok(())
}
