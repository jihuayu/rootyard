//! Issue #120: single-node paired PostgreSQL + Blob backup and new-incarnation restore.
#![cfg(unix)]

#[path = "w8a_pg_blob_support/lifecycle_guards.rs"]
mod lifecycle_guards;
#[path = "retention_roots_support/mod.rs"]
mod retention_roots_support;
#[path = "w8a_pg_blob_support/s3.rs"]
mod s3;
#[path = "w8a_pg_blob_support/seed.rs"]
mod seed;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow, bail, ensure};
use deadpool_postgres::Pool;
use rootyard::backup::w8a_paired::{
    W8aError, admit_deleter_epoch, capture_key_reference, check, create, fence_w8a_fresh_incarnation, restore,
    verify_key_reference,
};
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::config::Config;
use rootyard::db::Identity;
use rootyard::pulls::remote_merge_finalizer::{
    MergeReceiptStore, MergeStrategy, PendingMergeRecord, PgMergeStore, PullMergeState, init_remote_merge_tables,
};
use rootyard::ref_store::core::pack_commit::{
    AuthorizedCommitMode, PackCommitPlan, PgAuthorizedCommit, PrepareOutcome,
};
use rootyard::storage_lifecycle::models::Policy;
use s3::{EnvGuard, LoopbackS3};
use uuid::Uuid;

use crate::retention_roots_support::db::{Db, deadline};
use crate::retention_roots_support::git::git_binary;

const TEST_URL: &str = "ROOTYARD_TEST_DATABASE_URL";
const MAINTENANCE: &str = "ROOTYARD_STORAGE_MAINTENANCE";
const KEYRING: &str = "ROOTYARD_BLOB_KEYRING_DIR";
const BLOB_DELETE: &str = "ROOTYARD_BLOB_DELETE";
const WORKSPACE_DELETE: &str = "ROOTYARD_WORKSPACE_UNSAFE_REMOTE_DELETE";

fn find_extension(root: &Path, extension: &str) -> Result<PathBuf> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            if let Ok(found) = find_extension(&entry.path(), extension) {
                return Ok(found);
            }
        } else if entry.path().extension().and_then(|value| value.to_str()) == Some(extension) {
            return Ok(entry.path());
        }
    }
    Err(anyhow!("no .{extension} under {}", root.display()))
}

fn data_dir(temp: &Path, name: &str) -> PathBuf {
    temp.join(format!("{name}-data"))
}

fn config(database_url: String, temp: &Path, name: &str, git: &Path) -> Config {
    seed::build_config(database_url, data_dir(temp, name), git.to_path_buf())
}

async fn authorized_commit(
    db: &Db,
    store: &BlobStore,
    git: &Path,
    plan: &PackCommitPlan,
    actor: &Identity,
) -> Result<()> {
    let mode = match plan.commit_mode().as_str() {
        "accepted_subset" => AuthorizedCommitMode::AcceptedSubset,
        "atomic" => AuthorizedCommitMode::Atomic,
        other => bail!("unknown planned commit mode {other}"),
    };
    let authorized = PgAuthorizedCommit::new(store.clone(), git.to_path_buf())
        .map_err(|error| anyhow!("authorized pipeline rejected the Blob/Git configuration: {error:?}"))?;
    let prepared = match authorized.prepare(&db.pool, plan.clone(), deadline()).await? {
        PrepareOutcome::Prepared(prepared) => prepared,
        PrepareOutcome::Replayed(_) => return Err(anyhow!("authorized prepare replayed a fresh operation")),
    };
    let selection = authorized.select(&db.pool, *prepared, actor, mode, deadline()).await?;
    ensure!(selection.accepted_refs() == plan.refs().len() && !selection.is_all_rejected(), "decision rejected refs");
    let verified = authorized.verify(selection, deadline()).await?;
    let receipt = authorized.commit(&db.pool, &verified, deadline()).await?;
    ensure!(receipt.is_committed() && !receipt.replayed, "decided verified commit did not commit");
    Ok(())
}

fn is_key(error: &W8aError) -> bool {
    matches!(error, W8aError::KeyReferenceMismatch(_))
}
fn is_mixed(error: &W8aError) -> bool {
    matches!(error, W8aError::MixedPointInTime(_))
}
fn is_blob(error: &W8aError) -> bool {
    matches!(error, W8aError::MissingOrCorruptBlobArtifact(_))
}
fn is_gc(error: &W8aError) -> bool {
    matches!(error, W8aError::DestructiveGcForbidden(_))
}

async fn seed_fence_rows(pool: &Pool, repository_id: Uuid, owner_id: Uuid, token_id: Uuid) -> Result<Uuid> {
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
    let digest = "a".repeat(64);
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO ci_checkout_jobs(repository_id,job_id,owner_id,cancelled,revoked,plan)
             VALUES($1,$2,$3,true,false,NULL)",
            &[&repository_id, &Uuid::new_v4(), &owner_id],
        )
        .await?;
    client
        .execute(
            "INSERT INTO ref_store_decision_scopes(scope_kind,scope_id,version,state)
             VALUES('authority',$1,0,'OPEN') ON CONFLICT (scope_kind,scope_id) DO NOTHING",
            &[&repository_id],
        )
        .await?;
    let decision_id = Uuid::new_v4();
    client
        .execute(
            "INSERT INTO ref_store_publication_decisions(decision_id,repository_id,tenant_id,owner_id,actor_id,token_id,
                token_digest,operation_id,issuer_id,lane,sequence,mode,object_format,history_incarnation,authority_epoch,
                group_epoch,base_revision,base_gate_digest,command_digest,refs_digest,selected_refs_digest,selection_digest,
                policy_digest,facts_digest,authz_digest,dependencies_digest,packs_digest,hold_receipts_digest,
                captured_oid_digest,not_after_millis,created_db_millis,state)
             VALUES($1,$2,$2,$2,$2,$3,$4,$5,$2,'core',1,'atomic','sha1',$6,1,1,1,$4,$4,$4,$4,$4,$4,$4,$4,$4,$4,$4,$4,$7,$8,'OPEN')",
            &[
                &decision_id,
                &repository_id,
                &token_id,
                &digest,
                &Uuid::new_v4(),
                &Uuid::new_v4(),
                &(now_ms + 3_600_000),
                &now_ms,
            ],
        )
        .await?;
    Ok(decision_id)
}

async fn expect_failure(
    env: &mut EnvGuard,
    admin: &str,
    temp: &Path,
    git: &Path,
    archive: &Path,
    name: &str,
    predicate: fn(&W8aError) -> bool,
) -> Result<()> {
    let database = format!("w8a_{}", Uuid::new_v4().simple());
    seed::create_database(admin, &database).await?;
    let url = seed::with_database(admin, &database);
    env.update(TEST_URL, &url);
    let result = restore(&config(url, temp, name, git), archive, &temp.join(format!("{name}-compute")), true).await;
    let refused = matches!(&result, Err(error) if predicate(error));
    let _ = seed::drop_database(admin, &database).await;
    ensure!(refused, "{name} was not refused as expected: {result:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and PostgreSQL 17 pg_dump/pg_restore"]
async fn paired_pg_blob_fresh_incarnation_is_blank_of_source_authority() -> Result<()> {
    let server = LoopbackS3::shared();
    let temp = tempfile::tempdir()?;
    let git = git_binary()?;
    let admin = seed::database_url();
    let source_db = format!("w8a_{}", Uuid::new_v4().simple());
    seed::create_database(&admin, &source_db).await?;
    let source_url = seed::with_database(&admin, &source_db);
    let first_keys = seed::write_keyring(&temp.path().join("keys-first"))?;
    let second_keys = seed::write_keyring_with(&temp.path().join("keys-second"), "w8a-key-1", 0xA5)?;
    let keyring = first_keys.to_str().ok_or_else(|| anyhow!("keyring path is not UTF-8"))?.to_owned();
    let endpoint = server.endpoint().to_owned();
    let mut env = EnvGuard::set(&[
        ("ROOTYARD_BLOB_DRIVER", Some("opendal")),
        ("ROOTYARD_BLOB_SERVICE", Some("s3")),
        ("ROOTYARD_BLOB_BUCKET", Some(server.bucket())),
        ("ROOTYARD_BLOB_REGION", Some(server.region())),
        ("ROOTYARD_BLOB_ENDPOINT", Some(endpoint.as_str())),
        ("ROOTYARD_BLOB_ACCESS_KEY_ID", Some("w8a-access")),
        ("ROOTYARD_BLOB_SECRET_ACCESS_KEY", Some("w8a-secret")),
        ("ROOTYARD_BLOB_RETRY_MAX_TIMES", Some("3")),
        ("ROOTYARD_BLOB_ENCRYPTION_MODE", Some("provider-managed")),
        (KEYRING, None),
        ("ROOTYARD_BLOB_KMS_KEY_REF", Some("kms://w8a/source-key-1")),
        ("ROOTYARD_PAIRED_RAFT_CLUSTER_JSON", None),
        (BLOB_DELETE, Some("disabled")),
        (MAINTENANCE, Some("false")),
        (WORKSPACE_DELETE, Some("false")),
        (TEST_URL, Some(source_url.as_str())),
    ]);
    let source = Db::setup_public().await?;
    server.clear();
    let seeded = seed::seed_source(&source, &BlobStore::open(BlobProfile::from_env()?)?, &git).await?;
    ensure!(seeded.repos.len() == 2, "seed did not create both object formats");
    let open_decision_id =
        seed_fence_rows(&source.pool, seeded.repos[0].id, seeded.owner.identity.id, seeded.owner.identity.token_id)
            .await?;
    let source_config = config(source_url.clone(), temp.path(), "source", &git);
    seed::write_volume(&source_config.data_dir)?;
    let archive = temp.path().join("archive");
    let created = create(&source_config, &archive).await?;
    ensure!(created.format == 32 && created.sidecar.schema_head == 152, "paired format/schema differs");
    let checked = check(&archive)?;
    ensure!(checked.w8a_backup_id == created.w8a_backup_id, "check receipt differs from creation");

    let source_client = source.pool.get().await?;
    source_client
        .execute(
            "INSERT INTO ref_cas_projection_cursors(group_id,history_incarnation,group_epoch) VALUES(0,$1,1)",
            &[&Uuid::new_v4()],
        )
        .await?;
    let raft_archive = temp.path().join("raft-archive");
    let raft = create(&source_config, &raft_archive).await;
    source_client.execute("DELETE FROM ref_cas_projection_cursors", &[]).await?;
    ensure!(matches!(raft, Err(W8aError::RaftCutForbiddenInSingleNodeW8a(_))), "raft source was not refused");
    drop(source_client);

    let corrupt = temp.path().join("corrupt");
    seed::copy_tree(&archive, &corrupt)?;
    let pack = find_extension(&corrupt.join("format30"), "pack")?;
    let mut bytes = std::fs::read(&pack)?;
    bytes[0] ^= 0xff;
    std::fs::write(&pack, bytes)?;
    expect_failure(&mut env, &admin, temp.path(), &git, &corrupt, "corrupt", is_blob).await?;
    let missing = temp.path().join("missing");
    seed::copy_tree(&archive, &missing)?;
    std::fs::remove_file(find_extension(&missing.join("format30"), "idx")?)?;
    expect_failure(&mut env, &admin, temp.path(), &git, &missing, "missing", is_blob).await?;
    let swapped = temp.path().join("swapped");
    seed::copy_tree(&archive, &swapped)?;
    std::fs::write(swapped.join("format30/metadata.dump"), b"swapped")?;
    expect_failure(&mut env, &admin, temp.path(), &git, &swapped, "swapped", is_mixed).await?;
    let raft_shape = temp.path().join("raft-shape");
    seed::copy_tree(&archive, &raft_shape)?;
    std::fs::write(raft_shape.join("paired-manifest.json"), b"{}")?;
    ensure!(
        matches!(check(&raft_shape), Err(W8aError::RaftCutForbiddenInSingleNodeW8a(_))),
        "raft sidecar shape was not refused"
    );
    env.set_opt("ROOTYARD_BLOB_KMS_KEY_REF", Some("kms://w8a/wrong-key-2"));
    expect_failure(&mut env, &admin, temp.path(), &git, &archive, "wrong-kms", is_key).await?;
    env.set_opt("ROOTYARD_BLOB_ENCRYPTION_MODE", Some("local-envelope"));
    env.set_opt(KEYRING, Some(keyring.as_str()));
    env.set_opt("ROOTYARD_BLOB_KMS_KEY_REF", None);
    expect_failure(&mut env, &admin, temp.path(), &git, &archive, "wrong-mode", is_key).await?;
    let local_ref = capture_key_reference(created.w8a_backup_id, &created.sidecar.blob_backend_identity)?;
    let second_keyring = second_keys.to_str().ok_or_else(|| anyhow!("second keyring is not UTF-8"))?;
    env.set_opt(KEYRING, Some(second_keyring));
    ensure!(
        matches!(
            verify_key_reference(&local_ref, created.w8a_backup_id, &created.sidecar.blob_backend_identity),
            Err(W8aError::KeyReferenceMismatch(_))
        ),
        "local-envelope canary mismatch was not refused"
    );
    env.set_opt("ROOTYARD_BLOB_ENCRYPTION_MODE", Some("provider-managed"));
    env.set_opt(KEYRING, None);
    env.set_opt("ROOTYARD_BLOB_KMS_KEY_REF", Some("kms://w8a/source-key-1"));
    env.update(MAINTENANCE, "true");
    expect_failure(&mut env, &admin, temp.path(), &git, &archive, "gc", is_gc).await?;
    env.update(MAINTENANCE, "false");
    lifecycle_guards::run_lifecycle_guard_drills(&mut env, &admin, temp.path(), &git, server, &archive, &created)
        .await?;

    let destination = format!("w8a_{}", Uuid::new_v4().simple());
    seed::create_database(&admin, &destination).await?;
    let destination_url = seed::with_database(&admin, &destination);
    env.update(TEST_URL, &destination_url);
    let compute = temp.path().join("restore-compute");
    server.clear();
    let restored =
        restore(&config(destination_url.clone(), temp.path(), "restored", &git), &archive, &compute, true).await?;
    ensure!(restored.trusted_backup && restored.destination_trusted, "restore trust receipt differs");
    ensure!(restored.new_cluster_incarnation != seeded.cluster_incarnation, "cluster incarnation was not rotated");
    ensure!(
        restored.new_storage_authority_epoch > seeded.authority_epoch && restored.remote_delete_fenced,
        "storage authority epoch/fence differs"
    );
    ensure!(restored.repositories_fscked.len() == 2, "not every repository passed stock Git fsck");
    let formats: Vec<_> = restored.repositories_fscked.iter().map(|item| item.object_format.as_str()).collect();
    ensure!(formats.contains(&"sha1") && formats.contains(&"sha256"), "fsck did not cover both object formats");
    ensure!(
        restored.revoked_tokens >= 3
            && restored.revoked_sessions >= 1
            && restored.cancelled_ci_runs >= 1
            && restored.revoked_ci_checkouts >= 1
            && restored.expired_workspaces >= 1
            && restored.cancelled_decisions >= 1
            && restored.advanced_decision_scopes >= 1
            && restored.released_pins >= 2
            && restored.aborted_pull_merges == 0
            && restored.reset_deliveries >= 1,
        "fresh-incarnation fence receipt is incomplete: {restored:?}"
    );
    ensure!(!compute.exists(), "compute directory survived the restore");

    let destination_pool = seed::pool_for(&destination_url)?;
    ensure!(
        rootyard::auth::authenticate(&destination_pool, &seeded.owner.headers()).await.is_err(),
        "old API token survived"
    );
    ensure!(
        rootyard::auth::web_scope(rootyard::auth::authenticate(&destination_pool, &seeded.browser.headers()))
            .await
            .is_err(),
        "old browser credential survived"
    );
    let client = destination_pool.get().await?;
    lifecycle_guards::verify_restore_lineage(&client, seeded.cluster_incarnation, restored.new_cluster_incarnation)
        .await?;
    let ci: Vec<String> = client.query("SELECT state FROM ci_runs", &[]).await?.iter().map(|row| row.get(0)).collect();
    ensure!(ci.iter().all(|state| state == "cancelled"), "CI runs were not cancelled: {ci:?}");
    let checkout: Vec<(bool, bool, bool)> = client
        .query("SELECT plan IS NOT NULL, cancelled, revoked FROM ci_checkout_jobs", &[])
        .await?
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect();
    ensure!(
        checkout.iter().any(|(planned, _, revoked)| *planned && *revoked)
            && checkout.iter().any(|(planned, cancelled, revoked)| !*planned && *cancelled && !*revoked),
        "checkout revocation or its tombstone differs: {checkout:?}"
    );
    ensure!(
        client
            .query(
                "SELECT state = 'ready' AND lease_epoch >= 2 AND lease_until <= clock_timestamp() FROM workspaces",
                &[],
            )
            .await?
            .iter()
            .all(|row| row.get::<_, bool>(0)),
        "workspace lease was not expired"
    );
    let decision_row = client
        .query_one(
            "SELECT state, closed_code FROM ref_store_publication_decisions WHERE decision_id = $1",
            &[&open_decision_id],
        )
        .await?;
    ensure!(
        decision_row.get::<_, String>(0) == "CANCELLED"
            && decision_row.get::<_, Option<String>>(1).as_deref() == Some("restored_incarnation")
            && client
                .query("SELECT 1 FROM ref_store_publication_decisions WHERE state = 'OPEN'", &[])
                .await?
                .is_empty(),
        "open decision was not cancelled with the restored-incarnation code"
    );
    ensure!(
        !client.query("SELECT 1 FROM ref_store_decision_scopes WHERE version > 0", &[]).await?.is_empty(),
        "decision scope version was not advanced"
    );
    ensure!(
        client.query("SELECT 1 FROM ref_store_core_pins WHERE released_at IS NULL", &[]).await?.is_empty(),
        "an active pin survived the incarnation fence"
    );
    ensure!(
        client.query("SELECT 1 FROM ref_store_core_root_heads", &[]).await?.len() == 2,
        "active root heads were not preserved"
    );
    ensure!(
        client.query("SELECT 1 FROM event_deliveries WHERE state='leased'", &[]).await?.is_empty(),
        "a leased delivery survived the fence"
    );
    drop(client);
    let owner = Uuid::new_v4();
    for consumer in ["audit-log", "ref-index"] {
        loop {
            if rootyard::events::worker_once(&destination_pool, consumer, owner, 10).await? == 0 {
                break;
            }
        }
    }
    ensure!(rootyard::events::pending_count(&destination_pool).await? == 0, "outbox did not drain after restore");
    lifecycle_guards::verify_post_restore_startup_and_projection(
        &mut env,
        &destination_pool,
        config(destination_url.clone(), temp.path(), "other-mirror-clean", &git),
        seeded.owner.identity.id,
        seeded.owner.identity.token_id,
        &seeded.owner.identity.username,
        &seeded.repos[0].head_oid,
    )
    .await?;

    let policy = Policy::from_env()?;
    let mut fence_client = rootyard::db::connect_url(&destination_url).await?;
    ensure!(
        matches!(
            admit_deleter_epoch(&fence_client, seeded.authority_epoch, &policy).await,
            Err(W8aError::StaleDeleterFenced { .. })
        ),
        "source-epoch deleter was not fenced"
    );
    ensure!(
        matches!(
            admit_deleter_epoch(&fence_client, restored.new_storage_authority_epoch, &policy).await,
            Err(W8aError::StaleDeleterFenced { remote_delete_fenced: true, .. })
        ),
        "new-epoch deleter was not fenced by remote_delete_fenced"
    );
    let mut enabled = policy.clone();
    enabled.enabled = true;
    ensure!(
        matches!(
            admit_deleter_epoch(&fence_client, restored.new_storage_authority_epoch, &enabled).await,
            Err(W8aError::DestructiveGcForbidden(_))
        ),
        "enabled destructive GC was not refused before the fence"
    );

    init_remote_merge_tables(&destination_pool).await?;
    let record = PendingMergeRecord {
        attempt_id: Uuid::new_v4(),
        operation_id: Uuid::new_v4(),
        decision_id: open_decision_id,
        tenant_id: seeded.owner.identity.id,
        repository_id: seeded.repos[0].id,
        pull_number: 1,
        base_ref: "refs/heads/main".into(),
        expected_head_oid: "0".repeat(40),
        expected_base_oid: "0".repeat(40),
        candidate_target_oid: "0".repeat(40),
        expected_version: 1,
        expected_storage_generation: 1,
        strategy: MergeStrategy::FastForward,
        authz_epoch: 1,
        pack_sha256: "a".repeat(64),
        facts_digest: "a".repeat(64),
        state: PullMergeState::PendingMerge,
        commit_log_index: None,
        commit_log_term: None,
        merged_oid: None,
        terminal_digest: None,
        reject_reason: None,
    };
    PgMergeStore::new(destination_pool.clone()).insert_pending(&record).await?;
    let merge_fence =
        fence_w8a_fresh_incarnation(&mut fence_client, seeded.cluster_incarnation, seeded.authority_epoch).await?;
    ensure!(merge_fence.aborted_pull_merges == 1, "pending remote merge was not aborted");

    drop(fence_client);
    drop(destination_pool);
    drop(source);
    let _ = seed::drop_database(&admin, &destination).await;
    let _ = seed::drop_database(&admin, &source_db).await;
    Ok(())
}
