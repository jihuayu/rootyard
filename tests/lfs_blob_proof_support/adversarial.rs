//! Adversarial concurrency, pointer rejection, crash recovery, and shared-hold E2E checks (`Refs #145`).

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use rootyard::lfs::blob_proof_publication::{
    AttestationOutcome, LfsBlobRuntimeGate, LfsCollaboratorRole, LfsProofRejectCode, LfsPushAttestationRequest,
    LfsRefUpdateSpec, LfsRepoRealm, LfsTransferContext, PgLfsBlobStore, PointerResolutionSource, SharedLfsHoldGrant,
    attest_and_authorize_push, delete_or_retire_lfs_object, hydrate_clean_compute_view, upload_lfs_object_to_remote,
};
use rootyard::ref_store::GitObjectFormat;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

use super::{LoopbackS3, RunningLfsServer, init_bare_git_repo, run_git_ok, run_git_raw};

pub async fn exercise_concurrent_uploads_and_corrupt_retries(
    gate: &LfsBlobRuntimeGate,
    pg: &PgLfsBlobStore,
    realm: &LfsRepoRealm,
    alice_id: Uuid,
    scratch: &Path,
) -> Result<String> {
    let alice = pg.authenticate_principal("alice", "alice-tok").await?;
    let access = pg.authorize_repo_access(realm, &alice, true, true).await?;
    assert_eq!(access.actor_id, alice_id);

    let payload: Vec<u8> = (0..98_304u32).map(|i| ((i.wrapping_mul(31) ^ 0x5a) & 0xff) as u8).collect();
    let oid = hex::encode(Sha256::digest(&payload));
    let sz = payload.len() as i64;
    let ctx =
        LfsTransferContext { gate, pg, realm, access: &access, scratch_dir: scratch, timeout: Duration::from_secs(20) };

    let mut bad_bytes = payload.clone();
    bad_bytes[0] ^= 0xff;
    let (u1, u2, u3, bad_digest, bad_len) = tokio::join!(
        upload_lfs_object_to_remote(&ctx, &oid, sz, &payload),
        upload_lfs_object_to_remote(&ctx, &oid, sz, &payload),
        upload_lfs_object_to_remote(&ctx, &oid, sz, &payload),
        upload_lfs_object_to_remote(&ctx, &oid, sz, &bad_bytes),
        upload_lfs_object_to_remote(&ctx, &oid, sz + 9, &payload),
    );
    let r1 = u1?;
    let r2 = u2?;
    let r3 = u3?;
    ensure!(r1.hold_id == r2.hold_id && r2.hold_id == r3.hold_id, "concurrent uploads must converge on one hold");
    ensure!(r1.locator == r2.locator && r2.locator == r3.locator, "concurrent uploads must preserve winning locator");
    ensure!(bad_digest.unwrap_err().code == LfsProofRejectCode::SizeOrDigestMismatch);
    ensure!(bad_len.unwrap_err().code == LfsProofRejectCode::SizeOrDigestMismatch);

    // Physical deletion must remain strictly disabled by policy.
    let del_err = delete_or_retire_lfs_object(&ctx, &oid, false).await.expect_err("physical delete must be refused");
    ensure!(del_err.code == LfsProofRejectCode::DeleteDisabledByPolicy);
    Ok(oid)
}

pub struct PointerRejectionInput<'a> {
    pub srv: &'a RunningLfsServer,
    pub gate: &'a LfsBlobRuntimeGate,
    pub pg: &'a PgLfsBlobStore,
    pub realm: &'a LfsRepoRealm,
    pub home: &'a Path,
    pub committed_oid: &'a str,
    pub committed_size: i64,
}

pub async fn exercise_named_pointer_rejections_and_attestation_replay(inp: PointerRejectionInput<'_>) -> Result<()> {
    let PointerRejectionInput { srv, gate, pg, realm, home, committed_oid, committed_size } = inp;
    let url = format!("{}/{}/{}.git", srv.base_url, realm.owner_username, realm.repo_name).replacen(
        "http://",
        "http://alice:alice-tok@",
        1,
    );

    // 1. MissingRemoteBlob: push raw pointer referencing an unuploaded SHA-256 OID (`--no-verify` bypasses client pre-push).
    let missing_wt = TempDir::new()?;
    run_git_ok(missing_wt.path(), home, &["clone", &url, "."])?;
    let ghost_oid = "9e".repeat(32);
    let ghost_ptr = format!("version https://git-lfs.github.com/spec/v1\noid sha256:{ghost_oid}\nsize 777\n");
    std::fs::write(missing_wt.path().join("ghost.txt"), ghost_ptr)?;
    run_git_ok(missing_wt.path(), home, &["add", "ghost.txt"])?;
    run_git_ok(missing_wt.path(), home, &["commit", "-m", "ghost pointer"])?;
    let out_missing = run_git_raw(missing_wt.path(), home, &["push", "--no-verify", "origin", "main"])?;
    ensure!(!out_missing.status.success(), "push with missing remote blob must fail");
    let stderr_missing = String::from_utf8_lossy(&out_missing.stderr);
    ensure!(stderr_missing.contains("missing_remote_blob"), "expected missing_remote_blob, got: {stderr_missing}");

    // 2. SizeOrDigestMismatch: batch containing BOTH valid pointer and wrong-size pointer to the SAME committed OID.
    let bad_sz_wt = TempDir::new()?;
    run_git_ok(bad_sz_wt.path(), home, &["clone", &url, "."])?;
    let valid_ptr =
        format!("version https://git-lfs.github.com/spec/v1\noid sha256:{committed_oid}\nsize {committed_size}\n");
    let wrong_ptr = format!(
        "version https://git-lfs.github.com/spec/v1\noid sha256:{committed_oid}\nsize {}\n",
        committed_size + 55
    );
    std::fs::write(bad_sz_wt.path().join("ok_ref.ptr"), valid_ptr)?;
    std::fs::write(bad_sz_wt.path().join("wrong_ref.ptr"), wrong_ptr)?;
    run_git_ok(bad_sz_wt.path(), home, &["add", "ok_ref.ptr", "wrong_ref.ptr"])?;
    run_git_ok(bad_sz_wt.path(), home, &["commit", "-m", "dual valid + wrong-size pointer"])?;
    let out_sz = run_git_raw(bad_sz_wt.path(), home, &["push", "--no-verify", "origin", "main"])?;
    ensure!(!out_sz.status.success(), "wrong-size pointer must fail");
    let stderr_sz = String::from_utf8_lossy(&out_sz.stderr);
    ensure!(stderr_sz.contains("size_or_digest_mismatch"), "expected size_or_digest_mismatch, got: {stderr_sz}");

    // 3. MalformedLfsPointer: corrupt pointer header/body.
    let mal_wt = TempDir::new()?;
    run_git_ok(mal_wt.path(), home, &["clone", &url, "."])?;
    std::fs::write(
        mal_wt.path().join("corrupt.ptr"),
        "version https://git-lfs.github.com/spec/v1\noid sha256:not-a-valid-hex\nsize 10\n",
    )?;
    run_git_ok(mal_wt.path(), home, &["add", "corrupt.ptr"])?;
    run_git_ok(mal_wt.path(), home, &["commit", "-m", "malformed pointer"])?;
    let out_mal = run_git_raw(mal_wt.path(), home, &["push", "--no-verify", "origin", "main"])?;
    ensure!(!out_mal.status.success(), "malformed pointer must fail");
    let stderr_mal = String::from_utf8_lossy(&out_mal.stderr);
    ensure!(stderr_mal.contains("malformed_lfs_pointer"), "expected malformed_lfs_pointer, got: {stderr_mal}");

    // 4. Deterministic replay + AttestationEquivocation check on `attest_and_authorize_push`.
    let head_oid = run_git_ok(Path::new(&realm.bare_git_dir), home, &["rev-parse", "refs/heads/main"])?;
    let zero_oid = "0".repeat(head_oid.len());
    let alice = pg.authenticate_principal("alice", "alice-tok").await?;
    let access = pg.authorize_repo_access(realm, &alice, true, false).await?;
    let ctx = LfsTransferContext {
        gate,
        pg,
        realm,
        access: &access,
        scratch_dir: srv.scratch_dir.path(),
        timeout: Duration::from_secs(20),
    };
    let op_id = Uuid::new_v4();
    let req = LfsPushAttestationRequest {
        operation_id: op_id,
        updates: vec![LfsRefUpdateSpec {
            ref_name: "refs/heads/replay-check".into(),
            old_oid: zero_oid.clone(),
            new_oid: head_oid.clone(),
        }],
        git_object_dir: None,
        git_alternate_object_dirs: None,
    };
    let first = attest_and_authorize_push(&ctx, &req).await?;
    ensure!(matches!(first, AttestationOutcome::Issued(_)));
    let second = attest_and_authorize_push(&ctx, &req).await?;
    ensure!(matches!(second, AttestationOutcome::Replayed(_)));
    ensure!(first.attestation().attestation_id == second.attestation().attestation_id);
    ensure!(first.attestation().proof_digest == second.attestation().proof_digest);

    let mut equiv_req = req;
    equiv_req.updates[0].ref_name = "refs/heads/tampered-target".into();
    let equiv_err = attest_and_authorize_push(&ctx, &equiv_req).await.expect_err("equivocated replay must fail");
    ensure!(equiv_err.code == LfsProofRejectCode::AttestationEquivocation);
    Ok(())
}

pub struct RestartSharedHoldInput<'a> {
    pub s3: &'a LoopbackS3,
    pub root_prefix: &'a str,
    pub pg: &'a PgLfsBlobStore,
    pub realm: &'a LfsRepoRealm,
    pub fmt: GitObjectFormat,
    pub home: &'a Path,
    pub historical_commit: &'a str,
    pub shared_oid: &'a str,
    pub shared_bytes: &'a [u8],
}

pub async fn exercise_restart_recovery_hydration_and_shared_holds(inp: RestartSharedHoldInput<'_>) -> Result<()> {
    let RestartSharedHoldInput { s3, root_prefix, pg, realm, fmt, home, historical_commit, shared_oid, shared_bytes } =
        inp;
    // Simulate crashed in-flight upload attempt, then restart a clean server instance with empty local disk.
    pg.record_upload_attempt_start(
        Uuid::new_v4(),
        realm.owner_tenant_id,
        realm.repository_id,
        realm.owner_tenant_id,
        &"f1".repeat(32),
        1024,
    )
    .await?;

    let fresh_gate = LfsBlobRuntimeGate::configured(s3.open_store(root_prefix)?);
    let restarted = RunningLfsServer::start(fresh_gate.clone(), pg.clone()).await?;
    let rec_report = pg.reconcile_in_flight_uploads(realm.repository_id).await?;
    ensure!(rec_report.aborted_orphaned_attempts == 1);
    ensure!(rec_report.committed_objects_preserved >= 2);

    // Hydrate clean compute view at `historical_commit` purely from remote OpenDAL BlobStore.
    let bob = pg.authenticate_principal("bob", "bob-tok").await?;
    let bob_access = pg.authorize_repo_access(realm, &bob, false, false).await?;
    let compute_dir = TempDir::new()?;
    let ctx = LfsTransferContext {
        gate: &fresh_gate,
        pg,
        realm,
        access: &bob_access,
        scratch_dir: restarted.scratch_dir.path(),
        timeout: Duration::from_secs(20),
    };
    let hydration = hydrate_clean_compute_view(&ctx, historical_commit, compute_dir.path()).await?;
    ensure!(hydration.hydrated_files >= 1, "expected hydrated LFS file in compute view");
    let hydrated_weights = std::fs::read(compute_dir.path().join("weights.bin"))?;
    ensure!(hydrated_weights == shared_bytes, "compute view hydrated payload mismatch");

    // Provision cross-owner fork repository `dave/fork-engine` (`dave != alice`) and test SharedLfsHoldGrant.
    let dave = pg.register_principal(Uuid::new_v4(), &format!("dave_{}", &root_prefix[..6]), "dave-tok").await?;
    let fork_bare_dir = TempDir::new()?;
    let fmt_str = match fmt {
        GitObjectFormat::Sha1 => "sha1",
        GitObjectFormat::Sha256 => "sha256",
    };
    init_bare_git_repo(fork_bare_dir.path(), fmt_str)?;
    let fork_realm = pg
        .provision_repository(
            Uuid::new_v4(),
            dave.actor_id,
            &dave.username,
            "fork-engine",
            fmt,
            fork_bare_dir.path().to_str().context("utf8 path")?,
        )
        .await?;
    pg.grant_collaborator(fork_realm.repository_id, bob.actor_id, LfsCollaboratorRole::Write).await?;

    let src_blob =
        pg.load_committed_blob(realm.owner_tenant_id, realm.repository_id, shared_oid).await?.context("source blob")?;
    let grant_id = Uuid::new_v4();
    pg.grant_shared_hold(&SharedLfsHoldGrant {
        grant_id,
        source_tenant_id: realm.owner_tenant_id,
        source_repository_id: realm.repository_id,
        target_tenant_id: fork_realm.owner_tenant_id,
        target_repository_id: fork_realm.repository_id,
        grantee_actor_id: Some(bob.actor_id),
        oid_sha256: shared_oid.to_owned(),
        size_bytes: shared_bytes.len() as i64,
        source_hold_id: src_blob.hold_id,
        active: false,
    })
    .await?;

    let fork_url = format!("{}/{}/fork-engine.git", restarted.base_url, dave.username).replacen(
        "http://",
        "http://bob:bob-tok@",
        1,
    );
    let fork_wt = TempDir::new()?;
    run_git_ok(fork_wt.path(), home, &["init", "--initial-branch=main", &format!("--object-format={fmt_str}")])?;
    run_git_ok(fork_wt.path(), home, &["remote", "add", "origin", &fork_url])?;
    let ptr_body =
        format!("version https://git-lfs.github.com/spec/v1\noid sha256:{shared_oid}\nsize {}\n", shared_bytes.len());
    std::fs::write(fork_wt.path().join("shared_weights.bin"), ptr_body)?;
    run_git_ok(fork_wt.path(), home, &["add", "shared_weights.bin"])?;
    run_git_ok(fork_wt.path(), home, &["commit", "-m", "cross-owner shared pointer"])?;

    // Inactive shared hold must reject push with `unauthorized_shared_hold`.
    let denied = run_git_raw(fork_wt.path(), home, &["push", "--no-verify", "origin", "main"])?;
    ensure!(!denied.status.success(), "inactive shared hold push must fail");
    ensure!(String::from_utf8_lossy(&denied.stderr).contains("unauthorized_shared_hold"));

    // Activate shared hold -> push succeeds with `PointerResolutionSource::SharedHold`, and `git lfs pull` downloads cleanly!
    pg.set_shared_hold_active(grant_id, true).await?;
    let op_hdr = Uuid::new_v4();
    run_git_ok(
        fork_wt.path(),
        home,
        &[
            "-c",
            &format!("http.extraHeader=X-Rootyard-Operation-Id: {op_hdr}"),
            "push",
            "--no-verify",
            "origin",
            "main",
        ],
    )?;
    let fork_att = pg.load_attestation(fork_realm.repository_id, op_hdr).await?.context("fork attestation")?;
    ensure!(matches!(fork_att.pointers[0].resolution, PointerResolutionSource::SharedHold { .. }));

    let fork_clone = TempDir::new()?;
    run_git_ok(fork_clone.path(), home, &["clone", &fork_url, "."])?;
    run_git_ok(fork_clone.path(), home, &["lfs", "install", "--local"])?;
    std::fs::write(fork_clone.path().join(".gitattributes"), "*.bin filter=lfs diff=lfs merge=lfs -text\n")?;
    run_git_ok(fork_clone.path(), home, &["lfs", "pull"])?;
    ensure!(std::fs::read(fork_clone.path().join("shared_weights.bin"))? == shared_bytes);

    // Revoking shared hold immediately blocks subsequent cross-owner batch downloads.
    pg.set_shared_hold_active(grant_id, false).await?;
    let after_revoke = run_git_raw(fork_wt.path(), home, &["lfs", "fetch", "--all"])?;
    ensure!(!after_revoke.status.success(), "revoked shared hold must refuse lfs fetch");
    Ok(())
}
