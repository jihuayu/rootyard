//! Gate 15: a repository above eight pack pairs qualifies and an over-budget closure is refused
//! before any destination is published, with the `.partial` staging directory cleaned up (#153).
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow, ensure};
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

use rootyard::blob_store::opendal::BlobStore;
use rootyard::blob_store::protected::{ProtectedUploader, UploadSource};
use rootyard::config::Config;
use rootyard::db;
use rootyard::maintenance::paired_raft_backup::install_paired_write_raft_binding as bind_paired_write;
use rootyard::maintenance::paired_raft_backup::{
    DurableFreezeHandle, DurableFreezeRequest, Format30PairedBackupRequest, MtlsLiveRaftBackend, PairedBackupError,
    PairedWriteRaftScopeGuard, RepoBackupRegistrationSpec, create_format30_paired_raft_backup,
    enter_durable_pg_raft_freeze, load_pg_repo_backup_specs, restore_and_boot_format30_new_incarnation,
};
use rootyard::ref_store::contract::{IssuerLane, OperationIdentity, RequestDigest};
use rootyard::ref_store::core::artifact_hold::{
    AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactHoldPurpose, ArtifactSpec, HoldScope, PgArtifactHoldStore,
};
use rootyard::ref_store::core::decision_commit::{PgDecisionProtocol, RealmExpectation};
use rootyard::ref_store::core::pack_commit::{
    ContentDigest, PackArtifactRole, PackCommitExpectation, PackCommitPlan, PackCommitScope, PackMembershipEntry,
    PackRegistrationRequest, PackVerifier, PgPackCommit, PlannedArtifact, PlannedPack, VERIFIER_MAX_TOTAL_BYTES,
};
use rootyard::ref_store::core::types::{GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget, RefUpdate};
use rootyard::ref_store::serving::lookup;
use rootyard::ref_store::{CoreGate, GitObjectFormat};

use super::fixture::LoopbackS3;
use super::format30_helpers::{
    IssuedActor, find_git_bin, init_volume_dir, make_actor, make_backup_config, replace_db_in_url, run_git_cli,
    start_gateway,
};
use super::mtls_cluster::LiveMtlsRaftGroup;

const AUTHORITY: &str = "SELECT authority_id, generation FROM public.pando_storage_authorities WHERE singleton = true";
const MEMBERSHIPS: &str = "SELECT count(*) FROM public.ref_store_core_pack_memberships WHERE repository_id = $1";
const SEED_MEMBERSHIP: &str = "INSERT INTO public.ref_store_core_pack_memberships \
     (repository_id, pack_id, registration_id, artifact_set_digest, joined_revision) \
     SELECT repository_id, pack_id, registration_id, artifact_set_digest, gate_revision + 1 \
     FROM public.ref_store_core_pack_publications WHERE registration_id = $1";
const SEED_OPERATION: &str = "DELETE FROM public.ref_store_operations WHERE repository_id = $1 AND operation_id = $2";

/// Payload builder for the `i`-th pushed commit: `(file name, bytes)`.
type Payload = fn(usize) -> (String, Vec<u8>);

/// A fully bootstrapped source: PostgreSQL 17, one Blob store and one live 3-voter mTLS Raft group.
struct SourceEnv {
    s3: LoopbackS3,
    store: BlobStore,
    pool: deadpool_postgres::Pool,
    raft: MtlsLiveRaftBackend,
    owner: IssuedActor,
    addr: std::net::SocketAddr,
    gw: Option<tokio::task::JoinHandle<()>>,
    gate: CoreGate,
    repo_id: Uuid,
    cfg: Config,
    _binding: PairedWriteRaftScopeGuard,
    _group: LiveMtlsRaftGroup,
}

async fn stop_gateway(gw: &mut Option<tokio::task::JoinHandle<()>>) {
    if let Some(gw) = gw.take() {
        gw.abort();
        let _ = gw.await;
    }
}

/// Deterministic xorshift64 stream, so zlib cannot shrink a 6 MiB artifact.
fn incompressible_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn sha_len(path: &Path) -> Result<(String, u64)> {
    let bytes = fs::read(path)?;
    Ok((hex::encode(Sha256::digest(&bytes)), bytes.len() as u64))
}

fn text_payload(i: usize) -> (String, Vec<u8>) {
    (format!("f-{i}.txt"), format!("payload-{i}\n").into_bytes())
}

fn blob_payload(i: usize) -> (String, Vec<u8>) {
    (format!("blob-{i}.bin"), incompressible_bytes(0x9e37_79b9_7f4a_7c15 ^ (i as u64 + 1), 6 * 1024 * 1024))
}

async fn boot_source(git: &Path, dir: &Path, url: &str, gid: u64, repo: &str, bucket: &str) -> Result<SourceEnv> {
    let s3 = LoopbackS3::new();
    let store = s3.open_store(bucket)?;
    let group = LiveMtlsRaftGroup::start_three(gid)?;
    let raft = group.connect_backend(1)?;
    let pool = db::pool(url)?;
    db::migrate(&pool).await?;
    let binding = bind_paired_write(Arc::new(Mutex::new(group.connect_backend(1)?)), url)?;
    let owner = make_actor(&pool, &repo.replace('-', ""), true).await?;
    let (addr, gw) = start_gateway(pool.clone(), store.clone(), git.to_path_buf(), dir.join("gw")).await?;
    let created = reqwest::Client::new()
        .post(format!("http://{addr}/api/repos"))
        .bearer_auth(&owner.token)
        .json(&json!({ "name": repo, "object_format": "sha256" }))
        .send()
        .await?;
    ensure!(created.status().is_success(), "POST /api/repos failed");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let serving = lookup(&pool, &owner.identity, &owner.username, repo, true, store.backend_identity(), deadline)
        .await
        .map_err(|e| anyhow!("lookup: {}", e.1))?;
    let gate = serving.gate;
    let (repo_id, tenant) = (gate.repository_id(), gate.tenant_id());
    let (hi, ae, ge) = (gate.history_incarnation(), gate.authority_epoch(), gate.group_epoch());
    let exp = RealmExpectation::new(repo_id, tenant, gate.object_format(), hi, ae, ge)?;
    let mut client = pool.get().await?;
    PgDecisionProtocol.provision(&mut client, &exp, deadline).await?;
    drop(client);
    let cfg = make_backup_config(url.to_owned(), dir.join("vol"), git.to_path_buf());
    init_volume_dir(&cfg.data_dir)?;
    Ok(SourceEnv {
        s3,
        store,
        pool,
        raft,
        owner,
        addr,
        gw: Some(gw),
        gate,
        repo_id,
        cfg,
        _binding: binding,
        _group: group,
    })
}

/// Clone over Smart-HTTP and land `n` independent pushes, one commit each.
fn clone_and_push(git: &Path, dir: &Path, env: &SourceEnv, repo: &str, fill: Payload, n: usize) -> Result<()> {
    let (u, t) = (&env.owner.username, &env.owner.token);
    let url = format!("http://{u}:{t}@{}/git/{}/{repo}.git", env.addr, u);
    ensure!(run_git_cli(git, dir, &["clone", &url, "clone"]).status.success(), "clone");
    let clone = dir.join("clone");
    for i in 0..n {
        let (name, body) = fill(i);
        fs::write(clone.join(&name), body)?;
        ensure!(run_git_cli(git, &clone, &["add", "."]).status.success(), "add {name}");
        ensure!(run_git_cli(git, &clone, &["commit", "-q", "-m", &name]).status.success(), "commit {name}");
        let pushed = run_git_cli(git, &clone, &["push", "origin", "HEAD:refs/heads/main"]);
        ensure!(pushed.status.success(), "push {name}: {}", String::from_utf8_lossy(&pushed.stderr));
    }
    Ok(())
}

type Frozen = (Vec<RepoBackupRegistrationSpec>, DurableFreezeHandle);

async fn freeze_source(pool: &deadpool_postgres::Pool, raft: &mut MtlsLiveRaftBackend, url: &str) -> Result<Frozen> {
    let specs = load_pg_repo_backup_specs(&**pool.get().await?).await?;
    ensure!(specs.len() == 1, "the fixture must own exactly one source repository");
    let req = DurableFreezeRequest {
        fenced_deleter_epoch: 11,
        app_fence_seq: 3,
        scope_authz_floor: 25,
        repos: &specs,
        peer_repos_by_group: BTreeMap::new(),
        fence_database_url: url,
    };
    let mut client = pool.get().await?;
    let freeze = enter_durable_pg_raft_freeze(&mut client, raft, &mut BTreeMap::new(), &req).await?;
    Ok((specs, freeze))
}

fn backup_request<'a>(
    env: &'a SourceEnv,
    freeze: &'a DurableFreezeHandle,
    staging: &'a Path,
    destination: &'a Path,
) -> Format30PairedBackupRequest<'a> {
    Format30PairedBackupRequest {
        backup_id: Uuid::new_v4(),
        src_config: &env.cfg,
        freeze_handle: freeze,
        raft: &env.raft,
        peer_groups: Vec::new(),
        store: &env.store,
        staging_dir: staging,
        destination,
    }
}

/// Build one real `sha256` Git `.pack + .idx` pair holding a single 6 MiB incompressible blob.
fn seed_pack(git: &Path, scratch: &Path) -> Result<(PathBuf, PathBuf, String)> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    fs::create_dir_all(scratch)?;
    ensure!(run_git_cli(git, scratch, &["init", "--bare", "--object-format=sha256"]).status.success(), "bare init");
    fs::write(scratch.join("seed.bin"), incompressible_bytes(0xfeed_face_cafe_beef, 6 * 1024 * 1024))?;
    let hashed = run_git_cli(git, scratch, &["hash-object", "-w", "seed.bin"]);
    ensure!(hashed.status.success(), "hash-object failed: {}", String::from_utf8_lossy(&hashed.stderr));
    let blob_oid = String::from_utf8(hashed.stdout)?.trim().to_owned();
    let mut cmd = Command::new(git);
    cmd.current_dir(scratch).env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_CONFIG_GLOBAL", "/dev/null");
    cmd.args(["-c", "core.hooksPath=/dev/null", "-c", "gc.auto=0", "pack-objects"]).arg(scratch.join("seed"));
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("pack-objects has no stdin"))?
        .write_all(format!("{blob_oid}\n").as_bytes())?;
    let out = child.wait_with_output()?;
    ensure!(out.status.success(), "pack-objects failed: {}", String::from_utf8_lossy(&out.stderr));
    let name = String::from_utf8(out.stdout)?.trim().to_owned();
    let (pack, idx) = (scratch.join(format!("seed-{name}.pack")), scratch.join(format!("seed-{name}.idx")));
    ensure!(pack.is_file() && idx.is_file(), "pack-objects did not emit a pack/idx pair");
    Ok((pack, idx, blob_oid))
}

/// Register the seed pair through the real A3 hold + A4 register/verify pipeline, then activate it.
async fn register_over_budget_pair(env: &SourceEnv, git: &Path, scratch: &Path) -> Result<()> {
    let (pack_path, idx_path, blob_oid) = seed_pack(git, scratch)?;
    let ((pack_sha, pack_len), (idx_sha, idx_len)) = (sha_len(&pack_path)?, sha_len(&idx_path)?);
    let (pack_id, registration_id, op_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let gate = &env.gate;
    let (repo_id, tenant, fmt) = (env.repo_id, gate.tenant_id(), GitObjectFormat::Sha256);
    let (hist, ae, ge) = (gate.history_incarnation(), gate.authority_epoch(), gate.group_epoch());
    let mut c = env.pool.get().await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let auth = c.query_one(AUTHORITY, &[]).await?;
    let (authority, gen_id): (Uuid, i64) = (auth.get(0), auth.get(1));
    let baseline = PgPackCommit.capture_baseline(&mut c, repo_id, tenant, deadline).await?;
    let mut old = Vec::new();
    for pack in baseline.old_packs() {
        old.push(PackMembershipEntry::from_pack(pack)?);
    }
    let scope = PackCommitScope::new(repo_id, tenant, tenant, fmt, hist, ae, ge)?;
    let lane = IssuerLane::new("over-budget-seed")?;
    let digest = RequestDigest::of("over-budget-seed", &[op_id.as_bytes()]);
    let ident = OperationIdentity::new(repo_id, tenant, lane, 1, op_id, digest)?;
    let oid = GitOid::parse(fmt, &blob_oid)?;
    let update = RefUpdate::new(RefName::new("refs/tags/probe")?, RefPrecondition::Absent, RefTarget::Oid(oid));
    let pack_art = PlannedArtifact::new(PackArtifactRole::Pack, ContentDigest::parse(pack_sha.clone())?, pack_len)?;
    let idx_art = PlannedArtifact::new(PackArtifactRole::Idx, ContentDigest::parse(idx_sha.clone())?, idx_len)?;
    let planned = PlannedPack::new(pack_id, registration_id, pack_art, idx_art)?;
    let gv = baseline.gate();
    let exp = PackCommitExpectation::new(gv.revision(), *gv.digest(), baseline.mode())?;
    let mem = baseline.membership_digest();
    let plan = PackCommitPlan::new(scope, ident, exp, HeadUpdate::Keep, vec![update], mem, old, vec![planned])?;
    let _token = PgPackCommit.begin_pending(&mut c, &plan, deadline).await?;
    let hold = HoldScope::new(repo_id, tenant, tenant, ArtifactHoldPurpose::RefPublication, fmt, hist, ae, ge)?;
    let arts = vec![
        ArtifactSpec::new("gateway-pack", pack_sha.clone(), pack_len)?,
        ArtifactSpec::new("gateway-pack", idx_sha.clone(), idx_len)?,
    ];
    let (operation, backend) = (plan.identity().clone(), env.store.backend_identity().clone());
    let gate_digest = *gv.digest();
    let req_id = Uuid::new_v4();
    let req = AcquireArtifactHoldsRequest::new(hold, operation, req_id, backend, authority, gen_id, gate_digest, arts)?;
    let acquired = PgArtifactHoldStore.acquire(&mut c, &env.store, &req, deadline).await?;
    let AcquireOutcome::Granted { grant, .. } = acquired else {
        return Err(anyhow!("the over-budget A3 acquire must grant a fresh hold"));
    };
    let sources = [UploadSource::new(&pack_path), UploadSource::new(&idx_path)];
    let publisher = ProtectedUploader::new(env.store.clone());
    let publication = publisher.consume_and_upload(&env.pool, grant, &sources, deadline.into_std()).await?;
    let registration = PackRegistrationRequest::new(&plan, pack_id, &publication)?;
    PgPackCommit.register_publication(&mut c, registration, deadline).await?;
    let ctx = PgPackCommit.capture_context(&mut c, &plan, deadline).await?;
    let verifier = PackVerifier::new(env.store.clone(), git.to_path_buf())?;
    ensure!(verifier.verify(&plan, &ctx, deadline.into_std()).await.is_err(), "live A4 must refuse > 64 MiB");
    let tx = c.transaction().await?;
    tx.batch_execute("SET LOCAL session_replication_role = replica").await?;
    tx.execute(SEED_MEMBERSHIP, &[&registration_id]).await?;
    tx.execute(SEED_OPERATION, &[&repo_id, &op_id]).await?;
    tx.commit().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires live PostgreSQL 17 + built raft-node and rootyard-peer-attestor binaries"]
async fn gate15_admitted_over_eight_pairs_restores_and_verifies_end_to_end() -> Result<()> {
    let base_url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let admin = db::pool(&base_url)?;
    let suffix = &Uuid::new_v4().simple().to_string()[..12];
    let (src_db, dst_db) = (format!("gate15_src_{suffix}"), format!("gate15_dst_{suffix}"));
    for name in [&src_db, &dst_db] {
        admin.get().await?.batch_execute(&format!("CREATE DATABASE {name}")).await?;
    }
    let (src_url, dst_url) = (replace_db_in_url(&base_url, &src_db)?, replace_db_in_url(&base_url, &dst_db)?);
    let result: Result<()> = async {
        let git = find_git_bin()?;
        let dir = TempDir::new()?;
        let mut env = boot_source(&git, dir.path(), &src_url, 51, "gate15-nine", "paired-fmt30-d15-src").await?;
        clone_and_push(&git, dir.path(), &env, "gate15-nine", text_payload, 9)?;
        stop_gateway(&mut env.gw).await;
        let memberships: i64 = env.pool.get().await?.query_one(MEMBERSHIPS, &[&env.repo_id]).await?.get(0);
        ensure!(memberships == 9, "nine Smart-HTTP pushes must own nine active pairs, got {memberships}");
        let (specs, freeze) = freeze_source(&env.pool, &mut env.raft, &src_url).await?;
        ensure!(specs[0].expected_packs.len() == 9, "the source must own nine active pack pairs");
        let s3_env = env.s3.apply_env("paired-fmt30-d15-src");
        let arch = dir.path().join("gate15-archive");
        let request = backup_request(&env, &freeze, dir.path(), &arch);
        let (manifest, _receipt) = create_format30_paired_raft_backup(request).await?;
        let entries: Vec<_> = manifest.blob_closure.entries.iter().filter(|e| e.repository_id == env.repo_id).collect();
        let packs = entries.iter().filter(|e| e.role == "pack").count();
        let idxs = entries.iter().filter(|e| e.role == "idx").count();
        ensure!(packs == 9 && idxs == 9, "the admitted archive must carry nine pack/idx pairs, got {packs}/{idxs}");
        let repo_bytes: u64 = entries.iter().map(|e| e.length).sum();
        ensure!(repo_bytes <= VERIFIER_MAX_TOTAL_BYTES, "the admitted archive must stay within the verifier budget");
        drop(s3_env);
        // Empty the bucket: the restore must re-upload every archived blob into the same backend.
        env.s3.state.objects.lock().unwrap().clear();
        let dst_group = LiveMtlsRaftGroup::start_three(52)?;
        let mut boot = dst_group.connect_backend(1)?;
        let _dst = bind_paired_write(Arc::new(Mutex::new(dst_group.connect_backend(1)?)), &dst_url)?;
        let mut peers: BTreeMap<i64, MtlsLiveRaftBackend> = BTreeMap::new();
        let dcfg = make_backup_config(dst_url.clone(), dir.path().join("gate15-dst-vol"), git.clone());
        let work = dir.path().join("gate15-work");
        let restore_env = env.s3.apply_env("paired-fmt30-d15-src");
        let (outcome, _admission) =
            restore_and_boot_format30_new_incarnation(&arch, &work, &dcfg, &env.store, &mut boot, &mut peers).await?;
        drop(restore_env);
        ensure!(outcome.restored_repos == 1, "the over-eight-pair repository must be restored");
        let dst_pool = db::pool(&dcfg.database_url)?;
        let restored: i64 = dst_pool.get().await?.query_one(MEMBERSHIPS, &[&env.repo_id]).await?.get(0);
        ensure!(restored == 1, "nine archived pairs must consolidate into one new-realm pair, got {restored}");
        let dst_owner = make_actor(&dst_pool, &env.owner.username, false).await?;
        let (rgw, gw_jh) = start_gateway(dst_pool, env.store.clone(), git.clone(), dir.path().join("rgw")).await?;
        let (u, t) = (&dst_owner.username, &dst_owner.token);
        let rurl = format!("http://{u}:{t}@{rgw}/git/{u}/gate15-nine.git");
        ensure!(run_git_cli(&git, dir.path(), &["clone", &rurl, "gate15-rclone"]).status.success(), "restored clone");
        let rclone = dir.path().join("gate15-rclone");
        ensure!(run_git_cli(&git, &rclone, &["fsck", "--full"]).status.success(), "restored git fsck");
        let count = run_git_cli(&git, &rclone, &["rev-list", "--count", "HEAD"]);
        ensure!(count.status.success() && String::from_utf8_lossy(&count.stdout).trim() == "9", "nine commits");
        for i in 0..9 {
            ensure!(fs::read_to_string(rclone.join(format!("f-{i}.txt")))? == format!("payload-{i}\n"), "f-{i}");
        }
        gw_jh.abort();
        let _ = gw_jh.await;
        Ok(())
    }
    .await;
    if let Ok(c) = admin.get().await {
        for name in [&src_db, &dst_db] {
            let _ = c.batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)")).await;
        }
    }
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires live PostgreSQL 17 + built raft-node and rootyard-peer-attestor binaries"]
async fn gate15_over_budget_backup_refused_before_publishing_destination() -> Result<()> {
    let base_url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let admin = db::pool(&base_url)?;
    let db_name = format!("gate15_over_{}", &Uuid::new_v4().simple().to_string()[..12]);
    admin.get().await?.batch_execute(&format!("CREATE DATABASE {db_name}")).await?;
    let url = replace_db_in_url(&base_url, &db_name)?;
    let result: Result<()> = async {
        let git = find_git_bin()?;
        let dir = TempDir::new()?;
        let mut env = boot_source(&git, dir.path(), &url, 53, "gate15-over", "paired-fmt30-d15-over").await?;
        clone_and_push(&git, dir.path(), &env, "gate15-over", blob_payload, 10)?;
        stop_gateway(&mut env.gw).await;
        let memberships: i64 = env.pool.get().await?.query_one(MEMBERSHIPS, &[&env.repo_id]).await?.get(0);
        ensure!(memberships == 10, "ten Smart-HTTP pushes must own ten active pairs, got {memberships}");
        register_over_budget_pair(&env, &git, &dir.path().join("gate15-over-seed")).await?;
        let (specs, freeze) = freeze_source(&env.pool, &mut env.raft, &url).await?;
        ensure!(specs[0].expected_packs.len() == 11, "the source must own eleven active pack pairs");
        let total: u64 = specs[0].expected_packs.iter().map(|p| p.pack_bytes + p.idx_bytes).sum();
        ensure!(total > VERIFIER_MAX_TOTAL_BYTES, "the seeded closure must exceed the 64 MiB verifier budget");
        let s3_env = env.s3.apply_env("paired-fmt30-d15-over");
        let staging = dir.path().join("gate15-over-staging");
        fs::create_dir_all(&staging)?;
        let destination = dir.path().join("gate15-over-archive");
        let res = create_format30_paired_raft_backup(backup_request(&env, &freeze, &staging, &destination)).await;
        drop(s3_env);
        let refusal = match res {
            Err(PairedBackupError::RepositoryClosureExceedsVerifierBudget { repository_id, bound_bytes }) => {
                (repository_id, bound_bytes)
            }
            other => return Err(anyhow!("an over-budget closure must be refused before publication: {other:?}")),
        };
        ensure!(refusal == (Some(env.repo_id), VERIFIER_MAX_TOTAL_BYTES), "wrong refusal: {refusal:?}");
        let unpublished = !destination.exists() && !destination.join("COMPLETE").exists();
        ensure!(unpublished && !destination.join("manifest.json").exists(), "a refused backup publishes nothing");
        ensure!(fs::read_dir(&staging)?.next().is_none(), "the .partial staging directory must be removed");
        Ok(())
    }
    .await;
    if let Ok(c) = admin.get().await {
        let _ = c.batch_execute(&format!("DROP DATABASE IF EXISTS {db_name} WITH (FORCE)")).await;
    }
    result
}
