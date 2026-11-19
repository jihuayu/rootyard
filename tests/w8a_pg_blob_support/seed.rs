//! Source seeding and database/config helpers for the W8-A paired drill.
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, ensure};
use base64::Engine as _;
use deadpool_postgres::Pool;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::blob_store::protected::{ProtectedPublication, ProtectedUploader, UploadSource};
use rootyard::db::{self, Identity, Repository};
use rootyard::events::{self, OperationRecord, RefEventInput};
use rootyard::ref_store::GitObjectFormat;
use rootyard::ref_store::artifact_hold::{
    AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactHoldPurpose, ArtifactSpec, HoldScope, PgArtifactHoldStore,
};
use rootyard::ref_store::core::pack_commit::{PackCommitPlan, PackRegistrationRequest, PgPackCommit};
use rootyard::ref_store::core::retention_root::{PgRetentionRoots, RootPurpose, RootSelector};
use rootyard::ref_store::serving::{
    PgServingRetentionRoots, ProvisionRequest, ServingRootCreate, ServingRootIntent, provision,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::retention_roots_support::db::{Db, deadline, gate_version, grant_collaborator};
use crate::retention_roots_support::git::{GitRepo, PairFiles, digest_file};
use crate::retention_roots_support::pack;
const HOLD_NAMESPACE: &str = "core-pack";
pub struct Credential {
    pub identity: Identity,
    pub secret: String,
}
impl Credential {
    pub fn headers(&self) -> axum::http::HeaderMap {
        basic_headers(&self.identity.username, &self.secret)
    }
}
fn basic_headers(username: &str, secret: &str) -> axum::http::HeaderMap {
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{secret}"));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
    );
    headers
}
pub struct SeededRepo {
    pub id: Uuid,
    pub owner: String,
    pub name: String,
    pub format: GitObjectFormat,
    pub head_oid: String,
}
pub struct SourceSeed {
    pub owner: Credential,
    pub browser: Credential,
    pub repos: Vec<SeededRepo>,
    pub cluster_incarnation: Uuid,
    pub authority_epoch: i64,
}
pub fn database_url() -> String {
    std::env::var("ROOTYARD_TEST_DATABASE_URL").expect("ROOTYARD_TEST_DATABASE_URL must be set for W8-A")
}
pub fn with_database(admin: &str, name: &str) -> String {
    let (base, suffix) = match admin.find(['?', '#']) {
        Some(index) => (&admin[..index], &admin[index..]),
        None => (admin, ""),
    };
    let base = base.trim_end_matches('/');
    let prefix = base.rsplit_once('/').map(|(prefix, _)| prefix).unwrap_or(base);
    format!("{prefix}/{name}{suffix}")
}
pub async fn create_database(admin: &str, name: &str) -> Result<()> {
    ensure!(
        name.starts_with("w8a_") && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    );
    let client = db::connect_url(admin).await?;
    client.batch_execute(&format!("CREATE DATABASE {name}")).await?;
    Ok(())
}
pub async fn drop_database(admin: &str, name: &str) -> Result<()> {
    let client = db::connect_url(admin).await?;
    let _ = client.batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)")).await;
    Ok(())
}
pub async fn issue_actor(pool: &Pool, label: &str) -> Result<Credential> {
    let username = format!("{label}{}", &Uuid::new_v4().simple().to_string()[..12]);
    let issued = db::issue_token(pool, &username, true, false).await?;
    let username = issued["username"].as_str().context("issued token lacks username")?;
    let secret = issued["token"].as_str().context("issued token lacks secret")?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{secret}"));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
    );
    let identity = rootyard::auth::authenticate(pool, &headers)
        .await
        .map_err(|error| anyhow!("real token authentication failed: {}", error.1))?;
    Ok(Credential { identity, secret: secret.to_owned() })
}
pub fn build_config(database_url: String, data_dir: PathBuf, git: PathBuf) -> rootyard::config::Config {
    rootyard::config::Config {
        database_url,
        data_dir,
        bind: "127.0.0.1:0".parse().unwrap(),
        git,
        max_request_bytes: 128 * 1024 * 1024,
        max_output_bytes: 512 * 1024 * 1024,
        max_concurrent_git: 2,
        git_timeout: std::time::Duration::from_secs(120),
        git_memory_bytes: 1024 * 1024 * 1024,
        max_repo_bytes: 1024 * 1024 * 1024,
        max_pending_deliveries: 100_000,
        outbox_worker: false,
        metrics_bind: None,
    }
}
pub async fn provision_repo(
    pool: &Pool,
    store: &BlobStore,
    actor: &Identity,
    name: &str,
    format: GitObjectFormat,
) -> Result<Repository> {
    let receipt = provision(
        pool,
        actor,
        ProvisionRequest { owner: None, name: name.to_owned(), object_format: format },
        store.backend_identity(),
        deadline(),
    )
    .await
    .map_err(|error| anyhow!("serving provision failed: {error}"))?;
    ensure!(receipt.created, "serving provision unexpectedly replayed");
    ensure!(receipt.repository.storage_backend == "pg_refstore", "provisioned repository is not pg_refstore");
    Ok(receipt.repository)
}
pub async fn seed_source(db: &Db, store: &BlobStore, git: &Path) -> Result<SourceSeed> {
    let owner = issue_actor(&db.pool, "w8aowner").await?;
    let developer = issue_actor(&db.pool, "w8adev").await?;
    let browser = issue_actor(&db.pool, "w8aweb").await?;
    db.pool.get().await?.execute("UPDATE tokens SET kind='browser' WHERE id=$1", &[&browser.identity.token_id]).await?;
    let mut repos = Vec::new();
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let name = format!("w8a-{}", format.as_str());
        let repository = provision_repo(&db.pool, store, &owner.identity, &name, format).await?;
        grant_collaborator(&db.pool, repository.id, owner.identity.id, developer.identity.id, "admin").await?;
        repos.push(seed_one(db, store, git, &owner.identity, &repository, format).await?);
    }
    seed_runtime_rows(&db.pool, &owner, &developer, &browser, &repos).await?;
    let client = db.pool.get().await?;
    let row = client
        .query_one(
            "SELECT c.incarnation, a.authority_id, a.authority_epoch
               FROM public.cluster_authority c CROSS JOIN public.pando_storage_authorities a
              ORDER BY a.authority_epoch DESC LIMIT 1",
            &[],
        )
        .await?;
    Ok(SourceSeed { owner, browser, repos, cluster_incarnation: row.get(0), authority_epoch: row.get(2) })
}
async fn seed_one(
    db: &Db,
    store: &BlobStore,
    git: &Path,
    owner: &Identity,
    repository: &Repository,
    format: GitObjectFormat,
) -> Result<SeededRepo> {
    let gate = gate_version(&db.pool, repository.id, owner.id).await?;
    let fixture = GitRepo::new(git.to_path_buf(), format).await?;
    let head_oid = fixture.build_commit("file.txt", format!("w8a {}\n", format.as_str()).as_bytes(), "w8a").await?;
    fixture.update_ref("refs/heads/main", &head_oid).await?;
    let files = fixture.pack_all(&format!("w8a-{}", format.as_str())).await?;
    let refs = vec![pack::main_update(format, None, &head_oid)?];
    let draft = pack::draft(db, repository.id, owner.id, 1, &gate, refs, std::slice::from_ref(&files)).await?;
    let publication = publish(db, store, &draft.plan, &files).await?;
    let pack_id = draft.plan.packs().first().ok_or_else(|| anyhow!("plan has no pack"))?.pack_id();
    register(db, &draft.plan, pack_id, &publication).await?;
    crate::authorized_commit(db, store, git, &draft.plan, owner).await?;
    let snapshot = producer_snapshot(db, store, owner, repository, 3600).await?;
    let adapter = PgRetentionRoots::new(store.clone(), git.to_path_buf())
        .map_err(|error| anyhow!("retention-root adapter: {error}"))?;
    let input = ServingRootCreate {
        owner: repository.owner.clone(),
        name: repository.name.clone(),
        intent: ServingRootIntent {
            source_snapshot_id: snapshot.snapshot_id,
            selector: RootSelector::Snapshot,
            purpose: RootPurpose::Backup,
            idempotency_key: "w8a-root".into(),
        },
    };
    PgServingRetentionRoots::new(adapter)
        .create_actor_owned(&db.pool, owner, input, deadline())
        .await
        .map_err(|error| anyhow!("actor-owned root: {error}"))?;
    Ok(SeededRepo {
        id: repository.id,
        owner: repository.owner.clone(),
        name: repository.name.clone(),
        format,
        head_oid,
    })
}
async fn publish(db: &Db, store: &BlobStore, plan: &PackCommitPlan, file: &PairFiles) -> Result<ProtectedPublication> {
    let (pack_sha, pack_len) = digest_file(&file.pack)?;
    let (idx_sha, idx_len) = digest_file(&file.idx)?;
    let scope = HoldScope::new(
        plan.repository_id(),
        plan.tenant_id(),
        plan.owner_id(),
        ArtifactHoldPurpose::RefPublication,
        plan.object_format(),
        plan.history_incarnation(),
        plan.authority_epoch(),
        plan.group_epoch(),
    )?;
    let request = AcquireArtifactHoldsRequest::new(
        scope,
        plan.identity().clone(),
        Uuid::new_v4(),
        store.backend_identity().clone(),
        Uuid::new_v4(),
        1,
        *plan.expected().gate_digest(),
        vec![
            ArtifactSpec::new(HOLD_NAMESPACE, pack_sha, pack_len)?,
            ArtifactSpec::new(HOLD_NAMESPACE, idx_sha, idx_len)?,
        ],
    )?;
    let grant = {
        let mut client = db.pool.get().await?;
        match PgArtifactHoldStore.acquire(&mut client, store, &request, deadline()).await? {
            AcquireOutcome::Granted { grant, .. } => grant,
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("fresh A3 acquire replayed")),
        }
    };
    let uploader = ProtectedUploader::new(store.clone());
    let sources = [UploadSource::new(file.pack.clone()), UploadSource::new(file.idx.clone())];
    let publication = uploader
        .consume_and_upload(&db.pool, grant, &sources, deadline().into_std())
        .await
        .map_err(|error| anyhow!("protected upload refused: {error}"))?;
    ensure!(publication.receipts().len() == 2, "publication is not exactly one pair");
    Ok(publication)
}
async fn register(db: &Db, plan: &PackCommitPlan, pack_id: Uuid, publication: &ProtectedPublication) -> Result<()> {
    let mut client = db.pool.get().await?;
    let request = PackRegistrationRequest::new(plan, pack_id, publication)?;
    PgPackCommit.register_publication(&mut client, request, deadline()).await?;
    Ok(())
}
async fn producer_snapshot(
    db: &Db,
    store: &BlobStore,
    actor: &Identity,
    repository: &Repository,
    lease: i64,
) -> Result<pack::SourceSnapshot> {
    pack::create_serving_snapshot(db, store, actor, repository, lease).await
}

async fn seed_runtime_rows(
    pool: &Pool,
    owner: &Credential,
    developer: &Credential,
    browser: &Credential,
    repos: &[SeededRepo],
) -> Result<()> {
    let repo = repos.first().context("at least one seeded repository is required")?;
    ensure!(repo.format == GitObjectFormat::Sha1, "runtime rows use the SHA-1 repository");
    let client = pool.get().await?;
    let job_id = Uuid::new_v4();
    let pull = 1_i64;
    let expires = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64 + 3600;
    let config_digest = "0".repeat(64);
    let head_oid = repo.head_oid.as_str();
    let owner_id = owner.identity.id;
    client
        .execute(
            "INSERT INTO ci_runs(id,tenant_id,repository_id,pull_number,pull_version,context,job_id,head_oid,base_oid,
                                 storage_generation,config_sha256,state,lease_generation,lease_expires_unix,runner_id)
             VALUES($1,$2,$3,$4,1,'w8a',$5,$6,$6,1,$7,'leased',1,$8,'w8a-runner')",
            &[&Uuid::new_v4(), &owner_id, &repo.id, &pull, &job_id, &head_oid, &config_digest, &expires],
        )
        .await?;
    let plan = json!({
        "version": 1,
        "job_id": job_id.to_string(),
        "owner_id": owner_id.to_string(),
        "repository_id": repo.id.to_string(),
        "storage_generation": 1,
        "object_format": "sha1",
        "target_oid": head_oid,
        "source_receipt_sha256": "1".repeat(64),
        "mirror_audience": Uuid::new_v4().to_string(),
        "expires_unix": expires,
        "dependencies": {"version": 1},
    });
    let credential: &[u8] = &[0xA5u8; 32];
    client
        .execute(
            "INSERT INTO ci_checkout_jobs(repository_id,job_id,owner_id,cancelled,revoked,plan,issuer_token_id,credential_digest,expires_unix)
             VALUES($1,$2,$3,false,false,$4,$5,$6,$7)",
            &[&repo.id, &job_id, &owner_id, &plan, &developer.identity.token_id, &credential, &expires],
        )
        .await?;
    let csrf: &[u8] = &[0x42u8; 32];
    client
        .execute(
            "INSERT INTO web_sessions(token_id,csrf_digest,expires_at)
             VALUES($1,$2,clock_timestamp()+interval '1 hour')",
            &[&browser.identity.token_id, &csrf],
        )
        .await?;
    client
        .execute(
            "INSERT INTO workspaces(id,repository_id,owner_slug,repository_name,agent_id,creator_id,state,host_id,
                                    lease_epoch,lease_until,revision,git_generation)
             VALUES($1,$2,$3,$4,'w8a-agent',$5,'ready',$6,1,clock_timestamp()+interval '1 hour',0,0)",
            &[&Uuid::new_v4(), &repo.id, &repo.owner, &repo.name, &owner_id, &Uuid::new_v4()],
        )
        .await?;
    let operation = OperationRecord {
        id: Uuid::new_v4(),
        repository_id: repo.id,
        actor_id: owner_id,
        token_id: owner.identity.token_id,
        service_principal_id: None,
        actor_name: owner.identity.username.clone(),
        sequence: 1,
        storage_generation: 1,
        outcome: "recorded".into(),
        evidence: json!({"kind": "w8a_paired_seed"}),
        admission: None,
    };
    let change = RefEventInput {
        transaction_sequence: 1,
        ref_name: "refs/heads/main".into(),
        old_oid: "0".repeat(40),
        new_oid: repo.head_oid.clone(),
    };
    events::publish(pool, &operation, &[change]).await?;
    let event = events::event_id(operation.id, 1, "refs/heads/main");
    client
        .execute(
            "UPDATE event_deliveries SET state='leased',lease_owner=$1,lease_generation=1,
                    lease_until=clock_timestamp()+interval '1 hour',attempts=1
              WHERE event_id=$2 AND consumer='audit-log'",
            &[&Uuid::new_v4(), &event],
        )
        .await?;
    Ok(())
}
pub fn write_volume(directory: &Path) -> Result<()> {
    std::fs::create_dir_all(directory)?;
    let identity = directory.join(".volume-id");
    std::fs::write(&identity, Uuid::new_v4().to_string())?;
    set_mode(&identity, 0o600)?;
    let lock = directory.join(".rootyard.lock");
    std::fs::OpenOptions::new().write(true).create_new(true).open(&lock)?;
    Ok(())
}
pub fn write_keyring(directory: &Path) -> Result<PathBuf> {
    write_keyring_with(directory, "w8a-key-1", 0x5A)
}
pub fn write_keyring_with(directory: &Path, id: &str, key_byte: u8) -> Result<PathBuf> {
    std::fs::create_dir_all(directory)?;
    set_mode(directory, 0o700)?;
    let key = [key_byte; 32];
    let path = directory.join(format!("{id}.key"));
    std::fs::write(&path, key)?;
    set_mode(&path, 0o600)?;
    let manifest = json!({
        "schema": 1,
        "current": id,
        "keys": [{"key_id": id, "sha256": hex::encode(Sha256::digest(key))}],
    });
    let manifest_path = directory.join("keyring.json");
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    set_mode(&manifest_path, 0o600)?;
    Ok(directory.to_path_buf())
}
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}
pub fn copy_tree(source: &Path, target: &Path) -> Result<()> {
    std::fs::create_dir_all(target)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let destination = target.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &destination)?;
        } else {
            std::fs::copy(entry.path(), &destination)?;
        }
    }
    Ok(())
}
pub fn pool_for(url: &str) -> Result<Pool> {
    crate::retention_roots_support::db::pool_for(url, "public", 8, None)
}
