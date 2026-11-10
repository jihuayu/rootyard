//! Seed mode: the real API-produced format22 source for issue #169.
//!
//! Positive state only comes from production APIs:
//! * ready `pg_refstore` repositories from `ref_store::serving::provision` (the
//!   real create path, bound to the live store's immutable backend identity);
//! * three packs on the bound repository through A3 acquire/consume/upload, A4
//!   `register_publication` and native verified commits (a real multi-pack
//!   membership), reusing the unchanged `retention_roots_support::pack` helpers;
//! * one A5 snapshot + pin, released after the roots so the retained roots are
//!   the only protection;
//! * one active and one released retention root whose producer owner is a real
//!   token user that is neither the repository tenant nor a pack owner.
//!
//! Ordering matters: the gate pins pack ownership to the repository tenant, so
//! the bound repository is provisioned *first* and the empty/unrelated
//! repositories *after* its packs, so they stay genuinely empty.
//!
//! No SQL row here creates an artifact, publication, membership, snapshot, pin
//! or root. The only direct writes are the token rows of the production
//! `db::issue_token` and the fixture-local offline `data/.volume-id`.
use anyhow::{Result, anyhow, ensure};
use base64::Engine as _;
use deadpool_postgres::Pool;
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::db;
use rootyard::ref_store::core::pack_commit::RegisteredPack;
use rootyard::ref_store::core::retention_root::PgRetentionRoots;
use rootyard::ref_store::serving::{ProvisionRequest, provision};
use rootyard::ref_store::{CoreGateVersion, GitObjectFormat, PgRefStoreCore, VersionCheck};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use super::db::{Db, deadline};
use super::marker::{self, RegistrationBadge};
use super::pack::{self, Verified};
use super::{pack_plan, roots};

const SHA1: GitObjectFormat = GitObjectFormat::Sha1;
const PACKS: i64 = 3;
const ROOT_SLOTS: i64 = 2_000;

#[derive(Clone, Debug)]
pub struct Options {
    pub seed: PathBuf,
    pub data_dir: PathBuf,
    pub git: PathBuf,
    pub blob_root: String,
}

/// Parse `--seed/--data-dir/--git/--blob-root`; `None` means seed mode was not
/// requested (the caller then runs the offline digest-vector mode).
pub fn parse(args: &[String]) -> Result<Option<Options>> {
    if !args.iter().any(|arg| arg == "--seed") {
        return Ok(None);
    }
    let mut values: BTreeMap<&str, String> = BTreeMap::new();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        if !matches!(flag, "--seed" | "--data-dir" | "--git" | "--blob-root") {
            return Err(anyhow!("unknown fixture argument {flag}"));
        }
        let value = args.get(index + 1).cloned().ok_or_else(|| anyhow!("{flag} needs a value"))?;
        ensure!(values.insert(flag, value).is_none(), "{flag} was given twice");
        index += 2;
    }
    let take = |flag: &str| values.get(flag).cloned().ok_or_else(|| anyhow!("{flag} is required in seed mode"));
    let options = Options {
        seed: take("--seed")?.into(),
        data_dir: take("--data-dir")?.into(),
        git: take("--git")?.into(),
        blob_root: take("--blob-root")?,
    };
    ensure!(options.seed.is_absolute(), "--seed must be absolute");
    ensure!(options.data_dir.is_absolute(), "--data-dir must be absolute");
    ensure!(options.git.is_absolute(), "--git must be absolute");
    ensure!(options.blob_root.starts_with("format22-169-"), "--blob-root must be this fixture's own prefix");
    Ok(Some(options))
}

async fn current_gate(pool: &Pool, repo: Uuid, tenant: Uuid) -> Result<CoreGateVersion> {
    let mut client = pool.get().await?;
    match PgRefStoreCore.check_version(&mut client, repo, tenant, None, deadline()).await? {
        VersionCheck::Changed(version) | VersionCheck::Unchanged(version) => Ok(version),
        VersionCheck::Unknown => Err(anyhow!("core gate is missing")),
    }
}

/// Result of the production token issuance, before any identity is derived.
struct IssuedUser {
    user_id: Uuid,
    token: String,
}

/// Create a real user and its writable token through the production
/// `db::issue_token`. The user row precedes any token so no credential is ever
/// orphaned by a later fixture refusal.
async fn issued_user(pool: &Pool, prefix: &str) -> Result<IssuedUser> {
    let username = format!("{prefix}{}", &Uuid::new_v4().simple().to_string()[..12]);
    let issued = db::issue_token(pool, &username, true, false).await?;
    let user_id = issued["user_id"]
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| anyhow!("token response has no user id"))?;
    let token = issued["token"].as_str().ok_or_else(|| anyhow!("token response has no secret"))?.to_owned();
    Ok(IssuedUser { user_id, token })
}

/// Authenticate an issued token through the production `auth::authenticate`.
async fn authenticate(pool: &Pool, user: &IssuedUser) -> Result<db::Identity> {
    let username: String =
        pool.get().await?.query_one("SELECT username FROM users WHERE id=$1", &[&user.user_id]).await?.get(0);
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{}", user.token));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_str(&format!("Basic {encoded}")).map_err(|_| anyhow!("token header refused"))?,
    );
    let identity = rootyard::auth::authenticate(pool, &headers)
        .await
        .map_err(|error| anyhow!("real token authentication failed: {}", error.1))?;
    ensure!(!identity.read_only && identity.id == user.user_id, "issued token identity differs");
    Ok(identity)
}

/// One ready `pg_refstore` repository and its serving binding from the real
/// provision path (`ref_store::serving::{ProvisionRequest, provision}`).
async fn provision_with(pool: &Pool, actor: &db::Identity, name: &str, store: &BlobStore) -> Result<Uuid> {
    let receipt = provision(
        pool,
        actor,
        ProvisionRequest { owner: None, name: name.into(), object_format: SHA1 },
        store.backend_identity(),
        deadline(),
    )
    .await
    .map_err(|error| anyhow!("real provision of `{name}` refused: {error}"))?;
    ensure!(receipt.created, "fresh provision of `{name}` replayed instead of creating");
    ensure!(receipt.repository.storage_backend == "pg_refstore", "a provisioned repository is not pg_refstore");
    ensure!(receipt.repository.state == "ready", "a provisioned repository is not ready");
    Ok(receipt.repository.id)
}

/// One A3/A4/native verified registration of `files` at the current gate, with
/// an explicit producer owner (reusing the shared `publish`/`register`/`prove`/
/// `commit` helpers unchanged).
async fn commit_pair(
    db: &Db,
    store: &BlobStore,
    git: &Path,
    plan: &rootyard::ref_store::core::pack_commit::PackCommitPlan,
    token: &rootyard::ref_store::core::pack_commit::PackPendingToken,
    files: &super::git::PairFiles,
) -> Result<RegisteredPack> {
    let pack_id = plan.packs().first().ok_or_else(|| anyhow!("plan has no pack"))?.pack_id();
    let publication = pack_plan::publish(db, store, plan, files).await?;
    pack_plan::register(db, plan, pack_id, &publication).await?;
    let context = pack::closure(db, plan).await?;
    ensure!(context.new_packs().len() == 1, "one publication must close exactly one new pack");
    let proof = pack::prove(store, git, plan, &context).await?;
    let receipt = pack::commit(db, plan, token, &proof).await?;
    ensure!(receipt.is_committed() && !receipt.replayed, "verified commit did not commit");
    Ok(context.new_packs()[0].clone())
}

/// Fixture-local offline data directory: the operator-initialized volume
/// identity the real `backup --offline` CLI requires (no server runs).
fn write_volume_identity(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir.join("repos"))?;
    let volume = dir.join(".volume-id");
    ensure!(!volume.exists(), "refusing to overwrite an existing volume identity");
    std::fs::write(&volume, format!("{}\n", Uuid::new_v4()))?;
    std::fs::set_permissions(&volume, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub async fn run(options: &Options) -> Result<Value> {
    ensure!(options.git.is_absolute() && options.git.is_file(), "--git must be an absolute existing Git binary");
    ensure!(
        std::env::var("ROOTYARD_BLOB_ROOT").ok().as_deref() == Some(options.blob_root.as_str()),
        "ROOTYARD_BLOB_ROOT must equal --blob-root"
    );
    let profile = BlobProfile::from_env().map_err(|_| anyhow!("a supported Blob profile is required"))?;
    let store = BlobStore::open(profile).map_err(|_| anyhow!("the Blob backend could not be opened"))?;
    write_volume_identity(&options.data_dir)?;
    let db = Db::setup().await?;

    // 1. The bound repository through the real create path, then its three packs.
    //    Every user row exists before its token: a refusal never orphans a
    //    credential.
    let owner_user = issued_user(&db.pool, "fmt22owner").await?;
    let producer_user = issued_user(&db.pool, "fmt22producer").await?;
    let owner = authenticate(&db.pool, &owner_user).await?;
    authenticate(&db.pool, &producer_user).await?;
    let repo = provision_with(&db.pool, &owner, "bound", &store).await?;
    let tenant = owner.id;
    let mut verified: Verified = pack::verify_new(&db, &store, &options.git, SHA1).await?;
    // `verify_new` creates its own provisioning gitfs fixture; this format22
    // source must instead be the API-provisioned pg_refstore repository.
    verified.repo = repo;
    verified.tenant = tenant;
    verified.gate = current_gate(&db.pool, repo, tenant).await?;
    let mut registrations: Vec<RegisteredPack> = Vec::new();
    for sequence in 1..=PACKS {
        let files = verified.fixture.pack_all(&format!("format22-{sequence}")).await?;
        let refs = if sequence == 1 { vec![pack::main_update(SHA1, None, &verified.commit_oid)?] } else { Vec::new() };
        let draft =
            pack_plan::draft(&db, repo, tenant, tenant, sequence, &verified.gate, refs, std::slice::from_ref(&files))
                .await?;
        registrations.push(commit_pair(&db, &store, &options.git, &draft.plan, &draft.token, &files).await?);
        verified.gate = current_gate(&db.pool, repo, tenant).await?;
    }

    // 2. A5 snapshot + pin of the multi-pack membership.
    let source = pack::create_snapshot(&db, &verified, ROOT_SLOTS).await?;

    // 3. Roots whose producer owner differs from the repository tenant.
    let adapter = PgRetentionRoots::new(store.clone(), options.git.clone())
        .map_err(|error| anyhow!("retention roots adapter rejected the Blob/Git configuration: {error:?}"))?;
    let scope = roots::producer_scope(repo, tenant, producer_user.user_id, &verified.gate)?;
    let mut root_rows = Vec::new();
    for state in ["active", "released"] {
        let root_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        let candidate =
            roots::prepare(&adapter, &db.pool, scope, &source, root_id, operation_id, Uuid::new_v4(), deadline())
                .await
                .map_err(|error| anyhow!("{state} root prepare refused: {error:?}"))?;
        ensure!(candidate.pack_count() == PACKS, "a root candidate does not cover every registered pack");
        let register_digest = candidate.register_digest().as_hex();
        let receipt = roots::register(&adapter, &db.pool, candidate, Uuid::new_v4(), deadline())
            .await
            .map_err(|error| anyhow!("{state} root register refused: {error:?}"))?;
        if state == "released" {
            let released =
                roots::release(&adapter, &db.pool, scope, root_id, Uuid::new_v4(), &register_digest, deadline())
                    .await
                    .map_err(|error| anyhow!("released root release refused: {error:?}"))?;
            ensure!(released.state() == "released", "the released root did not reach released");
        } else {
            ensure!(
                receipt.state() == "active" && !receipt.replayed(),
                "the active root is not a fresh active capture"
            );
        }
        root_rows.push(json!({
            "root_id": root_id.to_string(),
            "operation_id": operation_id.to_string(),
            "state": state,
            "tenant_id": tenant.to_string(),
            "owner_id": producer_user.user_id.to_string(),
            "register_digest": register_digest,
        }));
    }
    // The source pin is released: the retained roots are now the only
    // protection of the registered packs (no snapshot/read declaration).
    pack::release_pin(&db.pool, source.scope, source.pin_id)
        .await
        .map_err(|error| anyhow!("A5 source pin release failed: {error}"))?;

    // 4. Empty and unrelated repositories last: created through the same API and
    //    never written, so they stay genuinely empty.
    let empty_owner = authenticate(&db.pool, &issued_user(&db.pool, "fmt22owner").await?).await?;
    let empty = provision_with(&db.pool, &empty_owner, "empty", &store).await?;
    let unrelated = provision_with(&db.pool, &owner, "unrelated", &store).await?;

    let registration_ids = registrations.iter().map(|pack| pack.registration_id()).collect::<Vec<_>>();
    let badges: Vec<RegistrationBadge> = marker::registration_badges(&db.pool, &registration_ids).await?;
    let mut retainable = Vec::new();
    for badge in &badges {
        let counts = marker::retainable_counts(&db.pool, badge.registration_id).await?;
        let declared = counts["root_packs"].as_i64().unwrap_or(0)
            + counts["snapshot_packs"].as_i64().unwrap_or(0)
            + counts["serving_read_packs"].as_i64().unwrap_or(0);
        ensure!(declared > 0, "a fixture registration is not retained by any root/snapshot/read declaration");
        ensure!(declared < 2, "a fixture registration is declared by more than one pack set");
        retainable.push(json!({"registration_id": badge.registration_id.to_string(), "declared": counts}));
    }
    let registration_json = badges
        .iter()
        .map(|badge| {
            json!({
                "registration_id": badge.registration_id.to_string(),
                "pack_id": badge.pack_id.to_string(),
                "pack_sha256": badge.pack_sha256,
                "idx_sha256": badge.idx_sha256,
                "roles": ["idx", "pack"],
            })
        })
        .collect::<Vec<_>>();
    let repository = |id: Uuid, owner: Uuid| {
        json!({"id": id.to_string(), "owner_id": owner.to_string(), "tenant_id": owner.to_string(),
               "state": "ready", "storage_backend": "pg_refstore"})
    };
    let marker = json!({
        "kind": marker::KIND,
        "format": 22,
        "schema_version": 147,
        "bound_repository_id": repo.to_string(),
        "empty_repository_id": empty.to_string(),
        "unrelated_repository_id": unrelated.to_string(),
        "repositories": [
            repository(repo, tenant),
            repository(empty, empty_owner.id),
            repository(unrelated, tenant),
        ],
        "tenant_id": tenant.to_string(),
        "producer_owner_id": producer_user.user_id.to_string(),
        "pack_owner_id": tenant.to_string(),
        "root_owner_id": producer_user.user_id.to_string(),
        "gate_revision": verified.gate.revision(),
        "source_snapshot_id": source.snapshot_id.to_string(),
        "source_pin_id": source.pin_id.to_string(),
        "registrations": registration_json,
        "retainable": retainable,
        "packs": PACKS,
        "roots": root_rows,
        "data_dir": options.data_dir.to_string_lossy(),
        "blob_root": options.blob_root,
    });
    marker::write(&options.seed, &marker)?;
    Ok(marker)
}
