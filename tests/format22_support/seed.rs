//! Seed mode: the real API-produced format22 source for issue #169.
//!
//! Positive state only comes from production APIs:
//! * ready `pg_refstore` repositories from `ref_store::serving::provision` (the
//!   real create path, bound to the live store's immutable backend identity);
//! * three packs on the bound repository through A3 acquire/consume/upload, A4
//!   `register_publication` and native verified commits as the *producer* owner
//!   (a real token user distinct from the repository tenant), a real multi-pack
//!   membership;
//! * one A5 snapshot + pin owned by that producer, released after the roots so
//!   the retained roots are the only protection;
//! * one active and one released retention root prepared and registered by the
//!   same producer owner from that producer-owned snapshot (the feature under
//!   test: a root owner that is not the repository tenant).
//!
//! Ordering matters: the bound repository is provisioned *first*, the owner
//! grants the producer `write` over the production collaborator route, and only
//! then do its packs commit; the empty/unrelated repositories are provisioned
//! *after*, so they stay genuinely empty. The producer never creates a
//! repository of its own and is never rewritten into the tenant: the
//! decision-gated `select` resolves the producer's effective role from the live
//! `repository_collaborators` row the owner's own request created.
//!
//! No SQL row here creates a repository, artifact, publication, collaborator,
//! membership, snapshot, pin or root, and no repository row is edited
//! afterwards. The only direct writes are the token rows of the production
//! `db::issue_token` and the fixture-local offline `data/.volume-id`.
use anyhow::{Result, anyhow, ensure};
use base64::Engine as _;
use deadpool_postgres::Pool;
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::db;
use rootyard::members::models::Role;
use rootyard::ref_store::core::pack_commit::{PackCommitPlan, RegisteredPack};
use rootyard::ref_store::core::retention_root::PgRetentionRoots;
use rootyard::ref_store::serving::{ProvisionRequest, provision};
use rootyard::ref_store::{CoreGateVersion, GitObjectFormat, PgRefStoreCore, VersionCheck};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use super::db::{Db, deadline};
use super::marker;
use super::pack;
use super::{http, pack_plan, repo, roots};

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
/// The secret stays inside this module and the HTTP helpers' arguments.
struct IssuedUser {
    user_id: Uuid,
    username: String,
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
    let username = issued["username"].as_str().ok_or_else(|| anyhow!("token response has no username"))?.to_owned();
    Ok(IssuedUser { user_id, username, token })
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
    ensure!(identity.username == user.username, "issued token belongs to another user");
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

/// Grant the producer `write` on the owner's bound repository through the real
/// owner route (`POST /api/repos/{owner}/bound/collaborators`), then read the
/// stored grant back through the producer's own token. The owner's admin role is
/// resolved by the production `auth::authorize_repo_with_role`; the insertion is
/// the production `members::rbac::upsert_collaborator`, never SQL here.
async fn grant_producer(
    http: &http::Http,
    owner_token: &str,
    owner_username: &str,
    producer: &IssuedUser,
) -> Result<Value> {
    let (owner_id, whoami_owner) = http.whoami(owner_token).await?;
    ensure!(whoami_owner == owner_username, "the owner token authenticates another user");
    let (status, body) =
        http.post_collaborator(owner_token, owner_username, "bound", &producer.username, Role::Write).await?;
    ensure!(status == axum::http::StatusCode::CREATED, "the owner collaborator grant answered {status}");
    http::ensure_created(&body, &producer.username, Role::Write)?;
    let stored_user: Uuid = body["user_id"]
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| anyhow!("the collaborator response has no user id"))?;
    ensure!(stored_user == producer.user_id, "the collaborator grant names another user");
    // The producer's own token must now read that exact grant.
    let (status, stored) = http.get_collaborator(&producer.token, owner_username, "bound", &producer.username).await?;
    ensure!(status == axum::http::StatusCode::OK, "the producer collaborator read answered {status}");
    http::ensure_read_back(&stored, producer.user_id, &producer.username, Role::Write)?;
    Ok(json!({
        "repository_owner_id": owner_id.to_string(),
        "user_id": producer.user_id.to_string(),
        "username": producer.username,
        "role": Role::Write.as_str(),
        "route": format!("/api/repos/{owner_username}/bound/collaborators"),
        "status": status.as_u16(),
    }))
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

/// Register `PACKS` verified packs as `producer` on the provisioned repository.
async fn packs(
    db: &Db,
    store: &BlobStore,
    target: &repo::Existing,
    git: &std::path::Path,
    fixture: &super::git::GitRepo,
    producer: &db::Identity,
) -> Result<(Vec<RegisteredPack>, PackCommitPlan, String)> {
    let mut gate = target.gate.clone();
    let first = fixture.build_commit("file.txt", b"root fixture\n", "format22 main").await?;
    fixture.update_ref("refs/heads/main", &first).await?;
    let mut head = first;
    let mut registrations: Vec<RegisteredPack> = Vec::new();
    let mut last_plan = None;
    for sequence in 1..=PACKS {
        let files = fixture.pack_all(&format!("format22-{sequence}")).await?;
        let refs = if sequence == 1 {
            vec![pack::main_update(SHA1, None, &head)?]
        } else {
            let next = fixture
                .build_commit("advance.txt", format!("pack {sequence}\n").as_bytes(), "format22 advance")
                .await?;
            fixture.update_ref("refs/heads/main", &next).await?;
            let refs = vec![pack::main_update(SHA1, Some(&head), &next)?];
            head = next;
            refs
        };
        let draft = pack_plan::draft(
            db,
            target.repo,
            target.tenant,
            producer.id,
            sequence,
            &gate,
            refs,
            std::slice::from_ref(&files),
        )
        .await?;
        // The provisioned repository is already under the irreversible
        // decision-required fence, so its packs commit through the same
        // decision-gated pipeline the serving first push uses.
        let new = repo::decided_pair(db, store, git, &draft, &files, producer).await?;
        registrations.extend(new);
        gate = current_gate(&db.pool, target.repo, target.tenant).await?;
        last_plan = Some(draft.plan);
    }
    ensure!(head == fixture.rev_parse("refs/heads/main").await?, "fixture HEAD changed during packing");
    Ok((registrations, last_plan.ok_or_else(|| anyhow!("no pack was planned"))?, head))
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
    let http = http::Http::open(&db, &options.git, &options.data_dir).await?;

    // 1. The bound repository through the real create path. Every user row
    //    exists before its token: a refusal never orphans a credential.
    let owner_user = issued_user(&db.pool, "fmt22owner").await?;
    let producer_user = issued_user(&db.pool, "fmt22producer").await?;
    let owner = authenticate(&db.pool, &owner_user).await?;
    let producer_identity = authenticate(&db.pool, &producer_user).await?;
    let producer = producer_user.user_id;
    ensure!(producer != owner.id, "the producer must be a different real user than the repository owner");
    let repo_id = provision_with(&db.pool, &owner, "bound", &store).await?;
    let tenant = owner.id;
    // The producer is a collaborator with `write`, through the owner's real HTTP
    // route, before any of its packs commits: the decision-gated `select`
    // resolves exactly this live role and refuses anything lower.
    let collaborator = grant_producer(&http, &owner_user.token, &owner.username, &producer_user).await?;
    let (target, fixture) = repo::open(&db, repo_id, tenant, &options.git).await?;
    // The pack producer (durable hold/publication/acquirer owner) is the real
    // token user, while the storage tenant/RAM-prefix identity of every blob
    // locator stays the repository tenant's; both are read from the real rows
    // by the drill and never assumed equal.
    let (registrations, last_plan, head) =
        packs(&db, &store, &target, &options.git, &fixture, &producer_identity).await?;
    ensure!(registrations.len() as i64 == PACKS, "not every planned pack registered");

    // 2. A5 snapshot + pin of the multi-pack membership, owned by the producer.
    let verified = pack::Verified {
        tenant,
        repo: repo_id,
        gate: current_gate(&db.pool, repo_id, tenant).await?,
        fixture,
        commit_oid: head,
        plan: last_plan.clone(),
        new_packs: registrations.clone(),
    };
    let snapshot = repo::producer_snapshot(&db, &verified, producer, ROOT_SLOTS).await?;
    let source = repo::as_source(&snapshot);

    // 3. Roots registered by the same producer owner as the snapshot/pin.
    let adapter = PgRetentionRoots::new(store.clone(), options.git.clone())
        .map_err(|error| anyhow!("retention roots adapter rejected the Blob/Git configuration: {error:?}"))?;
    let scope = roots::producer_scope(repo_id, tenant, producer, &verified.gate)?;
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
            let release_digest = marker::release_digest("format22-released");
            let released = roots::release(
                &adapter,
                &db.pool,
                scope,
                root_id,
                Uuid::new_v4(),
                &register_digest,
                &release_digest,
                deadline(),
            )
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
            "owner_id": producer.to_string(),
            "register_digest": register_digest,
        }));
    }
    // The source pin is released: the retained roots are now the only
    // protection of the registered packs (no snapshot/read declaration).
    repo::release_snapshot_pin(&db, &snapshot).await?;

    // 4. Empty and unrelated repositories last: created through the same API and
    //    never written, so they stay genuinely empty.
    let empty_owner = authenticate(&db.pool, &issued_user(&db.pool, "fmt22owner").await?).await?;
    let empty = provision_with(&db.pool, &empty_owner, "empty", &store).await?;
    let unrelated = provision_with(&db.pool, &owner, "unrelated", &store).await?;

    let badges = repo::registration_badges(&db, &last_plan, &registrations).await?;
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
                "artifact_set_digest": badge.artifact_set_digest,
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
        "bound_repository_id": repo_id.to_string(),
        "empty_repository_id": empty.to_string(),
        "unrelated_repository_id": unrelated.to_string(),
        "repositories": [
            repository(repo_id, tenant),
            repository(empty, empty_owner.id),
            repository(unrelated, tenant),
        ],
        "tenant_id": tenant.to_string(),
        "producer_owner_id": producer.to_string(),
        "producer_collaborator": collaborator,
        "pack_owner_id": producer.to_string(),
        "storage_tenant_id": tenant.to_string(),
        "root_owner_id": producer.to_string(),
        "gate_revision": verified.gate.revision(),
        "source_snapshot_id": snapshot.snapshot_id.to_string(),
        "source_pin_id": snapshot.pin_id.to_string(),
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
