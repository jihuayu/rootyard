//! Real loopback/PostgreSQL/Blob/Git plumbing shared by the `#174` HTTP cases.
//!
//! Every helper here drives the production router over a real TCP listener and
//! the production PostgreSQL/Blob/native paths. Refusals are observed exactly
//! as a network client sees them; no handler is called directly. The HTTP
//! observation vocabulary lives in [`http`] and is re-exported here.
use std::{
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, ensure};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::fixtures::{
    actor::Actor,
    db::{Db, deadline},
    git::{Git, assert_no_compute_views, clone_url},
};
use crate::{
    blob_git_gateway::{
        BlobGitConfig, BlobGitState,
        repo_session::{
            AuthorityKind, STANDALONE_GROUP_ID, SessionRealm, SessionRealmFields, SessionTokenCodec, SessionTokens,
        },
    },
    blob_store::{
        BlobBackendIdentity, BlobLocator, BlobProvider, config::BlobProfile, opendal::BlobStore,
        test_support::delete_exact,
    },
    ref_store::{
        MetadataPinPurpose,
        core::{
            MetadataSnapshotScope,
            decision_commit::{PgDecisionProtocol, RealmExpectation},
            pack_commit::PackArtifactRole,
            pack_snapshot::PgServingReads,
        },
        serving::{ServingRepository, lookup},
    },
};

mod http;

pub(super) use self::http::{
    MALFORMED_SESSION, contains, ensure_no_disclosure, is_denial, json_read, json_string, looks_like_refs, raw_get,
    status_succeeds,
};
use self::http::{PushSession, RawSession, ServerGuard, observe_push_session};

/// Test-only key id inside the signed frame; it is not secret.
const TEST_KEY_ID: u8 = 7;
/// Fixed test-only key bytes: a deterministic 32-byte sequence, not read from
/// the environment, so the outcome is stable and nothing secret is printed.
const TEST_KEY_BYTES: [u8; 32] = [0x5a; 32];
/// Lifetime signed into every frame for this run. Long enough for the slowest
/// real S3/Git case; expiry itself is minted deterministically via `issue_at`.
pub(super) const BOUNDED_LIFETIME: u32 = 300;
/// Lifetime of the manifest loaded through the production keyring loader.
const KEYRING_LIFETIME: u32 = 300;
/// The fixture commit pushed through the real receive pipeline.
pub(super) const COMMIT_FILE: &str = "readme.txt";
const COMMIT_CONTENT: &str = "session-bound fixture file\n";
pub(super) const PUSHED_REF: &str = "refs/heads/main";

/// One live loopback gateway plus the exact Blob store it serves.
pub(super) struct Gateway {
    pub address: SocketAddr,
    pub store: BlobStore,
    pub tokens: SessionTokens,
    pub git: Git,
    pub scratch: tempfile::TempDir,
    push: Arc<Mutex<PushSession>>,
    _server: ServerGuard,
}

impl Gateway {
    /// Build the production router over a real listener, with the production
    /// session key set attached exactly as `standalone` attaches it.
    pub(super) async fn start(db: &Db, store: BlobStore, tokens: SessionTokens) -> Result<Self> {
        let git = Git::new()?;
        let scratch = tempfile::tempdir().context("temporary gateway scratch root")?;
        let state = Arc::new(
            BlobGitState::new(BlobGitConfig {
                pool: db.pool.clone(),
                store: store.clone(),
                git_binary: git.binary().to_path_buf(),
                scratch_root: scratch.path().to_path_buf(),
                max_concurrent_requests: 4,
                max_request_bytes: 16 * 1024 * 1024,
                max_response_bytes: 64 * 1024 * 1024,
                max_inflight_bytes: 64 * 1024 * 1024,
                operation_deadline: Duration::from_secs(120),
                native_limits: Default::default(),
            })
            .map_err(|error| anyhow!("gateway configuration was refused: {error}"))?
            .with_sessions(tokens.clone()),
        );
        let push = Arc::new(Mutex::new(PushSession::default()));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let app = observe_push_session(crate::blob_git_gateway::router(state.clone()), push.clone());
        let server = ServerGuard::start(listener, app);
        Ok(Self { address, store, tokens, git, scratch, push, _server: server })
    }

    pub(super) fn base(&self, owner: &str, name: &str) -> String {
        format!("http://{}/api/repos/{owner}/{name}", self.address)
    }

    pub(super) async fn create_repository(&self, owner: &Actor, name: &str) -> Result<Value> {
        let response = reqwest::Client::new()
            .post(format!("http://{}/api/repos", self.address))
            .bearer_auth(&owner.token)
            .json(&json!({"name": name, "object_format": "sha1"}))
            .send()
            .await?;
        let status = response.status();
        let body: Value = response.json().await?;
        ensure!(
            status.is_success(),
            "create API returned {status}: {}",
            body["error"].as_str().unwrap_or("<no error body>")
        );
        ensure!(
            body["owner"].as_str() == Some(owner.username.as_str()) && body["name"].as_str() == Some(name),
            "create API returned another repository identity"
        );
        Ok(body)
    }

    /// Provision the migration-144 decision realm for the created repository,
    /// exactly as the integration gateway suite does.
    pub(super) async fn provision_decision_realm(&self, db: &Db, owner: &Actor, name: &str) -> Result<()> {
        let serving = serving(db, self, owner, name, true).await?;
        let gate = serving.gate;
        let expectation = RealmExpectation::new(
            gate.repository_id(),
            gate.tenant_id(),
            gate.object_format(),
            gate.history_incarnation(),
            gate.authority_epoch(),
            gate.group_epoch(),
        )
        .map_err(|error| anyhow!("decision realm expectation refused: {error}"))?;
        let mut client = db.pool.get().await?;
        PgDecisionProtocol
            .provision(&mut client, &expectation, deadline())
            .await
            .map_err(|error| anyhow!("decision realm provisioning refused: {error}"))?;
        Ok(())
    }

    /// A real native clone/commit/push through the real Smart HTTP routes.
    pub(super) async fn push_commit(&self, owner: &Actor, name: &str) -> Result<String> {
        let work = tempfile::tempdir().context("temporary Git work tree")?;
        let checkout = work.path().join("clone");
        let url = clone_url(self.address, &owner.username, name, &owner.username, &owner.token);
        let cloned = self.git.clone(work.path(), &url, "clone").await?;
        ensure!(cloned.success, "real Smart HTTP clone of the empty repository failed");
        let oid = self.git.commit(&checkout, COMMIT_FILE, COMMIT_CONTENT, "session fixture commit").await?;
        let pushed = self.git.run(&checkout, &["push", "origin", &format!("HEAD:{PUSHED_REF}")]).await?;
        ensure!(pushed.success, "real Smart HTTP push was refused");
        assert_no_compute_views(self.scratch.path()).await?;
        Ok(oid)
    }

    /// The push response's session headers, captured in memory only.
    pub(super) fn push_session(&self) -> RawSession {
        let push = self.push.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        push.snapshot()
    }
}

/// The real production token types, opened with one deterministic test-only
/// key bound to the actually opened Blob backend identity.
pub(super) fn test_tokens(backend: &BlobBackendIdentity) -> Result<SessionTokens> {
    let key = Zeroizing::new(TEST_KEY_BYTES);
    let codec = SessionTokenCodec::new([(TEST_KEY_ID, key)], TEST_KEY_ID, backend, BOUNDED_LIFETIME)
        .map_err(|_| anyhow!("test session codec was refused"))?;
    Ok(SessionTokens::new(codec))
}

/// Load a key set through the production on-disk loader: a private `0700`
/// directory with a `0600` schema-2 manifest and a `0600` 32-byte key file.
pub(super) fn keyring_tokens(backend: &BlobBackendIdentity) -> Result<(tempfile::TempDir, SessionTokens)> {
    let directory = tempfile::tempdir().context("temporary keyring directory")?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let manifest = json!({
        "schema": 2,
        "current": "v2",
        "lifetime_seconds": KEYRING_LIFETIME,
        "keys": [{"key_id": "v2", "id": 42}],
    });
    let manifest_path = directory.path().join("keyring.json");
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
    std::fs::set_permissions(&manifest_path, std::fs::Permissions::from_mode(0o600))?;
    let key_path = directory.path().join("v2.key");
    std::fs::write(&key_path, [0x6bu8; 32])?;
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    let tokens = crate::standalone::session_keyring::load(directory.path(), backend)?;
    Ok((directory, tokens))
}

pub(super) fn open_store() -> Result<BlobStore> {
    let profile = BlobProfile::from_env().map_err(|error| anyhow!("ROOTYARD_BLOB_* profile rejected: {error}"))?;
    ensure!(profile.provider() == BlobProvider::S3, "ROOTYARD_BLOB_SERVICE must be s3 for this suite");
    BlobStore::open(profile).map_err(|error| anyhow!("configured Blob store rejected: {error}"))
}

pub(super) fn unique_name(label: &str) -> String {
    format!("{label}-{}", &Uuid::new_v4().simple().to_string()[..12])
}

pub(super) async fn serving(
    db: &Db,
    gateway: &Gateway,
    owner: &Actor,
    name: &str,
    writable: bool,
) -> Result<ServingRepository> {
    lookup(&db.pool, &owner.identity, &owner.username, name, writable, gateway.store.backend_identity(), deadline())
        .await
        .map_err(|error| anyhow!("serving lookup refused: {}", error.1))
}

/// The exact live realm and gate revision a fresh authorized lookup states.
pub(super) struct LiveRealm {
    pub realm: SessionRealm,
    pub revision: i64,
}

pub(super) async fn live_realm(
    db: &Db,
    gateway: &Gateway,
    owner: &Actor,
    name: &str,
    writable: bool,
) -> Result<LiveRealm> {
    let serving = serving(db, gateway, owner, name, writable).await?;
    let gate = &serving.gate;
    let realm = SessionRealm::new(SessionRealmFields {
        tenant_id: gate.tenant_id(),
        repository_id: gate.repository_id(),
        object_format: gate.object_format(),
        history_incarnation: gate.history_incarnation(),
        authority: AuthorityKind::PgRefStore,
        authority_epoch: gate.authority_epoch(),
        group_id: STANDALONE_GROUP_ID,
        group_epoch: gate.group_epoch(),
        cluster_incarnation: serving.cluster_incarnation,
    })
    .map_err(|_| anyhow!("live session realm refused"))?;
    Ok(LiveRealm { realm, revision: gate.revision() })
}

pub(super) fn unix_now() -> Result<i64> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).context("trusted clock is before the Unix epoch")?;
    i64::try_from(elapsed.as_secs()).context("trusted clock does not fit i64 seconds")
}

/// Flip the final MAC byte while keeping the encoded length; the frame is then
/// authentic-looking but its HMAC no longer verifies.
pub(super) fn flip_mac(token: &str) -> Result<String> {
    let mut bytes = token.as_bytes().to_vec();
    let last = bytes.pop().ok_or_else(|| anyhow!("session token is empty"))?;
    bytes.push(if last == b'A' { b'B' } else { b'A' });
    Ok(String::from_utf8(bytes)?)
}

pub(super) async fn add_read_collaborator(db: &Db, repository_id: Uuid, tenant_id: Uuid, user_id: Uuid) -> Result<()> {
    db.pool
        .get()
        .await?
        .execute(
            "INSERT INTO repository_collaborators (repository_id, tenant_id, user_id, role)
             VALUES ($1, $2, $3, 'read')",
            &[&repository_id, &tenant_id, &user_id],
        )
        .await?;
    Ok(())
}

pub(super) async fn remove_collaborator(db: &Db, repository_id: Uuid, user_id: Uuid) -> Result<()> {
    db.pool
        .get()
        .await?
        .execute(
            "DELETE FROM repository_collaborators WHERE repository_id=$1 AND user_id=$2",
            &[&repository_id, &user_id],
        )
        .await?;
    Ok(())
}

/// Delete the registered `.pack` object of a pushed repository after its pin
/// was released, leaving the durable registration in place. A later serving
/// read must fail closed instead of returning the acknowledged refs.
pub(super) async fn delete_registered_pack(gateway: &Gateway, db: &Db, owner: &Actor, name: &str) -> Result<()> {
    let serving = serving(db, gateway, owner, name, false).await?;
    let gate = &serving.gate;
    let owner_id: Uuid = db
        .pool
        .get()
        .await?
        .query_one("SELECT owner_id FROM repositories WHERE id=$1", &[&gate.repository_id()])
        .await?
        .get(0);
    let scope = MetadataSnapshotScope::new(
        gate.repository_id(),
        gate.tenant_id(),
        owner_id,
        MetadataPinPurpose::Verification,
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )
    .map_err(|error| anyhow!("serving capture scope refused: {error}"))?;
    let reads = PgServingReads;
    let capture = reads.capture(&db.pool, &scope, gateway.store.backend_identity(), 60, deadline()).await?;
    let locator: BlobLocator = {
        let snapshot =
            capture.registered_snapshot().ok_or_else(|| anyhow!("private-pushed repository captured empty"))?;
        let pack = snapshot.packs().first().ok_or_else(|| anyhow!("pushed repository registered no pack"))?;
        pack.artifact(PackArtifactRole::Pack)
            .locator()
            .blob_locator()
            .map_err(|error| anyhow!("registered pack locator is invalid: {error}"))?
    };
    reads.release(&db.pool, &capture, deadline()).await.map_err(|error| anyhow!("capture release failed: {error}"))?;
    delete_exact(&gateway.store, &locator).await?;
    Ok(())
}
