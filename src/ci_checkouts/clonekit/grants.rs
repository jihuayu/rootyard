//! Narrow HMAC-signed CloneKit capability grants, authority revocation, and #36 dependency fencing.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    path::Path,
    pin::Pin,
    sync::RwLock,
};

use deadpool_postgres::Pool;
use ring::hmac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::manifest::{
    CLONEKIT_MANIFEST_SCHEMA, CloneKitError, CloneKitObjectFormat, run_git_command, valid_sha256_hex,
};

const GRANT_DOMAIN: &[u8] = b"rootyard.clonekit.grant.v1\0";
const LFS_POINTER_HEADER: &str = "version https://git-lfs.github.com/spec/v1";

/// Independent #36 LFS object grant bound inside a checkout job capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredLfsObject {
    pub repository_id: Uuid,
    pub path: String,
    pub oid: String,
    pub size: u64,
    pub grant_id: Uuid,
}

/// Independent #36 submodule repository checkout grant bound inside a job capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredSubmodule {
    pub path: String,
    pub repository_id: Uuid,
    pub target_oid: String,
    pub object_format: CloneKitObjectFormat,
    pub storage_generation: i64,
    pub grant_id: Uuid,
}

/// Independent #36 dependency grants required before materialized checkout completion.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloneKitDependencyGrants {
    pub lfs_objects: Vec<RequiredLfsObject>,
    pub submodules: Vec<RequiredSubmodule>,
}

/// Narrow capability grant bound to tenant, repo, exact target OID, job, audience, and expiry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloneKitGrantClaims {
    pub schema: u32,
    pub grant_id: Uuid,
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub owner_id: Uuid,
    pub history_id: Uuid,
    pub storage_generation: i64,
    pub object_format: CloneKitObjectFormat,
    pub target_oid: String,
    pub job_id: Uuid,
    pub audience: Uuid,
    pub issued_unix: i64,
    pub not_after_unix: i64,
    pub min_kit_generation: u64,
    pub allow_git_fallback: bool,
    pub dependencies: CloneKitDependencyGrants,
}

impl CloneKitGrantClaims {
    /// Validate non-cryptographic structural invariants on grant claims.
    pub fn validate(&self) -> Result<(), CloneKitError> {
        if self.schema != CLONEKIT_MANIFEST_SCHEMA {
            return Err(CloneKitError::Unauthorized("unsupported grant schema"));
        }
        if self.grant_id.is_nil()
            || self.tenant_id.is_nil()
            || self.repository_id.is_nil()
            || self.owner_id.is_nil()
            || self.history_id.is_nil()
            || self.job_id.is_nil()
            || self.audience.is_nil()
        {
            return Err(CloneKitError::Unauthorized("grant identifiers must be non-nil"));
        }
        if self.storage_generation <= 0 || self.not_after_unix <= self.issued_unix {
            return Err(CloneKitError::Unauthorized("grant generation or lifetime window invalid"));
        }
        if !self.object_format.valid_oid(&self.target_oid) {
            return Err(CloneKitError::Unauthorized("grant target_oid invalid for object_format"));
        }
        for lfs in &self.dependencies.lfs_objects {
            if lfs.repository_id.is_nil() || lfs.grant_id.is_nil() || !valid_sha256_hex(&lfs.oid) {
                return Err(CloneKitError::DependencyCheckFailed("malformed lfs grant entry".into()));
            }
        }
        for sub in &self.dependencies.submodules {
            if sub.repository_id.is_nil()
                || sub.grant_id.is_nil()
                || sub.storage_generation <= 0
                || !sub.object_format.valid_oid(&sub.target_oid)
            {
                return Err(CloneKitError::DependencyCheckFailed("malformed submodule grant entry".into()));
            }
        }
        Ok(())
    }
}

/// Signed capability envelope carrying claims + domain-separated HMAC-SHA256 tag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCloneKitGrant {
    pub claims: CloneKitGrantClaims,
    pub signature_hex: String,
}

/// Expected caller/runner context enforced against every signed CloneKit grant.
#[derive(Clone, Debug)]
pub struct GrantVerificationContext {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub history_id: Uuid,
    pub storage_generation: i64,
    pub object_format: CloneKitObjectFormat,
    pub target_oid: String,
    pub job_id: Uuid,
    pub audience: Uuid,
    pub now_unix: i64,
}

/// Live authority source queried before and during transfer to enforce revocation & fencing.
pub trait CloneKitAuthorityOracle: Send + Sync {
    /// Verify the job/grant remain active and non-revoked under the expected history/generation.
    fn check_active<'a>(
        &'a self,
        claims: &'a CloneKitGrantClaims,
    ) -> Pin<Box<dyn Future<Output = Result<(), CloneKitError>> + Send + 'a>>;

    /// Verify one independent #36 dependency grant ID remains active and unrevoked.
    fn check_dependency_grant<'a>(
        &'a self,
        grant_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<(), CloneKitError>> + Send + 'a>>;
}

/// Thread-safe in-memory authority oracle for deterministic unit and concurrency tests.
#[derive(Debug, Default)]
pub struct InMemoryAuthorityOracle {
    revoked_grants: RwLock<BTreeSet<Uuid>>,
    revoked_jobs: RwLock<BTreeSet<Uuid>>,
    revoked_dep_grants: RwLock<BTreeSet<Uuid>>,
    repo_histories: RwLock<BTreeMap<Uuid, (Uuid, i64)>>,
}

impl InMemoryAuthorityOracle {
    /// Create an empty permissive authority oracle.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record or update the authoritative `(history_id, storage_generation)` for a repository.
    pub fn set_repository_authority(&self, repository_id: Uuid, history_id: Uuid, storage_generation: i64) {
        self.repo_histories
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .insert(repository_id, (history_id, storage_generation));
    }

    /// Immediately revoke a capability grant ID.
    pub fn revoke_grant(&self, grant_id: Uuid) {
        self.revoked_grants.write().unwrap_or_else(|p| p.into_inner()).insert(grant_id);
    }

    /// Immediately revoke/cancel an entire CI checkout job ID.
    pub fn revoke_job(&self, job_id: Uuid) {
        self.revoked_jobs.write().unwrap_or_else(|p| p.into_inner()).insert(job_id);
    }

    /// Immediately revoke an independent #36 LFS/submodule grant ID.
    pub fn revoke_dependency_grant(&self, grant_id: Uuid) {
        self.revoked_dep_grants.write().unwrap_or_else(|p| p.into_inner()).insert(grant_id);
    }
}

impl CloneKitAuthorityOracle for InMemoryAuthorityOracle {
    fn check_active<'a>(
        &'a self,
        claims: &'a CloneKitGrantClaims,
    ) -> Pin<Box<dyn Future<Output = Result<(), CloneKitError>> + Send + 'a>> {
        let res = (|| {
            if self.revoked_grants.read().unwrap_or_else(|p| p.into_inner()).contains(&claims.grant_id) {
                return Err(CloneKitError::GrantRevoked("capability grant revoked"));
            }
            if self.revoked_jobs.read().unwrap_or_else(|p| p.into_inner()).contains(&claims.job_id) {
                return Err(CloneKitError::GrantRevoked("ci checkout job revoked or cancelled"));
            }
            if let Some(&(cur_hist, cur_gen)) =
                self.repo_histories.read().unwrap_or_else(|p| p.into_inner()).get(&claims.repository_id)
            {
                if cur_hist != claims.history_id {
                    return Err(CloneKitError::HistoryChanged { expected: claims.history_id, actual: cur_hist });
                }
                if cur_gen != claims.storage_generation {
                    return Err(CloneKitError::StaleGeneration {
                        expected_min: cur_gen.max(1) as u64,
                        actual: claims.storage_generation.max(0) as u64,
                    });
                }
            }
            Ok(())
        })();
        Box::pin(std::future::ready(res))
    }

    fn check_dependency_grant<'a>(
        &'a self,
        grant_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<(), CloneKitError>> + Send + 'a>> {
        let res = if self.revoked_dep_grants.read().unwrap_or_else(|p| p.into_inner()).contains(&grant_id) {
            Err(CloneKitError::DependencyCheckFailed(format!("dependency grant {grant_id} has been revoked")))
        } else {
            Ok(())
        };
        Box::pin(std::future::ready(res))
    }
}

/// PostgreSQL-backed live authority check reusing `ci_checkout_jobs` and `repositories`.
pub struct PgCheckoutAuthorityOracle {
    pool: Pool,
}

impl PgCheckoutAuthorityOracle {
    /// Wrap a `deadpool_postgres::Pool` for fail-closed authorization queries.
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }
}

impl CloneKitAuthorityOracle for PgCheckoutAuthorityOracle {
    fn check_active<'a>(
        &'a self,
        claims: &'a CloneKitGrantClaims,
    ) -> Pin<Box<dyn Future<Output = Result<(), CloneKitError>> + Send + 'a>> {
        Box::pin(async move {
            let client = self.pool.get().await.map_err(|e| CloneKitError::DatabaseFailed(e.to_string()))?;
            let row = client
                .query_opt(
                    "SELECT j.cancelled, j.revoked, j.expires_unix, r.state, r.storage_generation, \
                            extract(epoch FROM clock_timestamp())::bigint \
                     FROM ci_checkout_jobs j \
                     JOIN repositories r ON r.id = j.repository_id \
                     WHERE j.repository_id = $1 AND j.job_id = $2",
                    &[&claims.repository_id, &claims.job_id],
                )
                .await
                .map_err(|e| CloneKitError::DatabaseFailed(e.to_string()))?
                .ok_or(CloneKitError::GrantRevoked("ci_checkout_jobs row absent"))?;
            let (cancelled, revoked, expires_unix, state, current_gen, now_unix): (
                bool,
                bool,
                Option<i64>,
                String,
                i64,
                i64,
            ) = (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4), row.get(5));
            if cancelled || revoked || state != "ready" {
                return Err(CloneKitError::GrantRevoked("ci checkout job revoked or repository unready"));
            }
            if current_gen != claims.storage_generation {
                return Err(CloneKitError::StaleGeneration {
                    expected_min: current_gen.max(1) as u64,
                    actual: claims.storage_generation.max(0) as u64,
                });
            }
            if expires_unix.is_none_or(|exp| exp <= now_unix) {
                return Err(CloneKitError::GrantExpired);
            }
            Ok(())
        })
    }

    fn check_dependency_grant<'a>(
        &'a self,
        grant_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<(), CloneKitError>> + Send + 'a>> {
        Box::pin(async move {
            let client = self.pool.get().await.map_err(|e| CloneKitError::DatabaseFailed(e.to_string()))?;
            let row = client
                .query_opt(
                    "SELECT pj.cancelled, pj.revoked, r.state, \
                            d.expires_unix > extract(epoch FROM clock_timestamp())::bigint \
                     FROM ci_checkout_delegations d \
                     JOIN repositories r ON r.id = d.repository_id \
                     JOIN ci_checkout_jobs pj \
                       ON pj.repository_id = d.parent_repository_id AND pj.job_id = d.parent_job_id \
                     WHERE d.job_id = $1",
                    &[&grant_id],
                )
                .await
                .map_err(|e| CloneKitError::DatabaseFailed(e.to_string()))?;
            match row {
                Some(r)
                    if !r.get::<_, bool>(0)
                        && !r.get::<_, bool>(1)
                        && r.get::<_, String>(2) == "ready"
                        && r.get::<_, bool>(3) =>
                {
                    Ok(())
                }
                Some(_) => Err(CloneKitError::DependencyCheckFailed("delegation revoked, expired, or unready".into())),
                None => Err(CloneKitError::DependencyCheckFailed("missing #36 delegation grant".into())),
            }
        })
    }
}

fn transcript_bytes(claims: &CloneKitGrantClaims) -> Result<Vec<u8>, CloneKitError> {
    let json = serde_json::to_vec(claims).map_err(|e| CloneKitError::CorruptArtifact(e.to_string()))?;
    let mut msg = Vec::with_capacity(GRANT_DOMAIN.len() + json.len());
    msg.extend_from_slice(GRANT_DOMAIN);
    msg.extend_from_slice(&json);
    Ok(msg)
}

/// Sign [`CloneKitGrantClaims`] with HMAC-SHA256 using `signing_secret`.
pub fn sign_grant(claims: CloneKitGrantClaims, signing_secret: &[u8]) -> Result<SignedCloneKitGrant, CloneKitError> {
    if signing_secret.len() < 16 {
        return Err(CloneKitError::InvalidConfig("grant signing secret must be at least 16 bytes"));
    }
    claims.validate()?;
    let msg = transcript_bytes(&claims)?;
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, signing_secret), &msg);
    Ok(SignedCloneKitGrant { claims, signature_hex: hex::encode(tag.as_ref()) })
}

/// Verify grant signature, exact tenant/repo/history/format/OID/job/audience binding, expiry, and authority oracle.
pub async fn verify_grant(
    grant: &SignedCloneKitGrant,
    signing_secret: &[u8],
    ctx: &GrantVerificationContext,
    authority: &dyn CloneKitAuthorityOracle,
) -> Result<(), CloneKitError> {
    if signing_secret.len() < 16 {
        return Err(CloneKitError::InvalidConfig("grant signing secret must be at least 16 bytes"));
    }
    grant.claims.validate()?;
    let sig_bytes =
        hex::decode(&grant.signature_hex).map_err(|_| CloneKitError::Unauthorized("malformed grant mac"))?;
    let msg = transcript_bytes(&grant.claims)?;
    hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, signing_secret), &msg, &sig_bytes)
        .map_err(|_| CloneKitError::Unauthorized("grant signature mismatch"))?;

    let c = &grant.claims;
    if c.tenant_id != ctx.tenant_id {
        return Err(CloneKitError::CrossTenantDenied);
    }
    if c.repository_id != ctx.repository_id || c.object_format != ctx.object_format || c.target_oid != ctx.target_oid {
        return Err(CloneKitError::Unauthorized("grant repository, format, or target_oid mismatch"));
    }
    if c.job_id != ctx.job_id || c.audience != ctx.audience {
        return Err(CloneKitError::Unauthorized("grant job_id or audience mismatch"));
    }
    if c.history_id != ctx.history_id {
        return Err(CloneKitError::HistoryChanged { expected: ctx.history_id, actual: c.history_id });
    }
    if c.storage_generation != ctx.storage_generation {
        return Err(CloneKitError::StaleGeneration {
            expected_min: ctx.storage_generation.max(1) as u64,
            actual: c.storage_generation.max(0) as u64,
        });
    }
    if ctx.now_unix >= c.not_after_unix {
        return Err(CloneKitError::GrantExpired);
    }
    authority.check_active(c).await
}

/// Receipt proving every LFS pointer & submodule gitlink inside `target_oid` satisfied #36 independent authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencyVerificationReceipt {
    pub verified_lfs_count: usize,
    pub verified_submodule_count: usize,
}

fn parse_lfs_pointer(raw: &[u8]) -> Option<(String, u64)> {
    let text = std::str::from_utf8(raw).ok()?;
    if text.lines().next()?.trim() != LFS_POINTER_HEADER {
        return None;
    }
    let (mut oid, mut size) = (None, None);
    for line in text.lines().skip(1) {
        if let Some(rest) = line.strip_prefix("oid sha256:")
            && valid_sha256_hex(rest.trim())
        {
            oid = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("size ") {
            size = rest.trim().parse::<u64>().ok();
        }
    }
    oid.zip(size)
}

/// Fail-closed check ensuring any LFS pointers or submodule gitlinks in `target_oid` hold valid #36 grants.
pub async fn verify_tree_dependencies(
    git_binary: &Path,
    repo_dir: &Path,
    claims: &CloneKitGrantClaims,
    authority: &dyn CloneKitAuthorityOracle,
    lfs_objects_dir: Option<&Path>,
) -> Result<DependencyVerificationReceipt, CloneKitError> {
    let target_oid = &claims.target_oid;
    let granted = &claims.dependencies;
    if !claims.object_format.valid_oid(target_oid) {
        return Err(CloneKitError::IncompleteClosure("invalid target_oid for closure check".into()));
    }
    let tree_raw = run_git_command(git_binary, Some(repo_dir), &["ls-tree", "-lrz", "--full-tree", target_oid], None)?;
    let (mut gitlinks, mut small_blobs) = (Vec::new(), Vec::new());
    for record in tree_raw.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let line = std::str::from_utf8(record)
            .map_err(|_| CloneKitError::DependencyCheckFailed("non-utf8 path in ls-tree".into()))?;
        let (head, path) = line
            .split_once('\t')
            .ok_or_else(|| CloneKitError::DependencyCheckFailed("malformed ls-tree row".into()))?;
        let mut parts = head.split_ascii_whitespace();
        let (mode, kind, oid) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        let size = parts.next().and_then(|s| s.parse::<u64>().ok());
        if mode == "160000" && kind == "commit" {
            gitlinks.push((path.to_owned(), oid.to_owned()));
        } else if kind == "blob" {
            let size = size
                .ok_or_else(|| CloneKitError::DependencyCheckFailed("ls-tree blob row missing a valid size".into()))?;
            if size <= 1024 {
                small_blobs.push((path.to_owned(), oid.to_owned()));
            }
        }
    }

    for (path, oid) in &gitlinks {
        let sub = granted
            .submodules
            .iter()
            .find(|s| &s.path == path && &s.target_oid == oid)
            .ok_or_else(|| CloneKitError::DependencyCheckFailed(format!("ungranted submodule {path}@{oid}")))?;
        authority.check_dependency_grant(sub.grant_id).await?;
    }

    let mut verified_lfs = 0usize;
    for (path, blob_oid) in &small_blobs {
        let blob_raw = run_git_command(git_binary, Some(repo_dir), &["cat-file", "blob", blob_oid], None)?;
        if let Some((lfs_oid, lfs_size)) = parse_lfs_pointer(&blob_raw) {
            let lfs = granted
                .lfs_objects
                .iter()
                .find(|entry| &entry.path == path && entry.oid == lfs_oid && entry.size == lfs_size)
                .ok_or_else(|| CloneKitError::DependencyCheckFailed(format!("ungranted LFS {path} ({lfs_oid})")))?;
            authority.check_dependency_grant(lfs.grant_id).await?;
            if let Some(dir) = lfs_objects_dir {
                let data = std::fs::read(dir.join(&lfs.oid))
                    .map_err(|_| CloneKitError::DependencyCheckFailed(format!("missing LFS bytes for {}", lfs.oid)))?;
                if data.len() as u64 != lfs.size || hex::encode(Sha256::digest(&data)) != lfs.oid {
                    return Err(CloneKitError::DependencyCheckFailed(format!("corrupt LFS bytes for {}", lfs.oid)));
                }
            }
            verified_lfs += 1;
        }
    }
    Ok(DependencyVerificationReceipt { verified_lfs_count: verified_lfs, verified_submodule_count: gitlinks.len() })
}
