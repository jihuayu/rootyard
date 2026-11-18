//! Fail-closed OpenDAL Blob gate and authoritative subject/tenant/shared-hold authz (`Refs #145`).

use std::sync::Arc;

use axum::http::{HeaderMap, header};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::blob_store::{config::BlobProfile, opendal::BlobStore};

use super::types::{
    CommittedLfsBlobRecord, LfsAccessMode, LfsBlobError, LfsCollaboratorRole, LfsProofRejectCode, LfsRefUpdateSpec,
    SharedLfsHoldGrant, compute_ref_updates_digest,
};

const IDEMPOTENCY_OP_DOMAIN: &[u8] = b"rootyard/lfs/idempotency-op/v1:";
const DEFAULT_UPLOAD_OP_DOMAIN: &[u8] = b"rootyard/lfs/default-upload-op/v1:";
const DEFAULT_PUSH_OP_DOMAIN: &[u8] = b"rootyard/lfs/default-push-op/v1:";

/// Startup & request gate guaranteeing LFS never operates without an explicit remote OpenDAL `BlobStore`.
#[derive(Clone)]
pub enum LfsBlobRuntimeGate {
    Unconfigured { reason: String },
    Configured(Arc<BlobStore>),
}

impl std::fmt::Debug for LfsBlobRuntimeGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unconfigured { reason } => f.debug_struct("Unconfigured").field("reason", reason).finish(),
            Self::Configured(store) => {
                f.debug_struct("Configured").field("provider", &store.provider().as_str()).finish()
            }
        }
    }
}

impl LfsBlobRuntimeGate {
    pub fn unconfigured(reason: impl Into<String>) -> Self {
        Self::Unconfigured { reason: reason.into() }
    }

    pub fn configured(store: BlobStore) -> Self {
        Self::Configured(Arc::new(store))
    }

    /// Returns `true` when S4 remote-Blob-only LFS mode is enabled on the server process.
    pub fn blob_mode_requested() -> bool {
        std::env::var("ROOTYARD_LFS_BLOB_ONLY")
            .ok()
            .is_some_and(|v| matches!(v.trim(), "1" | "true" | "required" | "opendal"))
            || std::env::var_os("ROOTYARD_BLOB_DRIVER").is_some()
    }

    /// Opens the remote OpenDAL `BlobStore` from environment variables, converting missing or
    /// local/memory configurations into a fail-closed `Unconfigured` gate rather than panicking.
    pub fn from_env_gate() -> Self {
        match Self::open_from_env() {
            Ok(gate) => gate,
            Err(err) => Self::Unconfigured { reason: err.message },
        }
    }

    pub fn open_from_env() -> Result<Self, LfsBlobError> {
        let profile = BlobProfile::from_env().map_err(LfsBlobError::from_blob_error)?;
        Self::open_profile(profile)
    }

    pub fn open_profile(profile: BlobProfile) -> Result<Self, LfsBlobError> {
        let store = BlobStore::open(profile).map_err(LfsBlobError::from_blob_error)?;
        Ok(Self::Configured(Arc::new(store)))
    }

    /// Fail-closed request check: every LFS Batch, Transfer, Lock, Hydration, and Push
    /// Attestation path invokes this before touching PostgreSQL or Git.
    pub fn require_store(&self) -> Result<&BlobStore, LfsBlobError> {
        match self {
            Self::Configured(store) => Ok(store.as_ref()),
            Self::Unconfigured { reason } => Err(LfsBlobError::new(
                LfsProofRejectCode::RemoteBlobUnconfigured,
                format!("remote OpenDAL Blob is not configured: {reason}"),
            )),
        }
    }
}

/// Authoritative subject-to-tenant/repository relationship resolved from PostgreSQL
/// (`namespaces`, `users`, `organizations`, `organization_memberships`, `organization_teams`,
/// `repository_collaborators`, and `repository_teams` under `FOR SHARE`).
/// Never inferred by comparing two raw caller and tenant UUIDs directly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubjectTenantAuthority {
    PersonalNamespaceOwner { namespace_id: Uuid, namespace_slug: String },
    OrganizationMember { organization_id: Uuid, namespace_slug: String, role: LfsCollaboratorRole },
    RepositoryCollaborator { namespace_slug: String, role: LfsCollaboratorRole },
    Unrelated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedRepoAccess {
    pub repository_id: Uuid,
    pub owner_tenant_id: Uuid,
    pub actor_id: Uuid,
    pub actor_username: String,
    pub role: LfsCollaboratorRole,
    pub mode: LfsAccessMode,
}

impl AuthorizedRepoAccess {
    pub const fn is_cross_owner(&self) -> bool {
        !matches!(self.mode, LfsAccessMode::Owner)
    }
}

/// Evaluates repository access strictly from the authoritative PostgreSQL [`SubjectTenantAuthority`]
/// relationship — never comparing raw caller and tenant UUIDs directly.
pub fn evaluate_subject_tenant_access(
    repository_id: Uuid,
    owner_tenant_id: Uuid,
    actor_id: Uuid,
    actor_username: &str,
    authority: SubjectTenantAuthority,
    require_write: bool,
    require_admin: bool,
) -> Result<AuthorizedRepoAccess, LfsBlobError> {
    if repository_id.is_nil() || owner_tenant_id.is_nil() || actor_id.is_nil() {
        return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "nil repository, tenant, or actor UUID"));
    }
    let (role, mode) = match authority {
        SubjectTenantAuthority::PersonalNamespaceOwner { namespace_id, .. } => {
            if namespace_id != owner_tenant_id {
                return Err(LfsBlobError::new(
                    LfsProofRejectCode::UnauthorizedCollaborator,
                    "personal namespace authority row does not match repository owner namespace",
                ));
            }
            (LfsCollaboratorRole::Admin, LfsAccessMode::Owner)
        }
        SubjectTenantAuthority::OrganizationMember { organization_id, role, .. } => {
            (role, LfsAccessMode::OrganizationMember { organization_id, role })
        }
        SubjectTenantAuthority::RepositoryCollaborator { role, .. } => {
            (role, LfsAccessMode::Collaborator { role })
        }
        SubjectTenantAuthority::Unrelated => {
            return Err(LfsBlobError::new(
                LfsProofRejectCode::UnauthorizedCollaborator,
                format!("actor `{actor_username}` has no authoritative namespace/org/repo grant on {repository_id}"),
            ));
        }
    };

    if require_admin && !role.allows_admin() {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::UnauthorizedCollaborator,
            format!("actor `{actor_username}` lacks admin permission on repository {repository_id}"),
        ));
    }
    if require_write && !role.allows_write() {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::UnauthorizedCollaborator,
            format!("actor `{actor_username}` lacks write permission on repository {repository_id}"),
        ));
    }

    Ok(AuthorizedRepoAccess {
        repository_id,
        owner_tenant_id,
        actor_id,
        actor_username: actor_username.to_owned(),
        role,
        mode,
    })
}

/// Validates that a cross-owner [`SharedLfsHoldGrant`] authorizes `(target_tenant_id, target_repository_id)`
/// and `actor_id` to reference or download `(expected_oid, expected_size)` backed by `source_record`.
pub fn verify_shared_hold_grant(
    grant: &SharedLfsHoldGrant,
    source_record: &CommittedLfsBlobRecord,
    target_tenant_id: Uuid,
    target_repository_id: Uuid,
    actor_id: Uuid,
    expected_oid: &str,
    expected_size: i64,
) -> Result<(), LfsBlobError> {
    if !grant.active {
        return Err(LfsBlobError::new(LfsProofRejectCode::UnauthorizedSharedHold, "shared LFS hold grant is revoked"));
    }
    if grant.target_tenant_id != target_tenant_id || grant.target_repository_id != target_repository_id {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::UnauthorizedSharedHold,
            "shared LFS hold target repository/tenant mismatch",
        ));
    }
    if let Some(allowed_actor) = grant.grantee_actor_id
        && allowed_actor != actor_id
    {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::UnauthorizedSharedHold,
            "shared LFS hold grant is bound to a different grantee actor",
        ));
    }
    if grant.oid_sha256 != expected_oid || grant.size_bytes != expected_size {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::UnauthorizedSharedHold,
            "shared LFS hold OID or byte length mismatch",
        ));
    }
    if source_record.retired
        || source_record.tenant_id != grant.source_tenant_id
        || source_record.repository_id != grant.source_repository_id
        || source_record.oid_sha256 != expected_oid
        || source_record.size_bytes != expected_size
        || source_record.hold_id != grant.source_hold_id
    {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::UnauthorizedSharedHold,
            "shared LFS hold source object record missing, retired, or mismatched",
        ));
    }
    Ok(())
}

/// Deterministically maps an `X-Rootyard-Operation-Id` or `Idempotency-Key` header into a non-nil
/// operation [`Uuid`], rejecting conflicting duplicate headers.
pub fn extract_stable_operation_id(headers: &HeaderMap) -> Result<Option<Uuid>, LfsBlobError> {
    let mut chosen: Option<Uuid> = None;
    for hdr_name in ["x-rootyard-operation-id", "idempotency-key"] {
        for val in headers.get_all(hdr_name) {
            let text = val
                .to_str()
                .map_err(|_| LfsBlobError::new(LfsProofRejectCode::InvalidInput, "non-ASCII operation header"))?
                .trim();
            if text.is_empty() || text.len() > 128 {
                return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "invalid operation header length"));
            }
            let parsed = operation_token_to_uuid(text)?;
            if let Some(prev) = chosen {
                if prev != parsed {
                    return Err(LfsBlobError::new(
                        LfsProofRejectCode::AttestationEquivocation,
                        "conflicting operation identity headers on same request",
                    ));
                }
            } else {
                chosen = Some(parsed);
            }
        }
    }
    Ok(chosen)
}

pub fn operation_token_to_uuid(token: &str) -> Result<Uuid, LfsBlobError> {
    if let Ok(parsed) = Uuid::parse_str(token) {
        if parsed.is_nil() {
            return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "nil operation UUID forbidden"));
        }
        return Ok(parsed);
    }
    if !token.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-')) {
        return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "unsafe characters in operation key"));
    }
    let mut h = Sha256::new();
    h.update(IDEMPOTENCY_OP_DOMAIN);
    h.update(token.as_bytes());
    let digest = h.finalize();
    Ok(uuid_from_sha256_prefix(&digest))
}

fn uuid_from_sha256_prefix(digest: &[u8]) -> Uuid {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

/// Deterministically derives the default upload `operation_id` when an unmodified `git-lfs` client
/// omits `X-Rootyard-Operation-Id` / `Idempotency-Key`. `repair_epoch` increments strictly when a
/// previously committed canonical remote `BlobLocator` is verified missing and requires repair.
pub fn derive_default_upload_operation_id(
    repository_id: Uuid,
    actor_id: Uuid,
    oid_sha256: &str,
    size_bytes: i64,
    repair_epoch: u64,
) -> Uuid {
    let mut h = Sha256::new();
    h.update(DEFAULT_UPLOAD_OP_DOMAIN);
    h.update(repository_id.as_bytes());
    h.update(actor_id.as_bytes());
    h.update(oid_sha256.as_bytes());
    h.update(size_bytes.to_be_bytes());
    h.update(repair_epoch.to_be_bytes());
    uuid_from_sha256_prefix(&h.finalize())
}

/// Deterministically derives the default ref-publication attestation `operation_id` when an
/// unmodified `git push` client omits `X-Rootyard-Operation-Id` / `Idempotency-Key`.
pub fn derive_default_push_operation_id(repository_id: Uuid, actor_id: Uuid, updates: &[LfsRefUpdateSpec]) -> Uuid {
    let mut h = Sha256::new();
    h.update(DEFAULT_PUSH_OP_DOMAIN);
    h.update(repository_id.as_bytes());
    h.update(actor_id.as_bytes());
    h.update(compute_ref_updates_digest(updates).as_bytes());
    uuid_from_sha256_prefix(&h.finalize())
}

/// Parses HTTP `Authorization` header (`Basic base64(user:secret)` or `Bearer secret`).
pub fn extract_credentials_header(headers: &HeaderMap) -> Result<(String, String), LfsBlobError> {
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::Unauthenticated, "missing Authorization header"))?;
    if let Some(b64) = raw.strip_prefix("Basic ").or_else(|| raw.strip_prefix("basic ")) {
        let decoded = BASE64
            .decode(b64.trim())
            .map_err(|_| LfsBlobError::new(LfsProofRejectCode::Unauthenticated, "malformed Basic credentials"))?;
        let text = std::str::from_utf8(&decoded)
            .map_err(|_| LfsBlobError::new(LfsProofRejectCode::Unauthenticated, "non-UTF8 Basic credentials"))?;
        let (user, secret) = text
            .split_once(':')
            .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::Unauthenticated, "Basic auth missing colon"))?;
        if user.is_empty() || secret.is_empty() {
            return Err(LfsBlobError::new(LfsProofRejectCode::Unauthenticated, "empty Basic user or token"));
        }
        return Ok((user.to_owned(), secret.to_owned()));
    }
    if let Some(tok) = raw.strip_prefix("Bearer ").or_else(|| raw.strip_prefix("bearer ")) {
        let trimmed = tok.trim();
        if let Some((user, secret)) = trimmed.split_once(':') {
            if user.is_empty() || secret.is_empty() {
                return Err(LfsBlobError::new(LfsProofRejectCode::Unauthenticated, "empty Bearer user or token"));
            }
            return Ok((user.to_owned(), secret.to_owned()));
        }
        if !trimmed.is_empty() {
            return Ok((String::new(), trimmed.to_owned()));
        }
    }
    Err(LfsBlobError::new(LfsProofRejectCode::Unauthenticated, "unsupported Authorization scheme"))
}
