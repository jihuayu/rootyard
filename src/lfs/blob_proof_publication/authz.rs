//! Fail-closed OpenDAL Blob startup/request gate and cross-owner / shared-hold authz (`Refs #145`).

use std::sync::Arc;

use axum::http::{HeaderMap, header};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::blob_store::{config::BlobProfile, opendal::BlobStore};

use super::types::{
    CommittedLfsBlobRecord, LfsAccessMode, LfsBlobError, LfsCollaboratorRole, LfsProofRejectCode, SharedLfsHoldGrant,
};

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

    /// Strict startup constructor reading `ROOTYARD_BLOB_*` environment settings.
    /// Refuses missing, local-fs, memory, or invalid configurations fail-closed.
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LfsPrincipal {
    pub actor_id: Uuid,
    pub username: String,
    pub secret_sha256: String,
}

impl LfsPrincipal {
    pub fn hash_secret(secret: &str) -> String {
        hex::encode(Sha256::digest(secret.as_bytes()))
    }
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

/// Evaluates repository access without assuming `actor_id == owner_tenant_id`.
pub fn evaluate_repo_role_access(
    repository_id: Uuid,
    owner_tenant_id: Uuid,
    actor_id: Uuid,
    actor_username: &str,
    collaborator_role: Option<LfsCollaboratorRole>,
    require_write: bool,
    require_admin: bool,
) -> Result<AuthorizedRepoAccess, LfsBlobError> {
    if repository_id.is_nil() || owner_tenant_id.is_nil() || actor_id.is_nil() {
        return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "nil repository, tenant, or actor UUID"));
    }
    let (role, mode) = if actor_id == owner_tenant_id {
        (LfsCollaboratorRole::Admin, LfsAccessMode::Owner)
    } else if let Some(granted) = collaborator_role {
        (granted, LfsAccessMode::Collaborator { role: granted })
    } else {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::UnauthorizedCollaborator,
            format!("actor `{actor_username}` ({actor_id}) is neither owner nor collaborator on repo {repository_id}"),
        ));
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
            format!("actor `{actor_username}` has read-only role and cannot write/lock/push repository {repository_id}"),
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

/// Parses HTTP `Authorization` header (`Basic base64(user:secret)` or `Bearer user:secret`).
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
        let (user, secret) = tok
            .trim()
            .split_once(':')
            .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::Unauthenticated, "Bearer token must be user:secret"))?;
        if user.is_empty() || secret.is_empty() {
            return Err(LfsBlobError::new(LfsProofRejectCode::Unauthenticated, "empty Bearer user or token"));
        }
        return Ok((user.to_owned(), secret.to_owned()));
    }
    Err(LfsBlobError::new(LfsProofRejectCode::Unauthenticated, "unsupported Authorization scheme"))
}
