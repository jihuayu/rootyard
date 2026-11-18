//! Domain types, named rejection codes, pointer parser, and attestation digests (`Refs #145`).

use std::fmt;

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::blob_store::{BLOB_LOCATOR_SCHEMA, BlobError, BlobLocator};
use crate::lfs::models::{BatchObjectSpec, valid_lfs_oid};

const POINTER_V1: &str = "version https://git-lfs.github.com/spec/v1";
const POINTER_HAWSER: &str = "version https://hawser.github.com/spec/v1";
const POINTER_MEDIA: &str = "version http://git-media.io/v/2";
const MAX_POINTER_BYTES: usize = 1024;
const REF_UPDATES_DOMAIN: &[u8] = b"rootyard/lfs/ref-updates/v1";
const POINTER_RECEIPT_DOMAIN: &[u8] = b"rootyard/lfs/pointer-receipt/v1";
const ATTESTATION_DOMAIN: &[u8] = b"rootyard/lfs/pointer-attestation/v1";

/// Named fail-closed rejection codes for LFS Batch, Transfer, Locks, and Push Attestation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum LfsProofRejectCode {
    RemoteBlobUnconfigured,
    RemoteBlobUnreachable,
    Unauthenticated,
    InvalidInput,
    MalformedLfsPointer,
    MissingRemoteBlob,
    SizeOrDigestMismatch,
    ForeignBackendMismatch,
    UnauthorizedCollaborator,
    UnauthorizedSharedHold,
    LockedPathConflict,
    AttestationEquivocation,
    DeleteDisabledByPolicy,
    PgDatabase,
}

impl LfsProofRejectCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RemoteBlobUnconfigured => "remote_blob_unconfigured",
            Self::RemoteBlobUnreachable => "remote_blob_unreachable",
            Self::Unauthenticated => "unauthenticated",
            Self::InvalidInput => "invalid_input",
            Self::MalformedLfsPointer => "malformed_lfs_pointer",
            Self::MissingRemoteBlob => "missing_remote_blob",
            Self::SizeOrDigestMismatch => "size_or_digest_mismatch",
            Self::ForeignBackendMismatch => "foreign_backend_mismatch",
            Self::UnauthorizedCollaborator => "unauthorized_collaborator",
            Self::UnauthorizedSharedHold => "unauthorized_shared_hold",
            Self::LockedPathConflict => "locked_path_conflict",
            Self::AttestationEquivocation => "attestation_equivocation",
            Self::DeleteDisabledByPolicy => "delete_disabled_by_policy",
            Self::PgDatabase => "pg_database_error",
        }
    }

    pub const fn http_status(self) -> StatusCode {
        match self {
            Self::RemoteBlobUnconfigured | Self::RemoteBlobUnreachable | Self::PgDatabase => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::InvalidInput => StatusCode::BAD_REQUEST,
            Self::MalformedLfsPointer | Self::SizeOrDigestMismatch => StatusCode::UNPROCESSABLE_ENTITY,
            Self::MissingRemoteBlob => StatusCode::NOT_FOUND,
            Self::UnauthorizedCollaborator | Self::UnauthorizedSharedHold | Self::DeleteDisabledByPolicy => {
                StatusCode::FORBIDDEN
            }
            Self::ForeignBackendMismatch | Self::LockedPathConflict | Self::AttestationEquivocation => {
                StatusCode::CONFLICT
            }
        }
    }
}

impl fmt::Display for LfsProofRejectCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LfsBlobError {
    pub code: LfsProofRejectCode,
    pub message: String,
}

impl LfsBlobError {
    pub fn new(code: LfsProofRejectCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    pub fn from_blob_error(err: BlobError) -> Self {
        match err {
            BlobError::Config(m) | BlobError::UnsupportedService(m) => {
                Self::new(LfsProofRejectCode::RemoteBlobUnconfigured, m)
            }
            BlobError::NotFound => Self::new(LfsProofRejectCode::MissingRemoteBlob, "remote blob object not found"),
            BlobError::LengthMismatch { expected, actual } => Self::new(
                LfsProofRejectCode::SizeOrDigestMismatch,
                format!("remote blob size mismatch: expected {expected}, got {actual}"),
            ),
            BlobError::DigestMismatch { .. } => {
                Self::new(LfsProofRejectCode::SizeOrDigestMismatch, "remote blob SHA-256 mismatch")
            }
            BlobError::ForeignBackend => {
                Self::new(LfsProofRejectCode::ForeignBackendMismatch, "remote blob belongs to foreign backend")
            }
            BlobError::DeleteDisabled => Self::new(
                LfsProofRejectCode::DeleteDisabledByPolicy,
                "physical remote blob deletion is disabled by policy",
            ),
            other => Self::new(LfsProofRejectCode::RemoteBlobUnreachable, other.to_string()),
        }
    }
}

impl fmt::Display for LfsBlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for LfsBlobError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum LfsCollaboratorRole {
    Read,
    Write,
    Admin,
}

impl LfsCollaboratorRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, LfsBlobError> {
        match raw {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "admin" => Ok(Self::Admin),
            other => Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, format!("unknown LFS role `{other}`"))),
        }
    }

    pub const fn allows_write(self) -> bool {
        matches!(self, Self::Write | Self::Admin)
    }

    pub const fn allows_admin(self) -> bool {
        matches!(self, Self::Admin)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum LfsAccessMode {
    Owner,
    Collaborator { role: LfsCollaboratorRole },
    SharedHoldGrant { grant_id: Uuid, source_tenant_id: Uuid, source_repository_id: Uuid },
}

/// Serializable coordinate mirror of [`BlobLocator`]. Reconstructs only a read-only
/// [`BlobLocator`], never an [`crate::blob_store::UploadIntent`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredBlobLocatorRef {
    pub schema: u32,
    pub tenant_id: Uuid,
    pub authority_id: Uuid,
    pub generation: i64,
    pub attempt_id: Uuid,
    pub namespace: String,
    pub sha256: String,
    pub length: u64,
}

impl StoredBlobLocatorRef {
    pub fn from_locator(loc: &BlobLocator) -> Self {
        Self {
            schema: loc.schema(),
            tenant_id: loc.tenant_id(),
            authority_id: loc.authority_id(),
            generation: loc.generation(),
            attempt_id: loc.attempt_id(),
            namespace: loc.namespace().to_owned(),
            sha256: loc.sha256().to_owned(),
            length: loc.length(),
        }
    }

    pub fn to_locator(&self) -> Result<BlobLocator, LfsBlobError> {
        if self.schema != BLOB_LOCATOR_SCHEMA {
            return Err(LfsBlobError::new(
                LfsProofRejectCode::InvalidInput,
                format!("unsupported blob locator schema {}", self.schema),
            ));
        }
        BlobLocator::new(
            self.tenant_id,
            self.authority_id,
            self.generation,
            self.attempt_id,
            &self.namespace,
            &self.sha256,
            self.length,
        )
        .map_err(LfsBlobError::from_blob_error)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedLfsBlobRecord {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub oid_sha256: String,
    pub size_bytes: i64,
    pub locator: StoredBlobLocatorRef,
    pub hold_id: Uuid,
    pub acquire_request_id: Uuid,
    pub consume_request_id: Uuid,
    pub backend_identity_hex: String,
    pub uploader_actor_id: Uuid,
    pub retired: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SharedLfsHoldGrant {
    pub grant_id: Uuid,
    pub source_tenant_id: Uuid,
    pub source_repository_id: Uuid,
    pub target_tenant_id: Uuid,
    pub target_repository_id: Uuid,
    pub grantee_actor_id: Option<Uuid>,
    pub oid_sha256: String,
    pub size_bytes: i64,
    pub source_hold_id: Uuid,
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PointerResolutionSource {
    RepositoryBlob,
    SharedHold { grant_id: Uuid, source_tenant_id: Uuid, source_repository_id: Uuid },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedLfsPointer {
    pub git_blob_oid: String,
    pub oid_sha256: String,
    pub size_bytes: i64,
    pub locator: StoredBlobLocatorRef,
    pub backend_identity_hex: String,
    pub hold_id: Uuid,
    pub resolution: PointerResolutionSource,
    pub receipt_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LfsRefUpdateSpec {
    pub ref_name: String,
    pub old_oid: String,
    pub new_oid: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LfsPointerAttestation {
    pub attestation_id: Uuid,
    pub operation_id: Uuid,
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub actor_id: Uuid,
    pub access_mode: LfsAccessMode,
    pub object_format: String,
    pub ref_updates_digest: String,
    pub pointers: Vec<AttestedLfsPointer>,
    pub proof_digest: String,
}

impl LfsPointerAttestation {
    pub fn verify_integrity(&self) -> Result<(), LfsBlobError> {
        let expected = compute_attestation_digest(
            self.operation_id,
            self.tenant_id,
            self.repository_id,
            self.actor_id,
            &self.object_format,
            &self.ref_updates_digest,
            &self.pointers,
        );
        if expected != self.proof_digest {
            return Err(LfsBlobError::new(
                LfsProofRejectCode::AttestationEquivocation,
                "LFS pointer attestation proof_digest integrity mismatch",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttestationOutcome {
    Issued(LfsPointerAttestation),
    Replayed(LfsPointerAttestation),
}

impl AttestationOutcome {
    pub fn attestation(&self) -> &LfsPointerAttestation {
        match self {
            Self::Issued(a) | Self::Replayed(a) => a,
        }
    }

    pub const fn is_replayed(&self) -> bool {
        matches!(self, Self::Replayed(_))
    }
}

fn feed_str(h: &mut Sha256, s: &str) {
    h.update((s.len() as u64).to_be_bytes());
    h.update(s.as_bytes());
}

pub fn compute_ref_updates_digest(updates: &[LfsRefUpdateSpec]) -> String {
    let mut sorted: Vec<&LfsRefUpdateSpec> = updates.iter().collect();
    sorted.sort_unstable_by(|a, b| (&a.ref_name, &a.old_oid, &a.new_oid).cmp(&(&b.ref_name, &b.old_oid, &b.new_oid)));
    let mut h = Sha256::new();
    h.update(REF_UPDATES_DOMAIN);
    h.update([0]);
    h.update((sorted.len() as u64).to_be_bytes());
    for u in sorted {
        for s in [&u.ref_name, &u.old_oid, &u.new_oid] {
            feed_str(&mut h, s);
        }
    }
    hex::encode(h.finalize())
}

pub fn compute_pointer_receipt_digest(
    oid_sha256: &str,
    size_bytes: i64,
    locator: &StoredBlobLocatorRef,
    backend_identity_hex: &str,
    hold_id: Uuid,
) -> String {
    let mut h = Sha256::new();
    h.update(POINTER_RECEIPT_DOMAIN);
    h.update([0]);
    feed_str(&mut h, oid_sha256);
    h.update(size_bytes.to_be_bytes());
    h.update(locator.schema.to_be_bytes());
    for id in [locator.tenant_id, locator.authority_id, locator.attempt_id, hold_id] {
        h.update(id.as_bytes());
    }
    h.update(locator.generation.to_be_bytes());
    h.update(locator.length.to_be_bytes());
    for s in [&locator.namespace, &locator.sha256, backend_identity_hex] {
        feed_str(&mut h, s);
    }
    hex::encode(h.finalize())
}

pub fn compute_attestation_digest(
    operation_id: Uuid,
    tenant_id: Uuid,
    repository_id: Uuid,
    actor_id: Uuid,
    object_format: &str,
    ref_updates_digest: &str,
    pointers: &[AttestedLfsPointer],
) -> String {
    let mut ordered: Vec<&AttestedLfsPointer> = pointers.iter().collect();
    ordered.sort_unstable_by(|a, b| {
        (&a.git_blob_oid, &a.oid_sha256, a.size_bytes).cmp(&(&b.git_blob_oid, &b.oid_sha256, b.size_bytes))
    });
    let mut h = Sha256::new();
    h.update(ATTESTATION_DOMAIN);
    h.update([0]);
    for id in [operation_id, tenant_id, repository_id, actor_id] {
        h.update(id.as_bytes());
    }
    feed_str(&mut h, object_format);
    feed_str(&mut h, ref_updates_digest);
    h.update((ordered.len() as u64).to_be_bytes());
    for p in ordered {
        for s in [&p.git_blob_oid, &p.oid_sha256, &p.backend_identity_hex, &p.receipt_digest] {
            feed_str(&mut h, s);
        }
        h.update(p.size_bytes.to_be_bytes());
        h.update(p.hold_id.as_bytes());
        match &p.resolution {
            PointerResolutionSource::RepositoryBlob => h.update([1]),
            PointerResolutionSource::SharedHold { grant_id, source_tenant_id, source_repository_id } => {
                h.update([2]);
                for id in [*grant_id, *source_tenant_id, *source_repository_id] {
                    h.update(id.as_bytes());
                }
            }
        }
    }
    hex::encode(h.finalize())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PointerInspection {
    NonPointer,
    Valid(BatchObjectSpec),
    Malformed(&'static str),
}

/// Inspects a small Git blob (`<= 1024` bytes) and classifies it as an ordinary
/// non-pointer blob, a valid canonical/legacy Git LFS v1 pointer, or a malformed
/// LFS pointer (`MalformedLfsPointer`).
pub fn inspect_candidate_lfs_pointer(bytes: &[u8]) -> PointerInspection {
    if bytes.len() > MAX_POINTER_BYTES {
        return PointerInspection::NonPointer;
    }
    let Ok(raw_text) = std::str::from_utf8(bytes) else {
        return PointerInspection::NonPointer;
    };
    let trimmed = raw_text.trim_start();
    let line_end = trimmed.find('\n').unwrap_or(trimmed.len());
    let header = trimmed[..line_end].strip_suffix('\r').unwrap_or(&trimmed[..line_end]);
    if header != POINTER_V1 && header != POINTER_HAWSER && header != POINTER_MEDIA {
        return PointerInspection::NonPointer;
    }

    let mut oid_val: Option<String> = None;
    let mut size_val: Option<i64> = None;
    for raw_line in trimmed[line_end..].lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("oid sha256:") {
            if oid_val.is_some() || !valid_lfs_oid(rest) {
                return PointerInspection::Malformed("invalid or duplicate LFS pointer oid sha256");
            }
            oid_val = Some(rest.to_owned());
        } else if let Some(rest) = line.strip_prefix("size ") {
            if size_val.is_some() || rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
                return PointerInspection::Malformed("invalid or duplicate LFS pointer size");
            }
            let Ok(parsed) = rest.parse::<i64>() else {
                return PointerInspection::Malformed("LFS pointer size overflows i64");
            };
            if parsed < 0 {
                return PointerInspection::Malformed("negative LFS pointer size");
            }
            size_val = Some(parsed);
        } else if line.starts_with("oid ") {
            return PointerInspection::Malformed("unsupported LFS pointer hash algorithm");
        } else if !line.starts_with("ext-") {
            return PointerInspection::Malformed("unrecognized LFS pointer metadata key");
        }
    }
    match (oid_val, size_val) {
        (Some(oid), Some(size)) => PointerInspection::Valid(BatchObjectSpec { oid, size }),
        _ => PointerInspection::Malformed("incomplete LFS pointer missing oid or size"),
    }
}
