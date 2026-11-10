//! Bounded values, exact admission limits and typed errors of the global
//! artifact-hold ledger (A3, #113 dependency of #107).
//!
//! This module performs no IO and has no PostgreSQL dependency. Every limit is
//! a *logical reservation* bound, never a PostgreSQL WAL/RSS, filesystem or
//! provider-disk guarantee. `64` fixed global shards, per-tenant and
//! per-repository ceilings match migration 141 exactly; the migration repeats
//! the same ceilings as `CHECK` constraints and refuses any counter decrease.
//!
//! The scope/purpose here is a trusted internal identity. It is not an HTTP
//! authentication substitute and no route may construct one from request
//! parameters.
use crate::ref_store::contract::RefStoreError;
use crate::ref_store::core::types::GitObjectFormat;
use std::fmt;
use uuid::Uuid;

/// Hard maximum artifacts in one all-or-none acquire batch (also `MAX16`).
pub const MAX_BATCH_ARTIFACTS: usize = 16;

/// Fixed global shard count. There is no dynamic resharding and no global
/// counter: every shard is chosen from the stable acquire request UUID.
pub const GLOBAL_SHARDS: u32 = 64;

/// Global shard ceilings: 64 x 256 = 16384 holds, 64 x 128 MiB = 8 GiB
/// declared, 64 x 1 MiB = 64 MiB logical, 64 x 1024 = 65536 receipts.
pub const SHARD_MAX_HOLDS: i64 = 256;
pub const SHARD_MAX_DECLARED_BYTES: i64 = 128 * 1024 * 1024;
pub const SHARD_MAX_LOGICAL_BYTES: i64 = 1024 * 1024;
pub const SHARD_MAX_RECEIPTS: i64 = 1024;

/// Per-repository retained ceilings (all history, never active-only).
pub const REPO_MAX_HOLDS: i64 = 256;
pub const REPO_MAX_DECLARED_BYTES: i64 = 128 * 1024 * 1024;
pub const REPO_MAX_LOGICAL_BYTES: i64 = 4 * 1024 * 1024;
pub const REPO_MAX_RECEIPTS: i64 = 2048;

/// Per-tenant retained ceilings across every repository.
pub const TENANT_MAX_HOLDS: i64 = 1024;
pub const TENANT_MAX_DECLARED_BYTES: i64 = 512 * 1024 * 1024;
pub const TENANT_MAX_LOGICAL_BYTES: i64 = 16 * 1024 * 1024;
pub const TENANT_MAX_RECEIPTS: i64 = 8192;

/// Canonical immutable ACK/receipt body ceiling (64 KiB, per request).
pub const MAX_RECEIPT_BODY_BYTES: usize = 64 * 1024;

/// One artifact's declared content ceiling, matching `BlobLocator`'s
/// `MAX_OBJECT_BYTES` (`1 << 40`). Declared bytes are the locator length: the
/// caller declares them before any upload, and the raw writer later refuses a
/// source whose real length/digest differ.
pub const MAX_ARTIFACT_DECLARED_BYTES: u64 = 1 << 40;

/// Blob namespace ceiling (lowercase/digits/dash), matching `BlobLocator`.
pub const MAX_NAMESPACE_BYTES: usize = 48;
/// Conservative retained logical bytes of one hold row, excluding the
/// variable-length text fields.
const HOLD_ROW_OVERHEAD_BYTES: i64 = 512;
/// Bounded trusted purpose of a hold. One production purpose exists in this
/// slice; an unknown stored value is a database-integrity error, never a
/// default.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactHoldPurpose {
    RefPublication,
}

impl ArtifactHoldPurpose {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RefPublication => "ref_publication",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ArtifactHoldError> {
        match value {
            "ref_publication" => Ok(Self::RefPublication),
            _ => Err(ArtifactHoldError::Database("stored artifact hold purpose is not a bounded value".into())),
        }
    }
}

/// The trusted scope of one acquire/consume. Owner and purpose are trusted
/// internal identities; every field is rechecked against the durable ledger
/// row and the current repository/core-gate scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HoldScope {
    repository_id: Uuid,
    tenant_id: Uuid,
    owner_id: Uuid,
    purpose: ArtifactHoldPurpose,
    object_format: GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
}

impl HoldScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository_id: Uuid,
        tenant_id: Uuid,
        owner_id: Uuid,
        purpose: ArtifactHoldPurpose,
        object_format: GitObjectFormat,
        history_incarnation: Uuid,
        authority_epoch: i64,
        group_epoch: i64,
    ) -> Result<Self, ArtifactHoldError> {
        if repository_id.is_nil() || tenant_id.is_nil() || owner_id.is_nil() || history_incarnation.is_nil() {
            return Err(ArtifactHoldError::InvalidRequest(
                "artifact hold repository, tenant, owner and history ids must be non-nil".into(),
            ));
        }
        if authority_epoch <= 0 || group_epoch <= 0 {
            return Err(ArtifactHoldError::InvalidRequest("artifact hold gate epochs must be positive".into()));
        }
        Ok(Self {
            repository_id,
            tenant_id,
            owner_id,
            purpose,
            object_format,
            history_incarnation,
            authority_epoch,
            group_epoch,
        })
    }

    pub const fn repository_id(&self) -> Uuid {
        self.repository_id
    }
    pub const fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }
    pub const fn owner_id(&self) -> Uuid {
        self.owner_id
    }
    pub const fn purpose(&self) -> ArtifactHoldPurpose {
        self.purpose
    }
    pub const fn object_format(&self) -> GitObjectFormat {
        self.object_format
    }
    pub const fn history_incarnation(&self) -> Uuid {
        self.history_incarnation
    }
    pub const fn authority_epoch(&self) -> i64 {
        self.authority_epoch
    }
    pub const fn group_epoch(&self) -> i64 {
        self.group_epoch
    }
}

/// One canonical artifact specification supplied by the trusted caller. The
/// random attempt id/path is minted by the Blob byte layer *after* this value
/// is fixed and is deliberately absent from the caller request digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactSpec {
    namespace: String,
    sha256: String,
    length: u64,
}

impl ArtifactSpec {
    pub fn new(
        namespace: impl Into<String>,
        sha256: impl Into<String>,
        length: u64,
    ) -> Result<Self, ArtifactHoldError> {
        let namespace = namespace.into();
        if namespace.is_empty()
            || namespace.len() > MAX_NAMESPACE_BYTES
            || !namespace.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(ArtifactHoldError::InvalidRequest(
                "artifact namespace must be 1..=48 lowercase ASCII letters, digits or '-'".into(),
            ));
        }
        let sha256 = sha256.into();
        if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
            return Err(ArtifactHoldError::InvalidRequest("artifact digest must be lowercase sha256 hex".into()));
        }
        if length > MAX_ARTIFACT_DECLARED_BYTES {
            return Err(ArtifactHoldError::InvalidRequest(format!(
                "artifact declared length exceeds the {MAX_ARTIFACT_DECLARED_BYTES}-byte ceiling"
            )));
        }
        Ok(Self { namespace, sha256, length })
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn length(&self) -> u64 {
        self.length
    }

    /// Declared bytes charged to admission. `u64 -> i64` is exact because the
    /// constructor bounds the length to `1 << 40`.
    pub fn declared_bytes(&self) -> i64 {
        self.length as i64
    }

    /// Conservative retained logical bytes of the immutable hold row.
    pub fn logical_bytes(&self) -> i64 {
        HOLD_ROW_OVERHEAD_BYTES
            + self.namespace.len() as i64
            + self.sha256.len() as i64
            + "s3".len() as i64
            + std::mem::size_of::<Uuid>() as i64 * 6
    }
}

/// Stable shard of the global budget, derived only from the acquire request
/// UUID. A replay of that request always lands on the same shard.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ShardId(i32);

impl ShardId {
    pub fn of(request_id: Uuid) -> Self {
        let bytes = request_id.as_bytes();
        let raw = u64::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]);
        Self((raw % u64::from(GLOBAL_SHARDS)) as i32)
    }

    pub fn parse(value: i32) -> Result<Self, ArtifactHoldError> {
        if (0..GLOBAL_SHARDS as i32).contains(&value) {
            Ok(Self(value))
        } else {
            Err(ArtifactHoldError::Database("stored artifact hold shard id is out of range".into()))
        }
    }

    pub const fn as_i32(self) -> i32 {
        self.0
    }
}

/// Which admission scope refused a charge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoldQuotaScope {
    Shard,
    Tenant,
    Repository,
}

impl HoldQuotaScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Shard => "shard",
            Self::Tenant => "tenant",
            Self::Repository => "repository",
        }
    }
}

/// Retained admission resource named by backpressure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoldQuotaResource {
    Holds,
    DeclaredBytes,
    LogicalBytes,
    Receipts,
}

impl HoldQuotaResource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Holds => "holds",
            Self::DeclaredBytes => "declared_bytes",
            Self::LogicalBytes => "logical_bytes",
            Self::Receipts => "receipts",
        }
    }
}

/// Explicit capability declaration. Everything that needs a release, TTL,
/// physical GC, HTTP surface, serving profile, candidate/membership or logical
/// root is `false` because no safe implementation exists in this slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactHoldCapabilities {
    pub global_artifact_hold_ledger: bool,
    pub batch_acquire_all_or_none: bool,
    pub private_upload_grant: bool,
    pub durable_one_shot_consume: bool,
    pub protected_upload_readback: bool,
    pub permanent_active_holds: bool,
    pub artifact_release: bool,
    pub ttl_expiry: bool,
    pub physical_gc: bool,
    pub http_route: bool,
    pub serving_profile: bool,
    pub candidate_membership: bool,
    pub logical_roots: bool,
    pub retirement: bool,
}

impl ArtifactHoldCapabilities {
    pub const fn artifact_hold_increment() -> Self {
        Self {
            global_artifact_hold_ledger: true,
            batch_acquire_all_or_none: true,
            private_upload_grant: true,
            durable_one_shot_consume: true,
            protected_upload_readback: true,
            permanent_active_holds: true,
            artifact_release: false,
            ttl_expiry: false,
            physical_gc: false,
            http_route: false,
            serving_profile: false,
            candidate_membership: false,
            logical_roots: false,
            retirement: false,
        }
    }
}

/// Typed errors of the artifact-hold ledger.
///
/// `AcquireUnknown`/`ConsumeUnknown` are *not* aborts: a `COMMIT` was issued
/// and its acknowledgement was not observed, so the ledger may have committed.
/// They always carry the stable global ids needed for a receipt-only query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactHoldError {
    InvalidRequest(String),
    BatchTooLarge {
        artifacts: usize,
        max: usize,
    },
    DigestConflict {
        request_id: Uuid,
    },
    IdentityConflict {
        request_id: Uuid,
    },
    QuotaExceeded {
        scope: HoldQuotaScope,
        resource: HoldQuotaResource,
    },
    /// No durable pending parent operation with the exact bound identity.
    OperationNotPending {
        operation_id: Uuid,
    },
    OperationCancelled {
        operation_id: Uuid,
    },
    RepositoryNotFound,
    ScopeMismatch(&'static str),
    HoldNotFound {
        hold_id: Uuid,
    },
    HoldNotActive {
        hold_id: Uuid,
    },
    HoldAlreadyConsumed {
        hold_id: Uuid,
    },
    HoldIdentityMismatch {
        hold_id: Uuid,
    },
    /// The request/grant names a different physical Blob backend than the
    /// actually opened store (provider, endpoint, bucket/container, root,
    /// region or stable account identity). The refusal happens before any
    /// PostgreSQL transaction or provider IO and carries no descriptor,
    /// identity hash or credential.
    BackendMismatch,
    /// The immutable ledger rows disagree with each other or with a stored
    /// body. This is durable corruption: it is never `Unknown`, never a
    /// replay and never a grant.
    LedgerIntegrity(&'static str),
    ReceiptTooLarge {
        bytes: usize,
        max: usize,
    },
    Unsupported(&'static str),
    Timeout,
    AcquireUnknown {
        request_id: Uuid,
    },
    ConsumeUnknown {
        consume_request_id: Uuid,
        hold_ids: Vec<Uuid>,
    },
    Database(String),
    Registry(RefStoreError),
}

impl ArtifactHoldError {
    pub fn is_conflict(&self) -> bool {
        matches!(
            self,
            Self::DigestConflict { .. }
                | Self::IdentityConflict { .. }
                | Self::HoldAlreadyConsumed { .. }
                | Self::HoldIdentityMismatch { .. }
                | Self::BackendMismatch
        )
    }

    /// True when a `COMMIT` may have landed and the caller must query the
    /// stable request id instead of assuming the operation aborted.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::AcquireUnknown { .. } | Self::ConsumeUnknown { .. })
    }
}

impl From<RefStoreError> for ArtifactHoldError {
    fn from(error: RefStoreError) -> Self {
        match error {
            RefStoreError::Timeout => Self::Timeout,
            other => Self::Registry(other),
        }
    }
}

impl fmt::Display for ArtifactHoldError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(reason) => write!(formatter, "invalid artifact hold request: {reason}"),
            Self::BatchTooLarge { artifacts, max } => {
                write!(formatter, "artifact hold batch has {artifacts} artifacts, above the {max}-artifact maximum")
            }
            Self::DigestConflict { request_id } => {
                write!(formatter, "artifact hold request {request_id} was reused with a different semantic digest")
            }
            Self::IdentityConflict { request_id } => {
                write!(formatter, "artifact hold request {request_id} conflicts with a durable identity")
            }
            Self::QuotaExceeded { scope, resource } => write!(
                formatter,
                "artifact hold admission backpressure: retained {} {} quota is exhausted; nothing is evicted or refunded",
                scope.as_str(),
                resource.as_str()
            ),
            Self::OperationNotPending { operation_id } => write!(
                formatter,
                "parent ref-store operation {operation_id} is not durably pending; no artifact hold is authorised"
            ),
            Self::OperationCancelled { operation_id } => {
                write!(formatter, "parent ref-store operation {operation_id} is durably cancelled")
            }
            Self::RepositoryNotFound => formatter.write_str("artifact hold repository not found or not owned by the tenant"),
            Self::ScopeMismatch(field) => write!(formatter, "artifact hold scope mismatch on {field}"),
            Self::HoldNotFound { hold_id } => write!(formatter, "artifact hold {hold_id} not found in scope"),
            Self::HoldNotActive { hold_id } => write!(formatter, "artifact hold {hold_id} is not an active generation-1 hold"),
            Self::HoldAlreadyConsumed { hold_id } => {
                write!(formatter, "artifact hold {hold_id} already has a durable consume receipt")
            }
            Self::HoldIdentityMismatch { hold_id } => {
                write!(formatter, "artifact hold {hold_id} does not match the granted locator identity")
            }
            Self::BackendMismatch => formatter.write_str(
                "artifact hold is bound to a different physical Blob backend than the opened store; nothing was consumed, opened or written",
            ),
            Self::LedgerIntegrity(field) => {
                write!(formatter, "artifact hold ledger integrity violation on {field}; the answer is corruption, not an unknown outcome")
            }
            Self::ReceiptTooLarge { bytes, max } => {
                write!(formatter, "artifact hold receipt body is {bytes} bytes, above the {max}-byte maximum")
            }
            Self::Unsupported(capability) => write!(formatter, "artifact hold capability is unsupported: {capability}"),
            Self::Timeout => formatter.write_str("artifact hold transaction deadline expired"),
            Self::AcquireUnknown { request_id } => write!(
                formatter,
                "artifact hold acquire COMMIT outcome for global request {request_id} is unknown; the holds may exist, so query that request id for the immutable ACK and do not mint another grant"
            ),
            Self::ConsumeUnknown { consume_request_id, hold_ids } => write!(
                formatter,
                "artifact hold consume COMMIT outcome for consume request {consume_request_id} ({} holds) is unknown; the receipts may exist, so query that consume request id and upload nothing",
                hold_ids.len()
            ),
            Self::Database(message) => write!(formatter, "artifact hold database error: {message}"),
            Self::Registry(error) => write!(formatter, "artifact hold ref-store error: {error}"),
        }
    }
}

impl std::error::Error for ArtifactHoldError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shards_are_stable_and_bounded() {
        let request = Uuid::new_v4();
        assert_eq!(ShardId::of(request), ShardId::of(request));
        for _ in 0..32 {
            let shard = ShardId::of(Uuid::new_v4());
            assert!((0..64).contains(&shard.as_i32()));
        }
        assert!(ShardId::parse(-1).is_err());
        assert!(ShardId::parse(64).is_err());
        assert!(ShardId::parse(63).is_ok());
    }

    #[test]
    fn artifacts_are_bounded_and_checked() {
        assert!(ArtifactSpec::new("packs", "a".repeat(64), 1).is_ok());
        assert!(ArtifactSpec::new("", "a".repeat(64), 1).is_err());
        assert!(ArtifactSpec::new("Packs", "a".repeat(64), 1).is_err());
        assert!(ArtifactSpec::new("packs", "A".repeat(64), 1).is_err());
        assert!(ArtifactSpec::new("packs", "a".repeat(63), 1).is_err());
        assert!(ArtifactSpec::new("packs", "a".repeat(64), MAX_ARTIFACT_DECLARED_BYTES + 1).is_err());
        assert!(ArtifactSpec::new("packs", "a".repeat(64), MAX_ARTIFACT_DECLARED_BYTES).is_ok());
    }

    #[test]
    fn capability_claims_stay_false_for_unimplemented_features() {
        let capabilities = ArtifactHoldCapabilities::artifact_hold_increment();
        assert!(capabilities.global_artifact_hold_ledger);
        assert!(capabilities.durable_one_shot_consume);
        assert!(!capabilities.artifact_release);
        assert!(!capabilities.ttl_expiry);
        assert!(!capabilities.physical_gc);
        assert!(!capabilities.http_route);
        assert!(!capabilities.serving_profile);
        assert!(!capabilities.candidate_membership);
        assert!(!capabilities.logical_roots);
        assert!(!capabilities.retirement);
    }

    #[test]
    fn unknown_errors_are_never_conflicts() {
        let acquire = ArtifactHoldError::AcquireUnknown { request_id: Uuid::new_v4() };
        let consume =
            ArtifactHoldError::ConsumeUnknown { consume_request_id: Uuid::new_v4(), hold_ids: vec![Uuid::new_v4()] };
        assert!(acquire.is_unknown());
        assert!(consume.is_unknown());
        assert!(!acquire.is_conflict());
        assert!(!consume.is_conflict());
        assert!(acquire.to_string().contains("unknown"));
    }
}
