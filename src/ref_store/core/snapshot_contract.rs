//! Bounded scope, literal prefix, private keyset cursor and logical budgets for
//! the metadata-only snapshot contract (A2).
//!
//! This module performs no IO. Every access to a metadata snapshot/pin names an
//! explicit trusted internal scope: repository, tenant, owner, purpose, gate
//! epochs and object format. Owner and purpose are trusted internal identities,
//! never an HTTP authentication substitute, and purpose is a bounded enum.
//!
//! The page cursor is a private typed value derived from an issued page: it has
//! no `Deserialize`, no textual/signed encoding and no public constructor, so a
//! caller can neither forge nor decode one.
use super::super::contract::{MetadataPinPurpose, RefStoreError, RequestDigest};
use super::types::{GitObjectFormat, RefName};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Hard maximum refs copied into one immutable snapshot.
pub const MAX_SNAPSHOT_REFS: usize = 4096;
/// Hard maximum page size; a page always fetches `limit + 1` rows.
pub const MAX_SNAPSHOT_PAGE: u32 = 256;
/// Hard maximum lease a caller may request (one hour).
pub const MAX_PIN_LEASE_SECONDS: i64 = 3600;
/// Hard maximum canonical receipt body stored in the mutation ledger.
pub const MAX_RECEIPT_BODY_BYTES: usize = 4096;
/// Hard maximum logical metadata bytes for a single snapshot.
pub const MAX_SNAPSHOT_LOGICAL_BYTES: i64 = 8 * 1024 * 1024;

/// Retained per-repository admission bounds (all history, not active-only).
pub const REPO_MAX_SNAPSHOTS: i64 = 64;
pub const REPO_MAX_SNAPSHOT_REFS: i64 = 16_384;
pub const REPO_MAX_LOGICAL_BYTES: i64 = 16 * 1024 * 1024;
pub const REPO_MAX_RECEIPTS: i64 = 2_048;

/// Retained per-tenant admission bounds (all repositories, all history).
pub const TENANT_MAX_SNAPSHOTS: i64 = 256;
pub const TENANT_MAX_SNAPSHOT_REFS: i64 = 65_536;
pub const TENANT_MAX_LOGICAL_BYTES: i64 = 64 * 1024 * 1024;
pub const TENANT_MAX_RECEIPTS: i64 = 8_192;

const SNAPSHOT_HEADER_BYTES: i64 = 256;
const SNAPSHOT_REF_OVERHEAD_BYTES: i64 = 32;
const PIN_ROW_OVERHEAD_BYTES: i64 = 192;
const RECEIPT_OVERHEAD_BYTES: i64 = 64;

/// Typed pack answer. A2 can only answer `Unavailable`: there is no pack
/// manifest or blob receipt contract yet, so no pack membership is claimed and
/// a refs/HEAD metadata page is not a Git `ReadSnapshot`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackMembershipDescriptor {
    Unavailable { reason: &'static str },
}

impl PackMembershipDescriptor {
    pub const fn unavailable() -> Self {
        Self::Unavailable { reason: "pack manifest and blob receipt contract not implemented (#108/#109)" }
    }
    pub const fn complete_git_read_snapshot(&self) -> bool {
        false
    }
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Unavailable { reason } => reason,
        }
    }
}

/// The trusted scope every metadata snapshot/pin access must name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataSnapshotScope {
    repository_id: Uuid,
    tenant_id: Uuid,
    owner_id: Uuid,
    purpose: MetadataPinPurpose,
    object_format: GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
}

impl MetadataSnapshotScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository_id: Uuid,
        tenant_id: Uuid,
        owner_id: Uuid,
        purpose: MetadataPinPurpose,
        object_format: GitObjectFormat,
        history_incarnation: Uuid,
        authority_epoch: i64,
        group_epoch: i64,
    ) -> Result<Self, RefStoreError> {
        if repository_id.is_nil() || tenant_id.is_nil() || owner_id.is_nil() || history_incarnation.is_nil() {
            return Err(RefStoreError::InvalidIdentity(
                "metadata snapshot repository, tenant, owner and history ids must be non-nil".into(),
            ));
        }
        if authority_epoch <= 0 || group_epoch <= 0 {
            return Err(RefStoreError::InvalidIdentity("metadata snapshot gate epochs must be positive".into()));
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

    pub fn repository_id(&self) -> Uuid {
        self.repository_id
    }
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }
    pub fn owner_id(&self) -> Uuid {
        self.owner_id
    }
    pub fn purpose(&self) -> MetadataPinPurpose {
        self.purpose
    }
    pub fn object_format(&self) -> GitObjectFormat {
        self.object_format
    }
    pub fn history_incarnation(&self) -> Uuid {
        self.history_incarnation
    }
    pub fn authority_epoch(&self) -> i64 {
        self.authority_epoch
    }
    pub fn group_epoch(&self) -> i64 {
        self.group_epoch
    }
}

/// A literal, bounded ref prefix used by one page. It is compared literally,
/// never as a `LIKE` pattern, so `%`, `_` and `\` carry no meaning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefPrefix(String);

impl RefPrefix {
    pub fn new(value: impl Into<String>) -> Result<Self, RefStoreError> {
        let value = value.into();
        let bytes = value.len();
        if !(6..=1024).contains(&bytes) || !value.starts_with("refs/") || value.chars().any(char::is_control) {
            return Err(RefStoreError::InvalidIdentity(
                "metadata ref prefix must be 6..=1024 bytes, start with refs/ and contain no control characters".into(),
            ));
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Private typed keyset cursor bound to the whole page scope, snapshot, pin,
/// pin generation and literal prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataSnapshotCursor {
    scope: MetadataSnapshotScope,
    snapshot_id: Uuid,
    pin_id: Uuid,
    pin_generation: i64,
    prefix: Option<RefPrefix>,
    after: RefName,
}

impl MetadataSnapshotCursor {
    pub(super) fn new(
        scope: MetadataSnapshotScope,
        snapshot_id: Uuid,
        pin_id: Uuid,
        pin_generation: i64,
        prefix: Option<RefPrefix>,
        after: RefName,
    ) -> Self {
        Self { scope, snapshot_id, pin_id, pin_generation, prefix, after }
    }
    pub fn snapshot_id(&self) -> Uuid {
        self.snapshot_id
    }
    pub fn pin_id(&self) -> Uuid {
        self.pin_id
    }
    pub fn pin_generation(&self) -> i64 {
        self.pin_generation
    }
    pub fn after(&self) -> &RefName {
        &self.after
    }
    pub fn prefix(&self) -> Option<&RefPrefix> {
        self.prefix.as_ref()
    }

    /// A cursor is only reusable for the exact scope it was issued for.
    pub(super) fn binds(
        &self,
        scope: &MetadataSnapshotScope,
        snapshot_id: Uuid,
        pin_id: Uuid,
        pin_generation: i64,
        prefix: Option<&RefPrefix>,
    ) -> bool {
        self.scope == *scope
            && self.snapshot_id == snapshot_id
            && self.pin_id == pin_id
            && self.pin_generation == pin_generation
            && self.prefix.as_ref() == prefix
    }
}

/// Validation shared by the request constructors.
pub(super) fn validate_mutation_ids(request_id: Uuid, pin_id: Uuid, snapshot_id: Uuid) -> Result<(), RefStoreError> {
    if request_id.is_nil() || pin_id.is_nil() || snapshot_id.is_nil() {
        return Err(RefStoreError::InvalidIdentity("metadata request, pin and snapshot ids must be non-nil".into()));
    }
    Ok(())
}

pub(super) fn validate_lease(lease_seconds: i64) -> Result<(), RefStoreError> {
    if lease_seconds <= 0 || lease_seconds > MAX_PIN_LEASE_SECONDS {
        return Err(RefStoreError::InvalidIdentity(format!(
            "metadata pin lease must be 1..={MAX_PIN_LEASE_SECONDS} seconds"
        )));
    }
    Ok(())
}

/// Per-snapshot bound: too many refs or too many logical bytes is a typed
/// rejection before any row is written.
pub(super) fn snapshot_budget_guard(logical_bytes: i64, ref_count: usize) -> Result<(), RefStoreError> {
    if ref_count > MAX_SNAPSHOT_REFS || logical_bytes > MAX_SNAPSHOT_LOGICAL_BYTES {
        return Err(RefStoreError::MetadataSnapshotTooLarge { ref_count, max_refs: MAX_SNAPSHOT_REFS });
    }
    Ok(())
}

/// Conservative logical bytes of one snapshot header plus its ref rows.
pub(super) fn snapshot_logical_bytes(head_ref: &str, head_oid: Option<&str>, refs: &[(String, String)]) -> i64 {
    let refs_bytes =
        refs.iter().map(|(name, oid)| name.len() as i64 + oid.len() as i64 + SNAPSHOT_REF_OVERHEAD_BYTES).sum::<i64>();
    SNAPSHOT_HEADER_BYTES + head_ref.len() as i64 + head_oid.map_or(0, |oid| oid.len() as i64) + refs_bytes
}

/// Conservative retained bytes of the pin row created with a snapshot.
pub(super) fn pin_logical_bytes() -> i64 {
    PIN_ROW_OVERHEAD_BYTES
}

/// Conservative retained bytes of one immutable receipt body.
pub(super) fn receipt_logical_bytes(body_bytes: usize) -> i64 {
    body_bytes as i64 + RECEIPT_OVERHEAD_BYTES
}

/// Canonical digest over the captured refs, in byte-ordered name order.
pub(super) fn refs_digest(refs: &[(String, String)]) -> RequestDigest {
    let mut fields = Vec::with_capacity(refs.len() * 2);
    for (name, oid) in refs {
        fields.push(name.as_bytes());
        fields.push(oid.as_bytes());
    }
    RequestDigest::of("metadata-snapshot-refs-v1", &fields)
}

/// Convert database-clock micros into a `SystemTime` for display only; lease
/// decisions are always taken from the database clock, never a client clock.
pub(super) fn expires_at_from_micros(micros: i64) -> Result<SystemTime, RefStoreError> {
    if micros <= 0 {
        return Err(RefStoreError::Database("stored metadata timestamp must be positive".into()));
    }
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_micros(micros as u64))
        .ok_or_else(|| RefStoreError::Database("stored metadata timestamp is out of range".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> MetadataSnapshotScope {
        MetadataSnapshotScope::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            MetadataPinPurpose::Verification,
            GitObjectFormat::Sha1,
            Uuid::new_v4(),
            1,
            1,
        )
        .unwrap()
    }

    #[test]
    fn scope_requires_non_nil_ids_and_positive_epochs() {
        let (repo, tenant, owner, history) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let format = GitObjectFormat::Sha1;
        assert!(
            MetadataSnapshotScope::new(Uuid::nil(), tenant, owner, MetadataPinPurpose::Backup, format, history, 1, 1)
                .is_err()
        );
        assert!(
            MetadataSnapshotScope::new(repo, tenant, owner, MetadataPinPurpose::Backup, format, history, 0, 1).is_err()
        );
        assert!(
            MetadataSnapshotScope::new(repo, tenant, owner, MetadataPinPurpose::Backup, format, history, 1, 1).is_ok()
        );
    }

    #[test]
    fn prefixes_are_literal_and_bounded() {
        assert!(RefPrefix::new("refs/heads").is_ok());
        assert!(RefPrefix::new("heads/").is_err());
        assert!(RefPrefix::new("refs/").is_err());
        assert!(RefPrefix::new("refs/bad%").is_ok(), "percent is literal, not a pattern");
        assert!(RefPrefix::new("refs/bad\u{1}").is_err());
    }

    #[test]
    fn cursor_binds_full_scope() {
        let scope = scope();
        let (snapshot, pin) = (Uuid::new_v4(), Uuid::new_v4());
        let prefix = Some(RefPrefix::new("refs/heads/").unwrap());
        let cursor = MetadataSnapshotCursor::new(
            scope,
            snapshot,
            pin,
            3,
            prefix.clone(),
            RefName::branch("refs/heads/main").unwrap(),
        );
        assert!(cursor.binds(&scope, snapshot, pin, 3, prefix.as_ref()));
        assert!(!cursor.binds(&scope, snapshot, pin, 4, prefix.as_ref()));
        assert!(!cursor.binds(&scope, snapshot, pin, 3, None));
        assert!(!cursor.binds(&scope, Uuid::new_v4(), pin, 3, prefix.as_ref()));
    }

    #[test]
    fn refs_digest_is_order_sensitive_and_refs_are_counted() {
        let one = vec![("refs/heads/a".to_string(), "a".repeat(40)), ("refs/heads/b".to_string(), "b".repeat(40))];
        let mut two = one.clone();
        two.reverse();
        assert_ne!(refs_digest(&one), refs_digest(&two));
        assert!(snapshot_logical_bytes("refs/heads/a", Some(&"a".repeat(40)), &one) > 2 * 72);
    }
}
