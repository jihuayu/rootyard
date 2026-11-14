//! Typed preimage inputs and opaque digest/version outputs for the C1a codec.
//!
//! Constructing an input describes a prospective request. It does not validate,
//! authorize, register or retain anything; [`super::digest::operation_digest`]
//! performs the pure validation and canonical encoding. The two output types
//! are distinct 32-byte newtypes, have no serde implementation and expose no
//! arbitrary-byte constructor. They are values, not capabilities.
use crate::ref_store::contract::{IssuerLane, RequestDigest};
use crate::ref_store::core::contract::CommitMode;
use crate::ref_store::core::pack_commit::PlannedPack;
use crate::ref_store::core::types::{GitObjectFormat, HeadUpdate, RefName, RefPrecondition, RefTarget};
use std::fmt;
use uuid::Uuid;

/// Fixed ref authority named by the realm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityKind {
    Pg,
    Raft,
}

impl AuthorityKind {
    /// Canonical one-byte tag: `1 = pg`, `2 = raft`.
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Pg => 1,
            Self::Raft => 2,
        }
    }
}

/// Version kind fixed by the request, never inferred from the target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RefVersionKind {
    Publish,
    Delete,
    Repack,
}

impl RefVersionKind {
    /// Canonical one-byte tag: `1 = publish`, `2 = delete`, `3 = repack`.
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Publish => 1,
            Self::Delete => 2,
            Self::Repack => 3,
        }
    }
}

/// Per-ref base selector. The legacy shape is bound into the operation digest
/// for replay separation but can never mint a candidate `VersionId`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BaseRequestSelector {
    /// `0`: the old request shape did not carry a base selector.
    LegacyNotSupplied,
    /// `1`: explicitly no previous version; legal only for generation 1.
    ExplicitAbsent,
    /// `2`: the exact current head version supplied by the authority.
    Present(VersionId),
}

impl BaseRequestSelector {
    /// Canonical one-byte tag: `0 = legacy`, `1 = explicit absent`,
    /// `2 = present with id`.
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::LegacyNotSupplied => 0,
            Self::ExplicitAbsent => 1,
            Self::Present(_) => 2,
        }
    }
}

/// Complete realm of one ref-version namespace. `owner` and issuer scope are
/// operation fields, not `VersionId` fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RefVersionRealm {
    tenant_id: Uuid,
    repository_id: Uuid,
    history_incarnation: Uuid,
    authority_kind: AuthorityKind,
    authority_epoch: i64,
    group_id: i64,
    group_epoch: i64,
    object_format: GitObjectFormat,
}

impl RefVersionRealm {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        tenant_id: Uuid,
        repository_id: Uuid,
        history_incarnation: Uuid,
        authority_kind: AuthorityKind,
        authority_epoch: i64,
        group_id: i64,
        group_epoch: i64,
        object_format: GitObjectFormat,
    ) -> Self {
        Self {
            tenant_id,
            repository_id,
            history_incarnation,
            authority_kind,
            authority_epoch,
            group_id,
            group_epoch,
            object_format,
        }
    }

    pub(crate) fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    pub(crate) fn repository_id(&self) -> Uuid {
        self.repository_id
    }

    pub(crate) fn history_incarnation(&self) -> Uuid {
        self.history_incarnation
    }

    pub(crate) fn authority_kind(&self) -> AuthorityKind {
        self.authority_kind
    }

    pub(crate) fn authority_epoch(&self) -> i64 {
        self.authority_epoch
    }

    pub(crate) fn group_id(&self) -> i64 {
        self.group_id
    }

    pub(crate) fn group_epoch(&self) -> i64 {
        self.group_epoch
    }

    pub(crate) fn object_format(&self) -> GitObjectFormat {
        self.object_format
    }
}

/// One ref entry in the original request order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RefVersionIntent {
    name: RefName,
    kind: RefVersionKind,
    precondition: RefPrecondition,
    base: BaseRequestSelector,
    target: RefTarget,
}

impl RefVersionIntent {
    pub(crate) fn new(
        name: RefName,
        kind: RefVersionKind,
        precondition: RefPrecondition,
        base: BaseRequestSelector,
        target: RefTarget,
    ) -> Self {
        Self { name, kind, precondition, base, target }
    }

    pub(crate) fn name(&self) -> &RefName {
        &self.name
    }

    pub(crate) fn kind(&self) -> RefVersionKind {
        self.kind
    }

    pub(crate) fn precondition(&self) -> &RefPrecondition {
        &self.precondition
    }

    pub(crate) fn base(&self) -> &BaseRequestSelector {
        &self.base
    }

    pub(crate) fn target(&self) -> &RefTarget {
        &self.target
    }
}

/// Complete prospective mutation preimage. `refs` stay in original request
/// order; `packs` are canonically sorted by the codec. There is deliberately no
/// ref generation field: generation comes from the authority's base version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OperationDigestInput {
    realm: RefVersionRealm,
    owner_id: Uuid,
    issuer_id: Uuid,
    lane: IssuerLane,
    issuer_sequence: i64,
    operation_id: Uuid,
    expected_gate_revision: i64,
    expected_gate_digest: RequestDigest,
    commit_mode: CommitMode,
    head: HeadUpdate,
    refs: Vec<RefVersionIntent>,
    old_membership_digest: RequestDigest,
    packs: Vec<PlannedPack>,
}

impl OperationDigestInput {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        realm: RefVersionRealm,
        owner_id: Uuid,
        issuer_id: Uuid,
        lane: IssuerLane,
        issuer_sequence: i64,
        operation_id: Uuid,
        expected_gate_revision: i64,
        expected_gate_digest: RequestDigest,
        commit_mode: CommitMode,
        head: HeadUpdate,
        refs: Vec<RefVersionIntent>,
        old_membership_digest: RequestDigest,
        packs: Vec<PlannedPack>,
    ) -> Self {
        Self {
            realm,
            owner_id,
            issuer_id,
            lane,
            issuer_sequence,
            operation_id,
            expected_gate_revision,
            expected_gate_digest,
            commit_mode,
            head,
            refs,
            old_membership_digest,
            packs,
        }
    }

    pub(crate) fn realm(&self) -> &RefVersionRealm {
        &self.realm
    }

    pub(crate) fn owner_id(&self) -> Uuid {
        self.owner_id
    }

    pub(crate) fn issuer_id(&self) -> Uuid {
        self.issuer_id
    }

    pub(crate) fn lane(&self) -> &IssuerLane {
        &self.lane
    }

    pub(crate) fn issuer_sequence(&self) -> i64 {
        self.issuer_sequence
    }

    pub(crate) fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    pub(crate) fn expected_gate_revision(&self) -> i64 {
        self.expected_gate_revision
    }

    pub(crate) fn expected_gate_digest(&self) -> &RequestDigest {
        &self.expected_gate_digest
    }

    pub(crate) fn commit_mode(&self) -> CommitMode {
        self.commit_mode
    }

    pub(crate) fn head(&self) -> &HeadUpdate {
        &self.head
    }

    pub(crate) fn refs(&self) -> &[RefVersionIntent] {
        &self.refs
    }

    pub(crate) fn old_membership_digest(&self) -> &RequestDigest {
        &self.old_membership_digest
    }

    pub(crate) fn packs(&self) -> &[PlannedPack] {
        &self.packs
    }
}

/// Opaque canonical operation digest. The only constructor is the hash result
/// inside [`super::digest::operation_digest`].
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct OperationDigest([u8; 32]);

impl OperationDigest {
    pub(super) const fn from_canonical_hash(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(super) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for OperationDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "OperationDigest({})", hex::encode(self.0))
    }
}

/// Opaque candidate ref-version id. A value is not a registered version and is
/// not a retention, authorization or commit capability.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct VersionId([u8; 32]);

impl VersionId {
    pub(super) const fn from_canonical_hash(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw bytes for an internal preimage. This is still not a capability.
    pub(super) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(test)]
    pub(super) const fn from_test_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[cfg(test)]
    pub(crate) fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for VersionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "VersionId({})", hex::encode(self.0))
    }
}

/// Typed codec refusal. Variants carry only fixed field names/reasons, never
/// caller bytes, paths or credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RefVersionCodecError {
    NilIdentifier { field: &'static str },
    NegativeCounter { field: &'static str },
    ZeroCounter { field: &'static str },
    EmptyRefList,
    Capacity { field: &'static str, limit: usize, actual: usize },
    DuplicateRefName,
    DuplicatePackIdentity,
    ObjectFormatMismatch { field: &'static str },
    InvalidRequestShape { reason: &'static str },
    InvalidContentDigest,
    LengthOverflow { field: &'static str },
    NoMintForLegacyBase,
    MissingAuthorityBaseGeneration,
    UnexpectedAuthorityBaseGeneration,
    ZeroAuthorityBaseGeneration,
    GenerationOverflow,
}

impl fmt::Display for RefVersionCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NilIdentifier { field } => write!(formatter, "{field} must be non-nil"),
            Self::NegativeCounter { field } => write!(formatter, "{field} must not be negative"),
            Self::ZeroCounter { field } => write!(formatter, "{field} must be positive"),
            Self::EmptyRefList => formatter.write_str("an operation must contain at least one ref"),
            Self::Capacity { field, limit, actual } => {
                write!(formatter, "{field} exceeds its bound: {actual} > {limit}")
            }
            Self::DuplicateRefName => formatter.write_str("an operation must not repeat a ref name"),
            Self::DuplicatePackIdentity => formatter.write_str("an operation must not repeat a pack identity pair"),
            Self::ObjectFormatMismatch { field } => {
                write!(formatter, "{field} does not match the realm object format")
            }
            Self::InvalidRequestShape { reason } => write!(formatter, "invalid request shape: {reason}"),
            Self::InvalidContentDigest => formatter.write_str("planned content digest is not a sha256 digest"),
            Self::LengthOverflow { field } => write!(formatter, "{field} length cannot be encoded"),
            Self::NoMintForLegacyBase => {
                formatter.write_str("a legacy base selector cannot mint a candidate version id")
            }
            Self::MissingAuthorityBaseGeneration => {
                formatter.write_str("a present base requires an authority base generation")
            }
            Self::UnexpectedAuthorityBaseGeneration => {
                formatter.write_str("an explicit absent base must not carry an authority base generation")
            }
            Self::ZeroAuthorityBaseGeneration => formatter.write_str("an authority base generation must be positive"),
            Self::GenerationOverflow => formatter.write_str("the candidate ref generation overflowed"),
        }
    }
}

impl std::error::Error for RefVersionCodecError {}
