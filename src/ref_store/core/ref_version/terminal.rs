//! Canonical immutable ACK / replay terminal `T` and `TerminalDigest` (§2.5 & §2.5.1).
use super::commit_set::{CommitSetId, CommitSetInput};
use super::contract::{OperationDigest, RefVersionCodecError, RefVersionRealm};
use super::digest::{
    CanonicalWriter, ensure_present_oid, format_tag, hash_sha256, push_oid, require_non_nil, validate_realm,
};
use super::limits::{MAX_COMMIT_SET_REFS, count_u32, positive_u64};
use super::reasons::CausalRejectCode;
use crate::ref_store::core::types::{GitOid, RefName};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use uuid::Uuid;

const TERMINAL_DOMAIN: &[u8] = b"ry-version-terminal-v1";

/// Terminal outcome kind encoded as one byte (`1 = committed`, `2 = rejected`, `3 = cancelled`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionTerminalKind {
    Committed,
    Rejected,
    Cancelled,
}

impl VersionTerminalKind {
    pub const fn tag(self) -> u8 {
        match self {
            Self::Committed => 1,
            Self::Rejected => 2,
            Self::Cancelled => 3,
        }
    }
}

/// Per-ref outcome inside a canonical terminal (`1 = applied`, `2 = not_applied`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionResultOutcome {
    Applied,
    NotApplied(CausalRejectCode),
}

impl VersionResultOutcome {
    pub const fn tag(self) -> u8 {
        match self {
            Self::Applied => 1,
            Self::NotApplied(_) => 2,
        }
    }
}

/// One per-ref terminal result entry (`§2.5.1`).
///
/// For `Applied`, `old_oid`/`new_oid` are exact resulting OIDs (absent iff created/deleted).
/// For `NotApplied`, `old_oid`/`new_oid` are the **frozen requested** precondition and target
/// from `OperationDigestInput`, never a post-rejection live observed OID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionResultEntry {
    ref_name: RefName,
    outcome: VersionResultOutcome,
    old_oid: Option<GitOid>,
    new_oid: Option<GitOid>,
}

impl VersionResultEntry {
    pub fn new(
        ref_name: RefName,
        outcome: VersionResultOutcome,
        old_oid: Option<GitOid>,
        new_oid: Option<GitOid>,
    ) -> Self {
        Self { ref_name, outcome, old_oid, new_oid }
    }

    pub fn ref_name(&self) -> &RefName {
        &self.ref_name
    }

    pub const fn outcome(&self) -> VersionResultOutcome {
        self.outcome
    }

    pub const fn old_oid(&self) -> Option<GitOid> {
        self.old_oid
    }

    pub const fn new_oid(&self) -> Option<GitOid> {
        self.new_oid
    }
}

/// Preimage input for `T` and `TerminalDigest = SHA-256(T)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionTerminalInput {
    pub realm: RefVersionRealm,
    pub authority_seq: i64,
    pub operation_id: Uuid,
    pub operation_digest: OperationDigest,
    pub terminal_kind: VersionTerminalKind,
    pub commit_set_id: Option<CommitSetId>,
    pub results: Vec<VersionResultEntry>,
}

/// Canonical SHA-256 over immutable terminal bytes `T` (§2.5).
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TerminalDigest([u8; 32]);

impl TerminalDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for TerminalDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "TerminalDigest({})", hex::encode(self.0))
    }
}

/// Validated canonical terminal bytes `T` alongside its SHA-256 digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedTerminal {
    bytes: Vec<u8>,
    digest: TerminalDigest,
}

impl EncodedTerminal {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn digest(&self) -> TerminalDigest {
        self.digest
    }
}

/// Encode `T` and compute `TerminalDigest`, enforcing every §2.5.1 & §2.5.2 invariant.
pub fn encode_terminal(input: &VersionTerminalInput) -> Result<EncodedTerminal, RefVersionCodecError> {
    let realm = &input.realm;
    let realm_numbers = validate_realm(realm)?;
    let authority_seq = positive_u64(input.authority_seq, "authority_seq")?;
    require_non_nil(input.operation_id, "operation_id")?;
    validate_terminal_shape(input)?;
    let mut names = BTreeSet::new();
    for entry in &input.results {
        if !names.insert(entry.ref_name().as_str()) {
            return Err(RefVersionCodecError::DuplicateRefName);
        }
        if let Some(old_oid) = entry.old_oid() {
            ensure_present_oid(realm.object_format(), old_oid, "old_oid")?;
        }
        if let Some(new_oid) = entry.new_oid() {
            ensure_present_oid(realm.object_format(), new_oid, "new_oid")?;
        }
    }
    let mut sorted: Vec<&VersionResultEntry> = input.results.iter().collect();
    sorted.sort_by(|left, right| left.ref_name().as_str().cmp(right.ref_name().as_str()));

    let mut writer = CanonicalWriter::new();
    writer.push_len_prefixed(TERMINAL_DOMAIN)?;
    match input.commit_set_id {
        None => writer.push_u8(0),
        Some(commit_set_id) => {
            writer.push_u8(1);
            writer.push_len_prefixed(commit_set_id.as_bytes())?;
        }
    }
    writer.push_len_prefixed(realm.tenant_id().as_bytes())?;
    writer.push_len_prefixed(realm.repository_id().as_bytes())?;
    writer.push_len_prefixed(realm.history_incarnation().as_bytes())?;
    writer.push_u8(realm.authority_kind().tag());
    writer.push_u64(realm_numbers.authority_epoch);
    writer.push_u64(realm_numbers.group_id);
    writer.push_u64(realm_numbers.group_epoch);
    writer.push_u8(format_tag(realm.object_format()));
    writer.push_u64(authority_seq);
    writer.push_len_prefixed(input.operation_id.as_bytes())?;
    writer.push_len_prefixed(input.operation_digest.as_bytes())?;
    writer.push_u8(input.terminal_kind.tag());
    writer.push_u32(count_u32(sorted.len(), "terminal_results")?);
    for entry in sorted {
        writer.push_len_prefixed(entry.ref_name().as_str().as_bytes())?;
        writer.push_u8(entry.outcome().tag());
        push_optional_oid(&mut writer, entry.old_oid())?;
        push_optional_oid(&mut writer, entry.new_oid())?;
        match entry.outcome() {
            VersionResultOutcome::Applied => writer.push_len_prefixed(b"")?,
            VersionResultOutcome::NotApplied(code) => writer.push_len_prefixed(code.as_str().as_bytes())?,
        }
    }
    let bytes = writer.into_bytes();
    let digest = TerminalDigest(hash_sha256(&bytes));
    Ok(EncodedTerminal { bytes, digest })
}

/// Encode `T` while additionally proving a `Committed` terminal's applied results
/// match the accompanying [`CommitSetInput`] ref set and targets (§2.5.1).
pub fn encode_terminal_with_commit_set(
    input: &VersionTerminalInput,
    commit_set: Option<&CommitSetInput>,
) -> Result<EncodedTerminal, RefVersionCodecError> {
    if input.terminal_kind == VersionTerminalKind::Committed {
        let Some(commit_set) = commit_set else {
            return Err(RefVersionCodecError::InvalidRequestShape {
                reason: "committed terminal requires a matching commit set",
            });
        };
        let cs_id = super::commit_set::compute_commit_set_id(commit_set)?;
        if input.commit_set_id != Some(cs_id) {
            return Err(RefVersionCodecError::InvalidRequestShape {
                reason: "terminal commit_set_id differs from computed CommitSetId",
            });
        }
        let expected: BTreeMap<&str, Option<GitOid>> =
            commit_set.versions().iter().map(|v| (v.ref_name().as_str(), v.target().oid())).collect();
        let applied: BTreeMap<&str, Option<GitOid>> = input
            .results
            .iter()
            .filter(|r| matches!(r.outcome(), VersionResultOutcome::Applied))
            .map(|r| (r.ref_name().as_str(), r.new_oid()))
            .collect();
        if expected != applied {
            return Err(RefVersionCodecError::InvalidRequestShape {
                reason: "committed terminal applied results must equal commit set entries and targets",
            });
        }
    } else if commit_set.is_some() {
        return Err(RefVersionCodecError::InvalidRequestShape {
            reason: "rejected or cancelled terminals must not include a commit set",
        });
    }
    encode_terminal(input)
}

fn validate_terminal_shape(input: &VersionTerminalInput) -> Result<(), RefVersionCodecError> {
    if input.results.len() > MAX_COMMIT_SET_REFS {
        return Err(RefVersionCodecError::Capacity {
            field: "terminal_results",
            limit: MAX_COMMIT_SET_REFS,
            actual: input.results.len(),
        });
    }
    let has_applied = input.results.iter().any(|entry| matches!(entry.outcome(), VersionResultOutcome::Applied));
    match input.terminal_kind {
        VersionTerminalKind::Committed => {
            if input.commit_set_id.is_none() {
                return Err(RefVersionCodecError::InvalidRequestShape {
                    reason: "committed terminal requires commit_set_id",
                });
            }
            if !has_applied {
                return Err(RefVersionCodecError::InvalidRequestShape {
                    reason: "committed terminal requires at least one applied result",
                });
            }
        }
        VersionTerminalKind::Rejected => {
            if input.commit_set_id.is_some() {
                return Err(RefVersionCodecError::InvalidRequestShape {
                    reason: "rejected terminal must omit commit_set_id",
                });
            }
            if input.results.is_empty() {
                return Err(RefVersionCodecError::EmptyRefList);
            }
            if has_applied {
                return Err(RefVersionCodecError::InvalidRequestShape {
                    reason: "rejected terminal must not carry applied results",
                });
            }
        }
        VersionTerminalKind::Cancelled => {
            if input.commit_set_id.is_some() {
                return Err(RefVersionCodecError::InvalidRequestShape {
                    reason: "cancelled terminal must omit commit_set_id",
                });
            }
            if !input.results.is_empty() {
                return Err(RefVersionCodecError::InvalidRequestShape {
                    reason: "cancelled terminal must have zero results",
                });
            }
        }
    }
    Ok(())
}

fn push_optional_oid(writer: &mut CanonicalWriter, oid: Option<GitOid>) -> Result<(), RefVersionCodecError> {
    match oid {
        None => {
            writer.push_u8(0);
            Ok(())
        }
        Some(value) => {
            writer.push_u8(1);
            push_oid(writer, value)
        }
    }
}
