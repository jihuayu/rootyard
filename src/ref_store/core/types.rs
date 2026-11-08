//! Typed Git ref names, object ids, CAS expectations and HEAD rules.
//!
//! These types do not perform IO and never silently reinterpret the zero object
//! id: the wire form is converted explicitly into `Absent`/`Delete`, while a
//! live `GitOid` can never be all zeros.
use super::super::contract::RefStoreError;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, str::FromStr};

pub const MAX_REFS_PER_COMMIT: usize = 128;
const MIN_REF_BYTES: usize = 6;
const MAX_REF_BYTES: usize = 1024;
const BRANCH_PREFIX: &str = "refs/heads/";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitObjectFormat {
    Sha1,
    Sha256,
}

impl GitObjectFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    pub fn oid_hex_len(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }

    pub fn parse(value: &str) -> Result<Self, RefStoreError> {
        match value {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            _ => Err(RefStoreError::InvalidIdentity("object format must be sha1 or sha256".into())),
        }
    }
}

impl fmt::Display for GitObjectFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A non-zero SHA-1 or SHA-256 object id in lowercase hex.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GitOid {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}

impl GitOid {
    pub fn parse(format: GitObjectFormat, value: &str) -> Result<Self, RefStoreError> {
        if value.len() != format.oid_hex_len()
            || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(RefStoreError::InvalidIdentity(format!(
                "object id must be lowercase {} hex",
                format.as_str()
            )));
        }
        let bytes = hex::decode(value).map_err(|_| RefStoreError::InvalidIdentity("invalid object id hex".into()))?;
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(RefStoreError::InvalidIdentity("a live object id must not be the zero id".into()));
        }
        match format {
            GitObjectFormat::Sha1 => Ok(Self::Sha1(
                bytes.try_into().map_err(|_| RefStoreError::InvalidIdentity("invalid sha1 length".into()))?,
            )),
            GitObjectFormat::Sha256 => Ok(Self::Sha256(
                bytes.try_into().map_err(|_| RefStoreError::InvalidIdentity("invalid sha256 length".into()))?,
            )),
        }
    }

    /// Convert the Git `new` value: an all-zero id means deletion, anything
    /// else must be a real object id of exactly the gate's object format.
    pub fn target_value(format: GitObjectFormat, value: &str) -> Result<RefTarget, RefStoreError> {
        if value.len() == format.oid_hex_len() && value.bytes().all(|byte| byte == b'0') {
            return Ok(RefTarget::Delete);
        }
        Ok(RefTarget::Oid(Self::parse(format, value)?))
    }

    /// Convert the Git `old` value: an all-zero id means the ref must be absent.
    pub fn precondition_value(format: GitObjectFormat, value: &str) -> Result<RefPrecondition, RefStoreError> {
        if value.len() == format.oid_hex_len() && value.bytes().all(|byte| byte == b'0') {
            return Ok(RefPrecondition::Absent);
        }
        Ok(RefPrecondition::Present(Self::parse(format, value)?))
    }

    pub fn format(self) -> GitObjectFormat {
        match self {
            Self::Sha1(_) => GitObjectFormat::Sha1,
            Self::Sha256(_) => GitObjectFormat::Sha256,
        }
    }

    pub fn as_hex(self) -> String {
        match self {
            Self::Sha1(bytes) => hex::encode(bytes),
            Self::Sha256(bytes) => hex::encode(bytes),
        }
    }
}

impl fmt::Display for GitOid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_hex())
    }
}

/// A validated, repository-relative Git ref name.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RefName(String);

impl RefName {
    pub fn new(value: impl Into<String>) -> Result<Self, RefStoreError> {
        let value = value.into();
        if !valid_ref_name(&value) {
            return Err(RefStoreError::InvalidIdentity(format!("invalid ref name: {value:?}")));
        }
        Ok(Self(value))
    }

    /// HEAD may only point at a branch, never a tag or an arbitrary ref.
    pub fn branch(value: impl Into<String>) -> Result<Self, RefStoreError> {
        let name = Self::new(value)?;
        if !name.is_branch() {
            return Err(RefStoreError::InvalidIdentity("HEAD must name a refs/heads/ branch".into()));
        }
        Ok(name)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_branch(&self) -> bool {
        self.0.starts_with(BRANCH_PREFIX) && self.0.len() > BRANCH_PREFIX.len()
    }
}

impl fmt::Display for RefName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for RefName {
    type Err = RefStoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

fn valid_ref_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < MIN_REF_BYTES || bytes.len() > MAX_REF_BYTES || !value.starts_with("refs/") {
        return false;
    }
    if value.ends_with('/') || value.ends_with('.') || value.contains("//") || value.contains("..") {
        return false;
    }
    if value.contains("@{") || value.chars().any(|character| character.is_control()) {
        return false;
    }
    if value.bytes().any(|byte| matches!(byte, b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\' | 0x7f)) {
        return false;
    }
    value.split('/').all(|component| {
        !component.is_empty() && !component.starts_with('.') && !component.ends_with(".lock")
    })
}

/// Strict ancestor relationship used for `foo` vs `foo/bar` conflicts.
pub(crate) fn is_strict_prefix(ancestor: &str, descendant: &str) -> bool {
    descendant.len() > ancestor.len()
        && descendant.starts_with(ancestor)
        && descendant.as_bytes().get(ancestor.len()) == Some(&b'/')
}

/// Deterministic first conflict between two batch names, if any.
pub(crate) fn batch_prefix_conflict(refs: &[RefUpdate]) -> Option<(String, String)> {
    for (index, left) in refs.iter().enumerate() {
        for right in &refs[index + 1..] {
            let left_name = left.name().as_str();
            let right_name = right.name().as_str();
            if is_strict_prefix(left_name, right_name) {
                return Some((left_name.to_owned(), right_name.to_owned()));
            }
            if is_strict_prefix(right_name, left_name) {
                return Some((right_name.to_owned(), left_name.to_owned()));
            }
        }
    }
    None
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefPrecondition {
    /// The ref must not exist (or its old value was the zero object id).
    Absent,
    /// The current ref must equal this exact old object id.
    Present(GitOid),
}

impl RefPrecondition {
    pub fn from_old_oid(format: GitObjectFormat, value: &str) -> Result<Self, RefStoreError> {
        GitOid::precondition_value(format, value)
    }

    pub(crate) fn canonical_tag(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Present(_) => "present",
        }
    }

    pub(crate) fn oid(&self) -> Option<GitOid> {
        match self {
            Self::Absent => None,
            Self::Present(oid) => Some(*oid),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefTarget {
    Oid(GitOid),
    /// Delete the ref. The all-zero object id is never stored as a live value.
    Delete,
}

impl RefTarget {
    pub fn from_new_oid(format: GitObjectFormat, value: &str) -> Result<Self, RefStoreError> {
        GitOid::target_value(format, value)
    }

    pub(crate) fn canonical_tag(&self) -> &'static str {
        match self {
            Self::Oid(_) => "oid",
            Self::Delete => "delete",
        }
    }

    pub(crate) fn oid(&self) -> Option<GitOid> {
        match self {
            Self::Oid(oid) => Some(*oid),
            Self::Delete => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefUpdate {
    name: RefName,
    precondition: RefPrecondition,
    target: RefTarget,
}

impl RefUpdate {
    pub fn new(name: RefName, precondition: RefPrecondition, target: RefTarget) -> Self {
        Self { name, precondition, target }
    }

    pub fn name(&self) -> &RefName {
        &self.name
    }

    pub fn precondition(&self) -> &RefPrecondition {
        &self.precondition
    }

    pub fn target(&self) -> &RefTarget {
        &self.target
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeadUpdate {
    Keep,
    Retarget(RefName),
}

impl HeadUpdate {
    pub fn retarget(value: impl Into<String>) -> Result<Self, RefStoreError> {
        Ok(Self::Retarget(RefName::branch(value)?))
    }
}

/// Resolve the HEAD value after the batch. A rejected result means no ref or
/// gate row may be written; the caller records the terminal rejection only.
pub(crate) fn resolve_head(
    current_head: &str,
    existing: &BTreeMap<String, String>,
    refs: &[RefUpdate],
    head: &HeadUpdate,
) -> Result<String, (super::contract::CommitRejectCode, Option<String>)> {
    use super::contract::CommitRejectCode;
    let final_oid = |name: &str| -> Option<String> {
        if let Some(update) = refs.iter().find(|update| update.name().as_str() == name) {
            return update.target().oid().map(|oid| oid.as_hex());
        }
        existing.get(name).cloned()
    };
    match head {
        HeadUpdate::Keep => {
            if refs
                .iter()
                .any(|update| update.name().as_str() == current_head && update.target() == &RefTarget::Delete)
            {
                return Err((CommitRejectCode::HeadDeletedWithoutRetarget, Some(current_head.to_owned())));
            }
            Ok(current_head.to_owned())
        }
        HeadUpdate::Retarget(target) => {
            if final_oid(target.as_str()).is_none() {
                return Err((CommitRejectCode::HeadTargetMissing, Some(target.as_str().to_owned())));
            }
            Ok(target.as_str().to_owned())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(format: GitObjectFormat, byte: u8) -> GitOid {
        match format {
            GitObjectFormat::Sha1 => GitOid::Sha1([byte; 20]),
            GitObjectFormat::Sha256 => GitOid::Sha256([byte; 32]),
        }
    }

    #[test]
    fn object_ids_are_format_exact_and_zero_is_not_a_live_id() {
        assert!(GitOid::parse(GitObjectFormat::Sha1, &"a".repeat(40)).is_ok());
        assert!(GitOid::parse(GitObjectFormat::Sha256, &"a".repeat(64)).is_ok());
        assert!(GitOid::parse(GitObjectFormat::Sha1, &"a".repeat(64)).is_err());
        assert!(GitOid::parse(GitObjectFormat::Sha256, &"a".repeat(40)).is_err());
        assert!(GitOid::parse(GitObjectFormat::Sha1, &"A".repeat(40)).is_err());
        assert!(GitOid::parse(GitObjectFormat::Sha1, &"0".repeat(40)).is_err());
        assert_eq!(
            GitOid::target_value(GitObjectFormat::Sha1, &"0".repeat(40)).unwrap(),
            RefTarget::Delete
        );
        assert_eq!(
            GitOid::precondition_value(GitObjectFormat::Sha256, &"0".repeat(64)).unwrap(),
            RefPrecondition::Absent
        );
        assert_eq!(oid(GitObjectFormat::Sha1, 7).to_string(), "07".repeat(20));
    }

    #[test]
    fn ref_names_enforce_git_safe_components() {
        for good in ["refs/heads/main", "refs/tags/v1.0", "refs/heads/a_b", "refs/heads/feature/x"] {
            assert!(RefName::new(good).is_ok(), "{good}");
        }
        for bad in [
            "HEAD",
            "refs/",
            "refs//x",
            "refs/heads/",
            "refs/heads/x/",
            "refs/heads/x.lock",
            "refs/heads/.x",
            "refs/heads/x..y",
            "refs/heads/x y",
            "refs/heads/x~y",
            "refs/heads/x@ {y}",
            "refs/heads/x@{1}",
            "refs/heads/x\\y",
            "refs/heads/x.",
            "refs/heads/x\n",
        ] {
            assert!(RefName::new(bad).is_err(), "{bad:?}");
        }
        assert!(RefName::new(format!("refs/heads/{}", "x".repeat(1024))).is_err());
        assert!(RefName::branch("refs/tags/v1").is_err());
        assert!(RefName::branch("refs/heads/unborn").is_ok());
    }

    #[test]
    fn prefix_conflicts_are_strict_and_bidirectional() {
        let name = |value: &str| RefName::new(value).unwrap();
        let target = |byte| RefTarget::Oid(oid(GitObjectFormat::Sha1, byte));
        let batch = vec![
            RefUpdate::new(name("refs/heads/topic"), RefPrecondition::Absent, target(1)),
            RefUpdate::new(name("refs/heads/topic/sub"), RefPrecondition::Absent, target(2)),
        ];
        assert_eq!(
            batch_prefix_conflict(&batch),
            Some(("refs/heads/topic".into(), "refs/heads/topic/sub".into()))
        );
        assert!(is_strict_prefix("refs/heads/a", "refs/heads/a/b"));
        assert!(!is_strict_prefix("refs/heads/a", "refs/heads/ab"));
        assert!(!is_strict_prefix("refs/heads/a/b", "refs/heads/a"));
    }

    #[test]
    fn head_resolution_rejects_ambiguous_deletion_and_missing_retarget() {
        let name = |value: &str| RefName::new(value).unwrap();
        let target = |byte| RefTarget::Oid(oid(GitObjectFormat::Sha1, byte));
        let mut existing = BTreeMap::new();
        existing.insert("refs/heads/main".into(), oid(GitObjectFormat::Sha1, 1).as_hex());
        existing.insert("refs/heads/next".into(), oid(GitObjectFormat::Sha1, 2).as_hex());

        let delete_main = vec![RefUpdate::new(
            name("refs/heads/main"),
            RefPrecondition::Present(oid(GitObjectFormat::Sha1, 1)),
            RefTarget::Delete,
        )];
        assert_eq!(
            resolve_head("refs/heads/main", &existing, &delete_main, &HeadUpdate::Keep),
            Err((super::super::contract::CommitRejectCode::HeadDeletedWithoutRetarget, Some("refs/heads/main".into())))
        );
        assert_eq!(
            resolve_head(
                "refs/heads/main",
                &existing,
                &delete_main,
                &HeadUpdate::Retarget(name("refs/heads/next"))
            )
            .unwrap(),
            "refs/heads/next"
        );
        assert_eq!(
            resolve_head(
                "refs/heads/main",
                &existing,
                &delete_main,
                &HeadUpdate::Retarget(name("refs/heads/unborn"))
            ),
            Err((super::super::contract::CommitRejectCode::HeadTargetMissing, Some("refs/heads/unborn".into())))
        );
        let delete_next = vec![RefUpdate::new(
            name("refs/heads/next"),
            RefPrecondition::Present(oid(GitObjectFormat::Sha1, 2)),
            RefTarget::Delete,
        )];
        assert_eq!(
            resolve_head(
                "refs/heads/main",
                &existing,
                &delete_next,
                &HeadUpdate::Retarget(name("refs/heads/next"))
            ),
            Err((super::super::contract::CommitRejectCode::HeadTargetMissing, Some("refs/heads/next".into())))
        );
    }
}
