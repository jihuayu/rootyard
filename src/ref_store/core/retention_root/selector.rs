//! Exact root selectors: the whole captured snapshot or an explicit bounded OID set.
//!
//! The default selector is *derived from the sealed source snapshot* (the object ids of every captured ref
//! plus HEAD). The explicit selector lets a caller retain older objects that are not currently referenced by a
//! branch (for example a commit that still lives in one of the registered packs). Both forms are validated
//! strictly: non-empty, unique, lowercase hex of exactly the gate object-format width, never the
//! all-zero object id. No prefix/short OID is ever accepted.
//! Explicit selectors allow at most 256 OIDs; a whole snapshot retains the existing 4096-ref bound.
//!
//! Native closure is proven with **synthetic non-branch refs** (`refs/roots/oid/<oid>`) for every selected
//! object id that is not already an object id of a captured ref. Those names are non-branch, so a Blob/tree/tag
//! root object can never be mistaken for a branch commit (`refs/heads/*` requires a commit). HEAD itself is
//! passed through exactly: a captured HEAD object id, or unborn HEAD when the source snapshot had none.
use super::error::RootError;
use super::usage::MAX_ROOT_OIDS;
use crate::ref_store::contract::RefStoreError;
use crate::ref_store::core::pack_commit::{CapturedRef, VERIFIER_MAX_RESULT_REFS};
use crate::ref_store::core::types::{GitObjectFormat, GitOid, RefName};
use std::collections::{BTreeMap, BTreeSet};

/// Synthetic non-branch ref namespace used only inside the verifier workspace.
pub(super) const SYNTHETIC_ROOT_REF_PREFIX: &str = "refs/roots/oid/";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stored_selector_is_bounded_sorted_unique_and_canonical() {
        let format = GitObjectFormat::Sha1;
        let refs = [("a".repeat(40)), ("b".repeat(40))]
            .iter()
            .enumerate()
            .map(|(index, oid)| {
                CapturedRef::new(
                    RefName::new(format!("refs/tags/t{index}")).unwrap(),
                    GitOid::parse(format, oid).unwrap(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let head = "c".repeat(40);
        let snapshot = RootSelector::from_kind(RootSelectorKind::Snapshot, Vec::new());
        assert_eq!(
            resolve_oids(&snapshot, format, &refs, Some(&head)).unwrap(),
            ["a".repeat(40), "b".repeat(40), head.clone()]
        );
        // A stored explicit capture must be rejected for exactly what it holds: each case builds its own
        // selector from the stored rows, so an empty selector can never stand in for the real one.
        for (stored, head) in [
            (vec!["b".repeat(40), "a".repeat(40)], None),
            (vec!["a".repeat(40), "a".repeat(40)], None),
            (vec!["A".repeat(40)], None),
            (vec!["a".repeat(38)], None),
            (vec!["0".repeat(40)], None),
            (Vec::new(), None),
        ] {
            let explicit = RootSelector::from_kind(RootSelectorKind::Oids, stored.clone());
            assert_eq!(explicit.kind(), RootSelectorKind::Oids);
            assert!(resolve_oids(&explicit, format, &refs, head).is_err(), "{stored:?}");
        }
        // A non-empty explicit capture resolves to its own canonical sorted, unique set.
        let explicit = RootSelector::from_kind(RootSelectorKind::Oids, vec!["b".repeat(40), "a".repeat(40)]);
        assert_eq!(resolve_oids(&explicit, format, &refs, None).unwrap(), ["a".repeat(40), "b".repeat(40)]);
    }

    #[test]
    fn a_whole_snapshot_does_not_inherit_the_explicit_oid_limit() {
        let refs = (1u32..=300)
            .map(|index| {
                let mut bytes = [0u8; 20];
                bytes[..4].copy_from_slice(&index.to_be_bytes());
                CapturedRef::new(RefName::new(format!("refs/heads/branch-{index}")).unwrap(), GitOid::Sha1(bytes))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let whole = resolve_oids(&RootSelector::Snapshot, GitObjectFormat::Sha1, &refs, None).unwrap();
        assert_eq!(whole.len(), 300);
        assert!(resolve_oids(&RootSelector::ObjectIds(whole), GitObjectFormat::Sha1, &refs, None).is_err());
    }
}

/// The caller's selector intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RootSelector {
    /// The whole captured snapshot: every captured ref and HEAD are the root selectors.
    Snapshot,
    /// Explicit object ids (may include an older, currently unreferenced commit in a registered pack).
    ObjectIds(Vec<String>),
}

/// Stored selector discriminator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootSelectorKind {
    Snapshot,
    Oids,
}

impl RootSelectorKind {
    pub(super) const fn max_oids(self) -> usize {
        match self {
            Self::Snapshot => VERIFIER_MAX_RESULT_REFS,
            Self::Oids => MAX_ROOT_OIDS,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Oids => "oids",
        }
    }

    pub fn parse(value: &str) -> Result<Self, RootError> {
        match value {
            "snapshot" => Ok(Self::Snapshot),
            "oids" => Ok(Self::Oids),
            _ => Err(RootError::Store(RefStoreError::Database(
                "stored root selector kind is not a bounded enum value".into(),
            ))),
        }
    }
}

impl RootSelector {
    /// The selector that a stored discriminator names: the whole captured snapshot, or the
    /// explicit oid set held by the same capture.
    pub(super) fn from_kind(kind: RootSelectorKind, stored_oids: Vec<String>) -> Self {
        match kind {
            RootSelectorKind::Snapshot => Self::Snapshot,
            RootSelectorKind::Oids => Self::ObjectIds(stored_oids),
        }
    }

    pub fn kind(&self) -> RootSelectorKind {
        match self {
            Self::Snapshot => RootSelectorKind::Snapshot,
            Self::ObjectIds(_) => RootSelectorKind::Oids,
        }
    }
}

/// Validate one explicit object id and return its canonical (already lowercase) form.
fn validate_oid(format: GitObjectFormat, oid: &str, ordinal: usize) -> Result<String, RootError> {
    if oid.len() != format.oid_hex_len() {
        return Err(RootError::RootSelectorInvalid(format!(
            "object id at ordinal {ordinal} must be exactly {} lowercase hex characters",
            format.oid_hex_len()
        )));
    }
    let parsed = GitOid::parse(format, oid).map_err(|_| {
        RootError::RootSelectorInvalid(format!("object id at ordinal {ordinal} is not canonical lowercase hex"))
    })?;
    Ok(parsed.as_hex())
}

/// Resolve the final, sorted, unique selector object ids for this capture.
///
/// `refs` is the sealed captured ref set (already canonical and sorted). The returned vector is the exact
/// ordered selector set that is stored in `ref_store_core_root_oids` and proven natively.
pub(super) fn resolve_oids(
    selector: &RootSelector,
    format: GitObjectFormat,
    refs: &[CapturedRef],
    head_oid: Option<&str>,
) -> Result<Vec<String>, RootError> {
    let mut oids = match selector {
        RootSelector::Snapshot => {
            // Whole captured snapshot: every ref target plus the captured HEAD object id (HEAD is normally one
            // of the refs already, but the set is built explicitly so an unusual HEAD can never be dropped).
            let mut set = BTreeSet::new();
            for reference in refs {
                set.insert(reference.oid_hex().to_owned());
            }
            if let Some(oid) = head_oid {
                set.insert(oid.to_owned());
            }
            set.into_iter().collect::<Vec<_>>()
        }
        RootSelector::ObjectIds(values) => {
            let mut seen = BTreeSet::new();
            let mut resolved = Vec::with_capacity(values.len());
            for (ordinal, value) in values.iter().enumerate() {
                let oid = validate_oid(format, value, ordinal)?;
                if !seen.insert(oid.clone()) {
                    return Err(RootError::RootSelectorInvalid(format!("object id at ordinal {ordinal} is repeated")));
                }
                resolved.push(oid);
            }
            resolved.sort();
            resolved
        }
    };
    if oids.is_empty() {
        return Err(RootError::RootSelectorInvalid("a root needs at least one selector object id".into()));
    }
    let limit = selector.kind().max_oids();
    if oids.len() > limit {
        return Err(RootError::RootSelectorInvalid(format!(
            "this root selector allows at most {limit} object ids, got {}",
            oids.len()
        )));
    }
    oids.sort();
    oids.dedup();
    Ok(oids)
}

/// Build the exact native ref map for a root: every captured ref plus one synthetic non-branch ref per
/// selected object id that is not already a captured ref value.
///
/// The result is deterministic (sorted by name) and is what both `prepare` and every later root byte read use,
/// so the sealed native binding digest is reproducible from stored rows alone.
pub(super) fn native_refs(
    format: GitObjectFormat,
    refs: &[CapturedRef],
    oids: &[String],
) -> Result<Vec<CapturedRef>, RootError> {
    let mut by_name = BTreeMap::new();
    let mut covered = BTreeSet::new();
    for reference in refs {
        covered.insert(reference.oid_hex().to_owned());
        by_name.insert(reference.name().to_owned(), reference.clone());
    }
    for (ordinal, oid) in oids.iter().enumerate() {
        // Re-validate every stored/derived object id against the gate object format so no untyped string can
        // reach the native request.
        let canonical = validate_oid(format, oid, ordinal)?;
        if covered.contains(&canonical) {
            continue;
        }
        let name = format!("{SYNTHETIC_ROOT_REF_PREFIX}{canonical}");
        if by_name.contains_key(&name) {
            return Err(RootError::RootSelectorInvalid(
                "a synthetic root ref name collides with a captured ref".into(),
            ));
        }
        let parsed_name = RefName::new(&name)
            .map_err(|_| RootError::RootSelectorInvalid("synthetic ref name is not canonical".into()))?;
        let parsed_oid = parse_stored_oid(&canonical)?;
        let reference = CapturedRef::new(parsed_name, parsed_oid)?;
        by_name.insert(reference.name().to_owned(), reference);
    }
    if by_name.len() > VERIFIER_MAX_RESULT_REFS {
        return Err(RootError::RootSelectorInvalid(
            "captured refs plus synthetic root refs exceed the native verifier ref bound".into(),
        ));
    }
    Ok(by_name.into_values().collect())
}

/// Parse a stored lowercase object id without assuming the object-format width here; the caller compares the
/// parsed hex length with the gate format before use.
pub(super) fn parse_stored_oid(oid: &str) -> Result<GitOid, RootError> {
    let format = if oid.len() == GitObjectFormat::Sha1.oid_hex_len() {
        GitObjectFormat::Sha1
    } else if oid.len() == GitObjectFormat::Sha256.oid_hex_len() {
        GitObjectFormat::Sha256
    } else {
        return Err(RootError::Store(RefStoreError::Database("stored root object id has an unsupported width".into())));
    };
    GitOid::parse(format, oid)
        .map_err(|_| RootError::Store(RefStoreError::Database("stored root object id is not canonical".into())))
}
