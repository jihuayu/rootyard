//! Independent recomputation of the exact resulting ref/HEAD state.
//!
//! The closure context already carries `resulting_refs()`/`resulting_head()`, but
//! the proof must not trust a caller-supplied result: the verifier recomputes the
//! whole map from the plan's CAS batch applied to the *captured old* refs and
//! refuses unless the context agrees. That makes "the proof binds the resulting
//! refs" independent of the code path that built the context.
//!
//! HEAD follows the context, never a new policy: `HeadUpdate::Keep` keeps the
//! captured HEAD branch, `HeadUpdate::Retarget` names a branch, and an unborn
//! HEAD (the branch is not in the resulting set) stays unborn. The verifier only
//! checks that the native repository reproduces exactly that state.
use super::refuse;
use crate::ref_store::core::pack_commit::context::CapturedRef;
use crate::ref_store::core::pack_commit::error::PackCommitError;
use crate::ref_store::core::pack_commit::plan::PackCommitPlan;
use crate::ref_store::core::types::{GitObjectFormat, GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget};
use std::collections::BTreeMap;

/// One ref row of the recomputed or natively observed result.
pub(super) type RefMap = BTreeMap<String, String>;

/// Refuse anything that is not a canonical core ref name with a format-exact
/// lowercase oid.
pub(super) fn validate_ref(name: &str, oid_hex: &str, format: GitObjectFormat) -> Result<(), PackCommitError> {
    RefName::new(name).map_err(|_| refuse("closure carries a non-canonical ref name"))?;
    if oid_hex.len() != format.oid_hex_len()
        || !oid_hex.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(refuse("closure carries a malformed object id"));
    }
    GitOid::parse(format, oid_hex).map_err(|_| refuse("closure carries a malformed object id"))?;
    Ok(())
}

/// Apply the plan's CAS batch to the captured old refs.
pub(super) fn resulting_refs(plan: &PackCommitPlan, old: &[CapturedRef]) -> Result<RefMap, PackCommitError> {
    let format = plan.object_format();
    let mut result = RefMap::new();
    for reference in old {
        validate_ref(reference.name(), reference.oid_hex(), format)?;
        if result.insert(reference.name().to_owned(), reference.oid_hex().to_owned()).is_some() {
            return Err(refuse("captured old ref set repeats a name"));
        }
    }
    for update in plan.refs() {
        let current = result.get(update.name().as_str()).cloned();
        let satisfied = match update.precondition() {
            RefPrecondition::Absent => current.is_none(),
            RefPrecondition::Present(expected) => current.as_deref() == Some(expected.as_hex().as_str()),
        };
        if !satisfied {
            return Err(refuse("captured old ref does not satisfy the planned precondition"));
        }
        match update.target() {
            RefTarget::Delete => {
                result.remove(update.name().as_str());
            }
            RefTarget::Oid(oid) => {
                result.insert(update.name().as_str().to_owned(), oid.as_hex());
            }
        }
    }
    Ok(result)
}

/// The exact HEAD the plan/context pair describes, plus its branch oid when the
/// branch exists in the resulting ref set (otherwise HEAD is unborn).
pub(super) fn head_state(
    plan: &PackCommitPlan,
    captured_head: &RefName,
    resulting: &RefMap,
) -> Result<(RefName, Option<String>), PackCommitError> {
    let head = match plan.head() {
        HeadUpdate::Keep => {
            let deletes_head = plan.refs().iter().any(|update| {
                update.name().as_str() == captured_head.as_str() && update.target() == &RefTarget::Delete
            });
            if deletes_head {
                return Err(refuse("planned batch deletes the kept HEAD branch"));
            }
            captured_head.clone()
        }
        HeadUpdate::Retarget(target) => target.clone(),
    };
    if !head.is_branch() {
        return Err(refuse("resulting HEAD is not a live branch name"));
    }
    let oid = resulting.get(head.as_str()).cloned();
    if let Some(oid) = &oid {
        validate_ref(head.as_str(), oid, plan.object_format())?;
    }
    Ok((head, oid))
}

/// Strict parser for `git for-each-ref --format=%(refname) %(objectname)`.
pub(super) fn parse_ref_listing(bytes: &[u8], format: GitObjectFormat) -> Result<RefMap, PackCommitError> {
    let text = std::str::from_utf8(bytes).map_err(|_| refuse("native ref listing is not valid text"))?;
    if !text.is_empty() && !text.ends_with('\n') {
        return Err(refuse("native ref listing is truncated"));
    }
    let mut refs = RefMap::new();
    for line in text.lines() {
        let (name, oid) = line.split_once(' ').ok_or_else(|| refuse("native ref listing is malformed"))?;
        if name.contains(' ') || oid.contains(' ') {
            return Err(refuse("native ref listing is malformed"));
        }
        validate_ref(name, oid, format)?;
        if refs.insert(name.to_owned(), oid.to_owned()).is_some() {
            return Err(refuse("native ref listing repeats a name"));
        }
    }
    Ok(refs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ref_validation_is_format_exact() {
        assert!(validate_ref("refs/heads/main", &"a".repeat(40), GitObjectFormat::Sha1).is_ok());
        assert!(validate_ref("refs/heads/main", &"a".repeat(64), GitObjectFormat::Sha256).is_ok());
        assert!(validate_ref("refs/heads/main", &"a".repeat(64), GitObjectFormat::Sha1).is_err());
        assert!(validate_ref("refs/heads/main", &"A".repeat(40), GitObjectFormat::Sha1).is_err());
        assert!(validate_ref("heads/main", &"a".repeat(40), GitObjectFormat::Sha1).is_err());
        assert!(validate_ref("refs/heads/a b", &"a".repeat(40), GitObjectFormat::Sha1).is_err());
    }

    #[test]
    fn ref_listing_parser_refuses_duplicates_and_truncation() {
        let oid = "a".repeat(40);
        let listing = format!("refs/heads/main {oid}\n");
        let parsed = parse_ref_listing(listing.as_bytes(), GitObjectFormat::Sha1).expect("listing");
        assert_eq!(parsed.get("refs/heads/main").map(String::as_str), Some(oid.as_str()));
        assert!(parse_ref_listing(&listing.as_bytes()[..listing.len() - 1], GitObjectFormat::Sha1).is_err());
        let doubled = format!("{listing}{listing}");
        assert!(parse_ref_listing(doubled.as_bytes(), GitObjectFormat::Sha1).is_err());
        assert!(parse_ref_listing(format!("refs/heads/main {oid} {oid}\n").as_bytes(), GitObjectFormat::Sha1).is_err());
    }
}
