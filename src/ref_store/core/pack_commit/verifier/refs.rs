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
use crate::ref_store::core::pack_commit::contract::VERIFIER_PIPE_BYTES;
use crate::ref_store::core::pack_commit::error::PackCommitError;
use crate::ref_store::core::pack_commit::plan::PackCommitPlan;
use crate::ref_store::core::types::{
    GitObjectFormat, GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget, RefUpdate,
};
use std::collections::BTreeMap;

/// One ref row of the recomputed or natively observed result.
pub(super) type RefMap = BTreeMap<String, String>;

/// Header of the one packed-refs file this verifier writes.
///
/// Only `sorted` is claimed. The verifier does not compute peeled tag rows, so it
/// must not claim `peeled`/`fully-peeled`: Git then peels a tag on demand instead
/// of trusting an absent or forged peeled record. `RefMap` is a `BTreeMap`, whose
/// iteration order is byte-lexicographic refname order, which is exactly the
/// ordering the `sorted` token promises.
const PACKED_REFS_HEADER: &str = "# pack-refs with: sorted\n";

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

/// Serialize the exact resulting ref map as Git's packed-refs format.
///
/// Every row goes through the same `RefName`/`GitOid` validation as the rest of
/// the verifier. Names containing a newline, carriage return or NUL are refused
/// explicitly as a second line-injection barrier behind `RefName`; names are then
/// emitted as one `oid SP refname LF` record. Because the map is sorted and
/// duplicate keys are impossible, the result is canonical.
///
/// Directories may be arbitrarily deep here; there is deliberately no
/// segment-count or path-length workaround. A packed ref set must still be a
/// legal Git namespace, so a directory/file conflict such as `refs/heads/a` plus
/// `refs/heads/a/b` is refused instead of writing a map that `update-ref` would
/// have rejected.
///
/// HEAD is intentionally absent: it is a symbolic ref outside `refs/` and is
/// written and attested separately by the view. The output size keeps the same
/// aggregate verifier input bound the previous stdin batch used.
pub(super) fn packed_refs_file(refs: &RefMap, format: GitObjectFormat) -> Result<Vec<u8>, PackCommitError> {
    let row_hint = format.oid_hex_len().saturating_add(3);
    let mut output = Vec::with_capacity(PACKED_REFS_HEADER.len().saturating_add(refs.len().saturating_mul(row_hint)));
    output.extend_from_slice(PACKED_REFS_HEADER.as_bytes());
    for (name, oid) in refs {
        validate_ref(name, oid, format)?;
        if name.bytes().any(|byte| matches!(byte, b'\n' | b'\r' | 0)) {
            return Err(refuse("closure carries a ref name that cannot be packed"));
        }
        for (index, _) in name.match_indices('/') {
            if refs.contains_key(&name[..index]) {
                return Err(refuse("resulting ref set contains a ref directory/file conflict"));
            }
        }
        output.extend_from_slice(oid.as_bytes());
        output.push(b' ');
        output.extend_from_slice(name.as_bytes());
        output.push(b'\n');
        if output.len() > VERIFIER_PIPE_BYTES {
            return Err(refuse("resulting packed refs exceed the verifier input bound"));
        }
    }
    Ok(output)
}

/// Apply exactly one update subset (the atomic batch or the accepted subset of an
/// accepted-subset plan) to the captured old refs.
pub(super) fn resulting_refs_for(
    plan: &PackCommitPlan,
    old: &[CapturedRef],
    updates: &[RefUpdate],
) -> Result<RefMap, PackCommitError> {
    let format = plan.object_format();
    let mut result = RefMap::new();
    for reference in old {
        validate_ref(reference.name(), reference.oid_hex(), format)?;
        if result.insert(reference.name().to_owned(), reference.oid_hex().to_owned()).is_some() {
            return Err(refuse("captured old ref set repeats a name"));
        }
    }
    for update in updates {
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

/// HEAD state for one update subset. A selected subset must never delete the kept
/// HEAD branch and a retarget target must already exist in the resulting map.
pub(super) fn head_state_with(
    plan: &PackCommitPlan,
    updates: &[RefUpdate],
    captured_head: &RefName,
    resulting: &RefMap,
) -> Result<(RefName, Option<String>), PackCommitError> {
    let head = match plan.head() {
        HeadUpdate::Keep => {
            let deletes_head = updates.iter().any(|update| {
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

    #[test]
    fn packed_refs_are_sorted_validated_and_do_not_claim_peeled_state() {
        let mut refs = RefMap::new();
        // Deliberately inserted out of order: the serialized file must be sorted.
        refs.insert("refs/tags/v1".into(), "a".repeat(40));
        refs.insert("refs/notes/commits".into(), "c".repeat(40));
        refs.insert("refs/heads/topic".into(), "b".repeat(40));
        let packed = packed_refs_file(&refs, GitObjectFormat::Sha1).expect("packed refs");
        let expected = format!(
            "{PACKED_REFS_HEADER}{} refs/heads/topic\n{} refs/notes/commits\n{} refs/tags/v1\n",
            "b".repeat(40),
            "c".repeat(40),
            "a".repeat(40)
        );
        assert_eq!(packed, expected.as_bytes());
        let text = std::str::from_utf8(&packed).expect("text");
        assert_eq!(text.lines().next(), Some("# pack-refs with: sorted"));
        assert!(!text.contains("peeled"), "no peeled claim without peeled rows");
        assert!(!text.lines().any(|line| line.contains("HEAD")), "HEAD is not a packed ref row");
    }

    #[test]
    fn deeply_nested_legal_refs_are_packed_without_a_segment_restriction() {
        let mut refs = RefMap::new();
        for index in 0..128 {
            let mut name = String::from("refs/heads");
            for segment in 0..16 {
                name.push_str(&format!("/s{index}-{segment}"));
            }
            assert!(name.len() <= 1024);
            refs.insert(name, format!("{:040x}", index + 1));
        }
        let packed = packed_refs_file(&refs, GitObjectFormat::Sha1).expect("deep refs");
        let text = std::str::from_utf8(&packed).expect("text");
        assert_eq!(text.lines().count(), 129, "one header plus every deep ref");
        assert_eq!(text.matches(" refs/heads/").count(), 128);
        let names =
            text.lines().skip(1).filter_map(|line| line.split_once(' ').map(|(_, name)| name)).collect::<Vec<_>>();
        assert_eq!(names.len(), 128);
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]), "packed ref rows are sorted");
    }

    #[test]
    fn packed_refs_refuse_newline_injection_and_directory_file_conflicts() {
        let oid = "a".repeat(40);
        let mut injected = RefMap::new();
        injected.insert("refs/heads/main\nrefs/heads/evil".into(), oid.clone());
        assert!(packed_refs_file(&injected, GitObjectFormat::Sha1).is_err());

        let mut carriage = RefMap::new();
        carriage.insert("refs/heads/main\rrefs/heads/evil".into(), oid.clone());
        assert!(packed_refs_file(&carriage, GitObjectFormat::Sha1).is_err());

        let mut conflict = RefMap::new();
        conflict.insert("refs/heads/topic".into(), oid.clone());
        conflict.insert("refs/heads/topic/sub".into(), oid.clone());
        assert!(packed_refs_file(&conflict, GitObjectFormat::Sha1).is_err());

        let mut legal = RefMap::new();
        legal.insert("refs/heads/topic".into(), oid.clone());
        legal.insert("refs/heads/topical".into(), oid);
        assert!(packed_refs_file(&legal, GitObjectFormat::Sha1).is_ok());
    }

    #[test]
    fn packed_refs_are_format_exact() {
        let mut refs = RefMap::new();
        refs.insert("refs/heads/main".into(), "a".repeat(64));
        assert!(packed_refs_file(&refs, GitObjectFormat::Sha1).is_err());
        assert!(packed_refs_file(&refs, GitObjectFormat::Sha256).is_ok());
    }
}
