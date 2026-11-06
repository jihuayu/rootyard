use super::gitfs::{exported, parse_refs, plan_ref_mutations, valid_head};
use std::collections::BTreeMap;

fn oid(c: char) -> String {
    c.to_string().repeat(40)
}

#[test]
fn ref_parsing_rejects_reserved_and_malformed_refs() {
    let listing = format!("refs/heads/main {}\nrefs/tags/v1 {}\n", oid('a'), oid('b'));
    let refs = parse_refs(listing.as_bytes(), "sha1").unwrap();
    assert_eq!(refs.len(), 2);
    assert!(parse_refs(b"refs/rootyard-journal/x 0000000000000000000000000000000000000001\n", "sha1").is_err());
    assert!(parse_refs(b"refs/heads/main nothex\n", "sha1").is_err());
    assert!(parse_refs(b"refs/heads/main 0000000000000000000000000000000000000000\n", "sha1").is_err());
    assert!(parse_refs(b"refs/heads/main 0123456789012345678901234567890123456789", "sha1").is_err());
    assert!(
        parse_refs(
            b"refs/heads/main 0123456789012345678901234567890123456789\nrefs/heads/main 0123456789012345678901234567890123456789\n",
            "sha1"
        )
        .is_err()
    );
}

#[test]
fn exported_refs_cover_only_branches_and_tags() {
    assert!(exported("refs/heads/main"));
    assert!(exported("refs/tags/v1"));
    assert!(!exported("refs/rootyard-journal/abc"));
    assert!(!exported("refs/replace/abc"));
    assert!(!exported("refs/pull/1/head"));
    assert!(!exported("HEAD"));
}

#[test]
fn rollback_plan_keeps_internal_refs_and_removes_stale_authority_refs() {
    let mut current = BTreeMap::new();
    current.insert("refs/heads/main".to_string(), oid('a'));
    current.insert("refs/heads/stale".to_string(), oid('b'));
    current.insert("refs/tags/keep".to_string(), oid('c'));
    current.insert("refs/rootyard-journal/1".to_string(), oid('d'));
    let mut desired = BTreeMap::new();
    desired.insert("refs/heads/main".to_string(), oid('e'));
    desired.insert("refs/tags/keep".to_string(), oid('c'));
    let (updates, deletes) = plan_ref_mutations(&current, &desired);
    assert_eq!(updates, vec![("refs/heads/main".to_string(), oid('e'))]);
    assert_eq!(deletes, vec!["refs/heads/stale".to_string()]);
}

#[test]
fn head_must_be_an_authoritative_branch() {
    assert!(valid_head("refs/heads/main"));
    assert!(!valid_head("refs/tags/v1"));
    assert!(!valid_head("refs/heads/../escape"));
    assert!(!valid_head("refs/heads/bad name"));
}
