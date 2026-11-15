//! Unit tests for inline PR review comment anchor normalization, line counting, and strict serde parsing.

use super::{NewPullReviewComment, ReviewCommentListQuery, count_lines, normalize_diff_anchor};
use crate::pulls::review_comment_actions::PatchPullReviewComment;

#[test]
fn diff_anchor_normalization_enforces_paths_sides_and_line_bounds() {
    let (p, s, l) = normalize_diff_anchor("src/lib.rs", "right", 42).unwrap();
    assert_eq!(p, "src/lib.rs");
    assert_eq!(s, "right");
    assert_eq!(l, 42);

    let (p2, s2, l2) = normalize_diff_anchor("README.md", "left", 1).unwrap();
    assert_eq!(p2, "README.md");
    assert_eq!(s2, "left");
    assert_eq!(l2, 1);

    for (path, side, line) in [
        ("", "right", 1),
        ("../secret.txt", "right", 1),
        (".git/config", "right", 1),
        ("/abs/file.rs", "right", 1),
        ("src/lib.rs", "center", 1),
        ("src/lib.rs", "RIGHT", 1),
        ("src/lib.rs", "right", 0),
        ("src/lib.rs", "left", -5),
        ("src/lib.rs", "right", 10_000_001),
    ] {
        assert!(
            normalize_diff_anchor(path, side, line).is_err(),
            "expected anchor rejection for ({path:?}, {side:?}, {line})"
        );
    }
}

#[test]
fn blob_line_counter_handles_empty_trailing_and_missing_final_newlines() {
    assert_eq!(count_lines(b""), 0);
    assert_eq!(count_lines(b"single line"), 1);
    assert_eq!(count_lines(b"single line\n"), 1);
    assert_eq!(count_lines(b"one\ntwo"), 2);
    assert_eq!(count_lines(b"one\ntwo\n"), 2);
    assert_eq!(count_lines(b"\n\n"), 2);
}

#[test]
fn review_comment_inputs_enforce_deny_unknown_fields() {
    let valid_new = r#"{"path":"src/main.rs","side":"right","line":3,"body":"Check bounds"}"#;
    assert!(serde_json::from_str::<NewPullReviewComment>(valid_new).is_ok());

    let bad_new = r#"{"path":"src/main.rs","side":"right","line":3,"body":"Check bounds","extra":1}"#;
    assert!(serde_json::from_str::<NewPullReviewComment>(bad_new).is_err());

    let valid_patch = r#"{"expected_version":2,"body":"Updated note"}"#;
    assert!(serde_json::from_str::<PatchPullReviewComment>(valid_patch).is_ok());

    let bad_patch = r#"{"expected_version":2,"body":"Updated note","unknown":true}"#;
    assert!(serde_json::from_str::<PatchPullReviewComment>(bad_patch).is_err());

    assert!(serde_json::from_str::<ReviewCommentListQuery>(r#"{"outdated":true}"#).is_ok());
    assert!(serde_json::from_str::<ReviewCommentListQuery>(r#"{"outdated":true,"x":1}"#).is_err());

    let bad_rc = r#"{"repository_id":"00000000-0000-0000-0000-000000000000","pull_number":1,"number":1,"review_number":null,"in_reply_to_number":null,"author_id":"00000000-0000-0000-0000-000000000000","commit_oid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","base_oid":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","pull_version":1,"outdated":false,"path":"a.rs","side":"right","line":1,"body":"ok","version":1,"moderation_state":"visible","edited_at":null,"deleted_at":null,"moderation_reason":"","created_at":"2026-11-15T00:00:00Z","updated_at":"2026-11-15T00:00:00Z","extra":1}"#;
    assert!(serde_json::from_str::<super::PullReviewComment>(bad_rc).is_err());
}
