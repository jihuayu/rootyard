//! Unit tests for Forge collaboration validation, normalization, search, and notification helpers.

use super::{
    assignees::{AssigneeSetInput, AssigneeVersionQuery},
    labels::{
        LabelAttachmentInput, LabelListQuery, LabelVersionQuery, NewLabel, PatchLabel,
        normalize_label_color, normalize_label_name, validate_label_description,
    },
    moderation::{
        DELETED_COMMENT_BODY, ExpectedVersionQuery, HIDDEN_COMMENT_BODY, ModerateCommentInput,
        RevisionPageQuery, display_comment_body, sanitize_reason,
    },
    notifications::{
        NOTIFICATION_CHANNEL, NOTIFICATION_RETENTION_DAYS, NotificationQuery, ReadAllInput,
        sanitize_single_line, valid_iso_cursor_ts, visibility_and_scope_clause,
    },
    search::{SearchQuery, SearchScope, SearchSort, validate_search_query},
    subscriptions::{OptionalVersionQuery, SubscriptionInput},
};
use serde::de::DeserializeOwned;

fn assert_rejects_unknown<T: DeserializeOwned>(json: &str) {
    assert!(
        serde_json::from_str::<T>(json).is_err(),
        "expected unknown-field rejection for {json}"
    );
}

#[test]
fn search_query_validation_handles_bounds_and_control_chars() {
    let valid = SearchQuery {
        q: "  panic fix  ".to_owned(),
        scope: Some(SearchScope::Pulls),
        sort: Some(SearchSort::Number),
        cursor: None,
        limit: Some(15),
    };
    let (q, scope, sort, limit) = validate_search_query(&valid).unwrap();
    assert_eq!(q, "panic fix");
    assert_eq!(scope, SearchScope::Pulls);
    assert_eq!(sort, SearchSort::Number);
    assert_eq!(limit, 15);

    for bad in [
        SearchQuery { q: "   ".to_owned(), scope: None, sort: None, cursor: None, limit: None },
        SearchQuery { q: "bad\nline".to_owned(), scope: None, sort: None, cursor: None, limit: None },
        SearchQuery { q: "x".repeat(129), scope: None, sort: None, cursor: None, limit: None },
        SearchQuery { q: "bug".to_owned(), scope: None, sort: None, cursor: None, limit: Some(0) },
        SearchQuery { q: "bug".to_owned(), scope: None, sort: None, cursor: None, limit: Some(101) },
    ] {
        assert!(validate_search_query(&bad).is_err());
    }
}

#[test]
fn label_normalization_and_validation() {
    assert_eq!(normalize_label_name("bug").unwrap(), "bug");
    assert_eq!(normalize_label_name("priority: high").unwrap(), "priority: high");
    for bad in ["", " ", " leading", "trailing ", "bad\nlabel", &"x".repeat(65)] {
        assert!(normalize_label_name(bad).is_err(), "expected err for {bad:?}");
    }

    assert_eq!(normalize_label_color("#D73A4A").unwrap(), "d73a4a");
    assert_eq!(normalize_label_color("0e8a16").unwrap(), "0e8a16");
    for bad in ["", "#abc", "d73a4", "zzzzzz", "#d73a4a1"] {
        assert!(normalize_label_color(bad).is_err(), "expected err for {bad:?}");
    }

    assert!(validate_label_description("").is_ok());
    assert!(validate_label_description("Valid label description").is_ok());
    assert!(validate_label_description("bad\tcontrol").is_err());
    assert!(validate_label_description(&"d".repeat(257)).is_err());
}

#[test]
fn moderation_masking_and_reason_validation() {
    assert_eq!(display_comment_body("hello", "visible"), "hello");
    assert_eq!(display_comment_body("secret", "hidden"), HIDDEN_COMMENT_BODY);
    assert_eq!(display_comment_body("secret", "deleted"), DELETED_COMMENT_BODY);

    assert_eq!(sanitize_reason("").unwrap(), "");
    assert_eq!(sanitize_reason("off-topic spam").unwrap(), "off-topic spam");
    assert!(sanitize_reason("line1\nline2").is_err());
    assert!(sanitize_reason(&"r".repeat(513)).is_err());
}

#[test]
fn notification_channel_retention_and_helpers() {
    assert_eq!(NOTIFICATION_CHANNEL, "in_app");
    assert_eq!(NOTIFICATION_RETENTION_DAYS, 90);

    assert_eq!(sanitize_single_line("  hello\n\t world  ", 32, "fallback"), "hello world");
    assert_eq!(sanitize_single_line(" \r\n\t ", 32, "fallback"), "fallback");

    assert!(valid_iso_cursor_ts("2026-11-15T10:20:30.123456Z"));
    assert!(!valid_iso_cursor_ts(""));
    assert!(!valid_iso_cursor_ts("2026-11-15'; DROP TABLE users;--"));

    let restricted = visibility_and_scope_clause(true);
    let unrestricted = visibility_and_scope_clause(false);
    assert_ne!(restricted, unrestricted);
    assert!(restricted.contains("repo_read"));
    assert!(!unrestricted.contains("repo_read"));
}

#[test]
fn forge_input_structs_enforce_deny_unknown_fields() {
    assert!(serde_json::from_str::<NewLabel>(r##"{"name":"bug","color":"#0e8a16"}"##).is_ok());
    assert_rejects_unknown::<NewLabel>(r##"{"name":"bug","color":"#0e8a16","extra":1}"##);
    assert_rejects_unknown::<PatchLabel>(r#"{"expected_version":1,"color":"0e8a16","extra":1}"#);
    assert_rejects_unknown::<LabelVersionQuery>(r#"{"expected_version":1,"extra":1}"#);
    assert_rejects_unknown::<LabelListQuery>(r#"{"limit":10,"extra":1}"#);
    assert_rejects_unknown::<LabelAttachmentInput>(r#"{"expected_version":1,"labels":["bug"],"extra":1}"#);
    assert_rejects_unknown::<AssigneeSetInput>(r#"{"expected_version":1,"assignees":["alice"],"extra":1}"#);
    assert_rejects_unknown::<AssigneeVersionQuery>(r#"{"expected_version":1,"extra":1}"#);
    assert_rejects_unknown::<SubscriptionInput>(r#"{"state":"subscribed","extra":1}"#);
    assert_rejects_unknown::<OptionalVersionQuery>(r#"{"expected_version":1,"extra":1}"#);
    assert_rejects_unknown::<ReadAllInput>(r#"{"owner":"alice","extra":1}"#);
    assert_rejects_unknown::<NotificationQuery>(r#"{"unread_only":true,"extra":1}"#);
    assert_rejects_unknown::<ExpectedVersionQuery>(r#"{"expected_version":1,"extra":1}"#);
    assert_rejects_unknown::<ModerateCommentInput>(r#"{"expected_version":1,"action":"hide","extra":1}"#);
    assert_rejects_unknown::<RevisionPageQuery>(r#"{"after":0,"extra":1}"#);
    assert_rejects_unknown::<SearchQuery>(r#"{"q":"bug","extra":1}"#);
}
