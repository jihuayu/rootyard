//! Unit tests for Web UI collaboration forms, percent encoding, XSS escaping, and outdated badges.

use crate::{
    forge::{notifications::Notification, search::{SearchHit, SearchScope, SearchSort}},
    members::models::Role,
    pulls::{models::{PullRequest, PullReview}, review_comments::PullReviewComment},
    web::{
        collaboration_views::{
            WebAssigneesForm, WebCommentEditForm, WebCommentModerateForm, WebLabelsForm,
            WebNewLabelForm, WebNewReviewCommentForm, WebNotificationQuery, WebSearchQuery,
            WebSubscriptionForm, WebUpdateLabelForm, WebVersionForm, inject_before_main_end,
            pct_encode, render_notifications_view, render_pull_collab_html, render_search_view,
        },
        models::RepoHeaderCtx,
    },
};
use serde::de::DeserializeOwned;
use uuid::Uuid;

fn sample_header(role: Role) -> RepoHeaderCtx {
    RepoHeaderCtx {
        owner: "alice".to_owned(),
        name: "forge".to_owned(),
        repository_id: Uuid::nil(),
        owner_id: Uuid::nil(),
        effective_role: role,
        actor_username: "alice".to_owned(),
        storage_backend: "git".to_owned(),
        storage_generation: 1,
        repo_state: "ready".to_owned(),
    }
}

fn assert_rejects_unknown<T: DeserializeOwned>(json: &str) {
    assert!(serde_json::from_str::<T>(json).is_err());
}

#[test]
fn form_extractors_accept_string_and_number_ints_and_deny_unknown_fields() {
    let sub: WebSubscriptionForm = serde_json::from_str(r#"{"action":"subscribe","expected_version":""}"#).unwrap();
    assert_eq!(sub.action, "subscribe");
    assert_eq!(sub.expected_version, None);

    let sub2: WebSubscriptionForm = serde_json::from_str(r#"{"action":"ignore","expected_version":"4"}"#).unwrap();
    assert_eq!(sub2.expected_version, Some(4));

    let rc: WebNewReviewCommentForm = serde_json::from_str(
        r#"{"path":"src/lib.rs","side":"right","line":"12","body":"Fix typo"}"#,
    )
    .unwrap();
    assert_eq!(rc.line, 12);

    let edit: WebCommentEditForm = serde_json::from_str(r#"{"expected_version":5,"body":"Edited"}"#).unwrap();
    assert_eq!(edit.expected_version, 5);

    assert!(serde_json::from_str::<WebVersionForm>(r#"{"expected_version":"not-an-int"}"#).is_err());
    assert!(serde_json::from_str::<WebSearchQuery>(r#"{"q":"panic","limit":"25"}"#).is_ok());

    assert_rejects_unknown::<WebSearchQuery>(r#"{"q":"panic","extra":1}"#);
    assert_rejects_unknown::<WebNotificationQuery>(r#"{"cursor":"1","extra":1}"#);
    assert_rejects_unknown::<WebSubscriptionForm>(r#"{"action":"subscribe","extra":1}"#);
    assert_rejects_unknown::<WebNewLabelForm>(r#"{"name":"bug","color":"0e8a16","extra":1}"#);
    assert_rejects_unknown::<WebUpdateLabelForm>(r#"{"expected_version":"1","extra":1}"#);
    assert_rejects_unknown::<WebVersionForm>(r#"{"expected_version":"1","extra":1}"#);
    assert_rejects_unknown::<WebLabelsForm>(r#"{"expected_version":"1","extra":1}"#);
    assert_rejects_unknown::<WebAssigneesForm>(r#"{"expected_version":"1","extra":1}"#);
    assert_rejects_unknown::<WebCommentEditForm>(r#"{"expected_version":"1","body":"x","extra":1}"#);
    assert_rejects_unknown::<WebCommentModerateForm>(r#"{"expected_version":"1","action":"hide","extra":1}"#);
    assert_rejects_unknown::<WebNewReviewCommentForm>(r#"{"path":"a","side":"right","line":"1","body":"b","extra":1}"#);
}

#[test]
fn pct_encode_and_search_view_escape_untrusted_content() {
    assert_eq!(pct_encode("bug_v1.0~beta-2"), "bug_v1.0~beta-2");
    assert_eq!(pct_encode("a b&c=d"), "a%20b%26c%3Dd");

    let hit = SearchHit {
        kind: "issue".to_owned(),
        repository_id: Uuid::nil(),
        owner: "alice".to_owned(),
        repo: "forge".to_owned(),
        number: 7,
        comment_number: 0,
        state: Some("open".to_owned()),
        title: "<script>alert(1)</script>Title".to_owned(),
        excerpt: "bad <img src=x onerror=alert(2)>".to_owned(),
        updated_at: "2026-11-15T00:00:00Z".to_owned(),
    };
    let html = render_search_view(
        "/ui",
        "alice",
        None,
        Some("a & b"),
        (SearchScope::Issues.as_str(), SearchSort::Number.as_str()),
        &[hit],
        Some("next+cur=1"),
    );
    assert!(html.contains(r#"href="/ui/search""#));
    assert!(html.contains(r#"q=a%20%26%20b&scope=issues&sort=number&cursor=next%2Bcur%3D1"#));
    assert!(!html.contains("<script>alert(1)</script>"));
    assert!(!html.contains("onerror=alert(2)"));
}

#[test]
fn notifications_and_pull_collab_render_outdated_and_role_gated_forms() {
    let n = Notification {
        id: Uuid::nil(),
        repository_id: Uuid::nil(),
        owner: "alice".to_owned(),
        repo: "forge".to_owned(),
        recipient_id: Uuid::nil(),
        actor_id: None,
        channel: "in_app".to_owned(),
        target_type: "pull_review_comment".to_owned(),
        target_number: 3,
        event_kind: "pull_review_commented".to_owned(),
        delivery_key: "k1".to_owned(),
        title: "<b>Review</b>".to_owned(),
        body_excerpt: "<script>xss()</script>".to_owned(),
        delivery_count: 1,
        unread: true,
        read_at: None,
        expires_at: "2027-02-13T00:00:00Z".to_owned(),
        created_at: "2026-11-15T00:00:00Z".to_owned(),
        updated_at: "2026-11-15T00:00:00Z".to_owned(),
    };
    let n_html = render_notifications_view("/web", "alice", &[n], true, None);
    assert!(n_html.contains(r#"data-channel="in_app""#));
    assert!(!n_html.contains("<script>xss()</script>"));

    let pull = PullRequest {
        repository_id: Uuid::nil(),
        number: 3,
        author_id: Uuid::nil(),
        title: "PR".to_owned(),
        body: "Body".to_owned(),
        state: "open".to_owned(),
        head_ref: "refs/heads/feat".to_owned(),
        base_ref: "refs/heads/main".to_owned(),
        head_oid: "b".repeat(40),
        base_oid: "a".repeat(40),
        merge_commit_oid: None,
        merged_storage_generation: None,
        version: 2,
        label_version: 1,
        assignee_version: 1,
        created_at: "2026-11-15T00:00:00Z".to_owned(),
        updated_at: "2026-11-15T00:00:00Z".to_owned(),
    };
    let review = PullReview {
        repository_id: Uuid::nil(),
        pull_number: 3,
        number: 1,
        author_id: Uuid::nil(),
        state: "approved".to_owned(),
        commit_oid: "c".repeat(40),
        pull_version: 1,
        outdated: true,
        body: "LGTM on v1".to_owned(),
        created_at: "2026-11-15T00:00:00Z".to_owned(),
    };
    let rc = PullReviewComment {
        repository_id: Uuid::nil(),
        pull_number: 3,
        number: 1,
        review_number: Some(1),
        in_reply_to_number: None,
        author_id: Uuid::nil(),
        commit_oid: "c".repeat(40),
        base_oid: "a".repeat(40),
        pull_version: 1,
        outdated: true,
        path: "src/lib.rs".to_owned(),
        side: "right".to_owned(),
        line: 5,
        body: "Inline note".to_owned(),
        version: 1,
        moderation_state: "visible".to_owned(),
        edited_at: None,
        deleted_at: None,
        moderation_reason: String::new(),
        created_at: "2026-11-15T00:00:00Z".to_owned(),
        updated_at: "2026-11-15T00:00:00Z".to_owned(),
    };

    let maintain_html = render_pull_collab_html(
        &sample_header(Role::Maintain),
        &pull,
        &[review.clone()],
        &[],
        &[],
        None,
        &[(rc.clone(), "alice".to_owned())],
    );
    assert!(maintain_html.contains(r#"data-outdated-reviews="1""#));
    assert!(maintain_html.contains(r#"data-rc-outdated="true""#));
    assert!(maintain_html.contains("data-web-action=\"rc-mod\""));

    let triage_html = render_pull_collab_html(
        &sample_header(Role::Triage),
        &pull,
        &[review],
        &[],
        &[],
        None,
        &[(rc, "alice".to_owned())],
    );
    assert!(!triage_html.contains("data-web-action=\"rc-mod\""));

    let wrapped = inject_before_main_end("<main><p>x</p></main>".to_owned(), "<div>y</div>");
    assert_eq!(wrapped, "<main><p>x</p><div>y</div></main>");
}
