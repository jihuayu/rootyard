use super::*;
use crate::web::models::WebIssue;
use uuid::Uuid;

fn sample_header() -> RepoHeaderCtx {
    RepoHeaderCtx {
        owner: "alice".to_owned(),
        name: "forge".to_owned(),
        repository_id: Uuid::nil(),
        owner_id: Uuid::nil(),
        effective_role: Role::Admin,
        actor_username: "alice".to_owned(),
        storage_backend: "git".to_owned(),
        storage_generation: 1,
        repo_state: "ready".to_owned(),
    }
}

#[test]
fn test_html_response_sets_all_mandatory_security_headers() {
    let resp = html_response(StatusCode::OK, "<p>ok</p>".to_owned());
    assert_eq!(resp.status(), StatusCode::OK);
    let h = resp.headers();
    assert_eq!(h.get(header::CONTENT_SECURITY_POLICY).unwrap(), CSP_HEADER_VALUE);
    assert_eq!(h.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");
    assert_eq!(h.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    assert_eq!(h.get(header::REFERRER_POLICY).unwrap(), "no-referrer");
    assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
}

#[test]
fn test_views_escape_untrusted_fields_and_render_semantic_data_attributes() {
    let header = sample_header();
    let item = IssueViewItem {
        issue: WebIssue {
            repository_id: Uuid::nil(),
            number: 7,
            author_id: Uuid::nil(),
            title: "<script>alert(1)</script>Bug".to_owned(),
            body: "Hello **world** <img src=x onerror=alert(1)>".to_owned(),
            state: "open".to_owned(),
            version: 1,
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            updated_at: "2026-01-01T00:00:00Z".to_owned(),
        },
        author_username: "alice".to_owned(),
        comment_count: 0,
    };
    let html = render_issue_detail_view(&header, &item, &[]);
    assert!(html.contains(r#"data-view="issue-detail""#));
    assert!(html.contains(r#"data-issue-number="7""#));
    assert!(!html.contains("<script>alert(1)</script>"));
    assert!(!html.contains("onerror="));
}
