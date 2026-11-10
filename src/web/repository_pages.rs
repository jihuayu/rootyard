//! Repository HTML pages under `/web/repos/{owner}/{name}` and the legacy
//! `/ui/repos/{owner}/{name}` alias.
//!
//! Both prefixes expose exactly the same page set and HTTP methods; the
//! composition below concatenates one shared page table with both prefixes so
//! the Web and UI aliases cannot drift apart. Every page keeps using the
//! `web::handlers` views, which run the same token/session authorization as
//! the rest of the Web UI.

use crate::{AppState, web};

use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;

/// The page router before the session/Origin/CSRF middleware is attached.
///
/// The pages are editable over the same application state as the rest of the
/// Web UI; `src/web.rs` merges them into its root and attaches the single
/// session middleware there.
pub(in crate::web) type PageRouter = Router<Arc<AppState>>;

pub(in crate::web) fn router() -> PageRouter {
    Router::new().merge(pages("/web")).merge(pages("/ui"))
}

/// One page table, mounted verbatim under `prefix` (`/web` or `/ui`).
fn pages(prefix: &str) -> PageRouter {
    let page = |tail: &str| format!("{prefix}/repos/{{owner}}/{{name}}{tail}");
    let all = Router::new()
        .route(&page(""), get(web::handlers::repo_overview))
        .route(&page("/tree"), get(web::handlers::tree_view))
        .route(&page("/tree/{oid}"), get(web::handlers::tree_by_oid_view))
        .route(&page("/blob"), get(web::handlers::blob_view))
        .route(&page("/blob/{oid}"), get(web::handlers::blob_by_oid_view))
        .route(&page("/commits"), get(web::handlers::commits_view))
        .route(&page("/commits/{oid}"), get(web::handlers::commit_detail_view))
        .route(&page("/commits/{oid}/checks"), get(web::handlers::commit_checks_view))
        .route(&page("/compare"), get(web::handlers::compare_view))
        .route(&page("/issues"), get(web::handlers::issues_list_view).post(web::handlers::create_issue_web))
        .route(
            &page("/issues/{number}"),
            get(web::handlers::issue_detail_view)
                .post(web::handlers::update_issue_web)
                .patch(web::handlers::update_issue_web),
        )
        .route(&page("/issues/{number}/comments"), post(web::handlers::create_issue_comment_web))
        .route(&page("/pulls"), get(web::handlers::pulls_list_view).post(web::handlers::create_pull_web))
        .route(
            &page("/pulls/{number}"),
            get(web::handlers::pull_detail_view)
                .post(web::handlers::update_pull_web)
                .patch(web::handlers::update_pull_web),
        )
        .route(&page("/pulls/{number}/diff"), get(web::handlers::pull_diff_view))
        .route(
            &page("/pulls/{number}/reviews"),
            get(web::handlers::pull_reviews_view).post(web::handlers::create_review_web),
        )
        .route(&page("/pulls/{number}/checks"), get(web::handlers::pull_checks_view))
        .route(&page("/pulls/{number}/merge"), post(web::handlers::merge_pull_web))
        .route(&page("/audit"), get(web::handlers::audit_view));
    all
}
