//! Server-rendered HTML templates and HTTP security header builders for Part II Track 1
//! Web UI (`F33` & `F34`). Every view enforces strict CSP, `X-Content-Type-Options: nosniff`,
//! `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store`.
use crate::{
    browse::models::{CommitDetail, CommitsResponse, CompareResponse, TreeResponse},
    members::models::{AuditPage, Role},
    pulls::models::{CheckRun, PullRequest},
    web::{
        models::{BlobPreview, CommentViewItem, IssueViewItem, OverviewViewData, PullDetailViewData, RepoHeaderCtx},
        sanitize::{escape_html, render_safe_markdown},
    },
};
use axum::{
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};

pub const CSP_HEADER_VALUE: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

pub fn html_response(status: StatusCode, body: String) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::CONTENT_SECURITY_POLICY, CSP_HEADER_VALUE),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        body,
    )
        .into_response()
}

pub fn render_page_shell(header: &RepoHeaderCtx, view_name: &str, page_title: &str, inner_html: &str) -> String {
    let owner = escape_html(&header.owner);
    let repo = escape_html(&header.name);
    let role = header.effective_role.as_str();
    let actor = escape_html(&header.actor_username);
    let backend = escape_html(&header.storage_backend);
    let generation = header.storage_generation;
    let title = escape_html(page_title);
    let base_url = format!("/web/repos/{owner}/{repo}");
    let audit_nav = if header.effective_role >= Role::Maintain {
        format!(r#"<a href="{base_url}/audit" data-nav="audit">Audit Log</a>"#)
    } else {
        String::new()
    };

    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\"/>\n<title>{title} — {owner}/{repo}</title>\n<script src=\"/web/app.js\" defer></script>\n<style>body{{font-family:system-ui,sans-serif;margin:1.5rem;line-height:1.5}}nav a{{margin-right:1rem}}.badge{{padding:0.15rem 0.45rem;border-radius:4px;background:#eef}}.blob-truncation-banner{{padding:0.5rem;background:#fff3cd;border:1px solid #ffeeba}}</style>\n</head>\n<body data-view=\"{view_name}\" data-owner=\"{owner}\" data-repo=\"{repo}\" data-role=\"{role}\" data-actor=\"{actor}\" data-storage-backend=\"{backend}\" data-storage-generation=\"{generation}\">\n<header class=\"repo-header\" data-repo-id=\"{}\" data-repo-state=\"{}\">\n<h1><a href=\"{base_url}\">{owner}/{repo}</a> <span class=\"badge\" data-role-badge=\"{role}\">{role}</span></h1>\n<nav class=\"repo-nav\">\n<a href=\"/web/repos\">My repositories</a>\n<a href=\"{base_url}\" data-nav=\"overview\">Overview</a>\n<a href=\"{base_url}/tree\" data-nav=\"tree\">Files</a>\n<a href=\"{base_url}/commits\" data-nav=\"commits\">Commits</a>\n<a href=\"{base_url}/issues\" data-nav=\"issues\">Issues</a>\n<a href=\"{base_url}/pulls\" data-nav=\"pulls\">Pull Requests</a>\n{audit_nav}\n</nav>\n<form method=\"post\" action=\"/web/logout\"><button type=\"submit\">Sign out</button></form>\n</header>\n<main class=\"repo-main\">\n{inner_html}\n</main>\n</body>\n</html>\n",
        header.repository_id,
        escape_html(&header.repo_state),
    )
}

pub fn render_repo_overview(data: &OverviewViewData) -> String {
    let head_target = escape_html(data.head.target.as_deref().unwrap_or("HEAD"));
    let head_oid = escape_html(data.head.oid.as_deref().unwrap_or("unborn"));
    let latest_html = if let Some(ref c) = data.latest_commit {
        format!(
            "<div class=\"latest-commit\" data-latest-commit-oid=\"{}\"><strong>{}</strong> by <span>{}</span></div>",
            escape_html(&c.oid),
            escape_html(&c.subject),
            escape_html(&c.author_name),
        )
    } else {
        "<div class=\"latest-commit\" data-latest-commit-oid=\"none\">Empty repository</div>".to_owned()
    };

    let mut tree_items = String::new();
    if let Some(ref tree) = data.tree {
        for entry in &tree.items {
            let e_path = escape_html(&entry.path);
            let e_name = escape_html(&entry.name);
            let e_kind = escape_html(&entry.kind);
            let e_oid = escape_html(&entry.oid);
            tree_items.push_str(&format!(
                "<li class=\"tree-entry\" data-entry-kind=\"{e_kind}\" data-entry-path=\"{e_path}\" data-entry-oid=\"{e_oid}\">{e_name}</li>\n"
            ));
        }
    }

    let readme_section = if let Some(ref html) = data.readme_html {
        format!("<section class=\"readme-panel markdown-body\" data-readme=\"true\">\n{html}</section>\n")
    } else {
        String::new()
    };

    let inner = format!(
        "<section class=\"overview-summary\" data-branch-count=\"{}\" data-tag-count=\"{}\" data-open-issues=\"{}\" data-open-pulls=\"{}\" data-head-target=\"{head_target}\" data-head-oid=\"{head_oid}\">\n{latest_html}\n<ul class=\"tree-list\">\n{tree_items}</ul>\n{readme_section}</section>",
        data.branches.len(),
        data.tags.len(),
        data.open_issues,
        data.open_pulls,
    );
    render_page_shell(&data.header, "repo-overview", "Overview", &inner)
}

pub fn render_tree_view(header: &RepoHeaderCtx, tree: &TreeResponse) -> String {
    let mut items_html = String::new();
    for entry in &tree.items {
        let e_path = escape_html(&entry.path);
        let e_name = escape_html(&entry.name);
        let e_kind = escape_html(&entry.kind);
        let e_oid = escape_html(&entry.oid);
        let size = entry.size.unwrap_or(0);
        items_html.push_str(&format!(
            "<li class=\"tree-entry\" data-entry-kind=\"{e_kind}\" data-entry-path=\"{e_path}\" data-entry-oid=\"{e_oid}\" data-entry-size=\"{size}\"><span class=\"entry-name\">{e_name}</span></li>\n"
        ));
    }
    let inner = format!(
        "<section class=\"tree-browser\" data-root-oid=\"{}\" data-tree-oid=\"{}\" data-path=\"{}\" data-entry-count=\"{}\">\n<ul class=\"tree-list\">\n{items_html}</ul>\n</section>",
        escape_html(&tree.oid),
        escape_html(&tree.tree_oid),
        escape_html(&tree.path),
        tree.items.len(),
    );
    render_page_shell(header, "repo-tree", "Files", &inner)
}

pub fn render_blob_view(header: &RepoHeaderCtx, blob: &BlobPreview) -> String {
    let trunc_banner = if blob.truncated {
        format!(
            "<div class=\"blob-truncation-banner\" data-truncated-notice=\"true\">Preview truncated at {} bytes (full blob size: {} bytes).</div>\n",
            blob.preview_bytes, blob.total_size
        )
    } else {
        String::new()
    };

    let body_html = if blob.is_binary {
        let hex = escape_html(blob.hex_preview.as_deref().unwrap_or(""));
        format!(
            "<div class=\"binary-notice\" data-binary-notice=\"true\">Binary file ({} bytes) — showing bounded hexadecimal preview:</div>\n<pre class=\"blob-hex-preview\" data-hex-preview=\"true\">{hex}</pre>\n",
            blob.total_size
        )
    } else {
        let code = escape_html(blob.text_preview.as_deref().unwrap_or(""));
        let md_block = if let Some(ref md) = blob.rendered_markdown_html {
            format!("<div class=\"markdown-body\" data-markdown-preview=\"true\">{md}</div>\n")
        } else {
            String::new()
        };
        format!("{md_block}<pre class=\"blob-code\" data-text-preview=\"true\"><code>{code}</code></pre>\n")
    };

    let inner = format!(
        "<article class=\"blob-viewer\" data-blob-oid=\"{}\" data-path=\"{}\" data-binary=\"{}\" data-truncated=\"{}\" data-total-size=\"{}\" data-preview-bytes=\"{}\" data-line-count=\"{}\">\n{trunc_banner}{body_html}</article>",
        escape_html(&blob.oid),
        escape_html(&blob.path),
        blob.is_binary,
        blob.truncated,
        blob.total_size,
        blob.preview_bytes,
        blob.line_count,
    );
    render_page_shell(header, "repo-blob", &blob.path, &inner)
}

pub fn render_commits_view(header: &RepoHeaderCtx, rev: &str, commits: &CommitsResponse) -> String {
    let mut rows = String::new();
    for c in &commits.items {
        rows.push_str(&format!(
            "<li class=\"commit-item\" data-commit-oid=\"{}\" data-tree-oid=\"{}\"><strong class=\"commit-subject\">{}</strong> <span class=\"commit-author\">{}</span> <time data-authored-at=\"{}\">{}</time></li>\n",
            escape_html(&c.oid),
            escape_html(&c.tree_oid),
            escape_html(&c.subject),
            escape_html(&c.author_name),
            c.authored_at,
            c.authored_at,
        ));
    }
    let next_attr = commits.next_after.map_or_else(|| "none".to_owned(), |n| n.to_string());
    let inner = format!(
        "<section class=\"commits-log\" data-rev=\"{}\" data-commit-count=\"{}\" data-next-after=\"{next_attr}\">\n<ol class=\"commit-list\">\n{rows}</ol>\n</section>",
        escape_html(rev),
        commits.items.len(),
    );
    render_page_shell(header, "repo-commits", "Commits", &inner)
}

fn format_checks_list_html(checks: &[CheckRun]) -> String {
    let mut items = String::new();
    for chk in checks {
        let concl = escape_html(chk.conclusion.as_deref().unwrap_or("pending"));
        items.push_str(&format!(
            "<li class=\"check-run-item\" data-check-context=\"{}\" data-check-status=\"{}\" data-check-conclusion=\"{concl}\" data-check-attempt=\"{}\" data-check-sequence=\"{}\"><span class=\"check-ctx\">{}</span>: <span class=\"check-status\">{}</span> ({concl}) <pre class=\"check-output\">{}</pre></li>\n",
            escape_html(&chk.context),
            escape_html(&chk.status),
            chk.attempt,
            chk.sequence,
            escape_html(&chk.context),
            escape_html(&chk.status),
            escape_html(&chk.output),
        ));
    }
    format!("<ul class=\"check-run-list\">\n{items}</ul>")
}

pub fn render_commit_detail_view(
    header: &RepoHeaderCtx,
    detail: &CommitDetail,
    checks: &[CheckRun],
    diff: &str,
) -> String {
    let c = &detail.summary;
    let mut paths_html = String::new();
    for p in &detail.changed_paths {
        paths_html.push_str(&format!(
            "<li class=\"changed-path\" data-path=\"{}\">{}</li>\n",
            escape_html(p),
            escape_html(p),
        ));
    }
    let checks_html = format_checks_list_html(checks);
    let inner = format!(
        "<article class=\"commit-detail\" data-commit-oid=\"{}\" data-tree-oid=\"{}\" data-parent-count=\"{}\" data-check-count=\"{}\">\n<h2>{}</h2>\n<p class=\"commit-meta\">Author: {} &lt;{}&gt;</p>\n<pre class=\"commit-message\">{}</pre>\n<ul class=\"changed-paths\">\n{paths_html}</ul>\n<section class=\"commit-checks\" data-check-count=\"{}\">{checks_html}</section>\n<pre class=\"diff-view\">{}</pre>\n</article>",
        escape_html(&c.oid),
        escape_html(&c.tree_oid),
        c.parents.len(),
        checks.len(),
        escape_html(&c.subject),
        escape_html(&c.author_name),
        escape_html(&c.author_email),
        escape_html(&c.message),
        checks.len(),
        escape_html(diff),
    );
    render_page_shell(header, "commit-detail", &c.oid, &inner)
}

pub fn render_compare_view(header: &RepoHeaderCtx, base: &str, head: &str, cmp: &CompareResponse) -> String {
    let mut commits_html = String::new();
    for c in &cmp.commits {
        commits_html.push_str(&format!(
            "<li class=\"compare-commit\" data-commit-oid=\"{}\">{}</li>\n",
            escape_html(&c.oid),
            escape_html(&c.subject),
        ));
    }
    let inner = format!(
        "<section class=\"compare-view\" data-base=\"{}\" data-head=\"{}\" data-base-oid=\"{}\" data-head-oid=\"{}\" data-ahead=\"{}\" data-behind=\"{}\" data-fast-forward=\"{}\">\n<ol class=\"compare-commits\">\n{commits_html}</ol>\n<pre class=\"diff-view\">{}</pre>\n</section>",
        escape_html(base),
        escape_html(head),
        escape_html(&cmp.base_oid),
        escape_html(&cmp.head_oid),
        cmp.ahead,
        cmp.behind,
        cmp.fast_forward,
        escape_html(&cmp.diff),
    );
    render_page_shell(header, "repo-compare", "Compare", &inner)
}

pub fn render_issues_list_view(
    header: &RepoHeaderCtx,
    items: &[IssueViewItem],
    state_filter: Option<&str>,
    next_after: Option<i64>,
) -> String {
    let mut rows = String::new();
    for item in items {
        rows.push_str(&format!(
            "<li class=\"issue-row\" data-issue-number=\"{}\" data-issue-state=\"{}\" data-issue-author=\"{}\"><a href=\"/web/repos/{}/{}/issues/{}\"><span class=\"issue-num\">#{}</span> <strong class=\"issue-title\">{}</strong></a> <span class=\"issue-comments\" data-comment-count=\"{}\">({} comments)</span></li>\n",
            item.issue.number,
            escape_html(&item.issue.state),
            escape_html(&item.author_username),
            escape_html(&header.owner),
            escape_html(&header.name),
            item.issue.number,
            item.issue.number,
            escape_html(&item.issue.title),
            item.comment_count,
            item.comment_count,
        ));
    }
    let filter_str = escape_html(state_filter.unwrap_or("all"));
    let next_str = next_after.map_or_else(|| "none".to_owned(), |n| n.to_string());
    let create_form = if header.effective_role >= Role::Triage {
        format!(
            "<form data-web-action=\"issue\" action=\"/web/repos/{}/{}/issues\"><h2>New issue</h2><label>Title <input name=\"title\" required></label><label>Details <textarea name=\"body\"></textarea></label><button>Create issue</button><p class=\"form-result\" role=\"status\"></p></form>",
            escape_html(&header.owner),
            escape_html(&header.name)
        )
    } else {
        String::new()
    };
    let inner = format!(
        "<section class=\"issues-list\" data-state-filter=\"{filter_str}\" data-issue-count=\"{}\" data-next-after=\"{next_str}\">\n<ul class=\"issue-items\">\n{rows}</ul>\n{create_form}</section>",
        items.len(),
    );
    render_page_shell(header, "issues-list", "Issues", &inner)
}

pub fn render_issue_detail_view(header: &RepoHeaderCtx, issue: &IssueViewItem, comments: &[CommentViewItem]) -> String {
    let mut comments_html = String::new();
    for c in comments {
        let body_md = render_safe_markdown(&c.comment.body);
        comments_html.push_str(&format!(
            "<li class=\"issue-comment\" data-comment-number=\"{}\" data-comment-author=\"{}\"><div class=\"comment-body markdown-body\">{body_md}</div></li>\n",
            c.comment.number,
            escape_html(&c.author_username),
        ));
    }
    let issue_body_md = render_safe_markdown(&issue.issue.body);
    let comment_form = if header.effective_role >= Role::Triage {
        format!(
            "<form data-web-action=\"comment\" action=\"/web/repos/{}/{}/issues/{}/comments\"><label>Comment <textarea name=\"body\" required></textarea></label><button>Add comment</button><p class=\"form-result\" role=\"status\"></p></form>",
            escape_html(&header.owner),
            escape_html(&header.name),
            issue.issue.number
        )
    } else {
        String::new()
    };
    let inner = format!(
        "<article class=\"issue-detail\" data-issue-number=\"{}\" data-issue-state=\"{}\" data-issue-version=\"{}\" data-issue-author=\"{}\">\n<h2>#{} {}</h2>\n<div class=\"issue-body markdown-body\">{issue_body_md}</div>\n<ol class=\"issue-comments-list\" data-comment-count=\"{}\">\n{comments_html}</ol>\n{comment_form}</article>",
        issue.issue.number,
        escape_html(&issue.issue.state),
        issue.issue.version,
        escape_html(&issue.author_username),
        issue.issue.number,
        escape_html(&issue.issue.title),
        comments.len(),
    );
    render_page_shell(header, "issue-detail", &issue.issue.title, &inner)
}

pub fn render_pulls_list_view(
    header: &RepoHeaderCtx,
    items: &[PullRequest],
    state_filter: Option<&str>,
    next_after: Option<i64>,
) -> String {
    let mut rows = String::new();
    for pr in items {
        rows.push_str(&format!(
            "<li class=\"pull-row\" data-pull-number=\"{}\" data-pull-state=\"{}\" data-head-ref=\"{}\" data-base-ref=\"{}\" data-head-oid=\"{}\"><a href=\"/web/repos/{}/{}/pulls/{}\"><span class=\"pull-num\">#{}</span> <strong class=\"pull-title\">{}</strong></a></li>\n",
            pr.number,
            escape_html(&pr.state),
            escape_html(&pr.head_ref),
            escape_html(&pr.base_ref),
            escape_html(&pr.head_oid),
            escape_html(&header.owner),
            escape_html(&header.name),
            pr.number,
            pr.number,
            escape_html(&pr.title),
        ));
    }
    let filter_str = escape_html(state_filter.unwrap_or("all"));
    let next_str = next_after.map_or_else(|| "none".to_owned(), |n| n.to_string());
    let create_form = if header.effective_role >= Role::Write {
        format!(
            "<form data-web-action=\"pull\" action=\"/web/repos/{}/{}/pulls\"><h2>New pull request</h2><label>Title <input name=\"title\" required></label><label>Source branch <input name=\"head_ref\" required></label><label>Target branch <input name=\"base_ref\" value=\"main\" required></label><label>Details <textarea name=\"body\"></textarea></label><button>Create pull request</button><p class=\"form-result\" role=\"status\"></p></form>",
            escape_html(&header.owner),
            escape_html(&header.name)
        )
    } else {
        String::new()
    };
    let inner = format!(
        "<section class=\"pulls-list\" data-state-filter=\"{filter_str}\" data-pull-count=\"{}\" data-next-after=\"{next_str}\">\n<ul class=\"pull-items\">\n{rows}</ul>\n{create_form}</section>",
        items.len(),
    );
    render_page_shell(header, "pulls-list", "Pull Requests", &inner)
}

pub fn render_pull_detail_view(header: &RepoHeaderCtx, data: &PullDetailViewData) -> String {
    let pr = &data.pull;
    let body_md = render_safe_markdown(&pr.body);
    let mut reviews_html = String::new();
    for rev in &data.reviews {
        let rev_md = render_safe_markdown(&rev.body);
        reviews_html.push_str(&format!(
            "<li class=\"pull-review\" data-review-number=\"{}\" data-review-state=\"{}\" data-review-commit=\"{}\" data-review-author-id=\"{}\"><span class=\"review-state\">{}</span><div class=\"review-body markdown-body\">{rev_md}</div></li>\n",
            rev.number,
            escape_html(&rev.state),
            escape_html(&rev.commit_oid),
            rev.author_id,
            escape_html(&rev.state),
        ));
    }
    let checks_html = format_checks_list_html(&data.checks);
    let reason = escape_html(data.policy.reason.unwrap_or("ok"));
    let review_form = if data.can_approve {
        format!(
            "<form data-web-action=\"review\" action=\"/web/repos/{}/{}/pulls/{}/reviews\"><label>Review <textarea name=\"body\"></textarea></label><button>Approve</button><p class=\"form-result\" role=\"status\"></p></form>",
            escape_html(&header.owner),
            escape_html(&header.name),
            pr.number
        )
    } else {
        String::new()
    };
    let merge_form = if data.can_merge {
        format!(
            "<form data-web-action=\"merge\" action=\"/web/repos/{}/{}/pulls/{}/merge\"><button>Merge pull request</button><p class=\"form-result\" role=\"status\"></p></form>",
            escape_html(&header.owner),
            escape_html(&header.name),
            pr.number
        )
    } else {
        String::new()
    };
    let inner = format!(
        "<article class=\"pull-detail\" data-pull-number=\"{}\" data-pull-state=\"{}\" data-pull-version=\"{}\" data-head-ref=\"{}\" data-base-ref=\"{}\" data-head-oid=\"{}\" data-base-oid=\"{}\" data-merge-allowed=\"{}\" data-required-approvals=\"{}\" data-current-approvals=\"{}\" data-policy-reason=\"{reason}\" data-self-approval-disallowed=\"{}\" data-can-approve=\"{}\" data-can-merge=\"{}\">\n<h2>#{} {}</h2>\n<div class=\"pull-body markdown-body\">{body_md}</div>\n<section class=\"pull-reviews\" data-review-count=\"{}\"><ol>\n{reviews_html}</ol></section>\n<section class=\"checks-panel\" data-commit-oid=\"{}\" data-check-count=\"{}\">{checks_html}</section>\n<pre class=\"diff-view\">{}</pre>\n{review_form}{merge_form}</article>",
        pr.number,
        escape_html(&pr.state),
        pr.version,
        escape_html(&pr.head_ref),
        escape_html(&pr.base_ref),
        escape_html(&pr.head_oid),
        escape_html(&pr.base_oid),
        data.policy.allowed,
        data.policy.required_approvals,
        data.policy.current_approvals,
        data.disallow_self_approval,
        data.can_approve,
        data.can_merge,
        pr.number,
        escape_html(&pr.title),
        data.reviews.len(),
        escape_html(&pr.head_oid),
        data.checks.len(),
        escape_html(&data.diff.diff),
    );
    render_page_shell(header, "pull-detail", &pr.title, &inner)
}

pub fn render_check_runs_panel(
    header: &RepoHeaderCtx,
    commit_oid: &str,
    pull_number: Option<i64>,
    checks: &[CheckRun],
) -> String {
    let list_html = format_checks_list_html(checks);
    let pr_attr = pull_number.map_or_else(|| "none".to_owned(), |n| n.to_string());
    let inner = format!(
        "<section class=\"checks-panel\" data-commit-oid=\"{}\" data-pull-number=\"{pr_attr}\" data-check-count=\"{}\">\n{list_html}\n</section>",
        escape_html(commit_oid),
        checks.len(),
    );
    render_page_shell(header, "checks-panel", "Check Runs", &inner)
}

pub fn render_audit_view(header: &RepoHeaderCtx, page: &AuditPage) -> String {
    let mut rows = String::new();
    for entry in &page.items {
        let details_str = escape_html(&entry.details.to_string());
        rows.push_str(&format!(
            "<tr class=\"audit-row\" data-audit-id=\"{}\" data-audit-action=\"{}\" data-audit-actor=\"{}\" data-audit-target=\"{}\"><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{details_str}</code></td></tr>\n",
            entry.id,
            escape_html(&entry.action),
            escape_html(&entry.actor_name),
            escape_html(&entry.target_name),
            entry.id,
            escape_html(&entry.actor_name),
            escape_html(&entry.action),
            escape_html(&entry.target_name),
        ));
    }
    let next_str = page.next_after.map_or_else(|| "none".to_owned(), |n| n.to_string());
    let inner = format!(
        "<section class=\"audit-log-view\" data-audit-count=\"{}\" data-next-after=\"{next_str}\">\n<table class=\"audit-table\"><tbody>\n{rows}</tbody></table>\n</section>",
        page.items.len(),
    );
    render_page_shell(header, "repo-audit", "Audit Log", &inner)
}

#[cfg(test)]
#[path = "templates_tests.rs"]
mod tests;
