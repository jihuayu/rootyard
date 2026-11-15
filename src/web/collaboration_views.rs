//! Server-rendered collaboration HTML templates and form-safe extractors for Issue #86.

use crate::{
    forge::{
        assignees::AssigneeEntry,
        labels::RepoLabel,
        notifications::Notification,
        search::{SearchHit, SearchScope, SearchSort},
        subscriptions::Subscription,
    },
    members::models::Role,
    pulls::{
        models::{PullRequest, PullReview},
        review_comments::PullReviewComment,
    },
    web::{
        models::{CommentViewItem, RepoHeaderCtx},
        sanitize::escape_html,
        templates::CSP_HEADER_VALUE,
    },
};
use serde::{Deserialize, Deserializer, de};

pub fn deserialize_i64<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum IntOrStr {
        Int(i64),
        Str(String),
    }
    match IntOrStr::deserialize(deserializer)? {
        IntOrStr::Int(v) => Ok(v),
        IntOrStr::Str(s) => s
            .trim()
            .parse::<i64>()
            .map_err(|_| de::Error::custom("expected integer value")),
    }
}

pub fn deserialize_opt_i64<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OptIntOrStr {
        Int(i64),
        Str(String),
        Null,
    }
    match Option::<OptIntOrStr>::deserialize(deserializer)? {
        None | Some(OptIntOrStr::Null) => Ok(None),
        Some(OptIntOrStr::Int(v)) => Ok(Some(v)),
        Some(OptIntOrStr::Str(s)) => {
            let t = s.trim();
            if t.is_empty() {
                Ok(None)
            } else {
                t.parse::<i64>()
                    .map(Some)
                    .map_err(|_| de::Error::custom("expected optional integer value"))
            }
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSearchQuery {
    pub q: Option<String>,
    pub scope: Option<SearchScope>,
    pub sort: Option<SearchSort>,
    pub cursor: Option<String>,
    #[serde(default, deserialize_with = "deserialize_opt_i64")]
    pub limit: Option<i64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebNotificationQuery {
    pub unread_only: Option<String>,
    pub cursor: Option<String>,
    #[serde(default, deserialize_with = "deserialize_opt_i64")]
    pub limit: Option<i64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSubscriptionForm {
    pub action: String,
    #[serde(default, deserialize_with = "deserialize_opt_i64")]
    pub expected_version: Option<i64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebNewLabelForm {
    pub name: String,
    pub color: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebUpdateLabelForm {
    #[serde(deserialize_with = "deserialize_i64")]
    pub expected_version: i64,
    pub name: Option<String>,
    pub color: Option<String>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebVersionForm {
    #[serde(deserialize_with = "deserialize_i64")]
    pub expected_version: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebLabelsForm {
    #[serde(deserialize_with = "deserialize_i64")]
    pub expected_version: i64,
    #[serde(default)]
    pub labels: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebAssigneesForm {
    #[serde(deserialize_with = "deserialize_i64")]
    pub expected_version: i64,
    #[serde(default)]
    pub assignees: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebCommentEditForm {
    #[serde(deserialize_with = "deserialize_i64")]
    pub expected_version: i64,
    pub body: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebCommentModerateForm {
    #[serde(deserialize_with = "deserialize_i64")]
    pub expected_version: i64,
    pub action: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebNewReviewCommentForm {
    pub path: String,
    pub side: String,
    #[serde(deserialize_with = "deserialize_i64")]
    pub line: i64,
    pub body: String,
    pub commit_oid: Option<String>,
    pub base_oid: Option<String>,
    #[serde(default, deserialize_with = "deserialize_opt_i64")]
    pub review_number: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_opt_i64")]
    pub in_reply_to_number: Option<i64>,
}

pub fn pct_encode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn render_account_page_shell(
    prefix: &str,
    actor_username: &str,
    view_name: &str,
    page_title: &str,
    inner_html: &str,
) -> String {
    let title = escape_html(page_title);
    let actor = escape_html(actor_username);
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\"/>\n<meta http-equiv=\"Content-Security-Policy\" content=\"{CSP_HEADER_VALUE}\"/>\n<title>{title}</title>\n<script src=\"/web/app.js\" defer></script>\n<style>body{{font-family:system-ui,sans-serif;margin:1.5rem;line-height:1.5}}nav a{{margin-right:1rem}}.badge{{padding:0.15rem 0.45rem;border-radius:4px;background:#eef}}.outdated{{background:#f8d7da;color:#721c24}}</style>\n</head>\n<body data-view=\"{view_name}\" data-actor=\"{actor}\">\n<header>\n<h1>{title}</h1>\n<nav><a href=\"/web/repos\">My repositories</a><a href=\"{prefix}/search\" data-nav=\"search\">Search</a><a href=\"{prefix}/notifications\" data-nav=\"notifications\">Notifications</a></nav>\n<form method=\"post\" action=\"/web/logout\"><button type=\"submit\">Sign out</button></form>\n</header>\n<main>\n{inner_html}\n</main>\n</body>\n</html>\n"
    )
}

pub fn render_search_view(
    prefix: &str,
    actor_username: &str,
    header: Option<&RepoHeaderCtx>,
    q: Option<&str>,
    sort_scope: (&str, &str),
    hits: &[SearchHit],
    next_cursor: Option<&str>,
) -> String {
    let (scope, sort) = sort_scope;
    let query_esc = escape_html(q.unwrap_or(""));
    let action = header.map_or_else(
        || format!("{prefix}/search"),
        |h| format!("{prefix}/repos/{}/{}/search", escape_html(&h.owner), escape_html(&h.name)),
    );
    let mut rows = String::new();
    for hit in hits {
        let link = match hit.kind.as_str() {
            "repository" => format!("{prefix}/repos/{}/{}", escape_html(&hit.owner), escape_html(&hit.repo)),
            "issue" | "issue_comment" => format!("{prefix}/repos/{}/{}/issues/{}", escape_html(&hit.owner), escape_html(&hit.repo), hit.number),
            _ => format!("{prefix}/repos/{}/{}/pulls/{}", escape_html(&hit.owner), escape_html(&hit.repo), hit.number),
        };
        rows.push_str(&format!(
            "<li class=\"search-hit\" data-hit-kind=\"{}\" data-hit-owner=\"{}\" data-hit-repo=\"{}\" data-hit-number=\"{}\"><span class=\"badge\">{}</span> <a href=\"{link}\"><strong>{}</strong></a> <small>{}</small><p>{}</p></li>\n",
            escape_html(&hit.kind),
            escape_html(&hit.owner),
            escape_html(&hit.repo),
            hit.number,
            escape_html(&hit.kind),
            escape_html(&hit.title),
            escape_html(hit.state.as_deref().unwrap_or("")),
            escape_html(&hit.excerpt),
        ));
    }
    let next_link = next_cursor.map_or_else(String::new, |c| {
        format!(
            "<p><a class=\"next-page-link\" href=\"{action}?q={}&scope={}&sort={}&cursor={}\">Next page</a></p>",
            pct_encode(q.unwrap_or("")),
            pct_encode(scope),
            pct_encode(sort),
            pct_encode(c),
        )
    });
    let inner = format!(
        "<section class=\"search-panel\" data-scope=\"{}\" data-sort=\"{}\" data-hit-count=\"{}\">\n<form method=\"get\" action=\"{action}\"><label>Query <input name=\"q\" value=\"{query_esc}\" required/></label><label>Scope <input name=\"scope\" value=\"{}\"/></label><label>Sort <input name=\"sort\" value=\"{}\"/></label><button type=\"submit\">Search</button></form>\n<ul class=\"search-results\">\n{rows}</ul>\n{next_link}</section>",
        escape_html(scope),
        escape_html(sort),
        hits.len(),
        escape_html(scope),
        escape_html(sort),
    );
    match header {
        Some(h) => crate::web::templates::render_page_shell(h, "repo-search", "Search", &inner),
        None => render_account_page_shell(prefix, actor_username, "global-search", "Search", &inner),
    }
}

pub fn render_notifications_view(
    prefix: &str,
    actor_username: &str,
    items: &[Notification],
    unread_only: bool,
    next_cursor: Option<&str>,
) -> String {
    let mut rows = String::new();
    for n in items {
        let target_href = match n.target_type.as_str() {
            "issue" => format!("{prefix}/repos/{}/{}/issues/{}", escape_html(&n.owner), escape_html(&n.repo), n.target_number),
            "pull" | "pull_review" | "pull_review_comment" => {
                format!("{prefix}/repos/{}/{}/pulls/{}", escape_html(&n.owner), escape_html(&n.repo), n.target_number)
            }
            _ => format!("{prefix}/repos/{}/{}", escape_html(&n.owner), escape_html(&n.repo)),
        };
        let ack = if n.unread {
            format!(
                "<form data-web-action=\"notif-read\" action=\"{prefix}/notifications/{}/read\"><button>Mark read</button><p class=\"form-result\" role=\"status\"></p></form>",
                n.id
            )
        } else {
            "<span class=\"badge\">read</span>".to_owned()
        };
        rows.push_str(&format!(
            "<li class=\"notification-row\" data-notification-id=\"{}\" data-unread=\"{}\" data-channel=\"{}\" data-event-kind=\"{}\"><a href=\"{target_href}\"><strong>{}/{}</strong> — {}</a> <span>({})</span> {ack}</li>\n",
            n.id,
            n.unread,
            escape_html(&n.channel),
            escape_html(&n.event_kind),
            escape_html(&n.owner),
            escape_html(&n.repo),
            escape_html(&n.title),
            escape_html(&n.body_excerpt),
        ));
    }
    let next_link = next_cursor.map_or_else(String::new, |c| {
        format!(
            "<p><a class=\"next-page-link\" href=\"{prefix}/notifications?unread_only={}&cursor={}\">Next page</a></p>",
            unread_only,
            pct_encode(c)
        )
    });
    let inner = format!(
        "<section class=\"notifications-panel\" data-unread-only=\"{unread_only}\" data-notification-count=\"{}\">\n<form data-web-action=\"notif-read-all\" action=\"{prefix}/notifications/read-all\"><button>Mark all read</button><p class=\"form-result\" role=\"status\"></p></form>\n<ul class=\"notifications-list\">\n{rows}</ul>\n{next_link}</section>",
        items.len(),
    );
    render_account_page_shell(prefix, actor_username, "notifications", "Notifications", &inner)
}

pub fn render_labels_view(prefix: &str, header: &RepoHeaderCtx, labels: &[RepoLabel]) -> String {
    let base = format!("{prefix}/repos/{}/{}", escape_html(&header.owner), escape_html(&header.name));
    let mut rows = String::new();
    for l in labels {
        let lname = escape_html(&l.name);
        let lname_url = pct_encode(&l.name);
        let del = if header.effective_role >= Role::Triage {
            format!(
                "<form data-web-action=\"label-delete\" action=\"{base}/labels/{lname_url}/delete\"><input type=\"hidden\" name=\"expected_version\" value=\"{}\"/><button>Delete</button><p class=\"form-result\" role=\"status\"></p></form>",
                l.version
            )
        } else {
            String::new()
        };
        rows.push_str(&format!(
            "<li class=\"label-row\" data-label-name=\"{lname}\" data-label-color=\"{}\" data-label-version=\"{}\"><span class=\"badge\">#{}: {lname}</span> {} {del}</li>\n",
            escape_html(&l.color),
            l.version,
            escape_html(&l.color),
            escape_html(&l.description),
        ));
    }
    let create_form = if header.effective_role >= Role::Triage {
        format!(
            "<form data-web-action=\"label-create\" action=\"{base}/labels\"><h3>New label</h3><label>Name <input name=\"name\" required/></label><label>Color <input name=\"color\" value=\"0e8a16\" required/></label><label>Description <input name=\"description\"/></label><button>Create label</button><p class=\"form-result\" role=\"status\"></p></form>"
        )
    } else {
        String::new()
    };
    let inner = format!("<section class=\"labels-panel\" data-label-count=\"{}\">\n<ul>\n{rows}</ul>\n{create_form}</section>", labels.len());
    crate::web::templates::render_page_shell(header, "repo-labels", "Labels", &inner)
}

pub fn render_subscription_box(action_url: &str, sub: Option<&Subscription>) -> String {
    let state = sub.map_or("none", |s| s.state.as_str());
    let ver_attr = sub.map_or_else(String::new, |s| s.version.to_string());
    format!(
        "<div class=\"subscription-box\" data-subscription-state=\"{state}\">\n<span>Subscription: <strong class=\"badge\">{state}</strong></span>\n<form data-web-action=\"sub-watch\" action=\"{action_url}\"><input type=\"hidden\" name=\"action\" value=\"subscribe\"/><input type=\"hidden\" name=\"expected_version\" value=\"{ver_attr}\"/><button>Watch</button><p class=\"form-result\" role=\"status\"></p></form>\n<form data-web-action=\"sub-ignore\" action=\"{action_url}\"><input type=\"hidden\" name=\"action\" value=\"ignore\"/><input type=\"hidden\" name=\"expected_version\" value=\"{ver_attr}\"/><button>Ignore</button><p class=\"form-result\" role=\"status\"></p></form>\n<form data-web-action=\"sub-unsub\" action=\"{action_url}\"><input type=\"hidden\" name=\"action\" value=\"unsubscribe\"/><input type=\"hidden\" name=\"expected_version\" value=\"{ver_attr}\"/><button>Unsubscribe</button><p class=\"form-result\" role=\"status\"></p></form>\n</div>\n"
    )
}

pub fn render_overview_collab_html(header: &RepoHeaderCtx, label_count: usize, sub: Option<&Subscription>) -> String {
    let base = format!("/web/repos/{}/{}", escape_html(&header.owner), escape_html(&header.name));
    let sub_html = render_subscription_box(&format!("{base}/subscription"), sub);
    format!(
        "<section class=\"repo-collaboration\" data-label-count=\"{label_count}\">\n<p><a href=\"{base}/labels\">Labels ({label_count})</a> | <a href=\"{base}/search\">Search repo</a> | <a href=\"/web/notifications\">Notifications</a></p>\n{sub_html}</section>\n"
    )
}

pub fn render_issue_collab_html(
    header: &RepoHeaderCtx,
    issue_number: i64,
    versions: (i64, i64),
    labels: &[RepoLabel],
    assignees: &[AssigneeEntry],
    sub: Option<&Subscription>,
    comments: &[CommentViewItem],
) -> String {
    let (label_version, assignee_version) = versions;
    let base = format!("/web/repos/{}/{}/issues/{issue_number}", escape_html(&header.owner), escape_html(&header.name));
    let labels_list: String = labels.iter().map(|l| format!("<span class=\"badge\">{}</span> ", escape_html(&l.name))).collect();
    let assignees_list: String = assignees.iter().map(|a| format!("<span class=\"badge\">@{}</span> ", escape_html(&a.username))).collect();
    let sub_html = render_subscription_box(&format!("{base}/subscription"), sub);
    let mut mod_forms = String::new();
    for item in comments {
        let c = &item.comment;
        if header.effective_role >= Role::Triage {
            mod_forms.push_str(&format!(
                "<div class=\"comment-actions\" data-comment-number=\"{}\"><form data-web-action=\"comment-edit\" action=\"{base}/comments/{}/edit\"><input type=\"hidden\" name=\"expected_version\" value=\"{}\"/><input name=\"body\" value=\"{}\" required/><button>Edit #{}</button><p class=\"form-result\" role=\"status\"></p></form><form data-web-action=\"comment-delete\" action=\"{base}/comments/{}/delete\"><input type=\"hidden\" name=\"expected_version\" value=\"{}\"/><button>Delete #{}</button><p class=\"form-result\" role=\"status\"></p></form>",
                c.number, c.number, c.version, escape_html(&c.body), c.number, c.number, c.version, c.number,
            ));
            if header.effective_role >= Role::Maintain {
                mod_forms.push_str(&format!(
                    "<form data-web-action=\"comment-mod\" action=\"{base}/comments/{}/moderate\"><input type=\"hidden\" name=\"expected_version\" value=\"{}\"/><input name=\"action\" value=\"hide\"/><input name=\"reason\" placeholder=\"Reason\"/><button>Moderate #{}</button><p class=\"form-result\" role=\"status\"></p></form>",
                    c.number, c.version, c.number,
                ));
            }
            mod_forms.push_str("</div>\n");
        }
    }
    let meta_forms = if header.effective_role >= Role::Triage {
        format!(
            "<form data-web-action=\"issue-labels\" action=\"{base}/labels\"><input type=\"hidden\" name=\"expected_version\" value=\"{label_version}\"/><label>Labels (comma separated) <input name=\"labels\" value=\"{}\"/></label><button>Update labels</button><p class=\"form-result\" role=\"status\"></p></form>\n<form data-web-action=\"issue-assignees\" action=\"{base}/assignees\"><input type=\"hidden\" name=\"expected_version\" value=\"{assignee_version}\"/><label>Assignees (comma separated) <input name=\"assignees\" value=\"{}\"/></label><button>Update assignees</button><p class=\"form-result\" role=\"status\"></p></form>\n",
            labels.iter().map(|l| escape_html(&l.name)).collect::<Vec<_>>().join(","),
            assignees.iter().map(|a| escape_html(&a.username)).collect::<Vec<_>>().join(","),
        )
    } else {
        String::new()
    };
    format!(
        "<section class=\"issue-collaboration\" data-label-version=\"{label_version}\" data-assignee-version=\"{assignee_version}\">\n<div class=\"issue-labels\">Labels: {labels_list}</div>\n<div class=\"issue-assignees\">Assignees: {assignees_list}</div>\n{meta_forms}{sub_html}{mod_forms}</section>\n"
    )
}

pub fn render_pull_collab_html(
    header: &RepoHeaderCtx,
    pull: &PullRequest,
    reviews: &[PullReview],
    labels: &[RepoLabel],
    assignees: &[AssigneeEntry],
    sub: Option<&Subscription>,
    review_comments: &[(PullReviewComment, String)],
) -> String {
    let base = format!("/web/repos/{}/{}/pulls/{}", escape_html(&header.owner), escape_html(&header.name), pull.number);
    let outdated_rev_count = reviews.iter().filter(|r| r.outdated).count();
    let labels_list: String = labels.iter().map(|l| format!("<span class=\"badge\">{}</span> ", escape_html(&l.name))).collect();
    let assignees_list: String = assignees.iter().map(|a| format!("<span class=\"badge\">@{}</span> ", escape_html(&a.username))).collect();
    let sub_html = render_subscription_box(&format!("{base}/subscription"), sub);
    let mut rc_html = String::new();
    for (rc, author) in review_comments {
        let badge = if rc.outdated { "<span class=\"badge outdated\">outdated</span>" } else { "<span class=\"badge\">active</span>" };
        let acts = if header.effective_role >= Role::Triage {
            let mod_form = if header.effective_role >= Role::Maintain {
                format!(
                    "<form data-web-action=\"rc-mod\" action=\"{base}/review-comments/{}/moderate\"><input type=\"hidden\" name=\"expected_version\" value=\"{}\"/><input name=\"action\" value=\"hide\"/><input name=\"reason\" placeholder=\"Reason\"/><button>Moderate</button><p class=\"form-result\" role=\"status\"></p></form>",
                    rc.number, rc.version,
                )
            } else {
                String::new()
            };
            format!(
                "<form data-web-action=\"rc-edit\" action=\"{base}/review-comments/{}/edit\"><input type=\"hidden\" name=\"expected_version\" value=\"{}\"/><input name=\"body\" value=\"{}\" required/><button>Edit</button><p class=\"form-result\" role=\"status\"></p></form><form data-web-action=\"rc-delete\" action=\"{base}/review-comments/{}/delete\"><input type=\"hidden\" name=\"expected_version\" value=\"{}\"/><button>Delete</button><p class=\"form-result\" role=\"status\"></p></form>{mod_form}",
                rc.number, rc.version, escape_html(&rc.body), rc.number, rc.version,
            )
        } else {
            String::new()
        };
        rc_html.push_str(&format!(
            "<li class=\"pull-review-comment\" data-rc-number=\"{}\" data-rc-outdated=\"{}\" data-rc-commit=\"{}\" data-rc-path=\"{}\" data-rc-side=\"{}\" data-rc-line=\"{}\"><strong>@{}</strong> {badge} <code>{}:{} ({}) @ {}</code><p>{}</p>{acts}</li>\n",
            rc.number, rc.outdated, escape_html(&rc.commit_oid), escape_html(&rc.path), escape_html(&rc.side), rc.line,
            escape_html(author), escape_html(&rc.path), rc.line, escape_html(&rc.side), escape_html(&rc.commit_oid), escape_html(&rc.body),
        ));
    }
    let meta_forms = if header.effective_role >= Role::Triage {
        format!(
            "<form data-web-action=\"pull-labels\" action=\"{base}/labels\"><input type=\"hidden\" name=\"expected_version\" value=\"{}\"/><label>Labels <input name=\"labels\" value=\"{}\"/></label><button>Update labels</button><p class=\"form-result\" role=\"status\"></p></form>\n<form data-web-action=\"pull-assignees\" action=\"{base}/assignees\"><input type=\"hidden\" name=\"expected_version\" value=\"{}\"/><label>Assignees <input name=\"assignees\" value=\"{}\"/></label><button>Update assignees</button><p class=\"form-result\" role=\"status\"></p></form>\n<form data-web-action=\"pull-review-comment\" action=\"{base}/review-comments\"><h4>Inline line comment</h4><label>Path <input name=\"path\" required/></label><label>Side <input name=\"side\" value=\"right\" required/></label><label>Line <input name=\"line\" value=\"1\" required/></label><label>Body <textarea name=\"body\" required></textarea></label><button>Comment on line</button><p class=\"form-result\" role=\"status\"></p></form>\n",
            pull.label_version,
            labels.iter().map(|l| escape_html(&l.name)).collect::<Vec<_>>().join(","),
            pull.assignee_version,
            assignees.iter().map(|a| escape_html(&a.username)).collect::<Vec<_>>().join(","),
        )
    } else {
        String::new()
    };
    format!(
        "<section class=\"pull-collaboration\" data-outdated-reviews=\"{outdated_rev_count}\" data-review-comment-count=\"{}\">\n<div class=\"pull-labels\">Labels: {labels_list}</div>\n<div class=\"pull-assignees\">Assignees: {assignees_list}</div>\n{meta_forms}{sub_html}<ol class=\"pull-review-comments-list\">\n{rc_html}</ol>\n</section>\n",
        review_comments.len(),
    )
}

pub fn inject_before_main_end(html: String, fragment: &str) -> String {
    if let Some(pos) = html.rfind("</main>") {
        let mut out = String::with_capacity(html.len() + fragment.len());
        out.push_str(&html[..pos]);
        out.push_str(fragment);
        out.push_str(&html[pos..]);
        out
    } else {
        format!("{html}{fragment}")
    }
}
