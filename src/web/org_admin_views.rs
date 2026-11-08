//! Server-rendered HTML for the organization administration pages.
//!
//! Every value that reaches the document goes through
//! [`escape_html`](crate::web::sanitize::escape_html); identifiers are still
//! validated by the handlers before a page is built, so escaping is defence in
//! depth rather than the only barrier. Mutation forms follow the shared
//! `/web/app.js` convention (`data-web-action`, `method="post"`) and always
//! carry the current `expected_version` for an existing membership, so the
//! browser submits the same optimistic-concurrency value the backend checks.
//! No token, session secret, or CSRF value is ever rendered: the CSRF token is
//! read by the first-party script from its `SameSite=Strict` cookie only.

use crate::{pagination, web::sanitize::escape_html};

const ROLE_NAMES: [&str; 5] = ["read", "triage", "write", "maintain", "admin"];

/// Per-page authorization-derived context. `can_members`/`can_teams` are
/// computed from the existing backend role plus the token scope gate; when they
/// are false the page renders no mutation form at all, while the backend still
/// re-checks the request.
pub struct PageCtx {
    pub slug: String,
    pub role: String,
    pub actor: String,
    pub can_members: bool,
    pub can_teams: bool,
}

pub struct OrgRow {
    pub slug: String,
    pub role: String,
}

pub struct MemberRow {
    pub username: String,
    pub role: String,
    pub version: i64,
}

pub struct TeamRow {
    pub slug: String,
    pub name: String,
    pub role: String,
    pub version: i64,
    pub members: i64,
}

pub struct TeamMemberRow {
    pub username: String,
    pub role: Option<String>,
}

pub struct Overview {
    pub version: i64,
    pub created_at: String,
    pub members: i64,
    pub teams: i64,
    pub audit_entries: i64,
}

fn shell(page: &PageCtx, title: &str, inner: &str) -> String {
    let title = escape_html(title);
    let actor = escape_html(&page.actor);
    let role = escape_html(&page.role);
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{title}</title>\
         <script src=\"/web/app.js\" defer></script>\
         <style>body{{font-family:system-ui,sans-serif;margin:1.5rem;line-height:1.5}}\
         nav a{{margin-right:1rem}}.badge{{padding:0.15rem 0.45rem;border-radius:4px;background:#eef}}\
         .version{{color:#555;font-size:0.9em}}form{{margin:0.4rem 0}}</style></head>\
         <body data-view=\"organizations\" data-actor=\"{actor}\">\
         <nav class=\"site-nav\"><a href=\"/web/repos\">Repositories</a>\
         <a href=\"/web/organizations\">Organizations</a>\
         <a href=\"/web/settings/tokens\">Tokens</a>\
         <a href=\"/web/settings/sessions\">Sessions</a>\
         <form method=\"post\" action=\"/web/logout\"><button>Sign out</button></form></nav>\
         <header class=\"org-header\"><h1>{title}</h1>\
         <p>Signed in as <span class=\"actor\">{actor}</span> \
         <span class=\"badge\" data-org-role=\"{role}\">{role}</span></p></header>\
         <main class=\"org-main\">{inner}</main></body></html>"
    )
}

fn org_nav(page: &PageCtx) -> String {
    let base = escape_html(&format!("/web/organizations/{}", page.slug));
    format!(
        "<nav class=\"org-nav\"><a href=\"{base}\">Overview</a>\
         <a href=\"{base}/members\">Members</a><a href=\"{base}/teams\">Teams</a></nav>"
    )
}

fn role_options(selected: &str) -> String {
    let mut html = String::new();
    for role in ROLE_NAMES {
        let marked = if role == selected { " selected" } else { "" };
        html.push_str(&format!("<option value=\"{role}\"{marked}>{role}</option>"));
    }
    html
}

fn next_link(base: &str, limit: i64, next: Option<&str>) -> String {
    match next {
        Some(cursor) => {
            let href = format!("{base}?limit={limit}&cursor={}", pagination::query_value(cursor));
            format!(
                "<p class=\"next-page\"><a href=\"{}\">Next page</a></p>",
                escape_html(&href)
            )
        }
        None => "<p class=\"list-end\">End of list.</p>".to_owned(),
    }
}

pub fn render_organizations(page: &PageCtx, rows: &[OrgRow], limit: i64, next: Option<&str>) -> String {
    let mut items = String::new();
    for row in rows {
        let slug = escape_html(&row.slug);
        let href = escape_html(&format!("/web/organizations/{}", row.slug));
        let role = escape_html(&row.role);
        items.push_str(&format!(
            "<li class=\"org-row\" data-org-slug=\"{slug}\"><a href=\"{href}\">{slug}</a> \
             <span class=\"badge\" data-org-role=\"{role}\">{role}</span></li>"
        ));
    }
    if items.is_empty() {
        items.push_str("<li>You are not a member of any organization.</li>");
    }
    let inner = format!(
        "<p>Only organizations where your account holds a direct membership are listed. \
         Restricted tokens additionally need the <code>org:read</code> grant.</p>\
         <ul class=\"org-list\">{items}</ul>{}",
        next_link("/web/organizations", limit, next)
    );
    shell(page, "Organizations", &inner)
}

pub fn render_overview(page: &PageCtx, overview: &Overview) -> String {
    let slug = escape_html(&page.slug);
    let created = escape_html(&overview.created_at);
    let inner = format!(
        "{}<section class=\"org-overview\">\
         <p>Organization version {version} &middot; created {created}</p>\
         <ul><li><a href=\"/web/organizations/{slug}/members\">Members: {members}</a></li>\
         <li><a href=\"/web/organizations/{slug}/teams\">Teams: {teams}</a></li>\
         <li>Recorded audit entries: {audit}</li></ul></section>",
        org_nav(page),
        version = overview.version,
        members = overview.members,
        teams = overview.teams,
        audit = overview.audit_entries,
    );
    shell(page, &format!("Organization {}", page.slug), &inner)
}

pub fn render_members(page: &PageCtx, rows: &[MemberRow], limit: i64, next: Option<&str>) -> String {
    let action = escape_html(&format!("/web/organizations/{}/members", page.slug));
    let mut items = String::new();
    for row in rows {
        let username = escape_html(&row.username);
        let role = escape_html(&row.role);
        let actions = if page.can_members {
            let remove = escape_html(&format!(
                "/web/organizations/{}/members/{}/remove",
                page.slug, row.username
            ));
            let options = role_options(&row.role);
            format!(
                "<form method=\"post\" action=\"{action}\" data-web-action=\"org-member-set\">\
                 <input type=\"hidden\" name=\"username\" value=\"{username}\">\
                 <input type=\"hidden\" name=\"expected_version\" value=\"{}\">\
                 <select name=\"role\" aria-label=\"Role for {username}\">{options}</select>\
                 <button>Save role</button><p class=\"form-result\" role=\"status\"></p></form>\
                 <form method=\"post\" action=\"{remove}\" data-web-action=\"org-member-remove\">\
                 <button>Remove</button><p class=\"form-result\" role=\"status\"></p></form>",
                row.version,
            )
        } else {
            String::new()
        };
        items.push_str(&format!(
            "<li class=\"member-row\" data-member=\"{username}\">\
             <span class=\"member-name\">{username}</span> \
             <span class=\"badge\" data-member-role=\"{role}\">{role}</span> \
             <span class=\"version\">version {}</span>{actions}</li>",
            row.version,
        ));
    }
    if items.is_empty() {
        items.push_str("<li>No direct memberships.</li>");
    }
    let add = if page.can_members {
        format!(
            "<h2>Add member</h2>\
             <form method=\"post\" action=\"{action}\" data-web-action=\"org-member-set\">\
             <label>Username <input name=\"username\" maxlength=\"63\" required></label>\
             <label>Role <select name=\"role\">{options}</select></label>\
             <button>Add member</button><p class=\"form-result\" role=\"status\"></p></form>\
             <p>Adding an existing member here uses the versioned role form above instead.</p>",
            options = role_options("read"),
        )
    } else {
        "<p>Your role or token scope does not allow changing organization memberships.</p>".to_owned()
    };
    let base = format!("/web/organizations/{}/members", page.slug);
    let inner = format!(
        "{}\
         <p>Memberships grant organization-wide repository roles. Changes are audited server-side.</p>\
         <ul class=\"member-list\">{items}</ul>{}\
         {add}",
        org_nav(page),
        next_link(&base, limit, next),
    );
    shell(page, &format!("{} members", page.slug), &inner)
}

pub fn render_teams(page: &PageCtx, rows: &[TeamRow], limit: i64, next: Option<&str>) -> String {
    let mut items = String::new();
    for row in rows {
        let href = escape_html(&format!("/web/organizations/{}/teams/{}", page.slug, row.slug));
        let name = escape_html(&row.name);
        let slug = escape_html(&row.slug);
        let role = escape_html(&row.role);
        items.push_str(&format!(
            "<li class=\"team-row\" data-team-slug=\"{slug}\"><a href=\"{href}\">{name}</a> \
             <span class=\"badge\" data-team-role=\"{role}\">{role}</span> \
             <span class=\"version\">members {} &middot; version {}</span></li>",
            row.members, row.version,
        ));
    }
    if items.is_empty() {
        items.push_str("<li>No teams yet.</li>");
    }
    let create = if page.can_teams {
        format!(
            "<h2>Create team</h2>\
             <form method=\"post\" action=\"{action}\" data-web-action=\"org-team-create\">\
             <label>Slug <input name=\"slug\" pattern=\"[a-z0-9][a-z0-9_-]{{0,62}}\" maxlength=\"63\" required></label>\
             <label>Name <input name=\"name\" maxlength=\"128\" required></label>\
             <label>Role <select name=\"role\">{options}</select></label>\
             <button>Create team</button><p class=\"form-result\" role=\"status\"></p></form>",
            action = escape_html(&format!("/web/organizations/{}/teams", page.slug)),
            options = role_options("read"),
        )
    } else {
        "<p>Your role or token scope does not allow changing organization teams.</p>".to_owned()
    };
    let base = format!("/web/organizations/{}/teams", page.slug);
    let inner = format!(
        "{}\
         <p>Teams grant their role to every member on the team. Membership changes are audited.</p>\
         <ul class=\"team-list\">{items}</ul>{}\
         {create}",
        org_nav(page),
        next_link(&base, limit, next),
    );
    shell(page, &format!("{} teams", page.slug), &inner)
}

pub fn render_team(
    page: &PageCtx,
    team: &TeamRow,
    rows: &[TeamMemberRow],
    limit: i64,
    next: Option<&str>,
) -> String {
    let team_name = escape_html(&team.name);
    let team_role = escape_html(&team.role);
    let mut items = String::new();
    for row in rows {
        let username = escape_html(&row.username);
        let role = escape_html(row.role.as_deref().unwrap_or("not a member"));
        let actions = if page.can_teams {
            let remove = escape_html(&format!(
                "/web/organizations/{}/teams/{}/members/{}/remove",
                page.slug, team.slug, row.username
            ));
            format!(
                "<form method=\"post\" action=\"{remove}\" data-web-action=\"org-team-member-remove\">\
                 <button>Remove from team</button><p class=\"form-result\" role=\"status\"></p></form>"
            )
        } else {
            String::new()
        };
        items.push_str(&format!(
            "<li class=\"team-member-row\" data-team-member=\"{username}\">\
             <span class=\"member-name\">{username}</span> \
             <span class=\"badge\">{role}</span>{actions}</li>"
        ));
    }
    if items.is_empty() {
        items.push_str("<li>This team has no members.</li>");
    }
    let add = if page.can_teams {
        let action =
            escape_html(&format!("/web/organizations/{}/teams/{}/members", page.slug, team.slug));
        format!(
            "<h2>Add team member</h2>\
             <form method=\"post\" action=\"{action}\" data-web-action=\"org-team-member-add\">\
             <label>Username <input name=\"username\" maxlength=\"63\" required></label>\
             <button>Add to team</button><p class=\"form-result\" role=\"status\"></p></form>\
             <p>The user must already be an organization member.</p>"
        )
    } else {
        "<p>Your role or token scope does not allow changing team membership.</p>".to_owned()
    };
    let base = format!("/web/organizations/{}/teams/{}", page.slug, team.slug);
    let inner = format!(
        "{}\
         <p>Team <strong>{team_name}</strong> \
         <span class=\"badge\" data-team-role=\"{team_role}\">{team_role}</span> \
         <span class=\"version\">version {team_version}</span></p>\
         <p><a href=\"{teams_href}\">All teams</a></p>\
         <ul class=\"team-member-list\">{items}</ul>{}\
         {add}",
        org_nav(page),
        next_link(&base, limit, next),
        teams_href = escape_html(&format!("/web/organizations/{}/teams", page.slug)),
        team_version = team.version,
    );
    shell(page, &format!("{} team", team.slug), &inner)
}
