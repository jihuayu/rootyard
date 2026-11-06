//! Browser-only, expiring sessions exchanged from an existing API credential.
use crate::{AppState, Error, auth, db, web::templates::html_response};
use axum::{
    extract::{Form, State},
    http::{HeaderMap, Method, Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use rand::RngCore;
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

const SESSION_LIFETIME_SECONDS: i64 = 12 * 60 * 60;

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == name).then(|| value.trim_matches('"').to_owned())
        })
}
pub fn session_token(headers: &HeaderMap) -> Option<String> {
    cookie(headers, "rootyard_session").filter(|s| {
        s.len() == 68 && s.starts_with("ryt_") && s[4..].bytes().all(|b| b.is_ascii_hexdigit())
    })
}
fn browser_origin(headers: &HeaderMap) -> bool {
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    if host.is_empty() || host.contains('/') || host.contains('@') {
        return false;
    }
    let proto = if headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        == Some("https")
    {
        "https"
    } else {
        "http"
    };
    let expected = format!("{proto}://{host}");
    if headers.get_all(header::ORIGIN).iter().count() != 1 {
        return false;
    }
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    origin == Some(expected.as_str())
        || (origin == Some("null")
            && headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) == Some("same-origin"))
}
fn secure_cookie(headers: &HeaderMap) -> Result<bool, Error> {
    if headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        == Some("https")
    {
        return Ok(true);
    }
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if host.starts_with("127.0.0.1:")
        || host.starts_with("localhost:")
        || host == "localhost"
        || host == "127.0.0.1"
    {
        return Ok(false);
    }
    Err(Error(
        StatusCode::FORBIDDEN,
        "browser sign-in requires HTTPS",
    ))
}
fn new_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
fn set_cookie(
    res: &mut Response,
    name: &str,
    value: &str,
    http_only: bool,
    secure: bool,
    max_age: i64,
) {
    let flag = if http_only { "; HttpOnly" } else { "" };
    let secure_flag = if secure { "; Secure" } else { "" };
    let raw =
        format!("{name}={value}; Path=/; Max-Age={max_age}; SameSite=Strict{flag}{secure_flag}");
    res.headers_mut()
        .append(header::SET_COOKIE, raw.parse().unwrap());
}

pub async fn middleware(
    State(state): State<Arc<AppState>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let headers = request.headers();
    let method = request.method();
    if matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        let path = request.uri().path();
        let has_cookie =
            session_token(headers).is_some() || cookie(headers, "rootyard_token").is_some();
        if (has_cookie || path == "/web/login") && !browser_origin(headers) {
            return Error(StatusCode::FORBIDDEN, "browser request origin rejected").into_response();
        }
        if has_cookie
            && path != "/web/login"
            && path != "/web/logout"
            && !headers.contains_key(header::AUTHORIZATION)
        {
            let Some(session) = session_token(headers) else {
                return Error(StatusCode::FORBIDDEN, "browser session required").into_response();
            };
            let Some(csrf) = headers.get("x-csrf-token").and_then(|v| v.to_str().ok()) else {
                return Error(StatusCode::FORBIDDEN, "CSRF token required").into_response();
            };
            let Ok(client) = state.pool.get().await else {
                return Error::internal("database unavailable").into_response();
            };
            let row=client.query_opt("SELECT s.csrf_digest FROM web_sessions s JOIN tokens t ON t.id=s.token_id WHERE t.digest=$1 AND NOT t.revoked AND NOT s.revoked AND s.expires_at>clock_timestamp()", &[&db::digest(&session)]).await;
            let Ok(Some(row)) = row else {
                return Error::unauthorized().into_response();
            };
            if row.get::<_, Vec<u8>>(0) != db::digest(csrf) {
                return Error(StatusCode::FORBIDDEN, "CSRF token invalid").into_response();
            }
        }
    }
    auth::web_scope(next.run(request)).await
}

pub async fn login_page() -> Response {
    html_response(StatusCode::OK,"<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Rootyard sign in</title><h1>Sign in</h1><p>Enter your username and API token to open a short browser session.</p><form method=\"post\" action=\"/web/login\"><label>Username <input name=\"username\" autocomplete=\"username\" required></label><label>API token <input name=\"token\" type=\"password\" autocomplete=\"off\" required></label><button>Sign in</button></form></html>".to_owned())
}
#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    token: String,
}
pub async fn login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(input): Form<LoginForm>,
) -> Result<Response, Error> {
    let secure = secure_cookie(&headers)?;
    let mut auth_headers = HeaderMap::new();
    auth_headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {}", input.token)
            .parse()
            .map_err(|_| Error::unauthorized())?,
    );
    let actor = auth::authenticate(&state.pool, &auth_headers).await?;
    if actor.username != input.username {
        return Err(Error::unauthorized());
    }
    let secret = format!("ryt_{}", new_secret());
    let csrf = new_secret();
    let token_id = Uuid::new_v4();
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, false).await?;
    tx.execute("INSERT INTO tokens(id,user_id,digest,read_only,expires_at,kind) VALUES($1,$2,$3,$4,clock_timestamp()+interval '12 hours','browser')",
        &[&token_id,&actor.id,&db::digest(&secret),&actor.read_only]).await.map_err(Error::internal)?;
    tx.execute("INSERT INTO web_sessions(token_id,csrf_digest,expires_at) VALUES($1,$2,clock_timestamp()+interval '12 hours')",
        &[&token_id,&db::digest(&csrf)]).await.map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
    let mut res = Redirect::to("/web/repos").into_response();
    *res.status_mut() = StatusCode::SEE_OTHER;
    set_cookie(
        &mut res,
        "rootyard_session",
        &secret,
        true,
        secure,
        SESSION_LIFETIME_SECONDS,
    );
    set_cookie(
        &mut res,
        "rootyard_csrf",
        &csrf,
        false,
        secure,
        SESSION_LIFETIME_SECONDS,
    );
    res.headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    Ok(res)
}
pub async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let secure = secure_cookie(&headers)?;
    if let Some(secret) = session_token(&headers) {
        let client = state.pool.get().await.map_err(Error::internal)?;
        client.execute("UPDATE web_sessions s SET revoked=true FROM tokens t WHERE t.id=s.token_id AND t.digest=$1", &[&db::digest(&secret)]).await.map_err(Error::internal)?;
        client
            .execute(
                "UPDATE tokens SET revoked=true WHERE digest=$1 AND kind='browser'",
                &[&db::digest(&secret)],
            )
            .await
            .map_err(Error::internal)?;
    }
    let mut res = Redirect::to("/web/login").into_response();
    *res.status_mut() = StatusCode::SEE_OTHER;
    set_cookie(&mut res, "rootyard_session", "", true, secure, 0);
    set_cookie(&mut res, "rootyard_csrf", "", false, secure, 0);
    res.headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    Ok(res)
}
pub async fn discover(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = super::handlers::authenticate_web(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let rows=tx.query("SELECT DISTINCT ns.slug,r.name FROM repositories r JOIN namespaces ns ON ns.id=r.owner_id WHERE r.state='ready' AND (ns.user_id=$1 OR EXISTS(SELECT 1 FROM organization_memberships m WHERE m.organization_id=r.owner_id AND m.user_id=$1) OR EXISTS(SELECT 1 FROM organization_team_members tm WHERE tm.organization_id=r.owner_id AND tm.user_id=$1) OR EXISTS(SELECT 1 FROM repository_collaborators c WHERE c.repository_id=r.id AND c.user_id=$1) OR EXISTS(SELECT 1 FROM repository_team_members tm WHERE tm.repository_id=r.id AND tm.user_id=$1)) ORDER BY ns.slug,r.name LIMIT 101", &[&actor.id]).await.map_err(Error::internal)?;
    let mut html = String::from(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Repositories</title><h1>Repositories</h1><form method=\"post\" action=\"/web/logout\"><button>Sign out</button></form><ul>",
    );
    for row in rows.iter().take(100) {
        let owner: String = row.get(0);
        let name: String = row.get(1);
        let o = super::sanitize::escape_html(&owner);
        let n = super::sanitize::escape_html(&name);
        html.push_str(&format!(
            "<li><a href=\"/web/repos/{o}/{n}\">{o}/{n}</a></li>"
        ));
    }
    html.push_str("</ul></html>");
    auth::finish_tx(tx, &actor, false).await?;
    Ok(html_response(StatusCode::OK, html))
}

pub async fn app_js() -> Response {
    const SCRIPT: &str = r#"'use strict';
function cookie(name) {
  const part = document.cookie.split('; ').find(p => p.startsWith(name + '='));
  return part ? part.slice(name.length + 1) : '';
}
for (const form of document.querySelectorAll('form[data-web-action]')) {
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const action = form.dataset.webAction;
    const fields = Object.fromEntries(new FormData(form));
    let body = fields;
    if (action === 'review' || action === 'merge') {
      const pull = form.closest('.pull-detail');
      if (action === 'review') body = {state:'approved', commit_oid:pull.dataset.headOid, body:fields.body || ''};
      else body = {expected_version:Number(pull.dataset.pullVersion), expected_head_oid:pull.dataset.headOid, expected_base_oid:pull.dataset.baseOid};
    }
    const status = form.querySelector('.form-result');
    status.textContent = 'Saving…';
    try {
      const result = await fetch(form.action, {method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json', 'X-CSRF-Token':cookie('rootyard_csrf')},
        body:JSON.stringify(body)});
      if (result.status === 401) { location.assign('/web/login'); return; }
      if (!result.ok) { status.textContent = `Request failed (${result.status}). Check your permission or refresh the page.`; return; }
      location.reload();
    } catch (_) { status.textContent = 'Connection failed. Try again.'; }
  });
}
"#;
    let mut res = (StatusCode::OK, SCRIPT).into_response();
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        "text/javascript; charset=utf-8".parse().unwrap(),
    );
    res.headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    res
}
