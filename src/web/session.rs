//! Browser-only, expiring sessions exchanged from an existing API credential.
//!
//! A browser session is a short-lived `browser` token plus a CSRF-bound
//! `web_sessions` row. The session secret embeds the API token that authorized
//! sign-in so parent-token revocation also terminates the browser session. The
//! embedded parent id is bound by the secret's SHA-256 digest: changing it
//! invalidates the stored browser token instead of selecting another parent.
use crate::{AppState, Error, auth, db, web::templates::html_response};
use axum::{
    extract::{Form, Query, State},
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use base64::Engine;
use deadpool_postgres::Pool;
use rand::RngCore;
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

const SESSION_LIFETIME_SECONDS: i64 = 12 * 60 * 60;
const SESSION_PREFIX: &str = "ryt_";
const PARENT_HEX_LEN: usize = 32;
const DEFAULT_RETURN_TO: &str = "/web/repos";

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(header::COOKIE)?.to_str().ok()?.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name).then(|| value.trim_matches('"').to_owned())
    })
}

pub fn session_token(headers: &HeaderMap) -> Option<String> {
    cookie(headers, "rootyard_session")
        .filter(|s| s.len() == 68 && s.starts_with(SESSION_PREFIX) && s[4..].bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Normalise browser cookies into the `Authorization` header understood by
/// [`auth::authenticate`].
///
/// The browser credential is only the HttpOnly session cookie minted by
/// `/web/login`. Long-lived API tokens must not be replayed as raw web
/// cookies or headers; API clients can still use Authorization directly.
pub fn normalize_web_headers(headers: &HeaderMap) -> HeaderMap {
    if headers.contains_key(header::AUTHORIZATION) {
        return headers.clone();
    }
    let mut out = headers.clone();
    if let Some(tok) = session_token(headers)
        && let Ok(hv) = HeaderValue::from_str(&format!("Bearer {tok}"))
    {
        out.insert(header::AUTHORIZATION, hv);
    }
    out
}

/// Authenticate a browser request (session cookie) or an API request header.
pub async fn authenticate_web(pool: &Pool, headers: &HeaderMap) -> Result<db::Identity, Error> {
    auth::authenticate(pool, &normalize_web_headers(headers)).await
}

fn session_parent(secret: &str) -> Option<Uuid> {
    let bytes = hex::decode(secret.get(4..4 + PARENT_HEX_LEN)?).ok()?;
    Uuid::from_slice(&bytes).ok()
}

fn new_session_secret(parent: Uuid) -> String {
    let mut random = [0u8; 16];
    rand::rng().fill_bytes(&mut random);
    format!("{SESSION_PREFIX}{}{}", parent.simple(), hex::encode(random))
}

fn new_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn authorization_credential(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    if raw.len() > 512 {
        return None;
    }
    let (scheme, value) = raw.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") {
        return Some(value.to_owned());
    }
    if scheme.eq_ignore_ascii_case("basic") {
        let bytes = base64::engine::general_purpose::STANDARD.decode(value).ok()?;
        let pair = String::from_utf8(bytes).ok()?;
        return pair.split_once(':').map(|(_, token)| token.to_owned());
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WebAuthMode {
    CookieOnly,
    BrowserSession,
    HeaderApiOrOther,
}

async fn web_auth_mode(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    session: Option<&str>,
) -> Result<WebAuthMode, Box<Response>> {
    if !headers.contains_key(header::AUTHORIZATION) {
        return Ok(if session.is_some() { WebAuthMode::CookieOnly } else { WebAuthMode::HeaderApiOrOther });
    }
    let Some(credential) = authorization_credential(headers) else {
        return Ok(WebAuthMode::HeaderApiOrOther);
    };
    if credential.len() != 68
        || !credential.starts_with(SESSION_PREFIX)
        || !credential[4..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Ok(WebAuthMode::HeaderApiOrOther);
    }
    let client =
        state.pool.get().await.map_err(|_| Box::new(Error::internal("database unavailable").into_response()))?;
    let row = client
        .query_opt("SELECT kind FROM tokens WHERE digest=$1", &[&db::digest(&credential)])
        .await
        .map_err(|_| Box::new(Error::internal("database unavailable").into_response()))?;
    let is_browser = row.as_ref().is_some_and(|row| row.get::<_, String>(0) == "browser");
    if is_browser {
        if session == Some(credential.as_str()) {
            return Ok(WebAuthMode::BrowserSession);
        }
        // Browser credentials are only accepted through the HttpOnly session
        // cookie, where the middleware can bind them to the parent API token
        // and require CSRF for mutations.
        return Err(Box::new(Error::unauthorized().into_response()));
    }
    // An explicit Authorization header wins over any stale browser cookie.
    // API tokens remain independent; malformed/unknown credentials fail in
    // the handler without the stale cookie shadowing them.
    Ok(WebAuthMode::HeaderApiOrOther)
}

fn browser_origin(headers: &HeaderMap) -> bool {
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    if host.is_empty() || host.contains('/') || host.contains('@') {
        return false;
    }
    let proto =
        if headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()) == Some("https") { "https" } else { "http" };
    let expected = format!("{proto}://{host}");
    if headers.get_all(header::ORIGIN).iter().count() != 1 {
        return false;
    }
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    origin == Some(expected.as_str())
        || (origin == Some("null")
            && headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) == Some("same-origin"))
}

fn browser_navigation(headers: &HeaderMap) -> bool {
    headers.get("sec-fetch-mode").and_then(|v| v.to_str().ok()).is_some_and(|v| v.eq_ignore_ascii_case("navigate"))
        || headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()).is_some_and(|v| v.contains("text/html"))
}

fn secure_cookie(headers: &HeaderMap) -> Result<bool, Error> {
    if headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()) == Some("https") {
        return Ok(true);
    }
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    if host.starts_with("127.0.0.1:") || host.starts_with("localhost:") || host == "localhost" || host == "127.0.0.1" {
        return Ok(false);
    }
    Err(Error(StatusCode::FORBIDDEN, "browser sign-in requires HTTPS"))
}

fn set_cookie(res: &mut Response, name: &str, value: &str, http_only: bool, secure: bool, max_age: i64) {
    let flag = if http_only { "; HttpOnly" } else { "" };
    let secure_flag = if secure { "; Secure" } else { "" };
    let raw = format!("{name}={value}; Path=/; Max-Age={max_age}; SameSite=Strict{flag}{secure_flag}");
    res.headers_mut().append(header::SET_COOKIE, raw.parse().unwrap());
}

fn clear_cookies(res: &mut Response, headers: &HeaderMap) {
    let secure = secure_cookie(headers).unwrap_or(false);
    set_cookie(res, "rootyard_session", "", true, secure, 0);
    set_cookie(res, "rootyard_csrf", "", false, secure, 0);
    res.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn percent_decode_ascii(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len() {
                return None;
            }
            let decoded = hex_value(bytes[index + 1])? * 16 + hex_value(bytes[index + 2])?;
            if decoded > 0x7f {
                return None;
            }
            out.push(decoded);
            index += 3;
        } else {
            if byte > 0x7f {
                return None;
            }
            out.push(byte);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn header_safe_ascii(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'_'
                        | b'.'
                        | b'~'
                        | b'/'
                        | b'?'
                        | b'&'
                        | b'='
                        | b'%'
                        | b':'
                        | b'+'
                        | b'!'
                        | b'$'
                        | b'\''
                        | b'('
                        | b')'
                        | b'*'
                        | b'@'
                        | b','
                        | b';'
                        | b'['
                        | b']'
                )
        })
}

fn is_safe_return_to(value: &str) -> bool {
    if !header_safe_ascii(value) || value.starts_with("//") || value.contains("//") {
        return false;
    }
    let raw_path = value.split('?').next().unwrap_or("");
    let (Some(decoded_path), Some(decoded_whole)) = (percent_decode_ascii(raw_path), percent_decode_ascii(value))
    else {
        return false;
    };
    if !decoded_whole.is_ascii()
        || decoded_whole.contains('\\')
        || decoded_whole.contains('%')
        || decoded_whole.contains('#')
        || decoded_whole.chars().any(char::is_control)
    {
        return false;
    }
    if !(decoded_path.starts_with("/web/") || decoded_path.starts_with("/ui/"))
        || decoded_path.starts_with("/web/login")
        || decoded_path.contains("//")
        || decoded_path.contains('\\')
        || decoded_path.contains('%')
        || decoded_path.chars().any(char::is_control)
    {
        return false;
    }
    !decoded_path.split('/').any(|segment| segment == "." || segment == "..")
}

fn safe_return_to(value: Option<&str>) -> &str {
    value.filter(|candidate| is_safe_return_to(candidate)).unwrap_or(DEFAULT_RETURN_TO)
}

fn encode_query_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn login_target(path: &str, query: Option<&str>) -> String {
    match query.filter(|q| !q.is_empty()) {
        Some(q) => format!("{path}?{q}"),
        None => path.to_owned(),
    }
}

fn login_redirect(path: &str, query: Option<&str>, headers: &HeaderMap) -> Response {
    let target = login_target(path, query);
    let location = if is_safe_return_to(&target) {
        format!("/web/login?return_to={}", encode_query_value(&target))
    } else {
        "/web/login".to_owned()
    };
    let mut res = Redirect::to(&location).into_response();
    *res.status_mut() = StatusCode::SEE_OTHER;
    clear_cookies(&mut res, headers);
    res
}

fn error_page(status: StatusCode) -> Response {
    let (title, message) = match status {
        StatusCode::FORBIDDEN => {
            ("Permission denied", "Your account does not have access to this repository or action.")
        }
        StatusCode::NOT_FOUND => {
            ("Not found", "The requested repository or page was not found, or you do not have access to it.")
        }
        _ => ("Request failed", "The request could not be completed. Refresh the page or sign in again."),
    };
    let body = format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>{title}</title><h1>{title}</h1><p>{message}</p><p><a href=\"/web/repos\">My repositories</a> &middot; <a href=\"/web/login\">Sign in</a></p></html>"
    );
    html_response(status, body)
}

async fn validate_session(state: &Arc<AppState>, secret: &str, csrf: Option<&str>) -> Result<(), Box<Response>> {
    let Some(parent) = session_parent(secret) else {
        return Err(Box::new(Error::unauthorized().into_response()));
    };
    let client =
        state.pool.get().await.map_err(|_| Box::new(Error::internal("database unavailable").into_response()))?;
    let row = client
        .query_opt(
            "SELECT s.csrf_digest FROM web_sessions s \
             JOIN tokens t ON t.id=s.token_id \
             JOIN tokens p ON p.id=$2 AND p.user_id=t.user_id AND p.kind='api' \
                  AND p.is_restricted = false \
                  AND NOT p.revoked AND (p.expires_at IS NULL OR p.expires_at>clock_timestamp()) \
             WHERE t.digest=$1 AND NOT t.revoked AND NOT s.revoked \
               AND s.expires_at>clock_timestamp()",
            &[&db::digest(secret), &parent],
        )
        .await
        .map_err(|_| Box::new(Error::internal("database unavailable").into_response()))?;
    let Some(row) = row else {
        return Err(Box::new(Error::unauthorized().into_response()));
    };
    if let Some(csrf) = csrf
        && row.get::<_, Vec<u8>>(0) != db::digest(csrf)
    {
        return Err(Box::new(Error(StatusCode::FORBIDDEN, "CSRF token invalid").into_response()));
    }
    Ok(())
}

/// True when any `Authorization` value uses Basic. Browsers attach this
/// ambient credential after a `WWW-Authenticate` challenge, so it cannot be
/// treated like an explicit non-browser Bearer/API credential on a mutating
/// web route.
fn basic_authorization(headers: &HeaderMap) -> bool {
    // Treat *any* Basic Authorization value as ambient. Duplicate or mixed
    // headers must not smuggle a Basic credential past this gate.
    headers.get_all(header::AUTHORIZATION).iter().any(|value| {
        value
            .to_str()
            .ok()
            .and_then(|raw| raw.split_once(' '))
            .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
    })
}

pub async fn middleware(
    State(state): State<Arc<AppState>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let headers = request.headers().clone();
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().map(str::to_owned);
    let session = session_token(&headers);
    let mutation = matches!(method, Method::POST | Method::PUT | Method::PATCH | Method::DELETE);
    let is_navigation = browser_navigation(&headers);

    let auth_mode = match web_auth_mode(&state, &headers, session.as_deref()).await {
        Ok(mode) => mode,
        Err(response) => return *response,
    };
    let session_mode = matches!(auth_mode, WebAuthMode::CookieOnly | WebAuthMode::BrowserSession);

    if mutation {
        // Ambient Basic credentials are browser authority. Reject them for
        // every web mutation except the sign-in form itself (which already
        // enforces Origin), instead of letting them skip Origin/CSRF. Bearer
        // remains an explicit, non-ambient API credential.
        if path != "/web/login" && basic_authorization(&headers) {
            return Error(
                StatusCode::FORBIDDEN,
                "browser mutations require a session cookie and CSRF token",
            )
            .into_response();
        }
        if path == "/web/logout" {
            if session_mode && !browser_origin(&headers) {
                return Error(StatusCode::FORBIDDEN, "browser request origin rejected").into_response();
            }
        } else if path == "/web/login" {
            if !browser_origin(&headers) {
                return Error(StatusCode::FORBIDDEN, "browser request origin rejected").into_response();
            }
        } else if session_mode {
            let Some(secret) = session.as_deref() else {
                return Error::unauthorized().into_response();
            };
            if !browser_origin(&headers) {
                return Error(StatusCode::FORBIDDEN, "browser request origin rejected").into_response();
            }
            let Some(csrf) = headers.get("x-csrf-token").and_then(|v| v.to_str().ok()) else {
                return Error(StatusCode::FORBIDDEN, "CSRF token required").into_response();
            };
            if let Err(response) = validate_session(&state, secret, Some(csrf)).await {
                return *response;
            }
        }
    } else if session_mode
        && let Some(secret) = session.as_deref()
        && let Err(response) = validate_session(&state, secret, None).await
    {
        return if is_navigation { login_redirect(&path, query.as_deref(), &headers) } else { *response };
    }

    let response = auth::web_scope(next.run(request)).await;
    if is_navigation && matches!(method, Method::GET | Method::HEAD) {
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED {
            return login_redirect(&path, query.as_deref(), &headers);
        }
        if matches!(status, StatusCode::FORBIDDEN | StatusCode::NOT_FOUND) {
            return error_page(status);
        }
    }
    response
}

#[derive(Deserialize)]
pub struct ReturnTo {
    #[serde(default)]
    return_to: Option<String>,
}

fn render_login(target: &str, error: Option<&str>) -> Response {
    let hidden = super::sanitize::escape_html(target);
    let error_html = error
        .map(|message| format!("<p class=\"form-error\" role=\"alert\">{}</p>", super::sanitize::escape_html(message)))
        .unwrap_or_default();
    let body = format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Rootyard sign in</title><h1>Sign in</h1><p>Enter your username and API token to open a short browser session.</p>{error_html}<form method=\"post\" action=\"/web/login\"><input type=\"hidden\" name=\"return_to\" value=\"{hidden}\"><label>Username <input name=\"username\" autocomplete=\"username\" required></label><label>API token <input name=\"token\" type=\"password\" autocomplete=\"off\" required></label><button>Sign in</button></form></html>"
    );
    html_response(StatusCode::OK, body)
}

pub async fn login_page(Query(query): Query<ReturnTo>) -> Response {
    render_login(safe_return_to(query.return_to.as_deref()), None)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginForm {
    username: String,
    token: String,
    #[serde(default)]
    return_to: Option<String>,
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(input): Form<LoginForm>,
) -> Result<Response, Error> {
    let secure = secure_cookie(&headers)?;
    let target = safe_return_to(input.return_to.as_deref()).to_owned();
    let mut auth_headers = HeaderMap::new();
    auth_headers
        .insert(header::AUTHORIZATION, format!("Bearer {}", input.token).parse().map_err(|_| Error::unauthorized())?);
    let actor = match auth::authenticate(&state.pool, &auth_headers).await {
        Ok(actor) => actor,
        Err(error) if error.0 == StatusCode::UNAUTHORIZED => {
            let mut response = render_login(&target, Some("Invalid username or API token."));
            *response.status_mut() = StatusCode::UNAUTHORIZED;
            return Ok(response);
        }
        Err(error) => return Err(error),
    };
    if actor.username != input.username {
        let mut response = render_login(&target, Some("Invalid username or API token."));
        *response.status_mut() = StatusCode::UNAUTHORIZED;
        return Ok(response);
    }
    let secret = new_session_secret(actor.token_id);
    let csrf = new_secret();
    let token_id = Uuid::new_v4();
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let parent = client
        .query_opt(
            "SELECT kind, is_restricted FROM tokens WHERE id=$1 AND user_id=$2",
            &[&actor.token_id, &actor.id],
        )
        .await
        .map_err(Error::internal)?;
    let Some(parent) = parent else {
        return Err(Error::unauthorized());
    };
    let kind: String = parent.get(0);
    let restricted: bool = parent.get(1);
    if restricted {
        // Restricted API tokens cannot mint a browser child until a parent
        // binding exists: a child must never become an unrestricted proxy.
        let mut response = render_login(
            &target,
            Some("Restricted API tokens cannot open a browser session yet."),
        );
        *response.status_mut() = StatusCode::FORBIDDEN;
        return Ok(response);
    }
    if kind != "api" {
        let mut response = render_login(
            &target,
            Some("API token sign-in is required; browser sessions cannot sign in again."),
        );
        *response.status_mut() = StatusCode::UNAUTHORIZED;
        return Ok(response);
    }
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, false).await?;
    let inserted = tx
        .execute(
            "INSERT INTO tokens(id,user_id,digest,read_only,expires_at,kind,is_restricted) \
             SELECT $1,$2,$3,$4,LEAST(clock_timestamp()+interval '12 hours',COALESCE(p.expires_at,clock_timestamp()+interval '12 hours')),'browser',p.is_restricted \
             FROM tokens p WHERE p.id=$5 AND p.user_id=$2 AND p.kind='api' AND NOT p.revoked \
               AND p.is_restricted = false",
            &[
                &token_id,
                &actor.id,
                &db::digest(&secret),
                &actor.read_only,
                &actor.token_id,
            ],
        )
        .await
        .map_err(Error::internal)?;
    if inserted != 1 {
        return Err(Error::unauthorized());
    }
    tx.execute(
        "INSERT INTO web_sessions(token_id,csrf_digest,expires_at) SELECT $1,$2,expires_at FROM tokens WHERE id=$1",
        &[&token_id, &db::digest(&csrf)],
    )
    .await
    .map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
    let mut res = Redirect::to(&target).into_response();
    *res.status_mut() = StatusCode::SEE_OTHER;
    set_cookie(&mut res, "rootyard_session", &secret, true, secure, SESSION_LIFETIME_SECONDS);
    set_cookie(&mut res, "rootyard_csrf", &csrf, false, secure, SESSION_LIFETIME_SECONDS);
    res.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    Ok(res)
}

pub async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, Error> {
    let secure = secure_cookie(&headers)?;
    if let Some(secret) = session_token(&headers) {
        let client = state.pool.get().await.map_err(Error::internal)?;
        client
            .execute(
                "UPDATE web_sessions s SET revoked=true FROM tokens t WHERE t.id=s.token_id AND t.digest=$1",
                &[&db::digest(&secret)],
            )
            .await
            .map_err(Error::internal)?;
        client
            .execute("UPDATE tokens SET revoked=true WHERE digest=$1 AND kind='browser'", &[&db::digest(&secret)])
            .await
            .map_err(Error::internal)?;
    }
    let mut res = Redirect::to("/web/login").into_response();
    *res.status_mut() = StatusCode::SEE_OTHER;
    set_cookie(&mut res, "rootyard_session", "", true, secure, 0);
    set_cookie(&mut res, "rootyard_csrf", "", false, secure, 0);
    res.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    Ok(res)
}

pub async fn discover(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, Error> {
    let actor = authenticate_web(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, false).await?;
    // Restricted tokens discover only their exact repository grants. Ownership,
    // organisation and collaborator rows must not leak other repository names.
    let restricted = auth::token_is_restricted(&tx, &actor).await?;
    let rows = if restricted {
        tx.query(
            "SELECT DISTINCT ns.slug,r.name FROM repositories r JOIN namespaces ns ON ns.id=r.owner_id \
             WHERE r.state='ready' AND EXISTS (SELECT 1 FROM token_repository_scopes ts \
                 WHERE ts.token_id=$1 AND ts.repository_id=r.id) ORDER BY ns.slug,r.name LIMIT 101",
            &[&actor.token_id],
        )
        .await
        .map_err(Error::internal)?
    } else {
        tx.query("SELECT DISTINCT ns.slug,r.name FROM repositories r JOIN namespaces ns ON ns.id=r.owner_id WHERE r.state='ready' AND (ns.user_id=$1 OR EXISTS(SELECT 1 FROM organization_memberships m WHERE m.organization_id=r.owner_id AND m.user_id=$1) OR EXISTS(SELECT 1 FROM organization_team_members tm WHERE tm.organization_id=r.owner_id AND tm.user_id=$1) OR EXISTS(SELECT 1 FROM repository_collaborators c WHERE c.repository_id=r.id AND c.user_id=$1) OR EXISTS(SELECT 1 FROM repository_team_members tm WHERE tm.repository_id=r.id AND tm.user_id=$1)) ORDER BY ns.slug,r.name LIMIT 101", &[&actor.id]).await.map_err(Error::internal)?
    };
    let mut html = String::from(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Repositories</title><h1>Repositories</h1><form method=\"post\" action=\"/web/logout\"><button>Sign out</button></form>",
    );
    if rows.is_empty() {
        html.push_str("<p>No repositories are available to your account. Ask an owner for access.</p>");
    } else {
        html.push_str("<ul>");
        for row in rows.iter().take(100) {
            let owner: String = row.get(0);
            let name: String = row.get(1);
            let o = super::sanitize::escape_html(&owner);
            let n = super::sanitize::escape_html(&name);
            html.push_str(&format!("<li><a href=\"/web/repos/{o}/{n}\">{o}/{n}</a></li>"));
        }
        html.push_str("</ul>");
    }
    html.push_str("</html>");
    auth::finish_tx(tx, &actor, false).await?;
    Ok(html_response(StatusCode::OK, html))
}

#[path = "session_assets.rs"]
mod assets;
pub use assets::app_js;
