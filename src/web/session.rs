//! Browser-only, expiring sessions exchanged from an existing API credential.
//!
//! A browser session is a short-lived `browser` token plus a CSRF-bound
//! `web_sessions` row. The session secret embeds the API token that authorized
//! sign-in so parent-token revocation also terminates the browser session. The
//! embedded parent id is bound by the secret's SHA-256 digest: changing it
//! invalidates the stored browser token instead of selecting another parent.
use crate::{Error, application::MetadataState, auth, db, web::templates::html_response};
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
use uuid::Uuid;

mod return_to;
use return_to::{encode_query_value, is_safe_return_to, login_target, safe_return_to};

const SESSION_LIFETIME_SECONDS: i64 = 12 * 60 * 60;
const SESSION_PREFIX: &str = "ryt_";
const PARENT_HEX_LEN: usize = 32;

/// The exact read-alias namespace of the Blob gateway browser UI: the index
/// `GET /web/blob/api/repos` and every read below it.
const BLOB_API_ALIAS: &str = "/web/blob/api/repos";

/// The credential scheme one web-session refusal advertises.
const PAGE_CHALLENGE: &str = "Basic realm=\"Rootyard\", charset=\"UTF-8\"";
/// The JSON/API challenge of the Blob gateway aliases, identical to
/// [`crate::blob_git_gateway::Challenge::Bearer`].
const API_CHALLENGE: &str = "Bearer realm=\"Rootyard\"";

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

/// True only for the Blob gateway read aliases: exactly `/web/blob/api/repos`
/// and its descendants in whole path segments. Every other `/web` path (the
/// login/logout pages, the `/web/blob` page navigation, sibling `/web/*` pages)
/// and every `/git/*` path keeps the page challenge.
fn is_blob_api_alias(path: &str) -> bool {
    let Some(rest) = path.strip_prefix(BLOB_API_ALIAS) else { return false };
    rest.is_empty() || rest.starts_with('/')
}

/// Choose the challenge of a `401` the session middleware itself answers.
///
/// The API alias namespace advertises the JSON/API `Bearer` scheme, so a
/// cookie-only browser `fetch` that resolves promptly itself (no network
/// delay) can never start the Basic HTTP-auth exchange Chromium would
/// otherwise leave pending. Every other path keeps the page `Basic` challenge.
///
/// Only a `401` is looked at. Its status, body and every other header (cookies,
/// repeated values included) are the response's own; an answer that names no
/// challenge at all is left exactly as rendered.
fn session_challenge(mut response: Response, path: &str) -> Response {
    if response.status() == StatusCode::UNAUTHORIZED
        && response.headers().get(header::WWW_AUTHENTICATE).is_some_and(|value| value == PAGE_CHALLENGE)
    {
        let challenge = if is_blob_api_alias(path) { API_CHALLENGE } else { PAGE_CHALLENGE };
        response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static(challenge));
    }
    response
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WebAuthMode {
    CookieOnly,
    BrowserSession,
    HeaderApiOrOther,
}

async fn web_auth_mode(
    state: &MetadataState,
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

async fn validate_session(state: &MetadataState, secret: &str, csrf: Option<&str>) -> Result<(), Box<Response>> {
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
    State(state): State<MetadataState>,
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
        Err(response) => return session_challenge(*response, &path),
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
                return session_challenge(*response, &path);
            }
        }
    } else if session_mode
        && let Some(secret) = session.as_deref()
        && let Err(response) = validate_session(&state, secret, None).await
    {
        return if is_navigation {
            login_redirect(&path, query.as_deref(), &headers)
        } else {
            session_challenge(*response, &path)
        };
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
    State(state): State<MetadataState>,
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

pub async fn logout(State(state): State<MetadataState>, headers: HeaderMap) -> Result<Response, Error> {
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

#[path = "session_assets.rs"]
mod assets;
pub use assets::app_js;

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::header,
        response::{IntoResponse, Response},
    };

    use super::*;

    fn challenges(response: &Response) -> Vec<&str> {
        response.headers().get_all(header::WWW_AUTHENTICATE).iter().map(|v| v.to_str().unwrap()).collect()
    }

    /// Only the exact alias namespace and its descendants are API reads.
    #[test]
    fn only_the_blob_api_alias_namespace_is_scoped() {
        for path in [
            "/web/blob/api/repos",
            "/web/blob/api/repos/",
            "/web/blob/api/repos/owner/name",
            "/web/blob/api/repos/owner/name/refs",
            "/web/blob/api/repos/owner/name/tree/abc",
        ] {
            assert!(is_blob_api_alias(path), "{path} is a Blob API read alias");
        }
        for path in [
            "/web/login",
            "/web/logout",
            "/web/blob",
            "/web/blob/",
            "/web/blob/repos/owner/name",
            "/web/app.js",
            "/web/repos",
            "/web/settings/tokens",
            "/web/blob/api/repository",
            "/web/blob/api/repositories",
            "/web/blob/api/reposx",
            "/web/blob/api",
            "/web/blob/api/",
            "/git/owner/name.git/info/refs",
            "/api/repos",
            "",
        ] {
            assert!(!is_blob_api_alias(path), "{path} is not a Blob API read alias");
        }
    }

    /// A `Basic`-challenged session `401` on an alias read becomes exactly the
    /// API `Bearer` challenge.
    #[test]
    fn an_alias_unauthorized_advertises_exactly_the_bearer_challenge() {
        let page = Error::unauthorized().into_response();
        assert_eq!(challenges(&page), [PAGE_CHALLENGE], "precondition: the shared refusal is Basic");
        for path in ["/web/blob/api/repos", "/web/blob/api/repos/owner/name/refs"] {
            let response = session_challenge(page.clone(), path);
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(challenges(&response), [API_CHALLENGE], "{path}");
        }
    }

    /// Every other route keeps the existing page `Basic` challenge.
    #[test]
    fn page_login_and_other_routes_keep_the_basic_challenge() {
        let page = Error::unauthorized().into_response();
        for path in ["/web/login", "/web/logout", "/web/blob", "/web/blob/repos/o/n", "/web/repos", "/git/o/n.git"] {
            let response = session_challenge(page.clone(), path);
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(challenges(&response), [PAGE_CHALLENGE], "{path}");
        }
    }

    /// A non-`401` answer is never touched, on the alias or elsewhere.
    #[test]
    fn a_non_unauthorized_answer_is_unchanged() {
        for status in [StatusCode::OK, StatusCode::FORBIDDEN, StatusCode::NOT_FOUND, StatusCode::SERVICE_UNAVAILABLE] {
            let original = (status, "body").into_response();
            for path in ["/web/blob/api/repos", "/web/blob/api/repos/owner/name", "/web/login", "/web/repos"] {
                let response = session_challenge(original.clone(), path);
                assert_eq!(response.status(), status, "{path}");
                assert_eq!(response.headers(), original.headers(), "{path}");
            }
        }
    }

    /// The challenge is the only field that can change: status, body, cookies
    /// and every other header (repeated values included) stay the response's.
    #[test]
    fn the_challenge_rewrite_preserves_status_body_and_other_headers() {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let original = Error::unauthorized().into_response();
        let mut original = {
            let (mut parts, _) = original.into_parts();
            parts.headers.insert(header::SET_COOKIE, HeaderValue::from_static("rootyard_session=; Max-Age=0"));
            parts.headers.append(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            parts.headers.append(header::CACHE_CONTROL, HeaderValue::from_static("private"));
            Response::from_parts(parts, Body::from(r#"{"error":"valid credentials required"}"#))
        };
        let response = session_challenge(original.clone(), "/web/blob/api/repos/owner/name");
        assert_eq!(challenges(&original), [PAGE_CHALLENGE]);
        assert_eq!(challenges(&response), [API_CHALLENGE]);
        original.headers_mut().remove(header::WWW_AUTHENTICATE);
        response.headers_mut().remove(header::WWW_AUTHENTICATE);
        assert_eq!(response.status(), original.status());
        assert_eq!(response.headers(), original.headers());
        let read = |response: Response| {
            runtime.block_on(async move {
                let (parts, body) = response.into_parts();
                (parts.status, to_bytes(body, usize::MAX).await.unwrap())
            })
        };
        assert_eq!(read(response), read(original));
    }

    /// A `401` that names no challenge, or another authority's scheme, is not
    /// the session middleware's page refusal and is passed through untouched.
    #[test]
    fn an_unauthorized_without_the_page_challenge_is_passed_through() {
        let bare = Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::empty()).unwrap();
        let foreign = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "Negotiate")
            .body(Body::empty())
            .unwrap();
        for response in [bare.into_response(), foreign] {
            let existing = challenges(&response);
            let after = session_challenge(response, "/web/blob/api/repos");
            assert_eq!(challenges(&after), existing);
        }
    }

    /// `validate_session` refuses a secret whose embedded parent id does not
    /// decode before it ever touches the pool (`session_parent`). The session
    /// middleware hands that error to `session_challenge`, so an alias read
    /// answers an exactly-Bearer `401` without a live database; page paths keep
    /// Basic.
    #[tokio::test]
    async fn a_validate_session_rejection_is_bearer_challenged_on_alias_reads() {
        let (state, _scratch) = offline_metadata();
        let secret = format!("{SESSION_PREFIX}{}", "zz".repeat(32));
        assert_eq!(session_parent(&secret), None);
        let Err(rejected) = validate_session(&state, &secret, None).await else {
            panic!("a session without a decodable parent id must not validate");
        };
        let response = session_challenge(*rejected.clone(), "/web/blob/api/repos");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(challenges(&response), [API_CHALLENGE]);
        let page = (*rejected).into_response();
        let response = session_challenge(page, "/web/blob");
        assert_eq!(challenges(&response), [PAGE_CHALLENGE]);
    }

    fn offline_metadata() -> (MetadataState, tempfile::TempDir) {
        let config: tokio_postgres::Config =
            "host=127.0.0.1 port=1 user=rootyard dbname=rootyard".parse().expect("static connection string");
        let pool = deadpool_postgres::Pool::builder(deadpool_postgres::Manager::new(config, tokio_postgres::NoTls))
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .max_size(1)
            .build()
            .expect("offline pool");
        (MetadataState { pool }, tempfile::tempdir().expect("scratch"))
    }

    /// The real middleware source must route both of its session short
    /// circuits through `session_challenge` and leave the navigation redirect
    /// decision in place; this pins the wiring the offline tests cannot reach.
    #[test]
    fn both_session_short_circuits_use_the_challenge_helper() {
        let source = include_str!("session.rs");
        let middleware = source
            .split_once("pub async fn middleware(")
            .and_then(|(_, rest)| rest.split_once("\n}\n"))
            .map(|(body, _)| body)
            .expect("the middleware body");
        assert!(middleware.contains("Err(response) => return session_challenge(*response, &path)"));
        assert_eq!(middleware.matches("session_challenge(*response, &path)").count(), 2);
        assert!(middleware.contains("login_redirect(&path, query.as_deref(), &headers)"));
        assert!(!middleware.contains("WWW_AUTHENTICATE"), "the middleware never writes the header itself");
    }
}
