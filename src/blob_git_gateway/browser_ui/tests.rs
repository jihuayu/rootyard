use super::*;
use crate::blob_git_gateway::repo_session::{
    AuthorityKind, STANDALONE_GROUP_ID, SessionRealm, SessionRealmFields, SessionTokenCodec, SessionTokens,
    presented_bound,
};
use crate::ref_store::GitObjectFormat;

#[test]
fn query_decoding_is_optional_and_errsafe() {
    let uri: Uri = "/x?oid=HEAD&path=a%2Fb".parse().unwrap();
    let query: TreeQuery = optional_query(&uri).expect("valid query");
    assert_eq!(query.oid.as_deref(), Some("HEAD"));
    assert_eq!(query.path.as_deref(), Some("a/b"));
    let empty: Uri = "/x".parse().unwrap();
    let query: RefsQuery = optional_query(&empty).expect("empty query");
    assert!(query.prefix.is_none() && query.limit.is_none());
    let unknown: Uri = "/x?surprise=1".parse().unwrap();
    assert_eq!(
        optional_query::<TreeQuery>(&unknown).err(),
        Some(GatewayError::BadRequest("invalid repository browse parameters"))
    );
}

#[test]
fn the_assets_carry_no_data_or_credentials() {
    let shell = inline::shell();
    for marker in ["x-rootyard-session", "rs1.", "/web/blob/api/repos/", "<script>", "__STYLE__"] {
        assert!(!shell.contains(marker), "the shell carries {marker}");
    }
    assert!(shell.contains(r#"<script src="/web/app.js" defer>"#));
    assert!(!inline::SCRIPT.contains("innerHTML"), "repository data must never reach innerHTML");
    assert!(!inline::SCRIPT.contains("currentScript"), "there is no out-of-band bound producer");
    for storage in ["localStorage", "sessionStorage", "document.cookie", "location.search"] {
        assert!(!inline::SCRIPT.contains(storage), "the bound must not reach {storage}");
    }
    assert!(inline::SCRIPT.contains("credentials: 'same-origin'"));
    assert!(inline::SCRIPT.contains("textContent"));
    assert!(inline::SCRIPT.contains("scope === 'index' && Array.isArray(data) ? data"));
    assert!(inline::SCRIPT.contains("isObject(data) && Array.isArray(data.items) ? data.items"));
    assert!(!inline::SCRIPT.contains("data.page"));
    assert!(inline::SCRIPT.contains("This server did not provide a bounded session."));
    assert!(!inline::SCRIPT.contains("reads are anonymous"));
}

fn framed_token(revision: i64) -> String {
    let backend = crate::blob_store::test_support::blob_backend_identity("browser-ui-tests");
    let codec =
        SessionTokenCodec::new([(0_u8, zeroize::Zeroizing::new([0x5a; 32]))], 0, &backend, 120).expect("test codec");
    let realm = SessionRealm::new(SessionRealmFields {
        tenant_id: uuid::Uuid::from_bytes([1; 16]),
        repository_id: uuid::Uuid::from_bytes([2; 16]),
        object_format: GitObjectFormat::Sha1,
        history_incarnation: uuid::Uuid::from_bytes([3; 16]),
        authority: AuthorityKind::PgRefStore,
        authority_epoch: 1,
        group_id: STANDALONE_GROUP_ID,
        group_epoch: 1,
        cluster_incarnation: uuid::Uuid::from_bytes([4; 16]),
    })
    .expect("test realm");
    SessionTokens::new(codec).issue_for_test(&realm, revision).expect("test token").token().to_owned()
}

fn answer(status: u16, token: Option<&str>, revision: Option<&str>) -> axum::http::Response<axum::body::Body> {
    let mut builder = axum::http::Response::builder().status(status);
    for (name, value) in [(SESSION_HEADER, token), (REVISION_HEADER, revision)] {
        if let Some(value) = value {
            builder = builder.header(name, value);
        }
    }
    builder.body(axum::body::Body::empty()).unwrap()
}

fn presented(token: &str) -> HeaderValue {
    HeaderValue::from_str(token).expect("a framed token is a valid header value")
}

#[test]
fn a_presented_bound_requires_a_complete_non_regressing_answer() {
    let presented_token = framed_token(3);
    assert_eq!(presented_bound(&presented_token), Some(3));
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let run = |response: axum::http::Response<axum::body::Body>, bound: Option<HeaderValue>| {
        runtime.block_on(async move {
            match admit_bound(Ok(response), bound.as_ref()).await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap_or_default();
                    Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
                }
                Err(error) => Err(error),
            }
        })
    };
    let status = |response: axum::http::Response<axum::body::Body>, bound: Option<HeaderValue>| {
        run(response, bound).map(|(s, _)| s)
    };
    assert_eq!(status(answer(200, None, None), None).unwrap(), 200);
    for code in [503, 401, 403, 404, 400, 422] {
        assert_eq!(status(answer(code, None, None), Some(presented(&presented_token))).unwrap(), code);
    }
    const MARKER: &str = "REPO-DATA-MARKER-7f3a";
    let with_body = |token: Option<&str>, revision: Option<&str>| {
        let repository = format!(r#"{{"items":[{{"name":"{}"}}]}}"#, MARKER);
        let mut response = answer(200, token, revision).map(|_| axum::body::Body::from(repository));
        response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        response
    };
    let partial: [(&str, Option<&str>, Option<&str>); 2] =
        [("a revision without a token", None, Some("3")), ("a token without a revision", Some("rs1.next"), None)];
    let malformed: [(&str, Option<&str>, Option<&str>); 2] =
        [("a non-positive revision", Some("rs1.next"), Some("0")), ("an empty token", Some(""), Some("3"))];
    for (what, token, revision) in partial.into_iter().chain(malformed) {
        let refused = run(with_body(token, revision), Some(presented(&presented_token)));
        assert_eq!(refused.err(), Some(bound_refusal()), "{what} was admitted");
    }
    let newer_bound = framed_token(4);
    assert_eq!(presented_bound(&newer_bound), Some(4));
    let refused = run(with_body(Some(&presented_token), Some("3")), Some(presented(&newer_bound)));
    let rendered = match refused {
        Err(error) => {
            assert_eq!(error, bound_refusal());
            error.into_response()
        }
        Ok((_status, body)) => axum::http::Response::builder()
            .status(axum::http::StatusCode::OK)
            .body(axum::body::Body::from(body))
            .expect("a fresh rendering"),
    };
    assert_eq!(rendered.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let bytes = runtime.block_on(axum::body::to_bytes(rendered.into_body(), usize::MAX)).unwrap();
    let rendered = String::from_utf8_lossy(&bytes);
    assert!(!rendered.contains(MARKER), "the refused answer retained its repository body");
    assert!(!rendered.contains(r#""items""#), "the refused answer retained its repository shape");
    assert_eq!(status(answer(200, Some("rs1.next"), Some("3")), Some(presented(&presented_token))).unwrap(), 200);
    assert_eq!(
        status(answer(200, Some("rs1.next"), Some("3")), Some(presented(&newer_bound))).err(),
        Some(bound_refusal())
    );
}

#[test]
fn a_boundless_answer_is_passed_through_and_only_a_presented_bound_is_checked() {
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let admit = |response: axum::http::Response<axum::body::Body>, bound: Option<HeaderValue>| {
        runtime.block_on(async move {
            match admit_bound(Ok(response), bound.as_ref()).await {
                Ok(response) => Ok((response.status().as_u16(), response.headers().len())),
                Err(error) => Err(error),
            }
        })
    };
    assert_eq!(admit(answer(200, None, None), None), Ok((200, 0)));
    assert_eq!(admit(answer(200, Some("rs1.next"), Some("3")), None), Ok((200, 2)));
    let bound = presented(&framed_token(3));
    assert_eq!(admit(answer(200, Some("rs1.next"), Some("3")), Some(bound.clone())).err(), None);
    assert_eq!(admit(answer(200, None, None), Some(bound)).err(), Some(bound_refusal()));
    let script = inline::SCRIPT;
    assert!(
        script.contains("const hasToken = response.headers.has(TOKEN), hasRevision = response.headers.has(REVISION);")
    );
    assert!(script.contains("const headerless = !hasToken && !hasRevision;"));
    assert!(script.contains("if (headerless) return bound === null && revision === null ? NO_BOUND : null;"));
    assert!(
        script.contains("if (!hasToken || !hasRevision || !token || raw === null || raw.trim() === '') return null;")
    );
    assert!(!script.contains("const headerless = !token && (raw === null || raw.trim() === '');"));
}

#[test]
fn the_shell_authenticates_through_the_shared_cookie_helper() {
    let source = include_str!("../browser_ui.rs");
    let shell = body_of(source, "async fn spa_shell(", "// Read aliases", "the shell handler");
    assert!(shell.contains("crate::web::session::authenticate_web(state.pool(), &headers)"));
    assert!(shell.contains("tokio::time::timeout_at(deadline,"), "the page check is deadline-bounded");
    assert!(shell.contains("Ok(Err(error)) => return GatewayError::from(error).into_response()"));
    assert!(shell.contains("Err(_) => return GatewayError::Timeout.into_response()"));
    assert!(!shell.contains("super::session::authenticate("), "the shell must not read raw bearer headers");
    assert_eq!(shell.matches("GatewayError::Unauthorized").count(), 0, "no failure may collapse into a 401");
}

#[test]
fn every_alias_relays_a_challenged_json_handler() {
    let relaying = [
        "/repos",
        "/repos/{owner}/{name}",
        "/repos/{owner}/{name}/refs",
        "/repos/{owner}/{name}/commits",
        "/repos/{owner}/{name}/commits/{oid}",
        "/repos/{owner}/{name}/tree",
        "/repos/{owner}/{name}/tree/{oid}",
        "/repos/{owner}/{name}/blob",
        "/repos/{owner}/{name}/blob/{oid}",
        "/repos/{owner}/{name}/compare",
    ];
    let api = body_of(include_str!("../mod.rs"), ".route(\"/api/repos\"", ".route(\"/git/", "the /api routes");
    let source = include_str!("../browser_ui.rs");
    for route in relaying {
        assert!(api.contains(&format!(".route(\"/api{route}\"")), "the top-level route api{route} is registered");
        assert!(
            source.contains(&format!(".route(\"{route}\", ")),
            "the alias {route} is registered below /web/blob/api"
        );
    }
    for handler in ["api::list_repos", "history::refs", "history::commit", "browse::tree"] {
        assert!(source.contains(&format!("{handler}(")), "{handler} is relayed, not reimplemented");
    }
    let router = body_of(source, "pub(super) fn router()", "async fn normalize_session_headers", "the Web router");
    assert_eq!(
        router.matches(".layer(").count(),
        1,
        "only the cookie translation is layered: the challenge belongs to the relayed handler"
    );
}

fn body_of<'a>(source: &'a str, from: &str, to: &str, what: &str) -> &'a str {
    let start = source.find(from).unwrap_or_else(|| panic!("missing {what}"));
    let rest = &source[start..];
    let end = rest.find(to).unwrap_or_else(|| panic!("missing the end of the source"));
    &rest[..end]
}

#[test]
fn the_script_parses_the_whole_body_before_adopting_a_bound() {
    let script = inline::SCRIPT;
    let adopt = body_of(script, "function adopt(", "// Validate response headers", "the adopt function");
    assert!(adopt.contains("function adopt(nextToken, nextRevision)"), "the revision parameter must not shadow");
    assert!(adopt.contains("bound = nextToken;"), "the token is adopted");
    assert!(adopt.contains("revision = nextRevision;"), "the outer revision is updated");
    let read = body_of(script, "async function read(scope, url)", "async function repository(", "the read path");
    let headers = read.find("const next = admit(response);").expect("headers are admitted");
    let body = read.find("await response.json()").expect("the whole body is parsed");
    let shape = read.find("Array.isArray(data.items)").expect("the body shape is checked");
    let adopt = read.find("adopt(next.token, next.revision);").expect("the pair is adopted together");
    assert!(headers < body && body < shape && shape < adopt, "admission and parsing must precede adoption");
    assert!(read.contains("if (next !== NO_BOUND)"), "a headerless answer must keep the browser boundless");
    assert_eq!(read.matches("adopt(").count(), 1, "the read path adopts at exactly one site");
    assert!(!script.contains("currentScript"));
}

#[test]
fn a_failed_repository_read_stops_the_sequence() {
    let repository =
        body_of(inline::SCRIPT, "async function repository(", "async function index(", "the repository page");
    let refs = repository.find("const refs = await read(").expect("refs are read");
    let tree = repository.find("const tree = await read(").expect("the tree is read");
    let commits = repository.find("const commits = await read(").expect("the commits are read");
    let status = repository.find("show(bound ? READ : NO_SESSION, false);").expect("the success status");
    let stop = |at: usize, value: &str| {
        repository[at..]
            .find(&format!("if (!{value}) return;"))
            .map(|offset| at + offset)
            .unwrap_or_else(|| panic!("a failed {value} read must stop the sequence"))
    };
    assert!(stop(refs, "refs") < tree, "a failed refs read must not start the tree read");
    assert!(
        tree < stop(tree, "tree") && stop(tree, "tree") < commits,
        "a failed tree read must not start the commits read"
    );
    assert!(
        commits < stop(commits, "commits") && stop(commits, "commits") < status,
        "a failed commits read must precede the success status"
    );
    assert_eq!(repository.matches("show(bound ? READ : NO_SESSION, false);").count(), 1, "one closing success status");
    assert_eq!(repository.matches("show(").count(), 1, "the page itself shows no failure status of its own");
}
