use super::*;
use crate::blob_git_gateway::repo_session::{
    AuthorityKind, STANDALONE_GROUP_ID, SessionRealm, SessionRealmFields, SessionTokenCodec, SessionTokens,
    presented_bound,
};
use crate::ref_store::GitObjectFormat;

#[test]
fn query_decoding_is_optional_and_errsafe() {
    let uri: Uri = "/x?oid=HEAD&path=a%2Fb&limit=10".parse().unwrap();
    let query: TreeQuery = optional_query(&uri).expect("valid query");
    assert_eq!(query.oid.as_deref(), Some("HEAD"));
    assert_eq!(query.path.as_deref(), Some("a/b"));
    assert_eq!(query.limit, Some(10));
    let empty: Uri = "/x".parse().unwrap();
    let query: RefsQuery = optional_query(&empty).expect("empty query");
    assert!(query.prefix.is_none() && query.limit.is_none());
    let refs_limit: RefsQuery = optional_query(&"/x?limit=25".parse().unwrap()).expect("numeric refs limit");
    assert_eq!(refs_limit.limit, Some(25));
    let commits_page: CommitsQuery =
        optional_query(&"/x?after=5&limit=10".parse().unwrap()).expect("numeric commits paging");
    assert_eq!((commits_page.after, commits_page.limit), (Some(5), Some(10)));
    assert!(optional_query::<api::ListQuery>(&"/x?limit=10&cursor=abc".parse().unwrap()).is_ok());
    for invalid in ["/x?surprise=1", "/x?limit=abc"] {
        let uri: Uri = invalid.parse().unwrap();
        assert_eq!(
            optional_query::<TreeQuery>(&uri).err(),
            Some(GatewayError::BadRequest("invalid repository browse parameters"))
        );
        assert_eq!(
            optional_query::<api::ListQuery>(&uri).err(),
            Some(GatewayError::BadRequest("invalid repository browse parameters"))
        );
    }
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
    let cursor = read.find("parseCursor(scope, response, data, list)").expect("continuation cursor is validated");
    let recheck = read.find("const confirmed = admit(response);").expect("headers are re-checked after awaiting body");
    let adopt = read.find("adopt(confirmed.token, confirmed.revision);").expect("the pair is adopted together");
    assert!(
        headers < body && body < shape && shape < cursor && cursor < recheck && recheck < adopt,
        "admission, body, shape, cursor and post-await re-check must precede adoption"
    );
    assert!(!read[recheck..adopt].contains("await"), "no await may separate re-validation from adoption");
    assert!(read.contains("if (confirmed !== NO_BOUND)"), "a headerless answer must keep the browser boundless");
    assert_eq!(read.matches("adopt(").count(), 1, "the read path adopts at exactly one site");
    assert!(!script.contains("currentScript"));
}

#[test]
fn a_failed_repository_read_stops_the_sequence() {
    let repository =
        body_of(inline::SCRIPT, "async function repository(", "async function index(", "the repository page");
    let refs = repository.find("const refs = await mountSection(").expect("refs are read");
    let tree = repository.find("const tree = await mountSection(").expect("the tree is read");
    let commits = repository.find("const commits = await mountSection(").expect("the commits are read");
    let ready = repository.find("loadedAllSections = true;").expect("completion gate");
    let status = repository.find("finishStatus();").expect("the success status");
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
        commits < stop(commits, "commits") && stop(commits, "commits") < ready && ready < status,
        "a failed commits read must precede the completion gate and final status"
    );
    assert_eq!(repository.matches("finishStatus();").count(), 1, "one closing status transition");
    assert_eq!(repository.matches("show(").count(), 0, "the page itself shows no status before finishStatus");
}

#[test]
fn the_script_consumes_pagination_cursors_and_guards_partial_status() {
    let script = inline::SCRIPT;
    assert!(script.contains("NEXT_CURSOR = 'x-next-cursor'"));
    assert!(script.contains("const PARTIAL = 'More items remain. Use Load more to continue.';"));
    assert!(script.contains("?cursor=' + encodeURIComponent(cursor)"));
    assert!(script.contains("/refs?after=' + encodeURIComponent(cursor)"));
    assert!(script.contains("/tree?oid=HEAD&after=' + encodeURIComponent(cursor)"));
    assert!(script.contains("/commits?after=' + encodeURIComponent(String(cursor))"));

    let parse_cursor = body_of(script, "function parseCursor(", "// Adopt the pair", "the cursor parser");
    assert!(parse_cursor.contains("!list.length"), "empty pages carrying cursors must fail closed");
    assert!(parse_cursor.contains("Number.isSafeInteger(raw) && raw >= 0"));
    assert!(parse_cursor.contains("data.next_after"));

    let read_pages =
        body_of(script, "async function readPages(", "function finishStatus(", "the batch pagination loop");
    assert!(read_pages.contains("step < MAX_AUTO_PAGES"));
    assert!(read_pages.contains("seen.has(key)"), "repeated cursors must fail closed instead of looping");
    assert!(read_pages.contains("seen.add(key)"));

    let finish = body_of(script, "function finishStatus(", "function renderSection(", "status finalization");
    assert!(finish.contains("if (!loadedAllSections) { show(REFUSED, true); return; }"));
    assert!(finish.contains("sections.some(section => section.cursor !== null)"));
    let partial_branch = finish.find("if (incomplete) show(bound ? PARTIAL : PARTIAL_NO_SESSION, false);").unwrap();
    let read_branch = finish.find("else show(bound ? READ : NO_SESSION, false);").unwrap();
    assert!(partial_branch < read_branch);

    let render_section = body_of(script, "function renderSection(", "async function loadMore(", "section rendering");
    assert!(render_section.contains("button.disabled = loadingMore;"));
    assert!(render_section.contains("section.button = button;"));

    let load_more = body_of(script, "async function loadMore(", "async function mountSection(", "load more handler");
    assert!(load_more.contains("if (!loadedAllSections || loadingMore) return;"));
    assert!(load_more.contains("if (page !== section.scope || section.busy || section.cursor === null) return;"));
    let lock = load_more.find("loadingMore = true;").expect("global single-flight lock is taken");
    let disable_all =
        load_more.find("for (const entry of sections) if (entry.button) entry.button.disabled = true;").unwrap();
    let fetch_more = load_more.find("await readPages(").unwrap();
    let unlock = load_more.find("loadingMore = false;").expect("global single-flight lock is released");
    assert!(lock < disable_all && disable_all < fetch_more && fetch_more < unlock);
    assert_eq!(
        load_more.matches("for (const entry of sections) if (entry.button) entry.button.disabled = false;").count(),
        2,
        "all section buttons are restored on failure and completion"
    );
    assert!(load_more.contains("finishStatus();"));
}
