"""Real headless Chromium acceptance of the push-bound Blob browser (#174).

Started by the Rust case (`session_browser_acceptance.rs`) with two path-only
arguments: this script and one mode-0600 JSON config. The interpreter is the
Playwright virtualenv of the browser image (default
`/opt/session174-playwright/bin/python3`).

The client prints exactly one sanitized JSON line on stdout and never writes
stderr: a failure is a fixed uppercase reason code in that line, never an
exception message, a traceback, a URL, a cookie or a token.

What it drives on a brand-new persistent profile in the private run root:

1. no cookie exists at first, and every request is confined to the configured
   loopback origin (anything else is aborted and fails the run);
2. anonymous `/web/blob` is the origin's own `303` to
   `/web/login?return_to=%2Fweb%2Fblob`, never a public shell;
3. the real sign-in form receives the owner's API token; the session cookie is
   HttpOnly and `SameSite=Strict`, the CSRF cookie is readable, and no
   credential reaches a URL, the DOM or storage;
4. the signed-in `/web/blob` is a direct `200` under its CSP; the page's own
   script lists the repository and the real repository DOM link is clicked,
   which must render `References`, `Files at HEAD`, `Commits` and the pushed
   commit, with the page's own refs/tree/commits requests chained; the HEAD
   tree must list both real pushes, and every captured response revision must
   be at least the configured final-push `expected_revision`, the write bound
   (`API_READ_BOUND_INVALID` for an incomplete or behind view);
5. cookie-only fetches of `/api` and `/git` meet the origin's own denial: the
   `/api/repos` fetch must resolve directly with the actual `401`, while the
   Smart HTTP `info/refs` fetch either resolves with the actual `401` or has its
   own `AbortSignal.timeout` fire, past the configured five-second boundary,
   while Chromium waits on the origin's Basic challenge. Any thrown error, a
   timeout before that boundary or another status fails the run; nothing is
   hidden or rewritten on the way;
6. one labelled client-side fault, only after the real chain passed: a
   re-entered repository page is answered by the page itself with a synthetic
   `200` tree carrying the real refs token and the immediately lower
   revision; the UI must show its generic refusal, must not render the marker,
   the tree or the commits, and no commits request may begin.
"""

import asyncio
import json
import re
import sys
from pathlib import Path

TOKEN = "x-rootyard-session"
REVISION = "x-rootyard-session-revision"
SESSION_COOKIE = "rootyard_session"
CSRF_COOKIE = "rootyard_csrf"
SHELL = "/blob"
LOGIN = "/login"
FAULT_MARKER = "FAULT-INJECTION-MARKER-7f3a"
STEP_MS = 30_000
# The cookie-only fetches abort themselves below the step bound through their
# own `AbortSignal.timeout`, so the browser never waits past this bound and the
# pending Basic challenge of Smart HTTP is measured instead of hanging.
FETCH_TIMEOUT_MS = 5_000
# The only timeout the page-side cookie-only fetch reports: its own
# `TimeoutError`, which only its own `AbortSignal.timeout` produces.
TIMEOUT_REASON = "timeout_error"
# The fixed classifications of one cookie-only denial. A direct record carries
# the actual response status and no abort fact; a pending Basic challenge
# carries no status and instead the page's own TimeoutError and its integer
# elapsed time.
DENIAL_DIRECT = "direct_response"
DENIAL_PENDING = "basic_challenge_pending"

# The page-side storage read returns only one of these fixed status words; a
# Web Storage SecurityError is caught inside the page and never crosses the
# protocol boundary as an exception, so no engine message, origin or value
# can be reconstructed from the transport error.
STORAGE_STATUS_OK = "ok"
STORAGE_STATUS_DENIED = "denied"
STORAGE_READ_SCRIPT = f"""() => {{
    const read = (storage) => {{
        const entries = [];
        for (let index = 0; index < storage.length; index += 1) {{
            const key = storage.key(index);
            entries.push([key, storage.getItem(key)]);
        }}
        return entries;
    }};
    try {{
        const pairs = [read(localStorage), read(sessionStorage)];
        return {{status: '{STORAGE_STATUS_OK}', data: JSON.stringify(pairs)}};
    }} catch (_) {{
        const denied = error && error.name === 'SecurityError';
        return {{status: denied ? '{STORAGE_STATUS_DENIED}' : 'error'}};
    }}
}}"""

REASONS = frozenset(
    (
        "NO_ARGUMENTS",
        "CONFIG_UNREADABLE",
        "CONFIG_INVALID",
        "CONFIG_PATH_UNSAFE",
        "BROWSER_PLAYWRIGHT_UNAVAILABLE",
        "BROWSER_LAUNCH_FAILED",
        "BROWSER_SESSION_FAILED",
        "NAVIGATION_EXCEEDED",
        "ORIGIN_ESCAPE",
        "COOKIES_BEFORE_SIGN_IN",
        "ANONYMOUS_NOT_REDIRECTED",
        "ANONYMOUS_SHELL_SERVED",
        "LOGIN_PAGE_INVALID",
        "SIGN_IN_FAILED",
        "SESSION_COOKIE_INVALID",
        "CSRF_COOKIE_INVALID",
        "CREDENTIAL_IN_URL",
        "CREDENTIAL_IN_DOM",
        "CREDENTIAL_IN_STORAGE",
        "DOM_READ_FAILED",
        "STORAGE_READ_FAILED",
        "STORAGE_EVALUATION_FAILED",
        "STORAGE_ACCESS_DENIED",
        "SHELL_NOT_SERVED",
        "SHELL_CSP_MISSING",
        "SHELL_SCRIPT_INVALID",
        "LIST_NOT_RENDERED",
        "REPO_LINK_MISSING",
        "REPO_LINK_INVALID",
        "REPO_PAGE_INCOMPLETE",
        "REPO_PAGE_STATUS_INVALID",
        "READ_CHAIN_INVALID",
        "API_COOKIE_ONLY_FETCH_FAILED",
        "API_COOKIE_ONLY_STATUS_INVALID",
        "API_COOKIE_ONLY_TIMEOUT",
        "GIT_COOKIE_ONLY_FETCH_FAILED",
        "GIT_COOKIE_ONLY_STATUS_INVALID",
        "GIT_COOKIE_ONLY_TIMEOUT_EARLY",
        "API_READ_BOUND_INVALID",
        "FAULT_BOUND_INVALID",
        "FAULT_NOT_APPLIED",
        "FAULT_REFUSAL_MISSING",
        "FAULT_MARKER_RENDERED",
        "FAULT_COMMITS_RENDERED",
        "FAULT_COMMITS_REQUESTED",
        "CLIENT_FAILED",
    )
)


class Failure(Exception):
    """A fixed reason code; its text is never printed or chained."""

    def __init__(self, reason):
        reason = reason if reason in REASONS else "CLIENT_FAILED"
        super().__init__(reason)
        self.reason = reason


async def evaluate(page, expression, reason, arg=None):
    """Run one `page.evaluate` under the fixed step bound.

    A hanging in-page script (an unanswered fetch, a pending microtask) or a
    throwing one is mapped to the caller's fixed reason; the exception text,
    type and any argument stay behind this boundary.
    """
    try:
        return await asyncio.wait_for(page.evaluate(expression, arg), timeout=STEP_MS / 1000)
    except Exception:
        raise Failure(reason) from None


def summary(config, reason, extra):
    payload = {
        "result": "FAIL" if reason else "PASS",
        "reason": reason or "PASS",
        "mode": "client_fault_injection",
        "browser": extra.get("browser", ""),
    }
    payload.update({key: value for key, value in extra.items() if key != "browser"})
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def load_config(path):
    config_path = Path(path)
    if not config_path.is_absolute() or config_path.is_symlink():
        raise Failure("CONFIG_PATH_UNSAFE")
    if config_path.stat().st_mode & 0o077:
        raise Failure("CONFIG_PATH_UNSAFE")
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except OSError:
        raise Failure("CONFIG_UNREADABLE") from None
    except ValueError:
        raise Failure("CONFIG_INVALID") from None
    strings = ("origin", "username", "token", "repo", "oid", "file", "second_file", "chromium", "profile")
    if not isinstance(config, dict) or any(not isinstance(config.get(key), str) for key in strings):
        raise Failure("CONFIG_INVALID")
    revision = config.get("expected_revision")
    origin = config["origin"]
    if not re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", origin) or not isinstance(revision, int) or revision < 2:
        raise Failure("CONFIG_INVALID")
    if not Path(config["profile"]).is_absolute():
        raise Failure("CONFIG_INVALID")
    return config


class Client:
    """One run against the configured origin, keeping only throw-away state."""

    def __init__(self, config):
        self.config = config
        self.bound = config["expected_revision"]
        self.origin = config["origin"]
        self.owner = config["username"]
        self.repo = config["repo"]
        self.web = f"{self.origin}/web"
        self.scope = f"/web/blob/repos/{self.owner}/{self.repo}"
        self.alias = f"/web/blob/api/repos/{self.owner}/{self.repo}"
        self.tokens = {config["token"]}
        self.cookies = set()
        self.escaped = False
        self.commits_requests = 0
        self.route_statuses = {}
        self.read_pairs = {}

    # -- confinement and capture ----------------------------------------

    def confined(self, url):
        return url.startswith(self.origin + "/")

    def routes(self, context, page):
        """Bound every request to the origin, recording only throw-away data.

        Token strings seen on the wire are retained in memory to recognise a
        credential in a page, URL or storage; they never leave this process.
        Response statuses and session pairs are kept per exact route so the
        caller can attest the page's own read chain.
        """
        self.listen(page)

        async def confine(route, request):
            if not self.confined(request.url):
                self.escaped = True
                await route.abort()
                return
            await route.continue_()

        context.route("**/*", confine)
        # Every later page (a tab or popup opened by the run) is watched too.
        context.on("page", self.listen)

    def listen(self, page):
        """Register the response/request capture on one page."""

        def route_name(path):
            # Paths are path-only (the origin is already stripped); query
            # strings only ever bound a read and are never classified.
            if path == self.alias + "/refs":
                return "web_refs"
            if path == self.alias + "/tree":
                return "web_tree"
            if path == self.alias + "/commits":
                return "web_commits"
            if path == "/web" + SHELL:
                return "web_blob"
            if path == "/web/blob/api/repos":
                return "web_list"
            return None

        def observe_response(response):
            # Nothing is read from a response that left the origin.
            if not self.confined(response.url):
                self.escaped = True
                return
            headers = response.headers
            session = headers.get(TOKEN)
            if session:
                self.tokens.add(session)
            path = response.url[len(self.origin):].split("?", 1)[0]
            status = int(response.status)
            # The anonymous `/web/blob` answer is its own 303 sign-in redirect;
            # the later signed-in 200 shell is the distinct `web_blob` route.
            if path == "/web" + SHELL and status == 303:
                self.route_statuses.setdefault("web_signin_redirect", status)
            elif path == "/web" + LOGIN:
                # The GET 200 form must not hide the post's own 303 sign-in.
                if status == 303 or "web_login" not in self.route_statuses:
                    self.route_statuses["web_login"] = status
            else:
                name = route_name(path)
                if name is not None:
                    self.route_statuses[name] = status
            tail = path[len(self.alias) + 1:] if path.startswith(self.alias + "/") else None
            if tail in ("refs", "tree", "commits"):
                revision = headers.get(REVISION, "")
                self.read_pairs.setdefault(id(page), {}).setdefault(tail, []).append(
                    {"token": session, "revision": int(revision) if revision.isdecimal() else None}
                )

        def observe_request(request):
            # The one place a commit read is counted; a request that left the
            # origin is never counted, and its query is never classified.
            if self.confined(request.url):
                path = request.url[len(self.origin):].split("?", 1)[0]
                if path == self.alias + "/commits":
                    self.commits_requests += 1

        page.on("response", observe_response)
        page.on("request", observe_request)

    def check_origin(self):
        if self.escaped:
            raise Failure("ORIGIN_ESCAPE")

    async def remember_cookies(self, context):
        for cookie in await context.cookies(self.origin):
            name, value = cookie.get("name", ""), cookie.get("value", "")
            if name == SESSION_COOKIE and value:
                self.tokens.add(value)
            if len(value) >= 8:
                self.cookies.add(value)

    def secrets(self):
        return [value for value in self.cookies | self.tokens if len(value) >= 8]

    async def no_credentials(self, page):
        """No credential in the URL, the rendered DOM or the web storage.

        `CREDENTIAL_IN_STORAGE` alone means a secret was actually found in the
        serialized storage. Every diagnostic that could not read is a fixed,
        distinct reason and never a discovered leak: `DOM_READ_FAILED` for the
        rendered content, `STORAGE_EVALUATION_FAILED` for the transport of the
        storage evaluation, `STORAGE_ACCESS_DENIED` when the page caught a Web
        Storage SecurityError, and `STORAGE_READ_FAILED` for any other
        malformed or unreadable storage answer. Each stays a failure, so
        unreadable storage never passes. No reason carries exception text or
        class names, the stored text, a URL, an origin or a traceback.
        """
        if any(secret in page.url for secret in self.secrets()):
            raise Failure("CREDENTIAL_IN_URL")
        try:
            content = await page.content()
        except Exception:
            raise Failure("DOM_READ_FAILED") from None
        if not isinstance(content, str):
            raise Failure("DOM_READ_FAILED")
        if any(secret in content for secret in self.secrets()):
            raise Failure("CREDENTIAL_IN_DOM")
        answer = await evaluate(page, STORAGE_READ_SCRIPT, "STORAGE_EVALUATION_FAILED")
        if not isinstance(answer, dict):
            raise Failure("STORAGE_READ_FAILED")
        status = answer.get("status")
        if status == STORAGE_STATUS_DENIED:
            raise Failure("STORAGE_ACCESS_DENIED")
        if status != STORAGE_STATUS_OK:
            raise Failure("STORAGE_READ_FAILED")
        stored = answer.get("data")
        if not isinstance(stored, str):
            raise Failure("STORAGE_READ_FAILED")
        if any(secret in stored for secret in self.secrets()):
            raise Failure("CREDENTIAL_IN_STORAGE")

    async def status_has(self, page, fragment, reason):
        """Wait for the shell's own status line to name `fragment`."""
        try:
            await page.wait_for_function(
                "([fragment]) => { const node = document.querySelector('#status');"
                " return !!node && node.textContent.includes(fragment); }",
                arg=[fragment],
                timeout=STEP_MS,
            )
            return (await page.locator("#status").text_content()) or ""
        except Exception:
            raise Failure(reason) from None

    # -- the run --------------------------------------------------------

    async def run(self):
        try:
            from playwright.async_api import async_playwright
        except Exception:
            raise Failure("BROWSER_PLAYWRIGHT_UNAVAILABLE") from None
        try:
            async with async_playwright() as playwright:
                context = await playwright.chromium.launch_persistent_context(
                    self.config["profile"],
                    executable_path=self.config["chromium"],
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--no-first-run",
                        "--disable-background-networking",
                        "--disable-component-update",
                        "--disable-sync",
                        "--disable-default-apps",
                        "--disable-search-engine-choice-screen",
                    ],
                    service_workers="block",
                )
                try:
                    browser = context.browser
                    extra = {"browser": browser.version if browser else ""}
                    page = context.pages[0] if context.pages else await context.new_page()
                    self.routes(context, page)
                    extra.update(await self.flow(context, page))
                    self.check_origin()
                    return summary(self.config, None, extra)
                finally:
                    await context.close()
        except Failure:
            raise
        except Exception:
            raise Failure("BROWSER_SESSION_FAILED") from None

    async def goto(self, page, url, reason):
        try:
            await page.goto(url, wait_until="commit", timeout=STEP_MS)
        except Exception:
            raise Failure(reason) from None
        self.check_origin()
        return page

    async def flow(self, context, page):
        extra = {}

        # 1. A brand-new profile holds no cookie.
        if await context.cookies(self.origin):
            raise Failure("COOKIES_BEFORE_SIGN_IN")

        # 2. Anonymous navigation is the origin's own sign-in redirect. The
        # redirect target is the shared sign-in route (a navigation without a
        # cookie is redirected by the same shared middleware from `/web/login`
        # itself), so the first hop alone is inspected.
        await self.goto(page, self.web + SHELL, "NAVIGATION_EXCEEDED")
        request = await evaluate(
            page, "() => ({path: location.pathname, search: location.search})", "ANONYMOUS_NOT_REDIRECTED"
        )
        if request["path"] != "/web" + LOGIN or request["search"] != "?return_to=%2Fweb%2Fblob":
            raise Failure("ANONYMOUS_NOT_REDIRECTED")
        await page.wait_for_load_state("load", timeout=STEP_MS)
        await self.no_shell(page, "ANONYMOUS_SHELL_SERVED")
        if await page.title() != "Rootyard sign in":
            raise Failure("LOGIN_PAGE_INVALID")

        # 3. The real form with the owner's API token.
        await page.locator('input[name="username"]').fill(self.owner)
        await page.locator('input[name="token"]').fill(self.config["token"])
        async with page.expect_navigation(wait_until="commit", timeout=STEP_MS):
            await page.get_by_role("button", name="Sign in").click()
        self.check_origin()
        if await evaluate(page, "() => location.pathname", "SIGN_IN_FAILED") != "/web" + SHELL:
            raise Failure("SIGN_IN_FAILED")
        await self.remember_cookies(context)
        jars = {cookie["name"]: cookie for cookie in await context.cookies(self.origin)}
        session, csrf = jars.get(SESSION_COOKIE, {}), jars.get(CSRF_COOKIE, {})
        if not session.get("value") or session.get("httpOnly") is not True or session.get("sameSite") != "Strict":
            raise Failure("SESSION_COOKIE_INVALID")
        if not csrf.get("value") or csrf.get("httpOnly") is not False or csrf.get("sameSite") != "Strict":
            raise Failure("CSRF_COOKIE_INVALID")
        await page.wait_for_load_state("load", timeout=STEP_MS)
        await self.no_credentials(page)
        extra["cookies"] = {"session_http_only": True, "session_same_site": "Strict", "csrf_readable": True}

        # 4. The signed-in shell is a direct 200 under its CSP and loads only
        # its own script; the script lists the repository by name.
        await self.goto(page, self.web + SHELL, "SHELL_NOT_SERVED")
        served = await evaluate(
            page,
            """async () => {
                const response = await fetch(location.pathname, {credentials: 'same-origin'});
                return {status: response.status,
                        csp: response.headers.get('content-security-policy') || '',
                        type: response.headers.get('content-type') || ''};
            }""",
            "SHELL_NOT_SERVED",
        )
        if served["status"] != 200 or "text/html" not in served["type"]:
            raise Failure("SHELL_NOT_SERVED")
        if "script-src 'self'" not in served["csp"]:
            raise Failure("SHELL_CSP_MISSING")
        scripts = await evaluate(
            page, "() => Array.from(document.scripts).map((node) => node.src)", "SHELL_SCRIPT_INVALID"
        )
        if scripts != [self.web + "/app.js"]:
            raise Failure("SHELL_SCRIPT_INVALID")
        await self.rendered(page, "LIST_NOT_RENDERED")
        link = page.get_by_role("link", name=f"{self.owner}/{self.repo}", exact=True)
        try:
            await link.wait_for(state="visible", timeout=STEP_MS)
        except Exception:
            raise Failure("REPO_LINK_MISSING") from None
        if await link.get_attribute("href") != self.scope:
            raise Failure("REPO_LINK_INVALID")
        # The visible, correctly linked repository entry is the index's client
        # acceptance: only the status is recorded, the adapter proves identity.
        extra["list"] = {
            "status": self.route_statuses.get("web_list"),
            "items_shape": True,
            "accepted": True,
            "repository_link_clicked": True,
        }
        await link.click()
        await page.wait_for_url(self.origin + self.scope, timeout=STEP_MS)
        await page.wait_for_load_state("load", timeout=STEP_MS)
        self.check_origin()

        # Real read chain: refs (unbound), tree, commits, each presenting the
        # previous pair; the page's own status and content must prove it. The
        # rendered HEAD tree must carry both real pushes, and every captured
        # response revision must meet the final committed push's revision.
        status = await self.status_has(page, "Read complete.", "READ_CHAIN_INVALID")
        content = (await page.locator("#content").text_content()) or ""
        for heading in ("References", "Files at HEAD", "Commits"):
            if heading not in content:
                raise Failure("REPO_PAGE_INCOMPLETE")
        # Both real pushes' files (exactly as the tree names them) must render.
        first_file, second_file = self.config["file"], self.config["second_file"]
        if first_file not in content or second_file not in content:
            raise Failure("REPO_PAGE_INCOMPLETE")
        if self.config["oid"][:7] not in content:
            raise Failure("REPO_PAGE_INCOMPLETE")
        if "This server did not provide a bounded session." in status:
            raise Failure("READ_CHAIN_INVALID")
        reads = await self.page_reads(page)
        if reads["complete"] is not True:
            raise Failure("READ_CHAIN_INVALID")
        for tail in ("refs", "tree", "commits"):
            if reads[tail]["revision"] < self.bound:
                raise Failure("API_READ_BOUND_INVALID")
        extra["reads"] = {tail: {"revision": reads[tail]["revision"]} for tail in ("refs", "tree", "commits")}

        # 5. Cookie-only denial of the unchanged bearer-only routes, observed
        # exactly as the origin answers them. The Smart HTTP path is the
        # gateway's real `/git/{owner}/{name}/info/refs` form: `name` is the
        # configured bare repository name and the handler's `repository_name`
        # requires the `.git` suffix, so it is kept here.
        extra["denials"] = {
            "api": await self.cookie_only(page, "/api/repos", "api"),
            "git": await self.cookie_only(
                page, f"/git/{self.owner}/{self.repo}.git/info/refs?service=git-upload-pack", "git"
            ),
        }
        if extra["denials"]["api"].get("classification") != DENIAL_DIRECT:
            raise Failure("API_COOKIE_ONLY_STATUS_INVALID")
        if extra["denials"]["git"].get("classification") not in (DENIAL_DIRECT, DENIAL_PENDING):
            raise Failure("GIT_COOKIE_ONLY_STATUS_INVALID")

        # 6. The labelled client-side fault on its own page, only now that the
        # real UI chain passed; the fixed route names and statuses then close
        # the run.
        extra["fault"] = await self.inject(context)
        extra["routes"] = dict(self.route_statuses)
        return extra

    # -- reads ----------------------------------------------------------

    async def rendered(self, page, reason):
        """Wait until the page's own script rendered a list, so its first read
        has happened and a later page fetch presents the same bound."""
        await self.status_has(page, "", reason)

    async def page_reads(self, page):
        """The revisions of the page's own refs/tree/commits responses and
        whether the page's chain completed.

        Responses are not read back from requests: the protocol sends no
        revision on a request, so the page's ordered response pairs recorded by
        `listen` are the only source. The pairs belong to this page's own
        navigation; the fault page has its own and is never consulted. Response
        tokens stay in memory and are never returned or formatted."""
        tail_names = ("refs", "tree", "commits")
        try:
            await page.get_by_role("heading", name="Commits").wait_for(timeout=STEP_MS)
        except Exception:
            raise Failure("READ_CHAIN_INVALID") from None
        pairs = self.read_pairs.get(id(page)) or {}
        revisions = {}
        for tail in tail_names:
            responses = pairs.get(tail) or []
            if len(responses) != 1:
                raise Failure("READ_CHAIN_INVALID")
            response = responses[0]
            token = response.get("token") if isinstance(response, dict) else None
            revision = response.get("revision") if isinstance(response, dict) else None
            if not isinstance(token, str) or not token:
                raise Failure("READ_CHAIN_INVALID")
            if not isinstance(revision, int) or isinstance(revision, bool) or revision <= 0:
                raise Failure("READ_CHAIN_INVALID")
            revisions[tail] = revision
        seen = [revisions[tail] for tail in tail_names]
        return {
            "refs": {"revision": revisions["refs"]},
            "tree": {"revision": revisions["tree"]},
            "commits": {"revision": revisions["commits"]},
            "complete": all(later >= earlier for earlier, later in zip(seen, seen[1:])),
        }

    async def cookie_only(self, page, path, route):
        """One cookie-only fetch of a bearer-only route, classified honestly.

        The origin's answer reaches Chromium unchanged, its own
        `WWW-Authenticate` included, so the page must observe what the origin
        really answers. The page reports either an actual response status, or
        its own `AbortSignal.timeout` firing (recognised only by that signal's
        `TimeoutError` reason) together with an integer elapsed time measured
        by the page; any other rejection is reported as a failed fetch. Never
        the path, a request header, a cookie, a challenge, the response body or
        exception text leaves the page.

        The API read must resolve directly with the actual `401`. The Smart
        HTTP read may either resolve with the actual `401`, or still be waiting
        on the origin's Basic challenge when its own signal fires; that outcome
        is accepted only past the configured boundary and only as a pending
        challenge, never as a denial the page observed.

        The exact request is counted on this page while the read runs, and a
        direct or pending outcome requires exactly one attempt, so another
        request of the same shape (for example Chromium's settled Basic
        HTTP-auth exchange replaying a credential) can never stand in for it.
        """
        exact = self.origin + path
        attempts = []
        # Only while the page-side read itself runs is its request counted; no
        # request of this URL before it (or after it) counts.
        watching = {"active": True}

        def count(request):
            if watching["active"] and request.url == exact:
                attempts.append(1)

        page.on("request", count)
        try:
            answer = await evaluate(
                page,
                f"""async ([path, timeout, pending]) => {{
                    const started = performance.now();
                    const signal = AbortSignal.timeout(timeout);
                    let response;
                    try {{
                        response = await fetch(path, {{credentials: 'same-origin',
                            headers: {{Accept: 'application/json'}},
                            signal}});
                    }} catch (_) {{
                        const reason = signal.reason;
                        const timedOut = signal.aborted && reason !== undefined && reason !== null
                            && reason.name === 'TimeoutError';
                        if (pending && timedOut) {{
                            return {{
                                classification: '{DENIAL_PENDING}',
                                status: null,
                                abort: {{
                                    reason: '{TIMEOUT_REASON}',
                                    elapsed_ms: Math.ceil(performance.now() - started),
                                }},
                            }};
                        }}
                        return {{classification: 'fetch_failed', status: null, abort: null}};
                    }}
                    return {{
                        classification: '{DENIAL_DIRECT}',
                        status: response.status,
                        abort: null,
                    }};
                }}""",
                f"{route.upper()}_COOKIE_ONLY_FETCH_FAILED",
                [path, FETCH_TIMEOUT_MS, route == "git"],
            )
        finally:
            watching["active"] = False
            page.remove_listener("request", count)
        if not isinstance(answer, dict):
            raise Failure(f"{route.upper()}_COOKIE_ONLY_FETCH_FAILED")
        classification = answer.get("classification")
        status = answer.get("status")
        abort = answer.get("abort")
        if classification == DENIAL_DIRECT and abort is None:
            # The page's Fetch really resolved: only its actual status counts.
            if isinstance(status, bool) or status != 401:
                raise Failure(f"{route.upper()}_COOKIE_ONLY_STATUS_INVALID")
            return {"classification": DENIAL_DIRECT, "status": status, "abort": None}
        if classification == DENIAL_PENDING and route == "git" and status is None and isinstance(abort, dict):
            # A challenge still pending after the page's own signal fired: the
            # one request went out and was never answered.
            if len(attempts) != 1:
                raise Failure("GIT_COOKIE_ONLY_FETCH_FAILED")
            reason = abort.get("reason")
            elapsed = abort.get("elapsed_ms")
            if reason != TIMEOUT_REASON:
                raise Failure("GIT_COOKIE_ONLY_FETCH_FAILED")
            if isinstance(elapsed, bool) or not isinstance(elapsed, int):
                raise Failure("GIT_COOKIE_ONLY_FETCH_FAILED")
            if elapsed < FETCH_TIMEOUT_MS:
                raise Failure("GIT_COOKIE_ONLY_TIMEOUT_EARLY")
            return {
                "classification": DENIAL_PENDING,
                "status": None,
                "abort": {"reason": TIMEOUT_REASON, "elapsed_ms": elapsed},
            }
        if route == "api" and classification == DENIAL_PENDING:
            raise Failure("API_COOKIE_ONLY_TIMEOUT")
        raise Failure(f"{route.upper()}_COOKIE_ONLY_FETCH_FAILED")

    async def no_shell(self, page, reason):
        scripts = await evaluate(page, "() => Array.from(document.scripts).map((node) => node.src)", reason)
        if any(script.endswith("/web/app.js") for script in scripts):
            raise Failure(reason)

    async def inject(self, context):
        """A fresh fault page whose one tree answer is synthetic.

        The SPA issues its token-free refs read before any tree request, so by
        the interception this page's own first refs response pair already
        exists; the synthetic tree carries exactly that token and the revision
        one below it. The page is a labelled client fault and the answer is
        never presented as an upstream one. Only page-local facts and
        booleans leave this method: no token, URL or identity.
        """
        origin = self.origin
        target = origin + self.alias + "/tree?oid=HEAD"
        synthetic = {
            "oid": self.config["oid"],
            "tree_oid": self.config["oid"],
            "path": "",
            "items": [
                {
                    "name": FAULT_MARKER,
                    "path": FAULT_MARKER,
                    "mode": "100644",
                    "kind": "blob",
                    "oid": self.config["oid"],
                    "size": 1,
                }
            ],
            "next_after": None,
        }
        # ``routes`` registered ``context.on("page", self.listen)``, so creating
        # the page already attached its response/request capture exactly once;
        # a second ``self.listen(page)`` would duplicate both.
        page = await context.new_page()
        facts = {"intercepted": 0, "commits": 0, "failed": False}

        def observe_request(request):
            # Commits requests of this page only; the global count also holds
            # the successful UI chain and never speaks for the fault page.
            if self.confined(request.url):
                path = request.url[len(origin):].split("?", 1)[0]
                if path == self.alias + "/commits":
                    facts["commits"] += 1

        page.on("request", observe_request)

        async def fault(route, request):
            # This handler confines on its own: a request that left the origin
            # is aborted and fails the run, whatever other confinement exists.
            if not self.confined(request.url):
                self.escaped = True
                facts["failed"] = True
                await route.abort()
                return
            if request.url != target:
                await route.continue_()
                return
            pairs = (self.read_pairs.get(id(page)) or {}).get("refs") or []
            refs = pairs[0] if pairs else {}
            token = refs.get("token") if isinstance(refs, dict) else None
            revision = refs.get("revision") if isinstance(refs, dict) else None
            presented = request.headers.get(TOKEN)
            if (
                facts["intercepted"]
                or not isinstance(token, str)
                or not token
                or not isinstance(revision, int)
                or isinstance(revision, bool)
                or revision <= 1
                or not isinstance(presented, str)
                or presented != token
                or request.headers.get(REVISION) is not None
            ):
                # A malformed injection request is never answered with a pass.
                facts["failed"] = True
                await route.abort()
                return
            facts["intercepted"] += 1
            facts["uses_token"] = True
            facts["no_revision"] = True
            fault_revision = revision
            await route.fulfill(
                status=200,
                headers={
                    "content-type": "application/json",
                    "cache-control": "no-store",
                    "x-rootyard-client-fault": "1",
                    TOKEN: token,
                    REVISION: str(revision - 1),
                },
                body=json.dumps(synthetic),
            )

        await page.route("**/*", fault)
        await self.goto(page, self.web + self.scope, "FAULT_NOT_APPLIED")
        # The tree request alone produces the generic refusal; refs may already
        # have rendered before it.
        await self.fault_status(page)
        status = (await page.locator("#status").text_content()) or ""
        content = (await page.locator("#content").text_content()) or ""
        self.check_origin()
        if facts["failed"]:
            raise Failure("FAULT_BOUND_INVALID")
        if facts["intercepted"] != 1:
            raise Failure("FAULT_NOT_APPLIED")
        if facts["commits"] != 0:
            raise Failure("FAULT_COMMITS_REQUESTED")
        refusal_shown = "Read complete." not in status and "refused" in status
        marker_absent = FAULT_MARKER not in content
        tree_absent = "Files at HEAD" not in content and self.config["file"] not in content
        commits_absent = "Commits" not in content
        await self.no_credentials(page)
        return {
            "mode": "client_fault_injection",
            "refs_revision": fault_revision,
            "synthetic_revision": fault_revision - 1,
            "started": facts["intercepted"] == 1,
            "fault_uses_refs_token": facts.get("uses_token") is True,
            "fault_request_revision_absent": facts.get("no_revision") is True,
            "refusal_shown": refusal_shown,
            "marker_absent": marker_absent,
            "tree_absent": tree_absent,
            "commits_absent": commits_absent,
            "commits_not_requested": facts["commits"] == 0,
        }

    async def fault_status(self, page):
        try:
            await page.wait_for_function(
                "() => { const node = document.querySelector('#status');"
                " return !!node && node.getAttribute('data-kind') === 'error'; }",
                timeout=STEP_MS,
            )
            return (await page.locator("#status").text_content()) or ""
        except Exception:
            raise Failure("FAULT_REFUSAL_MISSING") from None


async def main(argv):
    if len(argv) != 1:
        print(summary({}, "NO_ARGUMENTS", {}), flush=True)
        return
    try:
        config = load_config(argv[0])
    except Failure as failure:
        print(summary({}, failure.reason, {}), flush=True)
        return
    except Exception:
        print(summary({}, "CONFIG_INVALID", {}), flush=True)
        return
    client = Client(config)
    try:
        line = await client.run()
    except Failure as failure:
        line = summary(config, failure.reason, {})
    except BaseException:
        line = summary(config, "CLIENT_FAILED", {})
    print(line, flush=True)


if __name__ == "__main__":
    try:
        asyncio.run(main(sys.argv[1:]))
    except BaseException:
        # Nothing but the one summary line ever reaches an output stream.
        print(summary({}, "CLIENT_FAILED", {}), flush=True)
