# Issue 47 final delta review

- Exact head: `b849a07fc2f872c36877080d150ce0344da4b410`
- Accepted base: `0a7c8b83afe9ae291f25373dba2e0f6edfbc5dbb`
- Delta reviewed: `0a7c8b8..b849a07` (only `src/web/session.rs`, docs, `TEST_INFRA.md`, `TEST_READY.md`, `tests/web_sessions.py`, `tests/browser_ui.py`)
- Verdict: **ACCEPT_ISSUE47_FINAL_DELTA_CLOSABLE_47_WITH_KNOWN_BOUNDED_PARENT_TOCTOU_P2**
- P1/blockers: **none**. New P2: **none**.

## Closable 47

Closable for isolated issue47 qualification. Both required native jobs passed on b849: the HTTP `browser_session_workflow` and the actual-Chromium `chromium_browser_workflow`. Certificate: `valid=true`, source/built/compiled `b849a07...`, production inputs `ceb29d9ff4937c736dc8c4d904a1b2ff793e47f955f236e9796bae1d12b7f5f4`, binary `def04d53a360c255b6f56d3bab8df04bfa965fb6f3e17cd2005b87ee40648f66` (actual `sha256sum` matches), harness hashes match the coordinator, and build inputs are byte-identical before/after the build.

## Delta findings

1. `return_to` hardening: `percent_decode_ascii` + `header_safe_ascii` + `is_safe_return_to` validate both the original and percent-decoded path, reject malformed/double-encoded `%`, non-ASCII/control/header-unsafe bytes, backslash, `#`, `//`, dot segments, and `/web/login`; unsafe values fall back to `/web/repos`. The new HTTP cases cover `%2e`, `%2E`, `%252e`, encoded question mark, unicode, spaces, control characters, and `/web/login`; all expect 303 to `/web/repos`, with no 500.
2. Credential selection: `WebAuthMode`/`web_auth_mode` make an explicit `Authorization` authoritative. A browser credential is accepted only through a matching `rootyard_session` cookie (`BrowserSession`); mismatch/no cookie is 401. API/other headers use `HeaderApiOrOther`, so a stale cookie cannot shadow them. `normalize_web_headers` returns the original headers whenever `Authorization` is present, so invalid headers do not fall back to the cookie.
3. CSRF/origin: cookie-only and matching-browser-header mutations still require Origin and `X-CSRF-Token`. The valid API-header + stale-cookie POST intentionally needs no cookie CSRF, as expected.
4. Scope separation: browser tokens remain rejected on `/api` and `/git`; API Authorization remains usable on `/web`.
5. Tests: HTTP covers parent API expiry while child browser token/web-session expiry is still future (401, navigation redirect, parent login 401), collaborator grant/discovery/removal/post-removal denial, legacy `token=` cookie denial, valid API header + stale cookie GET 200/POST 201, and cookieA/headerBrowserB 401. Chromium asserts and clicks the real `alice/demo` discovery link, then exercises issue, PR/merge and logout.
6. Docs: `docs/browser-sessions.md`, `docs/design/implementation-status.md`, `TEST_INFRA.md`, and `TEST_READY.md` state that raw `rootyard_token`/`token`/`X-Rootyard-Token` web auth is removed, the login-form exchange creates a parent-bound HttpOnly session, parent revocation/expiry is checked on new requests, pre-upgrade unparented cookies fail closed and require one re-sign-in, and explicit API Authorization wins over a stale cookie.
7. No DDL/schema/IdP/new feature: the only production-code change is `src/web/session.rs`; no migrations or schema changes.

## Known bounded P2 (accepted, non-blocking)

`P2-PARENT-REVOKE-TOCTOU`: parent revocation is enforced at HTTP admission/new requests, but an already-admitted web write can finish after parent API revocation/expiry. Commit-time verification rechecks the child browser token/web_sessions row and normal write checks, not the parent across the whole in-flight request. `docs/browser-sessions.md` truthfully declares this, states the parent is not held/rechecked for the whole request, that a narrow in-progress write may finish, and that immediate interruption is separate. Direct child-session revocation remains covered by the existing commit-time session check. This is the separately tracked #37 concern; it is not a new invalid-API-auth bypass and does not require new Identity/schema/row-lock scope for issue47.

## Residuals / integration note

- No separate HTTP assertion for invalid Authorization + valid cookie; no-fallback is structurally enforced by `normalize_web_headers` and confirmed by inspection.
- The collaborator block covers grant, discovery, removal and post-removal denial, but does not separately re-grant after removal. Non-blocking coverage note, not a delta product defect.
- `tests/backup_capabilities.py` still has the old `BrowserHarness.sign_in` dict-return alias; a different LFS worker owns that file. Primary will reconcile `CapabilityHarness` inheritance/aliases and run actual backup after merge. This is not a b849 product/DDL defect and does not block isolated issue47 qualification.

## Verification boundary

Read-only delta review: original source-review summary/findings, `git diff 0a7..b849`, relevant source/docs/tests, and the completed native reports/certificate/actual binary hash. No Cargo/build/test rerun, no network/GitHub/deploy, no secret/config/env reads.
