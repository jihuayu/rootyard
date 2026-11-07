# Browser sign-in and sessions

Rootyard exchanges an existing CLI-issued API credential for a short-lived
browser session. Visit `/web/login` and enter the username and API token once.
The server verifies the API token, creates a separate `browser` token plus a
CSRF-bound `web_sessions` row, stores only SHA-256 digests in PostgreSQL, and
redirects to a normalized `/web/` or `/ui/` return target. The API token is never
placed in a URL, cookie, or rendered page.

The `rootyard_session` cookie is HTTP-only, `SameSite=Strict`, and `Secure` on
HTTPS. Plain HTTP cookies are allowed only for explicit loopback development
hosts. Deployments behind a TLS proxy must forward the original HTTPS scheme.
The separate readable `rootyard_csrf` cookie supplies the token required in
`X-CSRF-Token` for cookie-authenticated Issue and PR mutations. The server also
checks the browser Origin against the request host. Sign-out revokes the
persisted session and its browser-only token before clearing both cookies.
Expired or revoked sessions lose access on the next request.

The 68-character session secret embeds a parent API-token UUID plus a random
nonce. The UUID is an identifier, not an API secret, and the stored digest binds
the whole secret: changing the embedded UUID makes the session lookup fail
closed. HTTP admission checks that the parent API token is still unrevoked and
unexpired, so revoking or expiring the API token denies the browser session on
new requests. Browser sessions created before this upgrade are unparented and
fail closed; users must sign in once again after deployment.

Raw `rootyard_token`, `token`, and `X-Rootyard-Token` Web credentials are no
longer accepted. Only the login form exchange is supported. A browser-session
secret is rejected as a Git or `/api` Bearer/Basic credential and is rejected on
Web routes unless it is presented through the matching `rootyard_session`
cookie. An explicit API `Authorization` header takes priority over an unrelated
stale browser cookie.

Parent revocation is checked when a request is admitted. Once a Web write has
passed admission, the browser token, session row, and repository RBAC are
rechecked at normal transaction commit, but the parent token is not held or
rechecked for the whole in-flight request. A narrow write already in progress
may therefore finish after parent revocation; immediate interruption of
admitted operations is a separate concern. Revoke the child session directly
when that stronger bound is required. Browser session tokens cannot authenticate
Git or `/api` routes. CLI-issued API tokens remain independent, retain their
existing read-only and revocation rules, and never appear in Web page source. A
read-only API credential can open a read-only browser session but cannot perform
Web mutations.
