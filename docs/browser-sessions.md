# Browser sign-in and sessions

Rootyard uses an existing CLI-issued API credential as the browser sign-in
mechanism. Visit `/web/login` and enter the username and API token once. The
server exchanges it for a separate random 12-hour browser session, stores only
secret digests in PostgreSQL, and redirects to `/web/repos`. The API token is
not placed in a URL, cookie, or rendered page. Repository discovery and each
page use the same role checks as the API.

The `rootyard_session` cookie is HTTP-only, `SameSite=Strict`, and `Secure` on
HTTPS. Plain HTTP cookies are allowed only for explicit loopback development
hosts. Deployments behind a TLS proxy must forward the original HTTPS scheme.
The separate readable `rootyard_csrf` cookie supplies the token required in
`X-CSRF-Token` for cookie-authenticated Issue and PR mutations. The server also
checks the browser Origin against the request host. Sign-out revokes the
persisted session and its browser-only token before clearing both cookies.
Expired or revoked sessions lose access on the next request.

Browser session tokens cannot authenticate Git or `/api` routes. CLI-issued
API tokens remain independent, retain their existing read-only and revocation
rules, and never appear in Web page source. A read-only API credential can
open a read-only browser session but cannot perform Web mutations.
