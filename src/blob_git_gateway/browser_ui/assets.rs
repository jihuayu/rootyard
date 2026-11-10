//! Static, first-party assets of the read-only Blob browser.

/// The CSP of the SPA shell only: the page renders dynamic lists through the
/// injected style tag the shell itself carries.
const SHELL_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// The inline style tag of the shell, part of its CSP.
pub(super) const SHELL_STYLE: &str = "<style>body{font:14px/1.5 system-ui,sans-serif;margin:0;color:#1d2327}header{padding:.6rem 1rem;border-bottom:1px solid #d0d4d9}main{padding:1rem}h1{font-size:1.2rem}h2{font-size:1rem;margin-top:1.4rem}table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:.25rem .5rem;border-bottom:1px solid #e6e8ea}code,.oid{font-family:ui-monospace,monospace;font-size:.85em}[data-kind=error]{color:#8a1c1c}</style>";

/// One shell for every page. It carries no repository name, list, session
/// bound or content. The script derives the page scope from
/// `location.pathname`; the server never embeds a bound in HTML, a URL, storage
/// or a cookie. The first repository read is token-free (the compatibility
/// path) and adopts the bound of its successful answer.
pub(super) const SHELL: &str = "<!doctype html>
<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>Rootyard Blob repositories</title>__STYLE__
</head>
<body><header><strong>Rootyard</strong> &middot; Blob repositories &middot; read only</header>
<main><p id=\"status\">Loading&hellip;</p><h1 id=\"title\"></h1><nav id=\"nav\"></nav><section id=\"content\"></section></main>
<script src=\"/web/app.js\" defer></script></body></html>
";

/// The only script. Repository data is rendered exclusively through
/// `textContent`/`createElement`; the script contains no `innerHTML`.
///
/// Session contract (read only):
///
/// * the first repository read presents no bound, so a keyless gateway stays
///   usable: while no bound was ever adopted, a successful answer with no
///   session headers at all (the index list handler issues none) is read and
///   labelled "no session bound", and the browser stays boundless; the index
///   list is such a read on every page;
/// * a half pair (only one session header) is always refused, and once a bound
///   was adopted even a headerless successful read is refused;
/// * a successful answer is read and parsed whole and must have the exact
///   `{items: [...]}` shape before anything is admitted; only then are its
///   headers validated against the previous bound and both token and revision
///   updated together;
/// * once a bound exists, every next read presents it and requires a complete,
///   valid, non-regressing bound in return; a fetch, body, schema, header or
///   `Behind` refusal keeps the old bound and renders no response data;
/// * the bound lives in closure variables, in memory only, and is never placed
///   in a URL, storage, a cookie or a DOM attribute.
pub(super) const SCRIPT: &str = "'use strict';
(function () {
  const TOKEN = 'x-rootyard-session', REVISION = 'x-rootyard-session-revision';
  const status = document.getElementById('status'), title = document.getElementById('title');
  const nav = document.getElementById('nav'), content = document.getElementById('content');
  const READ = 'Read complete.', NO_SESSION = 'Read complete. This server did not provide a bounded session.';
  const REFUSED = 'This read was refused. Reload the page to try again.';
  // The result of an accepted answer that carried no session headers at all:
  // nothing is adopted and the browser stays boundless.
  const NO_BOUND = Object.freeze({token: null, revision: null});
  let bound = null;
  let revision = null;
  let page = null;

  function show(text, error) {
    status.textContent = text;
    status.dataset.kind = error ? 'error' : 'ok';
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }
  function link(href, text) {
    const anchor = el('a', text);
    anchor.href = href;
    return anchor;
  }
  function short(oid) { return typeof oid === 'string' && oid.length > 12 ? oid.slice(0, 12) : String(oid); }
  function table(head, rows) {
    const table = el('table'), header = el('tr');
    for (const name of head) header.appendChild(el('th', name));
    table.appendChild(header);
    for (const cells of rows) {
      const row = el('tr');
      for (const cell of cells) {
        const data = el('td');
        data.appendChild(cell);
        row.appendChild(data);
      }
      table.appendChild(row);
    }
    return table;
  }
  function items(data) {
    return data && Array.isArray(data.items) ? data.items : null;
  }

  function isObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  // Adopt the pair this answer established. This is the only place that
  // changes the in-memory bound, and it runs only after the whole body was
  // read and parsed into the expected shape. Token and revision change
  // together, in one step; `nextRevision` is the parameter, never the closure
  // variable it replaces.
  function adopt(nextToken, nextRevision) {
    bound = nextToken;
    revision = nextRevision;
  }

  // Validate response headers against the previous bound; nothing is adopted
  // here. Without a bound ever adopted before (the first read of every page,
  // including the index list whose handler issues no session) an answer with
  // no session headers at all is accepted and returns the NO_BOUND result, so
  // a keyless gateway stays readable and stays boundless. A complete pair with
  // a positive, safe, non-regressing revision returns the pair to adopt. Every
  // other shape is refused with null: a partial pair always, any session
  // header set once a bound exists, a non-success and a regressing revision.
  function admit(response) {
    if (!response.ok) return null;
    const token = response.headers.get(TOKEN), raw = response.headers.get(REVISION);
    const hasToken = response.headers.has(TOKEN), hasRevision = response.headers.has(REVISION);
    const headerless = !hasToken && !hasRevision;
    if (headerless) return bound === null && revision === null ? NO_BOUND : null;
    if (!hasToken || !hasRevision || !token || raw === null || raw.trim() === '') return null;
    const nextRevision = Number(raw.trim());
    if (!Number.isSafeInteger(nextRevision) || nextRevision <= 0) return null;
    if (revision !== null && nextRevision < revision) return null;
    return {token: token, revision: nextRevision};
  }

  // One same-origin read. The cookie carries the browser session; the bound,
  // when known, travels only as a header. The bound advances only after the
  // status, headers and complete body all passed.
  async function read(scope, url) {
    const headers = {Accept: 'application/json'};
    if (bound) headers[TOKEN] = bound;
    const response = await fetch(url, {credentials: 'same-origin', headers}).catch(() => null);
    if (!response) { if (page === scope) show('The request could not be completed.', true); return null; }
    if (response.status === 401) {
      if (page === scope) show('Your sign-in has ended. Reload to sign in again.', true);
      return null;
    }
    const next = admit(response);
    if (!next) {
      if (page === scope) show(bound ? REFUSED : 'This read was refused. Reload to sign in again.', true);
      return null;
    }
    let data;
    try { data = await response.json(); } catch (_) { data = undefined; }
    const list = isObject(data) && Array.isArray(data.items) ? data.items : null;
    if (!list) {
      if (page === scope) show(REFUSED, true);
      return null;
    }
    if (next !== NO_BOUND) adopt(next.token, next.revision);
    return page === scope ? list : null;
  }

  async function repository(owner, name) {
    const scope = 'repos/' + owner + '/' + name;
    const base = '/web/blob/api/repos/' + encodeURIComponent(owner) + '/' + encodeURIComponent(name);
    page = scope;
    title.textContent = owner + '/' + name;
    clear(nav);
    clear(content);
    const refs = await read(scope, base + '/refs');
    if (!refs) return;
    content.appendChild(el('h2', 'References'));
    content.appendChild(refs.length ? table(['Name', 'Object', 'Kind'], refs.map(ref => [
      el('code', ref.name), el('code', short(ref.oid), 'oid'), el('span', ref.kind)
    ])) : el('p', 'This repository has no references yet.'));
    // A failed read already showed its refusal; the sequence stops there so a
    // later read cannot overwrite that status with a success.
    const tree = await read(scope, base + '/tree?oid=HEAD');
    if (!tree) return;
    content.appendChild(el('h2', 'Files at HEAD'));
    content.appendChild(tree.length ? table(['Path', 'Kind', 'Size'], tree.map(entry => [
      el('code', entry.path), el('span', entry.kind),
      el('span', entry.size === null || entry.size === undefined ? '' : entry.size)
    ])) : el('p', 'No files.'));
    const commits = await read(scope, base + '/commits');
    if (!commits) return;
    content.appendChild(el('h2', 'Commits'));
    content.appendChild(commits.length ? table(['Commit', 'Subject', 'Author'], commits.map(commit => [
      el('code', short(commit.oid), 'oid'), el('span', commit.subject), el('span', commit.author_name)
    ])) : el('p', 'No commits.'));
    show(bound ? READ : NO_SESSION, false);
  }

  async function index() {
    const scope = 'index';
    page = scope;
    title.textContent = 'Blob repositories';
    clear(nav);
    clear(content);
    const items = await read(scope, '/web/blob/api/repos');
    if (!items) return;
    content.appendChild(items.length ? table(['Repository', 'Format'], items.map(repo => [
      link('/web/blob/repos/' + encodeURIComponent(repo.owner) + '/' + encodeURIComponent(repo.name),
        repo.owner + '/' + repo.name),
      el('span', repo.object_format)
    ])) : el('p', 'No repositories are visible to this account.'));
    show(bound ? READ : NO_SESSION, false);
  }

  const match = /^\\/web\\/blob\\/repos\\/([^/]+)\\/([^/]+)\\/?$/.exec(location.pathname);
  try {
    if (match) repository(decodeURIComponent(match[1]), decodeURIComponent(match[2]));
    else index();
  } catch (_) { show(REFUSED, true); }
})();
";

/// The shell with its style tag in place.
pub(super) fn shell() -> String {
    SHELL.replace("__STYLE__", SHELL_STYLE)
}

/// The shell's response policy: its script is external (`script-src 'self'`) and
/// its only inline style is the static style tag above.
pub(super) const CSP: &str = SHELL_CSP;
