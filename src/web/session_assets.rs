//! First-party browser mutation helper served by the session routes.
use axum::{
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};

pub async fn app_js() -> Response {
    const SCRIPT: &str = r#"'use strict';
function cookie(name) {
  const part = document.cookie.split('; ').find(p => p.startsWith(name + '='));
  return part ? part.slice(name.length + 1) : '';
}
function checkedValues(form, name) {
  return Array.from(form.querySelectorAll('[name="' + name + '"]:checked')).map(input => input.value);
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
    } else if (action === 'token-create') {
      const repository = form.querySelector('select[name="repository_id"]');
      const organization = form.querySelector('select[name="organization_id"]');
      body = {
        display_name: fields.display_name,
        expires_in_days: Number(fields.expires_in_days),
        read_only: fields.read_only === 'true',
        repository_grants: repository && repository.value
          ? [{repository_id: repository.value, actions: checkedValues(form, 'repo_action')}] : [],
        namespace_grants: organization && organization.value
          ? [{organization_id: organization.value, actions: checkedValues(form, 'org_action')}] : []
      };
    } else if (action === 'token-scope') {
      const repositories = new Map();
      const organizations = new Map();
      for (const input of form.querySelectorAll('input[name="grant"]:checked')) {
        const parts = input.value.split(':');
        const target = parts[0] === 'repo' ? repositories : organizations;
        const id = parts[1];
        if (!target.has(id)) target.set(id, []);
        target.get(id).push(parts.slice(2).join(':'));
      }
      body = {
        expected_scope_version: Number(fields.expected_scope_version),
        repository_grants: Array.from(repositories, ([id, actions]) => ({repository_id: id, actions})),
        namespace_grants: Array.from(organizations, ([id, actions]) => ({organization_id: id, actions}))
      };
    } else if (action === 'token-rotate' || action === 'token-revoke' || action === 'session-revoke') {
      body = {};
    }
    const status = form.querySelector('.form-result');
    if (status) status.textContent = 'Saving…';
    try {
      const result = await fetch(form.action, {method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json', 'X-CSRF-Token':cookie('rootyard_csrf')},
        body:JSON.stringify(body)});
      if (result.status === 401) { location.assign('/web/login'); return; }
      if (!result.ok) { if (status) status.textContent = `Request failed (${result.status}). Check your permission or refresh the page.`; return; }
      const secretBox = form.dataset.secretOutput ? document.getElementById(form.dataset.secretOutput) : null;
      if (secretBox) {
        const data = await result.json();
        if (data && data.secret) {
          secretBox.querySelector('code').textContent = data.secret;
          secretBox.hidden = false;
          secretBox.scrollIntoView();
          if (status) status.textContent = 'Created. Copy the secret now; it is shown once.';
          form.reset();
          return;
        }
      }
      location.reload();
    } catch (_) { if (status) status.textContent = 'Connection failed. Try again.'; }
  });
}
"#;
    let mut res = (StatusCode::OK, SCRIPT).into_response();
    res.headers_mut().insert(header::CONTENT_TYPE, "text/javascript; charset=utf-8".parse().unwrap());
    res.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    res
}
