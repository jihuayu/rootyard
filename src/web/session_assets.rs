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
    }
    const status = form.querySelector('.form-result');
    status.textContent = 'Saving…';
    try {
      const result = await fetch(form.action, {method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json', 'X-CSRF-Token':cookie('rootyard_csrf')},
        body:JSON.stringify(body)});
      if (result.status === 401) { location.assign('/web/login'); return; }
      if (!result.ok) { status.textContent = `Request failed (${result.status}). Check your permission or refresh the page.`; return; }
      location.reload();
    } catch (_) { status.textContent = 'Connection failed. Try again.'; }
  });
}
"#;
    let mut res = (StatusCode::OK, SCRIPT).into_response();
    res.headers_mut().insert(header::CONTENT_TYPE, "text/javascript; charset=utf-8".parse().unwrap());
    res.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    res
}
