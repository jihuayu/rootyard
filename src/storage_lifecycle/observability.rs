//! Authorized, read-only observability of durable GitFS maintenance jobs.
//!
//! Contract: repository `maintain`/`admin` users (never a read-only token) may
//! list or fetch the jobs of one repository. Every query is repository-scoped,
//! so a job id or cursor from another repository can never reveal a row.
//!
//! Pagination is a newest-first keyset over `(created_at DESC, id DESC)`. The
//! opaque cursor is `v1:<job-id>`: a position is *derived from the named job in
//! the same repository*, so a forged timestamp, an unknown id, or a foreign
//! repository's id is rejected with `400` instead of being trusted. Results are
//! bounded (`limit` default 25, maximum 100) and an optional `state` filter is
//! applied before `limit+1`, so pages never contain non-matching rows.
use super::job_view::{JOB_FIELDS, JobPage, JobView};
use crate::{
    AppState, Error,
    auth::{self, Role, finish_tx as finish},
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use deadpool_postgres::Transaction;
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

const DEFAULT_LIMIT: i64 = 25;
const MAX_LIMIT: i64 = 100;
const CURSOR_PREFIX: &str = "v1:";

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobState {
    Queued,
    Running,
    Succeeded,
    Failed,
}

impl JobState {
    fn name(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    after: Option<String>,
    limit: Option<i64>,
    state: Option<JobState>,
}

impl ListQuery {
    fn bounds(&self) -> Result<(i64, Option<Uuid>, Option<&'static str>), Error> {
        let limit = self.limit.unwrap_or(DEFAULT_LIMIT);
        if !(1..=MAX_LIMIT).contains(&limit) {
            return Err(Error::bad_request());
        }
        let after = self.after.as_deref().map(cursor_id).transpose()?;
        Ok((limit, after, self.state.map(JobState::name)))
    }
}

/// Cursors are opaque to clients; only the exact canonical form is accepted so
/// no client-supplied ordering key (timestamp or offset) is ever trusted.
fn cursor_id(raw: &str) -> Result<Uuid, Error> {
    let value = raw.strip_prefix(CURSOR_PREFIX).ok_or_else(Error::bad_request)?;
    let id = Uuid::parse_str(value).map_err(|_| Error::bad_request())?;
    if id.to_string() != value {
        return Err(Error::bad_request());
    }
    Ok(id)
}

fn cursor(job: Uuid) -> String {
    format!("{CURSOR_PREFIX}{job}")
}

/// Resolve the cursor to the durable ordering key of a job in this repository.
/// A job id from any other repository, or an id that never existed, is the same
/// `400`: the response cannot disclose whether a foreign job exists.
async fn cursor_position(tx: &Transaction<'_>, repo: Uuid, job: Uuid) -> Result<String, Error> {
    let row = tx
        .query_opt(
            "SELECT created_at::text FROM storage_maintenance_jobs WHERE repository_id=$1 AND id=$2",
            &[&repo, &job],
        )
        .await
        .map_err(Error::internal)?;
    row.map(|row| row.get::<_, String>(0)).ok_or_else(Error::bad_request)
}

fn respond(value: impl serde::Serialize) -> Result<Response, Error> {
    Ok((StatusCode::OK, [(header::CACHE_CONTROL, "no-store")], Json(value)).into_response())
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let (limit, after, state_filter) = query.bounds()?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Maintain, crate::token_scopes::RepoAction::RepoRead).await?;
    let position = match after {
        Some(job) => Some(cursor_position(&tx, access.repo_id, job).await?),
        None => None,
    };
    let rows = tx
        .query(
            &format!(
                "SELECT {JOB_FIELDS} FROM storage_maintenance_jobs j \
                 WHERE j.repository_id=$1 \
                   AND ($2::text IS NULL OR j.state=$2) \
                   AND ($3::text IS NULL OR (j.created_at, j.id) < ($3::text::timestamptz, $4::uuid)) \
                 ORDER BY j.created_at DESC, j.id DESC LIMIT $5"
            ),
            &[&access.repo_id, &state_filter, &position, &after, &(limit + 1)],
        )
        .await
        .map_err(Error::internal)?;
    let more = rows.len() as i64 > limit;
    let items: Vec<JobView> = rows.iter().take(limit as usize).map(JobView::row).collect();
    let next_after = if more { items.last().map(|job| cursor(job.id)) } else { None };
    // Re-check the token after any lock wait, then release the read snapshot.
    finish(tx, &actor, false).await?;
    respond(JobPage { items, next_after })
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    Path((owner, name, job)): Path<(String, String, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Maintain, crate::token_scopes::RepoAction::RepoRead).await?;
    let row = tx
        .query_opt(
            &format!("SELECT {JOB_FIELDS} FROM storage_maintenance_jobs j WHERE j.repository_id=$1 AND j.id=$2"),
            &[&access.repo_id, &job],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    finish(tx, &actor, false).await?;
    respond(JobView::row(&row))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Query;

    type Bounds = (i64, Option<Uuid>, Option<&'static str>);

    // Mirrors the handler: a rejected extractor and a rejected value are both 400.
    fn bounds(uri: &str) -> Result<Bounds, Error> {
        let Query(query) = Query::<ListQuery>::try_from_uri(&uri.parse().unwrap()).map_err(|_| Error::bad_request())?;
        query.bounds()
    }

    #[test]
    fn cursor_round_trip_is_canonical_only() {
        let job = Uuid::new_v4();
        let encoded = cursor(job);
        assert_eq!(encoded, format!("v1:{job}"));
        assert_eq!(cursor_id(&encoded).unwrap(), job);
        assert_eq!(bounds(&format!("/jobs?after={encoded}")).unwrap().1, Some(job));
        for bad in [
            job.to_string(),
            format!("v2:{job}"),
            format!("v1:{}", job.simple()),
            format!("v1:{}", job.to_string().to_uppercase()),
            "v1:".into(),
            "v1:not-a-uuid".into(),
            format!("v1:{job}:extra"),
        ] {
            assert!(cursor_id(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn bounds_are_bounded_and_state_is_strict() {
        assert_eq!(bounds("/jobs").unwrap(), (25, None, None));
        assert_eq!(bounds("/jobs?limit=1").unwrap().0, 1);
        assert_eq!(bounds("/jobs?limit=100").unwrap().0, 100);
        assert_eq!(bounds("/jobs?state=running").unwrap().2, Some("running"));
        assert_eq!(bounds("/jobs?state=failed").unwrap().2, Some("failed"));
        for bad in [
            "/jobs?limit=0",
            "/jobs?limit=101",
            "/jobs?limit=-1",
            "/jobs?limit=",
            "/jobs?after=",
            "/jobs?after=123",
            "/jobs?state=",
            "/jobs?state=all",
            "/jobs?state=Open",
            "/jobs?state=queued&state=running",
            "/jobs?limit=1&limit=2",
            "/jobs?extra=1",
            "/jobs?after=v1:not-a-uuid",
        ] {
            assert!(bounds(bad).is_err(), "{bad}");
        }
    }
}
