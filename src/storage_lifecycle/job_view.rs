//! Public read-only projection of a durable maintenance job.
//!
//! Lease ownership (`lease_owner`, `lease_until`) and the claim generation are
//! worker fencing capabilities, so they are deliberately absent here. Only the
//! durable identity, lifecycle state, bounded progress/result/error documents
//! and timestamps are exposed. Timestamps are rendered by PostgreSQL to text so
//! the API does not depend on a Rust timestamp type for `TIMESTAMPTZ`.
use serde::Serialize;
use serde_json::Value;
use tokio_postgres::Row;
use uuid::Uuid;

/// Selected with the `j` alias for `storage_maintenance_jobs`; never include
/// lease-owner columns in this list.
pub const JOB_FIELDS: &str = "j.id, j.kind, j.state, j.attempt, j.repository_generation, j.progress, j.result, \
     j.last_error, j.created_at::text AS created_at, j.updated_at::text AS updated_at, \
     j.completed_at::text AS completed_at";

#[derive(Clone, Debug, Serialize)]
pub struct JobView {
    pub id: Uuid,
    pub kind: String,
    pub state: String,
    pub attempt: i32,
    pub repository_generation: i64,
    pub progress: Value,
    pub result: Option<Value>,
    pub error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
}

impl JobView {
    pub fn row(row: &Row) -> Self {
        Self {
            id: row.get("id"),
            kind: row.get("kind"),
            state: row.get("state"),
            attempt: row.get("attempt"),
            repository_generation: row.get("repository_generation"),
            progress: row.get("progress"),
            result: row.get("result"),
            error: row.get("last_error"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            completed_at: row.get("completed_at"),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct JobPage {
    pub items: Vec<JobView>,
    /// Cursor for the next (older) page; `null` when no further job matched.
    pub next_after: Option<String>,
}
