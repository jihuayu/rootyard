use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct Workspace {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub owner: String,
    pub repository: String,
    pub agent_id: String,
    pub creator_id: Uuid,
    pub state: String,
    pub host_id: Uuid,
    pub lease_epoch: i64,
    pub revision: i64,
    pub git_generation: i64,
    pub last_checkpoint_id: Option<Uuid>,
}
impl Workspace {
    pub fn from_row(row: &tokio_postgres::Row) -> Self {
        Self {
            id: row.get("id"),
            repository_id: row.get("repository_id"),
            owner: row.get("owner_slug"),
            repository: row.get("repository_name"),
            agent_id: row.get("agent_id"),
            creator_id: row.get("creator_id"),
            state: row.get("state"),
            host_id: row.get("host_id"),
            lease_epoch: row.get("lease_epoch"),
            revision: row.get("revision"),
            git_generation: row.get("git_generation"),
            last_checkpoint_id: row.get("last_checkpoint_id"),
        }
    }
}

pub const WS_COLUMNS: &str = "id,repository_id,owner_slug,repository_name,agent_id,creator_id,state,host_id,lease_epoch,revision,git_generation,last_checkpoint_id";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateWorkspace {
    pub owner: String,
    pub repository: String,
    pub agent_id: String,
    pub base_oid: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileQuery {
    pub path: String,
    pub view: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilePut {
    pub content_base64: String,
    pub expected_entry_version: i64,
    pub expected_workspace_revision: i64,
    pub lease_epoch: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitAction {
    pub action: String,
    pub paths: Option<Vec<String>>,
    pub expected_git_generation: i64,
    pub expected_workspace_revision: i64,
    pub lease_epoch: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointRequest {
    pub expected_workspace_revision: i64,
    pub lease_epoch: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkRequest {
    pub checkpoint_id: Uuid,
    pub new_agent_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRequest {
    pub agent_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsQuery {
    pub after_revision: Option<i64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRequest {
    pub expected_lease_epoch: i64,
}
