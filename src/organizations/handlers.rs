use crate::{
    AppState, Error, auth, db,
    members::models::{Role, json},
    token_scopes::NamespaceAction,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use deadpool_postgres::Transaction;
use serde::Deserialize;
use serde_json::{Value, json as sjson};
use std::sync::Arc;
use uuid::Uuid;

type Res = Result<Response, Error>;

// The two paginated list handlers live in a sibling file to keep this module
// focused on lifecycle and membership mutations. The re-export preserves the
// historical `organizations::handlers::{list_members,list_teams}` paths.
#[path = "listing.rs"]
mod listing;
pub use listing::{list_members, list_teams};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewOrganization {
    pub slug: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipInput {
    pub role: Role,
    pub expected_version: Option<i64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamInput {
    pub slug: String,
    pub name: String,
    pub role: Role,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferInput {
    pub new_owner: String,
}

/// Tenant IDs and remote object keys derive from the owner's namespace ID.
/// A transfer cannot be published safely until all such data is rekeyed as a
/// single recoverable operation, so the API explicitly refuses it for now.
pub async fn transfer_ownership(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<TransferInput>,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    if !db::valid_name(&input.new_owner) {
        return Err(Error::bad_request());
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Admin, crate::token_scopes::RepoAction::RepoAdmin)
        .await?;
    auth::finish_tx(tx, &actor, true).await?;
    Err(Error(StatusCode::CONFLICT, "repository ownership transfer is unsupported"))
}

async fn org_id(tx: &Transaction<'_>, slug: &str) -> Result<Uuid, Error> {
    if !db::valid_name(slug) {
        return Err(Error::not_found());
    }
    tx.query_opt("SELECT organization_id FROM namespaces WHERE slug=$1 AND kind='organization'", &[&slug])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)
        .map(|r| r.get(0))
}
async fn require_member(tx: &Transaction<'_>, org: Uuid, actor: Uuid, min: Role) -> Result<(), Error> {
    let row = tx
        .query_opt("SELECT role FROM organization_memberships WHERE organization_id=$1 AND user_id=$2", &[&org, &actor])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    if Role::parse(row.get::<_, &str>(0))? < min {
        return Err(Error(StatusCode::FORBIDDEN, "insufficient organization role"));
    }
    Ok(())
}
async fn lock_org_for_admin(tx: &Transaction<'_>, org: Uuid, actor: Uuid) -> Result<(), Error> {
    tx.query_one("SELECT id FROM organizations WHERE id=$1 FOR UPDATE", &[&org]).await.map_err(Error::internal)?;
    // Membership is read after the lock. A concurrently revoked admin cannot
    // act on the authority they held before waiting for that lock.
    require_member(tx, org, actor, Role::Admin).await
}
async fn audit(
    tx: &Transaction<'_>,
    org: Uuid,
    actor: Uuid,
    action: &str,
    target: &str,
    details: Value,
) -> Result<(), Error> {
    tx.execute(
        "INSERT INTO organization_audit_log (organization_id,actor_id,action,target,details) VALUES ($1,$2,$3,$4,$5)",
        &[&org, &actor, &action, &target, &details],
    )
    .await
    .map_err(Error::internal)?;
    Ok(())
}

async fn protect_last_admin(
    tx: &Transaction<'_>,
    org: Uuid,
    user: Uuid,
    current: Role,
    next: Option<Role>,
) -> Result<(), Error> {
    if current != Role::Admin || next == Some(Role::Admin) {
        return Ok(());
    }
    // Callers lock the organization row before reading memberships, so
    // concurrent demotions and removals cannot both observe another admin.
    let remaining: i64 = tx
        .query_one(
            "SELECT count(*) FROM organization_memberships WHERE organization_id=$1 AND user_id<>$2 AND role='admin'",
            &[&org, &user],
        )
        .await
        .map_err(Error::internal)?
        .get(0);
    if remaining == 0 {
        return Err(Error(StatusCode::CONFLICT, "cannot remove last organization administrator"));
    }
    Ok(())
}

pub async fn create_organization(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<NewOrganization>,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    auth::writable(&actor)?;
    if !db::valid_name(&input.slug) {
        return Err(Error::bad_request());
    }
    let key = auth::idempotency_key(&headers)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, true).await?;
    auth::reject_restricted_create(&tx, &actor).await?;
    let org = Uuid::new_v4();
    if let Some(key) = key {
        let inserted = tx.query_opt("INSERT INTO organization_creation_keys(actor_id,key,slug,organization_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING organization_id",
            &[&actor.id,&key,&input.slug,&org]).await.map_err(Error::internal)?;
        if inserted.is_none() {
            let existing = tx
                .query_one(
                    "SELECT slug,organization_id FROM organization_creation_keys WHERE actor_id=$1 AND key=$2",
                    &[&actor.id, &key],
                )
                .await
                .map_err(Error::internal)?;
            if existing.get::<_, &str>("slug") != input.slug {
                return Err(Error(StatusCode::CONFLICT, "idempotency key reused for another organization"));
            }
            let id: Uuid = existing.get("organization_id");
            auth::finish_tx(tx, &actor, true).await?;
            return Ok(json(StatusCode::CREATED, sjson!({"id":id,"slug":input.slug})));
        }
    }
    tx.execute("INSERT INTO organizations(id,created_by) VALUES($1,$2)", &[&org, &actor.id])
        .await
        .map_err(Error::internal)?;
    let inserted = tx.execute("INSERT INTO namespaces(id,slug,kind,organization_id) VALUES($1,$2,'organization',$1) ON CONFLICT (slug) DO NOTHING",
        &[&org,&input.slug]).await.map_err(Error::internal)?;
    if inserted == 0 {
        return Err(Error(StatusCode::CONFLICT, "namespace slug already exists"));
    }
    tx.execute(
        "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,'admin')",
        &[&org, &actor.id],
    )
    .await
    .map_err(Error::internal)?;
    audit(&tx, org, actor.id, "organization.created", &input.slug, sjson!({})).await?;
    auth::finish_tx(tx, &actor, true).await?;
    Ok(json(StatusCode::CREATED, sjson!({"id":org,"slug":input.slug})))
}

pub async fn get_organization(State(state): State<Arc<AppState>>, Path(slug): Path<String>, headers: HeaderMap) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let org = org_id(&tx, &slug).await?;
    auth::authorize_namespace_action(&tx, &actor, org, NamespaceAction::OrgRead).await?;
    require_member(&tx, org, actor.id, Role::Read).await?;
    let row = tx
        .query_one("SELECT version,created_by,created_at::text FROM organizations WHERE id=$1", &[&org])
        .await
        .map_err(Error::internal)?;
    auth::finish_tx(tx, &actor, false).await?;
    Ok(json(
        StatusCode::OK,
        sjson!({"id":org,"slug":slug,"version":row.get::<_,i64>(0),"created_by":row.get::<_,Uuid>(1),"created_at":row.get::<_,String>(2)}),
    ))
}

pub async fn put_member(
    State(state): State<Arc<AppState>>,
    Path((slug, username)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<MembershipInput>,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    if !db::valid_name(&username) || input.expected_version.is_some_and(|v| v <= 0) {
        return Err(Error::bad_request());
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let org = org_id(&tx, &slug).await?;
    auth::authorize_namespace_action(&tx, &actor, org, NamespaceAction::OrgMembersWrite).await?;
    lock_org_for_admin(&tx, org, actor.id).await?;
    let user: Uuid = tx
        .query_opt("SELECT id FROM users WHERE username=$1", &[&username])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?
        .get(0);
    let existing = tx
        .query_opt(
            "SELECT version,role FROM organization_memberships WHERE organization_id=$1 AND user_id=$2 FOR UPDATE",
            &[&org, &user],
        )
        .await
        .map_err(Error::internal)?;
    let (code, version) = if let Some(row) = existing {
        let version: i64 = row.get(0);
        if input.expected_version.is_some_and(|v| v != version) {
            return Err(Error(StatusCode::CONFLICT, "membership version conflict"));
        }
        protect_last_admin(&tx, org, user, Role::parse(row.get::<_, &str>("role"))?, Some(input.role)).await?;
        tx.execute("UPDATE organization_memberships SET role=$3,version=version+1,updated_at=clock_timestamp() WHERE organization_id=$1 AND user_id=$2", &[&org,&user,&input.role.as_str()]).await.map_err(Error::internal)?;
        (StatusCode::OK, version + 1)
    } else {
        if input.expected_version.is_some() {
            return Err(Error(StatusCode::CONFLICT, "membership version conflict"));
        }
        tx.execute(
            "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,$3)",
            &[&org, &user, &input.role.as_str()],
        )
        .await
        .map_err(Error::internal)?;
        (StatusCode::CREATED, 1)
    };
    audit(
        &tx,
        org,
        actor.id,
        "organization.member.upserted",
        &username,
        sjson!({"role":input.role.as_str(),"version":version}),
    )
    .await?;
    auth::finish_tx(tx, &actor, true).await?;
    Ok(json(code, sjson!({"username":username,"role":input.role.as_str(),"version":version})))
}

pub async fn delete_member(
    State(state): State<Arc<AppState>>,
    Path((slug, username)): Path<(String, String)>,
    headers: HeaderMap,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let org = org_id(&tx, &slug).await?;
    auth::authorize_namespace_action(&tx, &actor, org, NamespaceAction::OrgMembersWrite).await?;
    lock_org_for_admin(&tx, org, actor.id).await?;
    let target = tx.query_opt("SELECT m.user_id,m.role FROM organization_memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND u.username=$2 FOR UPDATE OF m", &[&org,&username]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    protect_last_admin(&tx, org, target.get("user_id"), Role::parse(target.get::<_, &str>("role"))?, None).await?;
    let deleted = tx
        .execute(
            "DELETE FROM organization_memberships WHERE organization_id=$1 AND user_id=$2",
            &[&org, &target.get::<_, Uuid>("user_id")],
        )
        .await
        .map_err(Error::internal)?;
    if deleted == 0 {
        return Err(Error::not_found());
    }
    audit(&tx, org, actor.id, "organization.member.removed", &username, sjson!({})).await?;
    auth::finish_tx(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, sjson!({"removed":true,"username":username})))
}

pub async fn create_team(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Json(input): Json<TeamInput>,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    if !db::valid_name(&input.slug) || input.name.trim().is_empty() || input.name.len() > 128 {
        return Err(Error::bad_request());
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let org = org_id(&tx, &slug).await?;
    auth::authorize_namespace_action(&tx, &actor, org, NamespaceAction::OrgTeamsWrite).await?;
    lock_org_for_admin(&tx, org, actor.id).await?;
    let id = Uuid::new_v4();
    let inserted = tx.execute("INSERT INTO organization_teams(id,organization_id,slug,name,role) VALUES($1,$2,$3,$4,$5) ON CONFLICT(organization_id,slug) DO NOTHING",
        &[&id,&org,&input.slug,&input.name,&input.role.as_str()]).await.map_err(Error::internal)?;
    if inserted == 0 {
        return Err(Error(StatusCode::CONFLICT, "organization team slug exists"));
    }
    audit(&tx, org, actor.id, "organization.team.created", &input.slug, sjson!({"role":input.role.as_str()})).await?;
    auth::finish_tx(tx, &actor, true).await?;
    Ok(json(StatusCode::CREATED, sjson!({"id":id,"slug":input.slug,"name":input.name,"role":input.role.as_str()})))
}

async fn change_team_member(
    state: Arc<AppState>,
    slug: String,
    team_slug: String,
    username: String,
    headers: HeaderMap,
    add: bool,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let org = org_id(&tx, &slug).await?;
    auth::authorize_namespace_action(&tx, &actor, org, NamespaceAction::OrgTeamsWrite).await?;
    lock_org_for_admin(&tx, org, actor.id).await?;
    let team: Uuid = tx
        .query_opt("SELECT id FROM organization_teams WHERE organization_id=$1 AND slug=$2", &[&org, &team_slug])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?
        .get(0);
    let user: Uuid = tx
        .query_opt("SELECT id FROM users WHERE username=$1", &[&username])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?
        .get(0);
    let changed = if add {
        tx.execute("INSERT INTO organization_team_members(team_id,organization_id,user_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", &[&team,&org,&user]).await.map_err(Error::internal)?
    } else {
        tx.execute("DELETE FROM organization_team_members WHERE team_id=$1 AND user_id=$2", &[&team, &user])
            .await
            .map_err(Error::internal)?
    };
    if !add && changed == 0 {
        return Err(Error::not_found());
    }
    audit(
        &tx,
        org,
        actor.id,
        if add { "organization.team.member.added" } else { "organization.team.member.removed" },
        &username,
        sjson!({"team":team_slug}),
    )
    .await?;
    auth::finish_tx(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, sjson!({"team":team_slug,"username":username,"member":add})))
}
pub async fn put_team_member(
    State(state): State<Arc<AppState>>,
    Path((slug, team, username)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Res {
    change_team_member(state, slug, team, username, headers, true).await
}
pub async fn delete_team_member(
    State(state): State<Arc<AppState>>,
    Path((slug, team, username)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Res {
    change_team_member(state, slug, team, username, headers, false).await
}
