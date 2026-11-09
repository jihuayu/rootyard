//! Small JSON API: create/list/get Blob-gateway repositories and resolve one
//! persisted operation identifier. Creation goes through the shared provision
//! authority; a name is never turned into a filesystem path here.
use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    error::GatewayError,
    serving::{ProvisionRequest, lookup, provision},
    session::{authenticate, authority_error, authorize_write, read_authorization},
    state::BlobGitState,
};
use crate::{
    db,
    members::models::Role,
    ref_store::{GitObjectFormat, OperationLookup, PgRefStore},
};

/// One page of repositories. A cursor names only the last returned
/// `(namespace, name, id)` position, so an insert after it is seen on a later
/// page and an insert before it is never replayed.
const DEFAULT_LIST_LIMIT: i64 = 100;
const MAX_LIST_LIMIT: i64 = 500;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateRepository {
    name: String,
    owner: Option<String>,
    object_format: Option<GitObjectFormat>,
}

#[derive(Deserialize)]
pub(super) struct ListQuery {
    limit: Option<i64>,
    cursor: Option<String>,
}

#[derive(Serialize)]
pub(super) struct RepositoryView {
    id: Uuid,
    owner: String,
    name: String,
    state: String,
    object_format: String,
    storage_backend: String,
    clone_path: String,
}

impl RepositoryView {
    fn new(repository: &db::Repository) -> Self {
        Self {
            id: repository.id,
            owner: repository.owner.clone(),
            name: repository.name.clone(),
            state: repository.state.clone(),
            object_format: repository.object_format.clone(),
            storage_backend: repository.storage_backend.clone(),
            clone_path: format!("/git/{}/{}.git", repository.owner, repository.name),
        }
    }
}

pub(super) async fn create_repo(
    State(state): State<Arc<BlobGitState>>,
    headers: HeaderMap,
    Json(input): Json<CreateRepository>,
) -> Result<Response, GatewayError> {
    let identity = authenticate(&state, &headers).await?;
    authorize_write(&identity)?;
    if !db::valid_name(&input.name) {
        return Err(GatewayError::BadRequest("invalid repository name"));
    }
    let deadline = state.deadline();
    let request = ProvisionRequest {
        owner: input.owner,
        name: input.name,
        object_format: input.object_format.unwrap_or(GitObjectFormat::Sha1),
    };
    let receipt = provision(state.pool(), &identity, request, state.store().backend_identity(), deadline)
        .await
        .map_err(GatewayError::from)?;
    let status = if receipt.created { StatusCode::CREATED } else { StatusCode::OK };
    let view = RepositoryView::new(&receipt.repository);
    Ok((status, [(header::CACHE_CONTROL, "no-store")], Json(view)).into_response())
}

pub(super) async fn list_repos(
    State(state): State<Arc<BlobGitState>>,
    Query(query): Query<ListQuery>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let identity = authenticate(&state, &headers).await?;
    let limit = query.limit.unwrap_or(DEFAULT_LIST_LIMIT);
    if !(1..=MAX_LIST_LIMIT).contains(&limit) {
        return Err(GatewayError::BadRequest("repository list limit is out of range"));
    }
    let deadline = state.deadline();
    // A cursor is bound to this actor/token, but it never widens permission: the
    // visibility, RBAC, scope and serving predicates are re-applied to the page.
    let scope = format!("blob-repositories:{}", identity.id);
    let (cursor_owner, cursor_name, cursor_id) = match query.cursor.as_deref() {
        None => (None, None, None),
        Some(raw) => decode_cursor(raw, &scope)?,
    };
    let backend = state.store().backend_identity().as_hex();
    let page_size = limit + 1;
    // Only a *serving* repository is advertised: ready `pg_refstore`, stable
    // transition, a ready durable binding whose exact owner/name/object format
    // and history/authority/group realm equal the live gate, and the digest of
    // the Blob backend this process actually opened. A bare core gate, a ready
    // row on another backend, or a binding for a different realm is not listed.
    let sql = format!(
        concat!(
            "{}",
            " JOIN ref_store_serving_repositories b ON b.repository_id=r.id",
            " JOIN ref_store_core_gates g ON g.repository_id=r.id",
            " WHERE (r.owner_id=$1",
            " OR EXISTS (SELECT 1 FROM repository_collaborators c WHERE c.repository_id=r.id AND c.user_id=$1)",
            " OR EXISTS (SELECT 1 FROM repository_teams t JOIN repository_team_members m ON m.team_id=t.id",
            "            WHERE t.repository_id=r.id AND m.user_id=$1)",
            " OR EXISTS (SELECT 1 FROM organization_memberships m WHERE m.organization_id=r.owner_id AND m.user_id=$1)",
            " OR EXISTS (SELECT 1 FROM organization_team_members m WHERE m.organization_id=r.owner_id AND m.user_id=$1))",
            " AND r.storage_backend='pg_refstore'",
            " AND r.state='ready' AND r.transition_state='stable'",
            " AND b.state='ready'",
            " AND b.owner_id=r.owner_id AND b.name=r.name AND b.object_format=r.object_format",
            " AND b.backend_identity=$8",
            " AND g.tenant_id=b.owner_id AND g.object_format=b.object_format",
            " AND g.history_incarnation=b.history_incarnation",
            " AND g.authority_epoch=b.authority_epoch",
            " AND g.group_epoch=b.group_epoch",
            " AND NOT EXISTS (SELECT 1 FROM pando_repository_states s WHERE s.repository_id=r.id)",
            " AND NOT EXISTS (SELECT 1 FROM repository_ref_projection p WHERE p.repository_id=r.id)",
            // A restricted token sees only repositories carrying its explicit
            // contents-read grant. It never discovers siblings through ownership,
            // organisation membership or collaborator rows.
            " AND (NOT $6 OR EXISTS (SELECT 1 FROM token_repository_scopes ts",
            "      WHERE ts.token_id=$7 AND ts.repository_id=r.id AND ts.action='contents_read'))",
            " AND ($2::text IS NULL OR (ns.slug,r.name,r.id) > ($2::text,$3::text,$4::uuid))",
            " ORDER BY ns.slug,r.name,r.id LIMIT $5"
        ),
        db::REPO_SELECT
    );
    let mut client = state.pooled(deadline).await?;
    let tx = tokio::time::timeout_at(deadline, client.transaction())
        .await
        .map_err(|_| GatewayError::Timeout)?
        .map_err(|_| GatewayError::Internal("authorization transaction failed"))?;
    let listing: Result<Vec<tokio_postgres::Row>, GatewayError> = async {
        // One absolute statement/lock bound for token, RBAC and the page query.
        crate::ref_store::pg::bound(&tx, deadline).await.map_err(GatewayError::from)?;
        crate::auth::verify_token(&tx, &identity, false).await.map_err(authority_error)?;
        // Locks the live token row FOR SHARE for this short transaction and
        // returns the exact restricted-grant mode used in the page predicate.
        let restricted = crate::auth::token_is_restricted(&tx, &identity).await.map_err(authority_error)?;
        let params: [&(dyn tokio_postgres::types::ToSql + Sync); 8] = [
            &identity.id,
            &cursor_owner,
            &cursor_name,
            &cursor_id,
            &page_size,
            &restricted,
            &identity.token_id,
            &backend,
        ];
        tokio::time::timeout_at(deadline, tx.query(&sql, &params))
            .await
            .map_err(|_| GatewayError::Timeout)?
            .map_err(|_| GatewayError::Internal("repository listing failed"))
    }
    .await;
    let _ = tokio::time::timeout_at(deadline, tx.rollback()).await;
    drop(client);
    let rows = listing?;
    let more = rows.len() > limit as usize;
    let items = rows
        .iter()
        .take(limit as usize)
        .map(db::Repository::from_row)
        .map(|repository| RepositoryView::new(&repository))
        .collect::<Vec<_>>();
    let next_cursor = if more {
        items.last().map(|repository| {
            let id = repository.id.to_string();
            crate::pagination::encode(&scope, &[repository.owner.as_str(), repository.name.as_str(), id.as_str()])
        })
    } else {
        None
    };
    let mut response = ([(header::CACHE_CONTROL, "no-store")], Json(items)).into_response();
    if let Some(cursor) = next_cursor {
        response.headers_mut().insert(
            header::HeaderName::from_static("x-next-cursor"),
            header::HeaderValue::from_str(&cursor)
                .map_err(|_| GatewayError::Internal("pagination cursor is not a valid header"))?,
        );
        let link = format!(
            "<{}?cursor={}&limit={}>; rel=\"next\"",
            uri.path(),
            crate::pagination::query_value(&cursor),
            limit
        );
        response.headers_mut().insert(
            header::LINK,
            header::HeaderValue::from_str(&link)
                .map_err(|_| GatewayError::Internal("pagination link is not a valid header"))?,
        );
    }
    Ok(response)
}

fn decode_cursor(raw: &str, scope: &str) -> Result<(Option<String>, Option<String>, Option<Uuid>), GatewayError> {
    let fields =
        crate::pagination::decode(raw, scope, 3).map_err(|_| GatewayError::BadRequest("invalid pagination cursor"))?;
    let [owner, name, id] = fields.as_slice() else {
        return Err(GatewayError::BadRequest("invalid pagination cursor"));
    };
    let id = Uuid::parse_str(id).map_err(|_| GatewayError::BadRequest("invalid pagination cursor"))?;
    if id.is_nil() || !db::valid_name(owner) || !db::valid_name(name) {
        return Err(GatewayError::BadRequest("invalid pagination cursor"));
    }
    Ok((Some(owner.clone()), Some(name.clone()), Some(id)))
}

pub(super) async fn get_repo(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, raw_name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let name = strip_name(&raw_name)?;
    let identity = authenticate(&state, &headers).await?;
    let deadline = state.deadline();
    let serving = lookup(state.pool(), &identity, &owner, name, false, state.store().backend_identity(), deadline)
        .await
        .map_err(authority_error)?;
    let view = RepositoryView::new(&serving.repository);
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(view)).into_response())
}

#[derive(Serialize)]
pub(super) struct OperationView {
    operation_id: Uuid,
    state: &'static str,
    /// The immutable durable terminal result (per-ref facts, registration ids
    /// and reject code) or `null` while the outcome is still unknown. It is the
    /// same persisted value the receive path replays; it never contains token
    /// material, a request digest or a byte grant.
    terminal: Option<serde_json::Value>,
}

pub(super) async fn get_operation(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, raw_name, operation)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let name = strip_name(&raw_name)?;
    let operation_id =
        Uuid::parse_str(&operation).map_err(|_| GatewayError::BadRequest("invalid operation identifier"))?;
    if operation_id.is_nil() {
        return Err(GatewayError::BadRequest("invalid operation identifier"));
    }
    let identity = authenticate(&state, &headers).await?;
    let deadline = state.deadline();
    // Reading a historical operation is a read: it must not require write
    // visibility (a read-only token may resolve the operation it issued). The
    // shared read lookup still verifies the live token, RBAC, contents-read
    // scope, ready binding and actual Blob backend. A write-only scoped token
    // that issued the durable intent is distinguished here: it may use the
    // write lookup, but only for this historical read and never to publish.
    let read_lookup =
        lookup(state.pool(), &identity, &owner, name, false, state.store().backend_identity(), deadline).await;
    let (serving, writable) = match read_lookup {
        Ok(serving) => (serving, false),
        Err(read_error) if !identity.read_only && read_error.0 == StatusCode::FORBIDDEN => {
            match lookup(state.pool(), &identity, &owner, name, true, state.store().backend_identity(), deadline).await
            {
                Ok(serving) => (serving, true),
                Err(_) => return Err(authority_error(read_error)),
            }
        }
        Err(error) => return Err(authority_error(error)),
    };
    let repository_id = serving.gate.repository_id();
    let owner_id = serving.gate.tenant_id();
    let authorization = read_authorization(state.clone(), &identity, &serving);
    let mut client = state.pooled(deadline).await?;
    let tx = tokio::time::timeout_at(deadline, client.transaction())
        .await
        .map_err(|_| GatewayError::Timeout)?
        .map_err(|_| GatewayError::Internal("authorization transaction failed"))?;
    let loaded: Result<(OperationLookup, Option<Role>), GatewayError> = async {
        crate::ref_store::pg::bound(&tx, deadline).await.map_err(GatewayError::from)?;
        let fresh = crate::ref_store::serving::lookup_in_tx(
            &tx,
            &identity,
            &owner,
            name,
            writable,
            state.store().backend_identity(),
            deadline,
        )
        .await
        .map_err(authority_error)?;
        authorization.ensure_same_realm(&fresh)?;
        let lookup = PgRefStore.get(&tx, repository_id, operation_id, deadline).await.map_err(GatewayError::from)?;
        // Distinguish a write intent from its reader: the durable issuer or a
        // *current* repository admin may resolve it. Read access to the
        // repository alone does not expose another actor's write facts.
        let role = if matches!(lookup, OperationLookup::Known(_)) {
            crate::members::rbac::resolve_effective_role(&*tx, repository_id, owner_id, identity.id)
                .await
                .map_err(GatewayError::from)?
                .map(|(effective, _, _)| effective)
        } else {
            None
        };
        Ok((lookup, role))
    }
    .await;
    let _ = tokio::time::timeout_at(deadline, tx.rollback()).await;
    drop(client);
    let (lookup, role) = loaded?;
    let record = match lookup {
        OperationLookup::Known(record) => record,
        OperationLookup::Unknown => return Err(GatewayError::NotFound),
    };
    let issued_by_actor = record.identity().issuer_id() == identity.id;
    let owner_admin = role.is_some_and(|role| role >= Role::Admin);
    if !issued_by_actor && !owner_admin {
        return Err(GatewayError::Forbidden("operation is visible only to its issuer or a current repository admin"));
    }
    let current_state = record.state().as_str();
    let terminal = record.terminal_result().map(|result| result.value().clone());
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(OperationView { operation_id, state: current_state, terminal }))
        .into_response())
}

/// Explicit refusal: the smart HTTP vertical does not implement an LFS media
/// service. It never pretends an LFS batch succeeded.
pub(super) async fn unsupported_lfs() -> Result<Response, GatewayError> {
    Err(GatewayError::NotImplemented("Git LFS is not implemented by the Blob Git gateway"))
}

/// Explicit refusal: merge production is a later extension.
pub(super) async fn unsupported_merge() -> Result<Response, GatewayError> {
    Err(GatewayError::NotImplemented("merge production is not implemented by the Blob Git gateway"))
}

/// Explicit refusal: a browser/tree producer is a later extension.
pub(super) async fn unsupported_browse() -> Result<Response, GatewayError> {
    Err(GatewayError::NotImplemented("browse/tree production is not implemented by the Blob Git gateway"))
}

fn strip_name(raw: &str) -> Result<&str, GatewayError> {
    let name = raw.strip_suffix(".git").unwrap_or(raw);
    if !db::valid_name(name) {
        return Err(GatewayError::NotFound);
    }
    Ok(name)
}
