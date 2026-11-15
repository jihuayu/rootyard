//! Keyset-paginated organization index and organization audit log read endpoints.
use crate::{AppState, Error, auth, db, members::models::Role, pagination, token_scopes::NamespaceAction};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, Uri},
};
use serde_json::{Value, json as sjson};
use std::sync::Arc;
use uuid::Uuid;

use super::handlers::{
    Res,
    listing::{OrgListQuery, bad_cursor, limit_of, page_response},
    org_id, require_member,
};

fn orgs_scope(actor: Uuid) -> String {
    format!("organizations:{actor}")
}

fn audit_scope(actor: Uuid, org: Uuid) -> String {
    format!("organization-audit:{actor}:{org}")
}

fn decode_org_cursor(raw: &str, actor: Uuid) -> Result<(String, Uuid), Error> {
    let fields = pagination::decode(raw, &orgs_scope(actor), 2)?;
    let [slug, org_id] = fields.as_slice() else {
        return Err(bad_cursor());
    };
    let org_id = Uuid::parse_str(org_id).map_err(|_| bad_cursor())?;
    if org_id.is_nil() || !db::valid_name(slug) {
        return Err(bad_cursor());
    }
    Ok((slug.clone(), org_id))
}

fn decode_audit_cursor(raw: &str, actor: Uuid, org: Uuid) -> Result<i64, Error> {
    let fields = pagination::decode(raw, &audit_scope(actor, org), 1)?;
    let [id] = fields.as_slice() else {
        return Err(bad_cursor());
    };
    let id: i64 = id.parse().map_err(|_| bad_cursor())?;
    if id <= 0 {
        return Err(bad_cursor());
    }
    Ok(id)
}

/// Paginated list of organizations where the caller holds direct membership
/// (narrowed by `org:read` namespace scopes when using a restricted token).
pub async fn list_organizations(
    State(state): State<Arc<AppState>>,
    Query(query): Query<OrgListQuery>,
    uri: Uri,
    headers: HeaderMap,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let limit = limit_of(&query)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, false).await?;
    let restricted = auth::token_is_restricted(&tx, &actor).await?;
    let scope_token_id = actor.scope_token_id();
    let cursor = match query.cursor.as_deref() {
        Some(raw) => Some(decode_org_cursor(raw, actor.id)?),
        None => None,
    };
    let rows = match &cursor {
        None => {
            tx.query(
                "SELECT o.id, ns.slug, m.role, o.version \
                 FROM organization_memberships m \
                 JOIN organizations o ON o.id = m.organization_id \
                 JOIN namespaces ns ON ns.organization_id = o.id AND ns.kind = 'organization' \
                 WHERE m.user_id = $1 AND (NOT $2 OR EXISTS ( \
                     SELECT 1 FROM token_namespace_scopes s \
                      WHERE s.token_id = $3 AND s.organization_id = o.id AND s.action = 'org:read')) \
                 ORDER BY ns.slug, o.id LIMIT $4",
                &[&actor.id, &restricted, &scope_token_id, &(limit + 1)],
            )
            .await
        }
        Some((slug, id)) => {
            tx.query(
                "SELECT o.id, ns.slug, m.role, o.version \
                 FROM organization_memberships m \
                 JOIN organizations o ON o.id = m.organization_id \
                 JOIN namespaces ns ON ns.organization_id = o.id AND ns.kind = 'organization' \
                 WHERE m.user_id = $1 AND (NOT $2 OR EXISTS ( \
                     SELECT 1 FROM token_namespace_scopes s \
                      WHERE s.token_id = $3 AND s.organization_id = o.id AND s.action = 'org:read')) \
                   AND (ns.slug, o.id) > ($4, $5) \
                 ORDER BY ns.slug, o.id LIMIT $6",
                &[&actor.id, &restricted, &scope_token_id, slug, id, &(limit + 1)],
            )
            .await
        }
    }
    .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let kept: Vec<_> = rows.iter().take(limit as usize).collect();
    let next_cursor = if more {
        kept.last().map(|r| {
            let id = r.get::<_, Uuid>(0).to_string();
            pagination::encode(&orgs_scope(actor.id), &[r.get::<_, &str>(1), id.as_str()])
        })
    } else {
        None
    };
    let items: Vec<Value> = kept
        .iter()
        .map(|r| {
            sjson!({
                "id": r.get::<_, Uuid>(0),
                "slug": r.get::<_, &str>(1),
                "role": r.get::<_, &str>(2),
                "version": r.get::<_, i64>(3),
            })
        })
        .collect();
    auth::finish_tx(tx, &actor, false).await?;
    page_response(items, more, next_cursor, &uri, limit)
}

/// Paginated audit log for one organization (`maintain` or `admin` direct role).
pub async fn list_audit_log(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
    Query(query): Query<OrgListQuery>,
    uri: Uri,
    headers: HeaderMap,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let limit = limit_of(&query)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let org = org_id(&tx, &slug).await?;
    auth::authorize_namespace_action(&tx, &actor, org, NamespaceAction::OrgRead).await?;
    require_member(&tx, org, actor.id, Role::Maintain).await?;
    let cursor = match query.cursor.as_deref() {
        Some(raw) => Some(decode_audit_cursor(raw, actor.id, org)?),
        None => None,
    };
    let rows = match cursor {
        None => {
            tx.query(
                "SELECT l.id, l.actor_id, u.username, l.action, l.target, l.details, l.created_at::text \
                 FROM organization_audit_log l \
                 LEFT JOIN users u ON u.id = l.actor_id \
                 WHERE l.organization_id = $1 \
                 ORDER BY l.id ASC LIMIT $2",
                &[&org, &(limit + 1)],
            )
            .await
        }
        Some(after_id) => {
            tx.query(
                "SELECT l.id, l.actor_id, u.username, l.action, l.target, l.details, l.created_at::text \
                 FROM organization_audit_log l \
                 LEFT JOIN users u ON u.id = l.actor_id \
                 WHERE l.organization_id = $1 AND l.id > $2 \
                 ORDER BY l.id ASC LIMIT $3",
                &[&org, &after_id, &(limit + 1)],
            )
            .await
        }
    }
    .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let kept: Vec<_> = rows.iter().take(limit as usize).collect();
    let next_cursor = if more {
        kept.last().map(|r| {
            let id = r.get::<_, i64>(0).to_string();
            pagination::encode(&audit_scope(actor.id, org), &[id.as_str()])
        })
    } else {
        None
    };
    let items: Vec<Value> = kept
        .iter()
        .map(|r| {
            sjson!({
                "id": r.get::<_, i64>(0),
                "actor_id": r.get::<_, Uuid>(1),
                "actor": r.get::<_, Option<&str>>(2),
                "action": r.get::<_, &str>(3),
                "target": r.get::<_, &str>(4),
                "details": r.get::<_, Value>(5),
                "created_at": r.get::<_, String>(6),
            })
        })
        .collect();
    auth::finish_tx(tx, &actor, false).await?;
    page_response(items, more, next_cursor, &uri, limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn org_and_audit_cursors_reject_cross_scope_replay() {
        let (actor_a, actor_b) = (Uuid::new_v4(), Uuid::new_v4());
        let (org_a, org_b) = (Uuid::new_v4(), Uuid::new_v4());
        let org_id_str = org_a.to_string();
        let org_cursor = pagination::encode(&orgs_scope(actor_a), &["acme", org_id_str.as_str()]);
        assert!(decode_org_cursor(&org_cursor, actor_a).is_ok());
        assert!(decode_org_cursor(&org_cursor, actor_b).is_err());

        let audit_cursor = pagination::encode(&audit_scope(actor_a, org_a), &["42"]);
        assert_eq!(decode_audit_cursor(&audit_cursor, actor_a, org_a).unwrap(), 42);
        assert!(decode_audit_cursor(&audit_cursor, actor_a, org_b).is_err());
        assert!(decode_audit_cursor(&audit_cursor, actor_b, org_a).is_err());
        assert!(decode_audit_cursor(&org_cursor, actor_a, org_a).is_err());
    }
}
