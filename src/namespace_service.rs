//! Immutable repository namespace revisions and Git view projection service.
#[path = "namespace_service/changesets.rs"]
mod changesets;
#[path = "namespace_service/handlers.rs"]
mod handlers;
#[path = "namespace_service/reverse.rs"]
mod reverse;
#[path = "namespace_service/views.rs"]
mod views;

use crate::AppState;
use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use std::sync::Arc;
use uuid::Uuid;

pub(crate) const PROPOSAL_REFS: &str = "refs/heads/rootyard-proposals";

pub(crate) fn proposal_ref_reserved(name: &str) -> bool {
    name == PROPOSAL_REFS || name.starts_with("refs/heads/rootyard-proposals/")
}

pub(crate) fn proposal_pin_ref(id: Uuid) -> String {
    format!("{PROPOSAL_REFS}/{id}")
}

#[derive(Debug,Clone,serde::Serialize,serde::Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProposalIntent {
    pub proposal_id:Uuid,
    pub repository_id:Uuid,
    pub target_oid:String,
}
impl ProposalIntent {
    pub(crate) fn validate(&self)->anyhow::Result<()> {
        anyhow::ensure!(!self.proposal_id.is_nil() && !self.repository_id.is_nil()
            && crate::ci_pins::valid_oid(&self.target_oid)
            && self.target_oid.bytes().any(|b|b!=b'0'),"invalid proposal pin intent");
        Ok(())
    }
    pub(crate) fn change(&self)->crate::journal::RefChange {
        crate::journal::RefChange{ref_name:proposal_pin_ref(self.proposal_id),
            old_oid:"0".repeat(self.target_oid.len()),new_oid:self.target_oid.clone()}
    }
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/namespaces", post(handlers::create))
        .route("/api/namespaces/{id}", get(handlers::get))
        .route("/api/namespaces/{id}/views", post(views::create))
        .route("/api/views/{id}", get(views::get))
        .route("/api/views/{id}/bundle", get(views::bundle))
        .route("/api/namespaces/{id}/changesets", post(changesets::create))
        .route("/api/changesets/{id}", get(changesets::get))
        .route("/api/changesets/{id}/review", post(changesets::review))
        .route(
            "/api/changesets/{id}/integrate",
            post(changesets::integrate),
        )
        .route("/api/changesets/{id}/recover", post(changesets::recover))
        .route(
            "/api/views/{id}/changesets",
            post(reverse::create).layer(DefaultBodyLimit::max(reverse::BODY_LIMIT)),
        )
}
