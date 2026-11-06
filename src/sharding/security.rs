//! Cluster control-plane authority is bound to a specific live, writable token.
use crate::{Error, auth, db::Identity};
use axum::http::StatusCode;
use deadpool_postgres::Transaction;

pub async fn require_operator(tx: &Transaction<'_>, actor: &Identity) -> Result<(), Error> {
    auth::verify_token(tx, actor, true).await?;
    let granted = tx.query_opt(
        "SELECT 1 FROM cluster_operator_tokens WHERE token_id = $1",
        &[&actor.token_id],
    ).await.map_err(Error::internal)?.is_some();
    if !granted {
        return Err(Error(StatusCode::FORBIDDEN, "cluster operator capability required"));
    }
    Ok(())
}
