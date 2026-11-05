use crate::{
    Error,
    db::{self, Identity},
};
pub use crate::members::models::{RepoAccess, Role};
use axum::http::{HeaderMap, StatusCode, header};
use base64::Engine;
use deadpool_postgres::{Pool, Transaction};
use uuid::Uuid;

pub async fn authenticate(pool: &Pool, headers: &HeaderMap) -> Result<Identity, Error> {
    let (user, token) = credentials(headers)?;
    let client = pool.get().await.map_err(Error::internal)?;
    let row = client.query_opt(
        "SELECT u.id, u.username, t.read_only, t.id FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.digest=$1 AND NOT t.revoked AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp())", &[&db::digest(&token)])
        .await.map_err(Error::internal)?.ok_or_else(Error::unauthorized)?;
    let identity = Identity {
        id: row.get(0),
        username: row.get(1),
        read_only: row.get(2),
        token_id: row.get(3),
        token_digest: db::digest(&token),
    };
    if user.as_ref().is_some_and(|u| u != &identity.username) {
        return Err(Error::unauthorized());
    }
    Ok(identity)
}

fn credentials(headers: &HeaderMap) -> Result<(Option<String>, String), Error> {
    credentials_for(headers, "ryt_")
}

pub(crate) fn credentials_for(
    headers: &HeaderMap,
    prefix: &str,
) -> Result<(Option<String>, String), Error> {
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return Err(Error::unauthorized());
    }
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(Error::unauthorized)?;
    if raw.len() > 512 {
        return Err(Error::unauthorized());
    }
    let (scheme, value) = raw.split_once(' ').ok_or_else(Error::unauthorized)?;
    let (user, token) = if scheme.eq_ignore_ascii_case("bearer") {
        (None, value.to_owned())
    } else if scheme.eq_ignore_ascii_case("basic") {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|_| Error::unauthorized())?;
        let pair = String::from_utf8(bytes).map_err(|_| Error::unauthorized())?;
        let (user, token) = pair.split_once(':').ok_or_else(Error::unauthorized)?;
        (Some(user.to_owned()), token.to_owned())
    } else {
        return Err(Error::unauthorized());
    }
    ;
    if token.len() != 68
        || !token.starts_with(prefix)
        || !token[4..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(Error::unauthorized());
    }
    Ok((user, token))
}

pub fn writable(identity: &Identity) -> Result<(), Error> {
    if identity.read_only {
        Err(Error(StatusCode::FORBIDDEN, "write permission required"))
    } else {
        Ok(())
    }
}

// Keys are opaque client operation identifiers, never authentication credentials.
// A repository-local namespace also prevents a key from silently changing targets.
pub fn idempotency_key(headers: &HeaderMap) -> Result<Option<&str>, Error> {
    let mut values = headers.get_all("idempotency-key").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Error::bad_request());
    }
    let key = value.to_str().map_err(|_| Error::bad_request())?;
    if !(1..=128).contains(&key.len())
        || !key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'-'))
    {
        return Err(Error::bad_request());
    }
    Ok(Some(key))
}

pub async fn authorize_repo_with_role(
    tx: &Transaction<'_>,
    actor: &Identity,
    owner: &str,
    name: &str,
    min_role: Role,
) -> Result<RepoAccess, Error> {
    if !db::valid_name(owner) || !db::valid_name(name) {
        return Err(Error::not_found());
    }
    // Keep lock order token/user -> repository -> creation key -> counter/issue/comment.
    // Revoke and read_only updates must wait for these transaction-scoped locks.
    tx.query_opt(
        "SELECT t.id FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.id=$1 AND t.user_id=$2 AND u.username=$3 FOR SHARE OF t,u",
        &[&actor.token_id, &actor.id, &actor.username],
    )
    .await
    .map_err(Error::internal)?
    .ok_or_else(Error::unauthorized)?;
    verify_token(tx, actor, false).await?;

    let row = tx
        .query_opt(
            "SELECT r.id, r.owner_id, r.state FROM repositories r JOIN users u ON u.id = r.owner_id WHERE u.username = $1 AND r.name = $2 FOR SHARE OF r",
            &[&owner, &name],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let repo_id: Uuid = row.get("id");
    let owner_id: Uuid = row.get("owner_id");
    let state: String = row.get("state");

    let Some((effective_role, _, _)) =
        crate::members::rbac::resolve_effective_role(tx, repo_id, owner_id, actor.id).await?
    else {
        return Err(Error::not_found());
    };

    if min_role >= Role::Triage {
        writable(actor)?;
        verify_token(tx, actor, true).await?;
    }
    if effective_role < min_role {
        return Err(Error(StatusCode::FORBIDDEN, "insufficient repository role"));
    }
    if state != "ready" {
        return Err(Error(StatusCode::CONFLICT, "repository is not ready"));
    }
    Ok(RepoAccess {
        repo_id,
        owner_id,
        role: effective_role,
    })
}

pub async fn authorize_repo_role(
    tx: &Transaction<'_>,
    actor: &Identity,
    owner: &str,
    name: &str,
    min_role: Role,
) -> Result<RepoAccess, Error> {
    authorize_repo_with_role(tx, actor, owner, name, min_role).await
}

pub async fn authorize_repo(
    tx: &Transaction<'_>,
    actor: &Identity,
    owner: &str,
    name: &str,
    write: bool,
) -> Result<Uuid, Error> {
    let min_role = if write { Role::Write } else { Role::Read };
    authorize_repo_with_role(tx, actor, owner, name, min_role)
        .await
        .map(|access| access.repo_id)
}

pub async fn verify_token(
    tx: &Transaction<'_>,
    actor: &Identity,
    write: bool,
) -> Result<(), Error> {
    // A separate statement observes the real database clock *after* lock waits.
    let row = tx.query_opt(
        "SELECT read_only FROM tokens WHERE id=$1 AND user_id=$2 AND digest=$3 AND NOT revoked AND (expires_at IS NULL OR expires_at > clock_timestamp())",
        &[&actor.token_id, &actor.id, &actor.token_digest],
    )
    .await
    .map_err(Error::internal)?
    .ok_or_else(Error::unauthorized)?;
    if write && row.get::<_, bool>(0) {
        return Err(Error(StatusCode::FORBIDDEN, "write permission required"));
    }
    Ok(())
}

pub async fn verify_active(
    pool: &Pool,
    actor: &Identity,
    repo_id: Uuid,
    write: bool,
) -> Result<(), Error> {
    let mut client = pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    verify_token(&tx, actor, write).await?;
    let row = tx
        .query_opt(
            "SELECT owner_id, state FROM repositories WHERE id=$1",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let owner_id: Uuid = row.get("owner_id");
    let state: String = row.get("state");
    if state != "ready" {
        return Err(Error(StatusCode::CONFLICT, "repository is not ready"));
    }
    let min_role = if write { Role::Write } else { Role::Read };
    let Some((eff, _, _)) =
        crate::members::rbac::resolve_effective_role(&tx, repo_id, owner_id, actor.id).await?
    else {
        return Err(Error::not_found());
    };
    if eff < min_role {
        return Err(Error(StatusCode::FORBIDDEN, "insufficient repository role"));
    }
    Ok(())
}

pub async fn finish_tx(tx: Transaction<'_>, actor: &Identity, write: bool) -> Result<(), Error> {
    // Allocation/row waits must not turn an expired token into a successful write.
    verify_token(&tx, actor, write).await?;
    tx.commit().await.map_err(Error::internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_malformed() {
        for value in ["", "Bearer ", "Basic ###", "Basic YTpi", "Token abc"] {
            let mut h = HeaderMap::new();
            h.insert(header::AUTHORIZATION, value.parse().unwrap());
            assert!(credentials(&h).is_err());
        }
    }
}
