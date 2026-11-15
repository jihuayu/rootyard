//! SQL authority helpers resolving direct API tokens and parent-bound browser children.

use crate::{
    Error,
    db::{self, Identity},
};
use deadpool_postgres::{Pool, Transaction};
use tokio_postgres::GenericClient;
use uuid::Uuid;

/// Authenticate a bearer/basic credential against live `api` or parent-bound `browser` tokens.
pub(super) async fn authenticate_identity(
    pool: &Pool,
    user: Option<String>,
    token: &str,
    browser_allowed: bool,
) -> Result<Identity, Error> {
    let candidate_parent = crate::token_management::models::session_parent(token);
    let digest = db::digest(token);
    let client = pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_opt(
            "SELECT u.id, u.username, (t.read_only OR COALESCE(p.read_only, false)), t.id, t.kind \
               FROM tokens t \
               JOIN users u ON u.id=t.user_id \
               LEFT JOIN tokens p ON t.kind='browser' AND p.id=$3 AND p.user_id=t.user_id AND p.kind='api' \
              WHERE t.digest=$1 AND NOT t.revoked \
                AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) \
                AND (t.kind='api' OR ($2 AND t.kind='browser' \
                     AND p.id IS NOT NULL AND NOT p.revoked \
                     AND (p.expires_at IS NULL OR p.expires_at > clock_timestamp()) \
                     AND EXISTS (SELECT 1 FROM web_sessions s WHERE s.token_id=t.id \
                                  AND NOT s.revoked AND s.expires_at>clock_timestamp())))",
            &[&digest, &browser_allowed, &candidate_parent],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::unauthorized)?;
    let kind: String = row.get(4);
    let identity = Identity {
        id: row.get(0),
        token_id: row.get(3),
        parent_token_id: if kind == "browser" { candidate_parent } else { None },
        username: row.get(1),
        read_only: row.get(2),
        token_digest: digest,
    };
    if user.as_ref().is_some_and(|u| u != &identity.username) {
        return Err(Error::unauthorized());
    }
    Ok(identity)
}

/// Lock the acting token (and bound parent API token when present) and return `is_restricted`.
pub(super) async fn token_is_restricted(
    tx: &Transaction<'_>,
    actor: &Identity,
    browser_allowed: bool,
) -> Result<bool, Error> {
    let row = match actor.parent_token_id {
        None => {
            tx.query_opt(
                "SELECT t.is_restricted FROM tokens t \
                  WHERE t.id=$1 AND t.user_id=$2 AND t.digest=$3 AND NOT t.revoked AND t.kind='api' \
                    AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) \
                  FOR SHARE OF t",
                &[&actor.token_id, &actor.id, &actor.token_digest],
            )
            .await
        }
        Some(parent_id) => {
            if !browser_allowed {
                return Err(Error::unauthorized());
            }
            tx.query_opt(
                "SELECT (t.is_restricted OR p.is_restricted) FROM tokens t \
                   JOIN tokens p ON p.id=$4 AND p.user_id=t.user_id AND p.kind='api' \
                  WHERE t.id=$1 AND t.user_id=$2 AND t.digest=$3 AND t.kind='browser' \
                    AND NOT t.revoked AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) \
                    AND NOT p.revoked AND (p.expires_at IS NULL OR p.expires_at > clock_timestamp()) \
                    AND EXISTS (SELECT 1 FROM web_sessions s WHERE s.token_id=t.id \
                                 AND NOT s.revoked AND s.expires_at>clock_timestamp()) \
                  FOR SHARE OF t, p",
                &[&actor.token_id, &actor.id, &actor.token_digest, &parent_id],
            )
            .await
        }
    }
    .map_err(Error::internal)?
    .ok_or_else(Error::unauthorized)?;
    Ok(row.get(0))
}

/// Verify token liveness (and bound parent liveness when present) and return combined `read_only`.
pub(super) async fn token_read_only(
    tx: &Transaction<'_>,
    actor: &Identity,
    browser_allowed: bool,
) -> Result<bool, Error> {
    let row = match actor.parent_token_id {
        None => {
            tx.query_opt(
                "SELECT t.read_only FROM tokens t \
                  WHERE t.id=$1 AND t.user_id=$2 AND t.digest=$3 AND NOT t.revoked AND t.kind='api' \
                    AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp())",
                &[&actor.token_id, &actor.id, &actor.token_digest],
            )
            .await
        }
        Some(parent_id) => {
            if !browser_allowed {
                return Err(Error::unauthorized());
            }
            tx.query_opt(
                "SELECT (t.read_only OR p.read_only) FROM tokens t \
                   JOIN tokens p ON p.id=$4 AND p.user_id=t.user_id AND p.kind='api' \
                  WHERE t.id=$1 AND t.user_id=$2 AND t.digest=$3 AND t.kind='browser' \
                    AND NOT t.revoked AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) \
                    AND NOT p.revoked AND (p.expires_at IS NULL OR p.expires_at > clock_timestamp()) \
                    AND EXISTS (SELECT 1 FROM web_sessions s WHERE s.token_id=t.id \
                                 AND NOT s.revoked AND s.expires_at>clock_timestamp())",
                &[&actor.token_id, &actor.id, &actor.token_digest, &parent_id],
            )
            .await
        }
    }
    .map_err(Error::internal)?
    .ok_or_else(Error::unauthorized)?;
    Ok(row.get(0))
}

/// Verify token liveness before Git/ref writes without digest access (generic client path).
pub(super) async fn write_token_read_only<C: GenericClient + Sync>(
    client: &C,
    actor_id: Uuid,
    token_id: Uuid,
    parent_token_id: Option<Uuid>,
    browser: bool,
) -> Result<bool, Error> {
    let row = match parent_token_id {
        None => {
            client
                .query_opt(
                    "SELECT t.read_only FROM tokens t \
                      WHERE t.id=$1 AND t.user_id=$2 AND NOT t.revoked AND t.kind='api' \
                        AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp())",
                    &[&token_id, &actor_id],
                )
                .await
        }
        Some(parent_id) => {
            if !browser {
                return Err(Error::unauthorized());
            }
            client
                .query_opt(
                    "SELECT (t.read_only OR p.read_only) FROM tokens t \
                       JOIN tokens p ON p.id=$3 AND p.user_id=t.user_id AND p.kind='api' \
                      WHERE t.id=$1 AND t.user_id=$2 AND t.kind='browser' \
                        AND NOT t.revoked AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) \
                        AND NOT p.revoked AND (p.expires_at IS NULL OR p.expires_at > clock_timestamp()) \
                        AND EXISTS (SELECT 1 FROM web_sessions s WHERE s.token_id=t.id \
                                     AND NOT s.revoked AND s.expires_at>clock_timestamp())",
                    &[&token_id, &actor_id, &parent_id],
                )
                .await
        }
    }
    .map_err(Error::internal)?
    .ok_or_else(Error::unauthorized)?;
    Ok(row.get(0))
}

/// Step 1 of publication-window verification: acquire `FOR SHARE` on `t` (and `p`).
pub(super) async fn lock_publication_tokens(
    tx: &Transaction<'_>,
    actor: &Identity,
    browser: bool,
) -> Result<(), Error> {
    let found = match actor.parent_token_id {
        None => {
            tx.query_opt(
                "SELECT true FROM tokens t \
                  WHERE t.id=$1 AND t.user_id=$2 AND t.digest=$3 AND NOT t.revoked AND t.kind='api' \
                    AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) FOR SHARE OF t",
                &[&actor.token_id, &actor.id, &actor.token_digest],
            )
            .await
        }
        Some(parent_id) => {
            if !browser {
                return Err(Error::unauthorized());
            }
            tx.query_opt(
                "SELECT true FROM tokens t \
                   JOIN tokens p ON p.id=$4 AND p.user_id=t.user_id AND p.kind='api' \
                  WHERE t.id=$1 AND t.user_id=$2 AND t.digest=$3 AND NOT t.revoked AND t.kind='browser' \
                    AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) \
                    AND NOT p.revoked AND (p.expires_at IS NULL OR p.expires_at > clock_timestamp()) \
                    AND EXISTS (SELECT 1 FROM web_sessions s WHERE s.token_id=t.id \
                                 AND NOT s.revoked AND s.expires_at>clock_timestamp()) \
                  FOR SHARE OF t, p",
                &[&actor.token_id, &actor.id, &actor.token_digest, &parent_id],
            )
            .await
        }
    }
    .map_err(Error::internal)?;
    found.ok_or_else(Error::unauthorized)?;
    Ok(())
}

/// Step 2 of publication-window verification: re-read live flags after lock acquisition.
pub(super) async fn recheck_publication_tokens(
    tx: &Transaction<'_>,
    actor: &Identity,
    browser: bool,
) -> Result<(bool, bool, bool), Error> {
    let row = match actor.parent_token_id {
        None => {
            tx.query_opt(
                "SELECT t.read_only, (t.expires_at IS NULL OR t.expires_at > clock_timestamp()), (t.kind='api') \
                   FROM tokens t WHERE t.id=$1 AND t.user_id=$2 AND t.digest=$3 AND NOT t.revoked",
                &[&actor.token_id, &actor.id, &actor.token_digest],
            )
            .await
        }
        Some(parent_id) => {
            tx.query_opt(
                "SELECT (t.read_only OR p.read_only), \
                        ((t.expires_at IS NULL OR t.expires_at > clock_timestamp()) \
                         AND (p.expires_at IS NULL OR p.expires_at > clock_timestamp())), \
                        ($4 AND t.kind='browser' AND NOT p.revoked AND EXISTS \
                         (SELECT 1 FROM web_sessions s WHERE s.token_id=t.id AND NOT s.revoked \
                          AND s.expires_at>clock_timestamp())) \
                   FROM tokens t \
                   JOIN tokens p ON p.id=$5 AND p.user_id=t.user_id AND p.kind='api' \
                  WHERE t.id=$1 AND t.user_id=$2 AND t.digest=$3 AND NOT t.revoked",
                &[&actor.token_id, &actor.id, &actor.token_digest, &browser, &parent_id],
            )
            .await
        }
    }
    .map_err(Error::internal)?
    .ok_or_else(Error::unauthorized)?;
    Ok((row.get(0), row.get(1), row.get(2)))
}
