use crate::{
    Error,
    db::{self, Identity},
};
use axum::http::{HeaderMap, StatusCode, header};
use base64::Engine;
use deadpool_postgres::Pool;

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
    };
    if token.len() != 68
        || !token.starts_with("ryt_")
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
