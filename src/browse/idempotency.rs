//! Repository-scoped idempotency claims for ref transactions.
//!
//! A claim is inserted and finalized in the same PostgreSQL transaction as the
//! operation and outbox settlement. If that transaction aborts after native Git
//! already published the refs, the claim disappears with it; the journal keeps
//! an idempotency fingerprint so recovery can replay the recorded operation
//! instead of re-running the CAS against already-published refs.
use crate::Error;
use axum::http::StatusCode;
use deadpool_postgres::Transaction;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn digest(domain: &[u8], value: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(value);
    hex::encode(hash.finalize())
}

/// Stable, non-secret fingerprints persisted with the journal operation.
pub(crate) fn fingerprint(key: &str, request: &Value) -> (String, String) {
    let key = digest(b"rootyard-ref-idempotency-key-v1\0", key.as_bytes());
    let request = digest(
        b"rootyard-ref-idempotency-request-v1\0",
        &serde_json::to_vec(request).expect("in-memory Value serializes"),
    );
    (key, request)
}

/// Insert the claim or return the response already committed for this exact
/// repository/key/request tuple.
pub(crate) async fn claim(
    tx: &Transaction<'_>,
    tenant: Uuid,
    repo: Uuid,
    key: &str,
    request: &Value,
) -> Result<Option<Value>, Error> {
    let inserted = tx
        .execute(
            "INSERT INTO forge_creation_requests (tenant_id,repository_id,idempotency_key,request) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
            &[&tenant, &repo, &key, &request],
        )
        .await
        .map_err(Error::internal)?;
    if inserted == 1 {
        return Ok(None);
    }
    let row = tx
        .query_one(
            "SELECT request,response FROM forge_creation_requests WHERE tenant_id=$1 AND repository_id=$2 AND idempotency_key=$3",
            &[&tenant, &repo, &key],
        )
        .await
        .map_err(Error::internal)?;
    if row.get::<_, Value>("request") != *request {
        return Err(Error(StatusCode::CONFLICT, "idempotency key conflict"));
    }
    row.get::<_, Option<Value>>("response")
        .map(Some)
        .ok_or_else(|| Error::internal("incomplete creation record"))
}

/// Finalize the claim in the caller-owned settlement transaction.
pub(crate) async fn record(
    tx: &Transaction<'_>,
    tenant: Uuid,
    repo: Uuid,
    key: Option<&str>,
    response: &Value,
) -> Result<(), Error> {
    if let Some(key) = key {
        let changed = tx
            .execute(
                "UPDATE forge_creation_requests SET response=$4 WHERE tenant_id=$1 AND repository_id=$2 AND idempotency_key=$3 AND response IS NULL",
                &[&tenant, &repo, &key, &response],
            )
            .await
            .map_err(Error::internal)?;
        if changed != 1 {
            return Err(Error::internal("creation record was not finalized"));
        }
    }
    Ok(())
}

/// Replay an operation whose native CAS and journal receipt survived a crash
/// before its settlement transaction committed. The fingerprint is journal
/// derived, so a caller cannot mint a replay from HTTP input alone.
pub(crate) async fn replay_terminal(
    tx: &Transaction<'_>,
    tenant: Uuid,
    repo: Uuid,
    key: &str,
    request: &Value,
) -> Result<Option<Value>, Error> {
    let (key_sha256, request_sha256) = fingerprint(key, request);
    let rows = tx
        .query(
            "SELECT id,storage_generation,sequence,outcome,evidence FROM git_operations \
             WHERE repository_id=$1 AND evidence->>'idempotency_key_sha256'=$2 \
             ORDER BY storage_generation DESC,sequence DESC",
            &[&repo, &key_sha256],
        )
        .await
        .map_err(Error::internal)?;
    for row in rows {
        let outcome: String = row.get("outcome");
        let evidence: Value = row.get("evidence");
        if outcome == "no_ref_changes" {
            // A failed pre-CAS attempt released its claim; the same key may be
            // retried, exactly as before settlement became transactional.
            continue;
        }
        if evidence["idempotency_request_sha256"] != request_sha256 {
            return Err(Error(StatusCode::CONFLICT, "idempotency key conflict"));
        }
        if outcome == "unknown" {
            return Err(Error(
                StatusCode::CONFLICT,
                "reference transaction outcome requires recovery",
            ));
        }
        if outcome != "recorded" {
            continue;
        }
        let updates = evidence
            .get("requested")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| Error::internal("recorded operation lacks requested refs"))?;
        let response = json!({
            "operation_id": row.get::<_, Uuid>("id"),
            "repository_id": repo,
            "storage_generation": row.get::<_, i64>("storage_generation"),
            "sequence": row.get::<_, i64>("sequence"),
            "atomic": true,
            "updates": updates,
        });
        tx.execute(
            "INSERT INTO forge_creation_requests (tenant_id,repository_id,idempotency_key,request,response) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
            &[&tenant, &repo, &key, &request, &response],
        )
        .await
        .map_err(Error::internal)?;
        let saved = tx
            .query_one(
                "SELECT request,response FROM forge_creation_requests WHERE tenant_id=$1 AND repository_id=$2 AND idempotency_key=$3",
                &[&tenant, &repo, &key],
            )
            .await
            .map_err(Error::internal)?;
        if saved.get::<_, Value>("request") != *request {
            return Err(Error(StatusCode::CONFLICT, "idempotency key conflict"));
        }
        if let Some(response) = saved.get::<_, Option<Value>>("response") {
            return Ok(Some(response));
        }
        // The insert above normally already carried the response. A null read
        // means an existing in-flight row won the conflict; finalize it here.
        let response = tx
            .query_one(
                "UPDATE forge_creation_requests SET response=$4 WHERE tenant_id=$1 AND repository_id=$2 AND idempotency_key=$3 AND response IS NULL RETURNING response",
                &[&tenant, &repo, &key, &response],
            )
            .await
            .map_err(Error::internal)?
            .get::<_, Value>(0);
        return Ok(Some(response));
    }
    Ok(None)
}
