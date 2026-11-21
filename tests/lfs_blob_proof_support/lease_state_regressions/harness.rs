//! Shared PostgreSQL, protected-upload, and raw HTTP helpers for lease regressions (`Refs #145`).

use std::time::{Duration, Instant as StdInstant};

use anyhow::{Context, Result, ensure};
use base64::Engine as _;
use deadpool_postgres::Pool;
use reqwest::StatusCode;
use rootyard::{
    blob_store::opendal::BlobStore,
    blob_store::protected::{ProtectedPublication, ProtectedUploader, UploadSource},
    lfs::blob_proof_publication::{
        CommittedLfsBlobRecord, LfsBlobError, LfsBlobRuntimeGate, LfsProofRejectCode, LfsRepoRealm, PgLfsBlobStore,
        StoredBlobLocatorRef,
    },
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant as TokioInstant;
use uuid::Uuid;

use super::super::TestActor;

pub(super) async fn upload_hold_candidate(
    pg: &PgLfsBlobStore,
    gate: &LfsBlobRuntimeGate,
    realm: &LfsRepoRealm,
    actor_id: Uuid,
    oid: &str,
    payload: &[u8],
) -> Result<CommittedLfsBlobRecord> {
    let store: BlobStore = gate.require_store()?.clone();
    let dir = TempDir::new()?;
    let path = dir.path().join("candidate.bin");
    std::fs::write(&path, payload)?;
    let grant = pg
        .acquire_lfs_upload_hold(
            &store,
            realm,
            oid,
            payload.len() as u64,
            TokioInstant::now() + Duration::from_secs(20),
        )
        .await?;
    let publication = ProtectedUploader::new(store)
        .consume_and_upload(pg.pool(), grant, &[UploadSource::new(&path)], StdInstant::now() + Duration::from_secs(20))
        .await
        .map_err(|e| anyhow::anyhow!("protected upload failed: {e}"))?;
    candidate_record(realm, actor_id, oid, payload.len() as i64, &publication)
}

fn candidate_record(
    realm: &LfsRepoRealm,
    actor_id: Uuid,
    oid: &str,
    size: i64,
    publication: &ProtectedPublication,
) -> Result<CommittedLfsBlobRecord> {
    let pr = publication.receipts().first().context("missing protected receipt")?;
    Ok(CommittedLfsBlobRecord {
        tenant_id: realm.owner_tenant_id,
        repository_id: realm.repository_id,
        oid_sha256: oid.to_owned(),
        size_bytes: size,
        locator: StoredBlobLocatorRef::from_locator(pr.receipt().locator()),
        hold_id: pr.hold_id(),
        acquire_request_id: publication.acquire_request_id(),
        consume_request_id: publication.consume_request_id(),
        backend_identity_hex: pr.receipt().backend_identity().as_hex().to_owned(),
        uploader_actor_id: actor_id,
        retired: false,
    })
}

pub(super) struct AttemptRowSpec {
    pub attempt_id: Uuid,
    pub op_id: Option<Uuid>,
    pub live: bool,
}

pub(super) async fn insert_attempt(
    pg: &PgLfsBlobStore,
    realm: &LfsRepoRealm,
    actor_id: Uuid,
    oid: &str,
    size: i64,
    spec: AttemptRowSpec,
) -> Result<()> {
    let AttemptRowSpec { attempt_id, op_id, live } = spec;
    let lease_secs = if live { 120.0 } else { -5.0 };
    pg.pool()
        .get()
        .await?
        .execute(
            "INSERT INTO lfs_blob_upload_attempts(
            attempt_id, tenant_id, repository_id, actor_id, oid_sha256, size_bytes, operation_id, lease_until, state
         ) VALUES($1,$2,$3,$4,$5,$6,$7, clock_timestamp() + make_interval(secs => $8), 'pending')",
            &[&attempt_id, &realm.owner_tenant_id, &realm.repository_id, &actor_id, &oid, &size, &op_id, &lease_secs],
        )
        .await?;
    Ok(())
}

pub(super) fn expect_equivocation(res: Result<CommittedLfsBlobRecord, LfsBlobError>) -> Result<()> {
    let err = res.err().context("expected attestation equivocation")?;
    ensure!(err.code == LfsProofRejectCode::AttestationEquivocation, "unexpected reject code {:?}", err.code);
    Ok(())
}

pub(super) async fn assert_no_object_rows(pool: &Pool, realm: &LfsRepoRealm, oid: &str) -> Result<()> {
    let blobs = count_rows(
        pool,
        "SELECT COUNT(*) FROM lfs_blob_objects WHERE repository_id=$1 AND oid_sha256=$2",
        realm.repository_id,
        oid,
    )
    .await?;
    ensure!(blobs == 0, "lfs_blob_objects must stay empty for {oid}");
    let objects = count_rows(
        pool,
        "SELECT COUNT(*) FROM lfs_objects WHERE repository_id=$1 AND oid=$2",
        realm.repository_id,
        oid,
    )
    .await?;
    ensure!(objects == 0, "lfs_objects must stay empty for {oid}");
    Ok(())
}

pub(super) async fn wait_pending_attempt(pool: &Pool, repository_id: Uuid, oid: &str) -> Result<(Uuid, Option<Uuid>)> {
    for _ in 0..50 {
        let row = pool
            .get()
            .await?
            .query_opt(
                "SELECT attempt_id, operation_id FROM lfs_blob_upload_attempts
                 WHERE repository_id=$1 AND oid_sha256=$2 AND state='pending'
                 ORDER BY created_at DESC LIMIT 1",
                &[&repository_id, &oid],
            )
            .await?;
        if let Some(r) = row {
            return Ok((r.get(0), r.get(1)));
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    anyhow::bail!("no pending upload attempt appeared for oid {oid}")
}

pub(super) async fn wait_null_op_attempt(pool: &Pool, repository_id: Uuid, oid: &str) -> Result<Uuid> {
    let (attempt, op) = wait_pending_attempt(pool, repository_id, oid).await?;
    ensure!(op.is_none(), "attempt must not bind an operation before default resolution");
    Ok(attempt)
}

pub(super) async fn attempt_state(pool: &Pool, attempt_id: Uuid) -> Result<String> {
    Ok(pool
        .get()
        .await?
        .query_one("SELECT state FROM lfs_blob_upload_attempts WHERE attempt_id=$1", &[&attempt_id])
        .await?
        .get(0))
}

pub(super) async fn op_state(pool: &Pool, repository_id: Uuid, operation_id: Uuid) -> Result<String> {
    Ok(pool
        .get()
        .await?
        .query_one(
            "SELECT state FROM lfs_blob_upload_operations WHERE repository_id=$1 AND operation_id=$2",
            &[&repository_id, &operation_id],
        )
        .await?
        .get(0))
}

pub(super) async fn count_rows(pool: &Pool, sql: &str, repository_id: Uuid, oid: &str) -> Result<i64> {
    Ok(pool.get().await?.query_one(sql, &[&repository_id, &oid]).await?.get(0))
}

pub(super) struct StreamSpec<'a> {
    pub op_tok: Option<&'a str>,
    pub oid: &'a str,
    pub first: &'a [u8],
    pub sized: bool,
}

pub(super) async fn open_upload_stream(
    base_url: &str,
    realm: &LfsRepoRealm,
    actor: &TestActor,
    spec: StreamSpec<'_>,
) -> Result<TcpStream> {
    let host = base_url.strip_prefix("http://").context("http base url")?;
    let mut stream = TcpStream::connect(host).await?;
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", actor.username, actor.token));
    let op_line = spec.op_tok.map(|t| format!("X-Rootyard-Operation-Id: {t}\r\n")).unwrap_or_default();
    let (target, framing) = if spec.sized {
        (format!("{}/{}", spec.oid, spec.first.len()), format!("Content-Length: {}\r\n", spec.first.len()))
    } else {
        (spec.oid.to_owned(), "Transfer-Encoding: chunked\r\n".to_owned())
    };
    let head = format!(
        "PUT /{}/{}.git/info/lfs/objects/{target} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Basic {auth}\r\n{op_line}Content-Type: application/octet-stream\r\n{framing}Connection: close\r\n\r\n",
        realm.owner_username, realm.repo_name
    );
    stream.write_all(head.as_bytes()).await?;
    if spec.sized {
        stream.write_all(&spec.first[..spec.first.len().min(8_192)]).await?;
    } else {
        write_chunk(&mut stream, spec.first).await?;
    }
    stream.flush().await?;
    Ok(stream)
}

async fn write_chunk(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    stream.write_all(format!("{:X}\r\n", bytes.len()).as_bytes()).await?;
    stream.write_all(bytes).await?;
    stream.write_all(b"\r\n").await?;
    Ok(())
}

pub(super) async fn finish_stream(mut stream: TcpStream, sized: bool, rest: &[u8]) -> Result<StatusCode> {
    if sized {
        let tail = rest.get(8_192..).unwrap_or_default();
        stream.write_all(tail).await?;
    } else {
        if !rest.is_empty() {
            write_chunk(&mut stream, rest).await?;
        }
        stream.write_all(b"0\r\n\r\n").await?;
    }
    stream.flush().await?;
    read_status(stream).await
}

async fn read_status(mut stream: TcpStream) -> Result<StatusCode> {
    let mut head = Vec::new();
    let mut buf = [0u8; 4096];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&head);
    let code = text.split_whitespace().nth(1).context("HTTP status line")?.parse::<u16>()?;
    Ok(StatusCode::from_u16(code)?)
}
