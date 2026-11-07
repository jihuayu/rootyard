//! Peer transport for online repository migration: bounded receipt
//! collection, snapshot/delta transfer, cutover sidecar finalization and
//! the signed delegation envelope shared by those requests.
use crate::{
    AppState, Error,
    sharding::{
        models::{conflict, unix_now},
        replication::{self, TransferMeta},
        replication_target::{self, SnapshotReceipt},
        transport::{self, DELEGATION_HEADER, ENVELOPE_LIFETIME_SECONDS, Envelope},
    },
};
use axum::http::StatusCode;
use bytes::Bytes;
use futures_util::StreamExt;
use std::path::Path as FsPath;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

const MAX_RECEIPT_BYTES: usize = 2048;

/// Collect a peer receipt with a hard byte cap. The body may have unknown
/// length; only this bounded buffer is allocated and an oversized single chunk
/// is rejected before being appended. Error text is never logged or returned.
pub(super) async fn collect_bounded<S, E>(mut stream: S, cap: usize) -> Result<Vec<u8>, Error>
where
    S: futures_util::Stream<Item = Result<Bytes, E>> + Unpin,
{
    let mut body = Vec::with_capacity(cap.min(512));
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| Error(StatusCode::BAD_GATEWAY, "replica receipt interrupted"))?;
        if chunk.len() > cap.saturating_sub(body.len()) {
            return Err(Error(StatusCode::BAD_GATEWAY, "replica receipt too large"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn read_receipt<T: serde::de::DeserializeOwned>(upstream: reqwest::Response) -> Result<T, Error> {
    let body = collect_bounded(upstream.bytes_stream(), MAX_RECEIPT_BYTES).await?;
    serde_json::from_slice(&body).map_err(Error::internal)
}

pub(super) async fn send_transfer(
    state: &AppState,
    target_url: &str,
    envelope: &Envelope,
    path_and_query: &str,
    meta: &TransferMeta,
    bundle: Option<&FsPath>,
) -> Result<SnapshotReceipt, Error> {
    let mut url = transport::validate_endpoint(target_url)?;
    let (path, query) = path_and_query.split_once('?').ok_or_else(Error::bad_request)?;
    url.set_path(path);
    url.set_query(Some(query));
    let prefix = futures_util::stream::once({
        let bytes = replication::encode_meta(meta)?;
        async move { Ok::<_, std::io::Error>(Bytes::from(bytes)) }
    });
    let reader: Box<dyn tokio::io::AsyncRead + Send + Unpin> = match bundle {
        Some(path) => Box::new(tokio::fs::File::open(path).await.map_err(Error::internal)?),
        None => Box::new(tokio::io::empty()),
    };
    let body = reqwest::Body::wrap_stream(prefix.chain(ReaderStream::new(reader)));
    let http = transport::cluster_client(state.config.git_timeout)?;
    let upstream = http
        .post(url)
        .header(DELEGATION_HEADER, transport::sign(envelope)?)
        .body(body)
        .send()
        .await
        .map_err(|_| Error(StatusCode::BAD_GATEWAY, "replica transfer interrupted"))?;
    let status = upstream.status();
    if status != StatusCode::OK {
        // Never log or return untrusted peer error text. Only the HTTP status
        // and a fixed source-facing class cross the trust boundary.
        eprintln!("rootyard: replica transfer rejected target_status={status}");
        return match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                Err(conflict("replica rejected snapshot transfer: unauthorized"))
            }
            StatusCode::CONFLICT => Err(conflict("replica rejected snapshot transfer: conflict")),
            StatusCode::PAYLOAD_TOO_LARGE | StatusCode::UNPROCESSABLE_ENTITY => {
                Err(conflict("replica rejected snapshot transfer: invalid body"))
            }
            status if status.is_server_error() => {
                Err(Error(StatusCode::BAD_GATEWAY, "replica transfer failed on target"))
            }
            _ => Err(conflict("replica rejected snapshot transfer")),
        };
    }
    read_receipt::<SnapshotReceipt>(upstream).await
}

pub(super) async fn send_sidecar_finalize(
    state: &AppState,
    target_url: &str,
    envelope: &Envelope,
    path: &str,
    operation_id: Uuid,
) -> Result<(), Error> {
    let mut url = transport::validate_endpoint(target_url)?;
    url.set_path(path);
    let http = transport::cluster_client(state.config.git_timeout)?;
    let upstream = http
        .post(url)
        .header(DELEGATION_HEADER, transport::sign(envelope)?)
        .body(Vec::new())
        .send()
        .await
        .map_err(|_| Error(StatusCode::BAD_GATEWAY, "target sidecar finalization interrupted"))?;
    if upstream.status() != StatusCode::OK {
        return Err(conflict("cutover committed but target CI sidecar publication is pending recovery"));
    }
    let receipt = read_receipt::<replication_target::FinalizeReceipt>(upstream).await?;
    if receipt.operation_id != operation_id || receipt.state != "published" {
        return Err(conflict("target CI sidecar finalization receipt mismatch"));
    }
    Ok(())
}

pub(super) fn envelope(
    authority_incarnation: Uuid,
    actor: &crate::db::Identity,
    repository_id: Uuid,
    target_node_id: &str,
    route_epoch: i64,
    fencing_token: i64,
    storage_generation: i64,
    path_and_query: String,
) -> Envelope {
    Envelope {
        version: 1,
        authority_incarnation,
        nonce: Uuid::new_v4(),
        expires_unix: unix_now() + ENVELOPE_LIFETIME_SECONDS,
        actor_id: actor.id,
        token_id: actor.token_id,
        repository_id,
        target_node_id: target_node_id.to_owned(),
        route_epoch,
        fencing_token,
        storage_generation,
        method: "POST".into(),
        path_and_query,
    }
}
