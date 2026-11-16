//! Bounded mTLS tenant Raft RPC client with explicit SAN binding and deadline-shared leader redirect.

use std::time::Duration;

use tokio::time::{Instant, timeout_at};

use crate::cluster::{read_frame_bounded_async, write_frame_bounded_async};
use crate::mtls::MtlsClient;
use crate::streaming::{ReceivedStream, StreamConfig, read_stream_bounded};
use crate::tenant_rpc::types::{
    MAX_TENANT_RPC_FRAME_BYTES, TenantRpcError, TenantRpcErrorCode, TenantRpcRequest, TenantRpcResponse,
};

/// Client enforcing mTLS server SAN binding, caller absolute deadlines, and bounded redirect following.
#[derive(Clone)]
pub struct TenantRpcClient {
    mtls: MtlsClient,
    deadline: Duration,
    max_redirects: usize,
}

impl TenantRpcClient {
    /// Creates a bounded client with shared deadline budget across redirects.
    pub fn new(mtls: MtlsClient, deadline: Duration, max_redirects: usize) -> Self {
        Self { mtls, deadline, max_redirects }
    }

    /// Sends one unary RPC to a fixed node without automatic redirect following.
    pub async fn call_once(
        &self,
        addr: &str,
        target_node_id: u64,
        req: &TenantRpcRequest,
    ) -> Result<TenantRpcResponse, TenantRpcError> {
        let stop_at = Instant::now() + self.deadline;
        self.roundtrip_until(addr, target_node_id, req, stop_at).await
    }

    /// Sends a unary RPC and follows structured `LeaderRedirect` hops inside the original deadline budget.
    pub async fn call_with_redirect(
        &self,
        initial_addr: &str,
        initial_node_id: u64,
        req: &TenantRpcRequest,
    ) -> Result<(TenantRpcResponse, u64, usize), TenantRpcError> {
        let stop_at = Instant::now() + self.deadline;
        let mut addr = initial_addr.to_owned();
        let mut target_id = initial_node_id;

        for hop in 0..=self.max_redirects {
            let resp = self.roundtrip_until(&addr, target_id, req, stop_at).await?;
            match resp {
                TenantRpcResponse::LeaderRedirect(redir) => {
                    if hop == self.max_redirects {
                        return Err(TenantRpcError::new(
                            TenantRpcErrorCode::RedirectExhausted,
                            format!("leader redirect budget ({}) exhausted", self.max_redirects),
                        ));
                    }
                    addr = redir.leader_addr;
                    target_id = redir.leader_id;
                }
                TenantRpcResponse::Error(err) => return Err(err),
                other => return Ok((other, target_id, hop)),
            }
        }
        Err(TenantRpcError::new(TenantRpcErrorCode::RedirectExhausted, "redirect loop"))
    }

    /// Opens a tenant-scoped stream, follows `LeaderRedirect`, and verifies bounded chunk delivery.
    pub async fn stream_with_redirect(
        &self,
        initial_addr: &str,
        initial_node_id: u64,
        req: &TenantRpcRequest,
        stream_cfg: &StreamConfig,
        chunk_delay: Option<Duration>,
    ) -> Result<(ReceivedStream, u64, u64), TenantRpcError> {
        let stop_at = Instant::now() + self.deadline;
        let mut addr = initial_addr.to_owned();
        let mut target_id = initial_node_id;

        for hop in 0..=self.max_redirects {
            let fut = async {
                let mut tls = self
                    .mtls
                    .connect_peer(&addr, target_id)
                    .await
                    .map_err(|e| TenantRpcError::new(TenantRpcErrorCode::UnauthorizedCert, e.to_string()))?;
                write_frame_bounded_async(&mut tls, req, MAX_TENANT_RPC_FRAME_BYTES).await.map_err(|e| {
                    let code = if e.kind() == std::io::ErrorKind::InvalidInput {
                        TenantRpcErrorCode::PayloadTooLarge
                    } else {
                        TenantRpcErrorCode::QuorumUnavailable
                    };
                    TenantRpcError::new(code, e.to_string())
                })?;
                let first: TenantRpcResponse = read_frame_bounded_async(&mut tls, MAX_TENANT_RPC_FRAME_BYTES)
                    .await
                    .map_err(|e| TenantRpcError::new(TenantRpcErrorCode::QuorumUnavailable, e.to_string()))?
                    .ok_or_else(|| {
                        TenantRpcError::new(TenantRpcErrorCode::QuorumUnavailable, "peer closed mTLS stream")
                    })?;
                Ok::<_, TenantRpcError>((tls, first))
            };
            let (mut tls, first) = timeout_at(stop_at, fut).await.map_err(|_| {
                TenantRpcError::new(TenantRpcErrorCode::DeadlineExceeded, "stream RPC deadline expired")
            })??;

            match first {
                TenantRpcResponse::LeaderRedirect(redir) => {
                    if hop == self.max_redirects {
                        return Err(TenantRpcError::new(
                            TenantRpcErrorCode::RedirectExhausted,
                            "stream redirect budget exhausted",
                        ));
                    }
                    addr = redir.leader_addr;
                    target_id = redir.leader_id;
                }
                TenantRpcResponse::Error(err) => return Err(err),
                TenantRpcResponse::StreamStarted { storage_generation, raft_term, .. } => {
                    let received = read_stream_bounded(&mut tls, stream_cfg, chunk_delay)
                        .await
                        .map_err(|e| TenantRpcError::new(TenantRpcErrorCode::BackpressureCancelled, e.to_string()))?;
                    return Ok((received, raft_term, storage_generation));
                }
                other => {
                    return Err(TenantRpcError::new(
                        TenantRpcErrorCode::InvalidRequest,
                        format!("unexpected stream start response {other:?}"),
                    ));
                }
            }
        }
        Err(TenantRpcError::new(TenantRpcErrorCode::RedirectExhausted, "stream redirect loop"))
    }

    async fn roundtrip_until(
        &self,
        addr: &str,
        target_node_id: u64,
        req: &TenantRpcRequest,
        stop_at: Instant,
    ) -> Result<TenantRpcResponse, TenantRpcError> {
        let fut = async {
            let mut tls = self
                .mtls
                .connect_peer(addr, target_node_id)
                .await
                .map_err(|e| TenantRpcError::new(TenantRpcErrorCode::UnauthorizedCert, e.to_string()))?;
            write_frame_bounded_async(&mut tls, req, MAX_TENANT_RPC_FRAME_BYTES).await.map_err(|e| {
                let code = if e.kind() == std::io::ErrorKind::InvalidInput {
                    TenantRpcErrorCode::PayloadTooLarge
                } else {
                    TenantRpcErrorCode::QuorumUnavailable
                };
                TenantRpcError::new(code, e.to_string())
            })?;
            let resp = read_frame_bounded_async::<_, TenantRpcResponse>(&mut tls, MAX_TENANT_RPC_FRAME_BYTES)
                .await
                .map_err(|e| TenantRpcError::new(TenantRpcErrorCode::QuorumUnavailable, e.to_string()))?
                .ok_or_else(|| TenantRpcError::new(TenantRpcErrorCode::QuorumUnavailable, "peer closed mTLS stream"))?;
            Ok::<_, TenantRpcError>(resp)
        };
        timeout_at(stop_at, fut).await.map_err(|_| {
            TenantRpcError::new(TenantRpcErrorCode::DeadlineExceeded, "tenant Raft RPC deadline exceeded")
        })?
    }
}
