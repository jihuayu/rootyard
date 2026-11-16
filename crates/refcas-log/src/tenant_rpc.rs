//! Tenant-scoped mTLS Raft RPC protocol, leader redirect, ReadIndex, and bounded streaming.

mod client;
mod realm;
mod server;
mod types;

pub use client::TenantRpcClient;
pub use realm::GroupRealmRegistry;
pub use server::{TenantRpcServer, TenantServerConfig};
pub use types::{
    LeaderRedirect, MAX_TENANT_RPC_FRAME_BYTES, RealmEpoch, TenantOp, TenantRpcError, TenantRpcErrorCode,
    TenantRpcRequest, TenantRpcResponse, format_scoped_bearer_token, verify_scoped_bearer_token,
};
