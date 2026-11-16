//! Wire protocol types, scoped bearer tokens, and fail-closed realm epoch contracts for tenant Raft RPC.

use std::fmt;

use openraft::LogId;
use serde::{Deserialize, Serialize};

use crate::E;
use crate::mtls::{RpcCapability, TenantCertScope, validate_group_id, validate_non_nil_uuid};
use crate::state_machine::SmCommand;
use crate::streaming::StreamConfig;

/// Bounded wire frame cap (2 MiB) for tenant-scoped unary JSON RPC envelopes.
pub const MAX_TENANT_RPC_FRAME_BYTES: usize = 2 * 1024 * 1024;

/// Authoritative business realm coordinates checked on every tenant-scoped Raft RPC.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmEpoch {
    pub tenant_id: String,
    pub group_id: String,
    pub authority_id: String,
    pub history_id: String,
    pub group_epoch: u64,
    pub storage_generation: u64,
}

impl RealmEpoch {
    /// Validates structural non-nil UUID, bounded group, and positive epoch/generation invariants.
    pub fn validate_syntax(&self) -> Result<(), TenantRpcError> {
        validate_non_nil_uuid(&self.tenant_id)
            .map_err(|e| TenantRpcError::new(TenantRpcErrorCode::InvalidRequest, e.to_string()))?;
        validate_group_id(&self.group_id)
            .map_err(|e| TenantRpcError::new(TenantRpcErrorCode::WrongGroup, e.to_string()))?;
        validate_non_nil_uuid(&self.authority_id)
            .map_err(|e| TenantRpcError::new(TenantRpcErrorCode::StaleAuthority, e.to_string()))?;
        validate_non_nil_uuid(&self.history_id)
            .map_err(|e| TenantRpcError::new(TenantRpcErrorCode::StaleHistory, e.to_string()))?;
        if self.group_epoch == 0 {
            return Err(TenantRpcError::new(TenantRpcErrorCode::StaleGroupEpoch, "group_epoch must be positive"));
        }
        if self.storage_generation == 0 {
            return Err(TenantRpcError::new(
                TenantRpcErrorCode::StaleStorageGeneration,
                "storage_generation must be positive",
            ));
        }
        Ok(())
    }
}

/// Structured Raft leader hint returned by followers; carries `raft_term`, never business generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaderRedirect {
    pub leader_id: u64,
    pub leader_addr: String,
    pub raft_term: u64,
}

/// Tenant-scoped Raft RPC operation variants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TenantOp {
    ReadIndex,
    LinearizableGet { key: String },
    ProposeKv { command: SmCommand },
    ProposeRaw { payload: Vec<u8> },
    StreamCompute { prefix: String, planned_chunks: u32, chunk_bytes: usize, stream_config: StreamConfig },
}

impl TenantOp {
    /// Minimum narrow capability required by both the X.509 URI SAN and bearer token.
    pub fn required_capability(&self) -> RpcCapability {
        match self {
            Self::ReadIndex | Self::LinearizableGet { .. } => RpcCapability::Read,
            Self::ProposeKv { .. } | Self::ProposeRaw { .. } => RpcCapability::Write,
            Self::StreamCompute { .. } => RpcCapability::Stream,
        }
    }
}

/// Authenticated envelope presented over verified mTLS connections.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantRpcRequest {
    pub realm: RealmEpoch,
    pub bearer_token: String,
    pub op: TenantOp,
}

/// Machine-readable refusal codes distinguishing authorization, epoch fences, quorum loss, and backpressure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TenantRpcErrorCode {
    UnauthorizedCert,
    CrossTenantDenied,
    WrongGroup,
    ForbiddenCapability,
    WideTokenRejected,
    StaleAuthority,
    StaleHistory,
    StaleGroupEpoch,
    StaleStorageGeneration,
    PayloadTooLarge,
    QuorumUnavailable,
    DeadlineExceeded,
    RedirectExhausted,
    BackpressureCancelled,
    InvalidRequest,
    Internal,
}

/// Structured error returned by `TenantRpcServer` and `TenantRpcClient`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantRpcError {
    pub code: TenantRpcErrorCode,
    pub message: String,
}

impl TenantRpcError {
    pub fn new(code: TenantRpcErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

impl fmt::Display for TenantRpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for TenantRpcError {}

/// Wire response returned on a tenant-scoped mTLS RPC call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TenantRpcResponse {
    ReadIndex {
        read_log_id: Option<LogId<u64>>,
        applied_count: u64,
        state_digest_hex: String,
        raft_term: u64,
        storage_generation: u64,
    },
    LinearizableValue {
        value: Option<String>,
        read_log_id: Option<LogId<u64>>,
        raft_term: u64,
        storage_generation: u64,
    },
    CommitReceipt {
        log_index: u64,
        raft_term: u64,
        storage_generation: u64,
    },
    StreamStarted {
        stream_id: u64,
        planned_chunks: u64,
        planned_bytes: u64,
        read_log_id: Option<LogId<u64>>,
        raft_term: u64,
        storage_generation: u64,
    },
    LeaderRedirect(LeaderRedirect),
    Error(TenantRpcError),
}

/// Formats a canonical narrow tenant/group/authority/capability bearer token (`ryt1;...`).
pub fn format_scoped_bearer_token(
    tenant_id: &str,
    group_id: &str,
    authority_id: &str,
    cap: RpcCapability,
) -> Result<String, E> {
    let tid = validate_non_nil_uuid(tenant_id)?;
    let gid = validate_group_id(group_id)?;
    let aid = validate_non_nil_uuid(authority_id)?;
    Ok(format!("ryt1;tenant={tid};group={gid};auth={aid};cap={}", cap.as_str()))
}

/// Rejects wide/unscoped bearer tokens and verifies exact binding to `cert`, `authority_id`, and `required`.
pub fn verify_scoped_bearer_token(
    raw: &str,
    cert: &TenantCertScope,
    expected_authority_id: &str,
    required: RpcCapability,
) -> Result<(), TenantRpcError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.contains('*')
        || trimmed.contains('+')
        || trimmed.contains(',')
        || matches!(trimmed, "all" | "global" | "wildcard" | "unscoped" | "root" | "admin")
    {
        return Err(TenantRpcError::new(
            TenantRpcErrorCode::WideTokenRejected,
            "wide, wildcard, multi-scope, or unscoped bearer token rejected",
        ));
    }
    let parts: Vec<&str> = trimmed.split(';').collect();
    if parts.len() != 5 || parts[0] != "ryt1" {
        return Err(TenantRpcError::new(
            TenantRpcErrorCode::WideTokenRejected,
            "bearer token lacks strict narrow ryt1 tenant/group/authority/capability binding",
        ));
    }
    let tid = parts[1].strip_prefix("tenant=").ok_or_else(|| {
        TenantRpcError::new(TenantRpcErrorCode::WideTokenRejected, "malformed bearer token tenant claim")
    })?;
    let gid = parts[2].strip_prefix("group=").ok_or_else(|| {
        TenantRpcError::new(TenantRpcErrorCode::WideTokenRejected, "malformed bearer token group claim")
    })?;
    let aid = parts[3].strip_prefix("auth=").ok_or_else(|| {
        TenantRpcError::new(TenantRpcErrorCode::WideTokenRejected, "malformed bearer token authority claim")
    })?;
    let cap_str = parts[4].strip_prefix("cap=").ok_or_else(|| {
        TenantRpcError::new(TenantRpcErrorCode::WideTokenRejected, "malformed bearer token capability claim")
    })?;

    if validate_non_nil_uuid(tid).is_err() || validate_group_id(gid).is_err() || validate_non_nil_uuid(aid).is_err() {
        return Err(TenantRpcError::new(
            TenantRpcErrorCode::WideTokenRejected,
            "bearer token uses invalid or broad tenant/group/authority identifier",
        ));
    }
    let tok_cap = RpcCapability::parse(cap_str)
        .map_err(|_| TenantRpcError::new(TenantRpcErrorCode::WideTokenRejected, "invalid token capability"))?;

    if tid != cert.tenant_id {
        return Err(TenantRpcError::new(
            TenantRpcErrorCode::CrossTenantDenied,
            format!("bearer token tenant {tid} mismatches cert tenant {}", cert.tenant_id),
        ));
    }
    if gid != cert.group_id {
        return Err(TenantRpcError::new(
            TenantRpcErrorCode::WrongGroup,
            format!("bearer token group {gid} mismatches cert group {}", cert.group_id),
        ));
    }
    if aid != expected_authority_id {
        return Err(TenantRpcError::new(
            TenantRpcErrorCode::StaleAuthority,
            format!("bearer token authority {aid} mismatches active authority {expected_authority_id}"),
        ));
    }
    if tok_cap != required || !cert.allows(required) {
        return Err(TenantRpcError::new(
            TenantRpcErrorCode::ForbiddenCapability,
            format!("missing required capability {:?} (token {:?})", required, tok_cap),
        ));
    }
    Ok(())
}
