//! Authoritative per-group realm epoch registry enforcing fail-closed scope and fence checks.

use std::collections::{BTreeMap, BTreeSet};

use crate::mtls::TenantCertScope;
use crate::tenant_rpc::types::{
    RealmEpoch, TenantRpcError, TenantRpcErrorCode, TenantRpcRequest, verify_scoped_bearer_token,
};

/// Mutable replica-side authoritative realm table enforcing fail-closed epoch and closed-tenant fences.
#[derive(Clone, Debug)]
pub struct GroupRealmRegistry {
    group_id: String,
    tenants: BTreeMap<String, RealmEpoch>,
    closed_tenants: BTreeSet<String>,
}

impl GroupRealmRegistry {
    /// Initializes an authoritative registry bound to exactly one Ref-CAS `group_id`.
    pub fn new(group_id: impl Into<String>) -> Self {
        Self { group_id: group_id.into(), tenants: BTreeMap::new(), closed_tenants: BTreeSet::new() }
    }

    pub fn upsert_tenant(&mut self, epoch: RealmEpoch) {
        self.closed_tenants.remove(&epoch.tenant_id);
        self.tenants.insert(epoch.tenant_id.clone(), epoch);
    }

    pub fn close_tenant(&mut self, tenant_id: &str) {
        self.closed_tenants.insert(tenant_id.to_owned());
    }

    pub fn rotate_authority(&mut self, tenant_id: &str, new_authority_id: impl Into<String>) {
        if let Some(entry) = self.tenants.get_mut(tenant_id) {
            entry.authority_id = new_authority_id.into();
        }
    }

    pub fn rotate_history(&mut self, tenant_id: &str, new_history_id: impl Into<String>) {
        if let Some(entry) = self.tenants.get_mut(tenant_id) {
            entry.history_id = new_history_id.into();
        }
    }

    pub fn advance_group_epoch(&mut self, tenant_id: &str, new_group_epoch: u64) {
        if let Some(entry) = self.tenants.get_mut(tenant_id) {
            entry.group_epoch = new_group_epoch;
        }
    }

    pub fn bump_storage_generation(&mut self, tenant_id: &str, new_generation: u64) {
        if let Some(entry) = self.tenants.get_mut(tenant_id) {
            entry.storage_generation = new_generation;
        }
    }

    pub(super) fn verify_request(
        &self,
        cert: &TenantCertScope,
        req: &TenantRpcRequest,
    ) -> Result<RealmEpoch, TenantRpcError> {
        req.realm.validate_syntax()?;
        if cert.tenant_id != req.realm.tenant_id {
            return Err(TenantRpcError::new(
                TenantRpcErrorCode::CrossTenantDenied,
                format!("mTLS cert tenant {} cannot access tenant {}", cert.tenant_id, req.realm.tenant_id),
            ));
        }
        if cert.group_id != req.realm.group_id || req.realm.group_id != self.group_id {
            return Err(TenantRpcError::new(
                TenantRpcErrorCode::WrongGroup,
                format!(
                    "group mismatch: server hosts {}, cert {}, req {}",
                    self.group_id, cert.group_id, req.realm.group_id
                ),
            ));
        }
        if self.closed_tenants.contains(&req.realm.tenant_id) {
            return Err(TenantRpcError::new(
                TenantRpcErrorCode::CrossTenantDenied,
                format!("tenant {} realm is closed", req.realm.tenant_id),
            ));
        }
        let auth = self.tenants.get(&req.realm.tenant_id).ok_or_else(|| {
            TenantRpcError::new(
                TenantRpcErrorCode::CrossTenantDenied,
                format!("tenant {} is not registered on group {}", req.realm.tenant_id, self.group_id),
            )
        })?;

        verify_scoped_bearer_token(&req.bearer_token, cert, &auth.authority_id, req.op.required_capability())?;

        if req.realm.authority_id != auth.authority_id {
            return Err(TenantRpcError::new(
                TenantRpcErrorCode::StaleAuthority,
                format!("stale authority_id {:?}, active {:?}", req.realm.authority_id, auth.authority_id),
            ));
        }
        if req.realm.history_id != auth.history_id {
            return Err(TenantRpcError::new(
                TenantRpcErrorCode::StaleHistory,
                format!("stale history_id {:?}, active {:?}", req.realm.history_id, auth.history_id),
            ));
        }
        if req.realm.group_epoch != auth.group_epoch {
            return Err(TenantRpcError::new(
                TenantRpcErrorCode::StaleGroupEpoch,
                format!("stale group_epoch {}, active {}", req.realm.group_epoch, auth.group_epoch),
            ));
        }
        if req.realm.storage_generation != auth.storage_generation {
            return Err(TenantRpcError::new(
                TenantRpcErrorCode::StaleStorageGeneration,
                format!(
                    "stale storage_generation {}, active {} (raft_term never replaces business storage_generation)",
                    req.realm.storage_generation, auth.storage_generation
                ),
            ));
        }
        Ok(auth.clone())
    }
}
