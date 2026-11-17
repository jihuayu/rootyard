use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::MerkleSyncError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceAuthAction {
    Read,
    Write,
    Checkpoint,
    RestoreFork,
    BackupExport,
    BackupRestore,
}

impl WorkspaceAuthAction {
    pub fn requires_write(self) -> bool {
        matches!(self, Self::Write | Self::Checkpoint | Self::RestoreFork | Self::BackupRestore)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessContext {
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub user_id: Uuid,
    pub history_id: Uuid,
    pub workspace_id: Uuid,
    pub lease_epoch: i64,
    pub request_id: Uuid,
}

impl AccessContext {
    pub fn validate_ids(&self) -> Result<(), MerkleSyncError> {
        if self.tenant_id.is_nil()
            || self.repo_id.is_nil()
            || self.user_id.is_nil()
            || self.history_id.is_nil()
            || self.workspace_id.is_nil()
            || self.request_id.is_nil()
            || self.lease_epoch <= 0
        {
            return Err(MerkleSyncError::AccessDenied("invalid or nil access context identifiers".into()));
        }
        Ok(())
    }
}

/// Strict scoped lookup key for remote/local chunk & node reuse.
/// A content digest alone is NEVER sufficient for reuse or lookup across
/// tenants, repositories, histories, or physical Blob backends.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantRepoScopeKey {
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub backend_identity_hex: String,
    pub sha256: String,
}

impl TenantRepoScopeKey {
    pub fn new(
        tenant_id: Uuid,
        repo_id: Uuid,
        history_id: Uuid,
        backend_identity_hex: &str,
        sha256: &str,
    ) -> Result<Self, MerkleSyncError> {
        if tenant_id.is_nil() || repo_id.is_nil() || history_id.is_nil() || backend_identity_hex.len() != 64 {
            return Err(MerkleSyncError::TenantScopeMismatch("invalid scope key fields".into()));
        }
        Ok(Self {
            tenant_id,
            repo_id,
            history_id,
            backend_identity_hex: backend_identity_hex.to_owned(),
            sha256: sha256.to_owned(),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct HistoryFenceRegistry {
    inner: Arc<Mutex<HistoryFenceState>>,
}

#[derive(Debug, Default)]
struct HistoryFenceState {
    active: BTreeMap<(Uuid, Uuid), Uuid>,
    fenced: BTreeMap<(Uuid, Uuid), BTreeSet<Uuid>>,
}

impl HistoryFenceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_active(&self, tenant_id: Uuid, repo_id: Uuid, history_id: Uuid) -> Result<(), MerkleSyncError> {
        if tenant_id.is_nil() || repo_id.is_nil() || history_id.is_nil() {
            return Err(MerkleSyncError::InvalidInput("nil history fence identifier".into()));
        }
        let mut st = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if st.fenced.get(&(tenant_id, repo_id)).is_some_and(|set| set.contains(&history_id)) {
            return Err(MerkleSyncError::StaleHistoryFenced("cannot re-register already fenced history_id".into()));
        }
        st.active.entry((tenant_id, repo_id)).or_insert(history_id);
        Ok(())
    }

    pub fn advance_fence(
        &self,
        tenant_id: Uuid,
        repo_id: Uuid,
        new_history_id: Uuid,
    ) -> Result<Option<Uuid>, MerkleSyncError> {
        if tenant_id.is_nil() || repo_id.is_nil() || new_history_id.is_nil() {
            return Err(MerkleSyncError::InvalidInput("nil history fence identifier".into()));
        }
        let mut st = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if st.fenced.get(&(tenant_id, repo_id)).is_some_and(|set| set.contains(&new_history_id)) {
            return Err(MerkleSyncError::StaleHistoryFenced("new_history_id was already fenced".into()));
        }
        let prev = st.active.insert((tenant_id, repo_id), new_history_id);
        if let Some(old) = prev
            && old != new_history_id
        {
            st.fenced.entry((tenant_id, repo_id)).or_default().insert(old);
        }
        Ok(prev)
    }

    pub fn verify_live(&self, tenant_id: Uuid, repo_id: Uuid, history_id: Uuid) -> Result<(), MerkleSyncError> {
        let st = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let key = (tenant_id, repo_id);
        if st.fenced.get(&key).is_some_and(|set| set.contains(&history_id)) {
            return Err(MerkleSyncError::StaleHistoryFenced("history_id has been fenced".into()));
        }
        match st.active.get(&key) {
            Some(&active) if active == history_id => Ok(()),
            Some(_) => Err(MerkleSyncError::StaleHistoryFenced("history_id does not match active repo history".into())),
            None => Err(MerkleSyncError::AccessDenied("repository history is unregistered".into())),
        }
    }
}

pub trait WorkspaceAuthorizer: Send + Sync {
    fn authorize(&self, ctx: &AccessContext, action: WorkspaceAuthAction) -> Result<(), MerkleSyncError>;
    fn verify_history_live(&self, tenant_id: Uuid, repo_id: Uuid, history_id: Uuid) -> Result<(), MerkleSyncError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserGrant {
    pub can_read: bool,
    pub can_write: bool,
}

#[derive(Clone, Debug, Default)]
pub struct LiveWorkspaceAuthRegistry {
    grants: Arc<Mutex<AuthRegistryState>>,
    fences: HistoryFenceRegistry,
}

#[derive(Debug, Default)]
struct AuthRegistryState {
    user_grants: BTreeMap<(Uuid, Uuid, Uuid), UserGrant>,
    workspace_bindings: BTreeMap<Uuid, (Uuid, Uuid, i64)>,
}

impl LiveWorkspaceAuthRegistry {
    pub fn new(fences: HistoryFenceRegistry) -> Self {
        Self { grants: Arc::new(Mutex::new(AuthRegistryState::default())), fences }
    }

    pub fn fences(&self) -> &HistoryFenceRegistry {
        &self.fences
    }

    pub fn grant_user(&self, tenant_id: Uuid, repo_id: Uuid, user_id: Uuid, can_read: bool, can_write: bool) {
        let mut st = self.grants.lock().unwrap_or_else(|p| p.into_inner());
        st.user_grants.insert((tenant_id, repo_id, user_id), UserGrant { can_read, can_write });
    }

    pub fn revoke_user(&self, tenant_id: Uuid, repo_id: Uuid, user_id: Uuid) {
        let mut st = self.grants.lock().unwrap_or_else(|p| p.into_inner());
        st.user_grants.remove(&(tenant_id, repo_id, user_id));
    }

    pub fn bind_workspace(&self, workspace_id: Uuid, tenant_id: Uuid, repo_id: Uuid, lease_epoch: i64) {
        let mut st = self.grants.lock().unwrap_or_else(|p| p.into_inner());
        st.workspace_bindings.insert(workspace_id, (tenant_id, repo_id, lease_epoch));
    }
}

impl WorkspaceAuthorizer for LiveWorkspaceAuthRegistry {
    fn authorize(&self, ctx: &AccessContext, action: WorkspaceAuthAction) -> Result<(), MerkleSyncError> {
        ctx.validate_ids()?;
        self.fences.verify_live(ctx.tenant_id, ctx.repo_id, ctx.history_id)?;
        let st = self.grants.lock().unwrap_or_else(|p| p.into_inner());
        let grant = st
            .user_grants
            .get(&(ctx.tenant_id, ctx.repo_id, ctx.user_id))
            .ok_or_else(|| MerkleSyncError::AccessDenied("user lacks active repo access".into()))?;
        if action.requires_write() && !grant.can_write {
            return Err(MerkleSyncError::AccessDenied("write permission required".into()));
        }
        if !grant.can_read {
            return Err(MerkleSyncError::AccessDenied("read permission required".into()));
        }
        if let Some(&(t, r, expected_epoch)) = st.workspace_bindings.get(&ctx.workspace_id) {
            if t != ctx.tenant_id || r != ctx.repo_id {
                return Err(MerkleSyncError::TenantScopeMismatch("workspace bound to different tenant/repo".into()));
            }
            if ctx.lease_epoch < expected_epoch {
                return Err(MerkleSyncError::NotQuiescent("stale workspace lease_epoch".into()));
            }
        }
        Ok(())
    }

    fn verify_history_live(&self, tenant_id: Uuid, repo_id: Uuid, history_id: Uuid) -> Result<(), MerkleSyncError> {
        self.fences.verify_live(tenant_id, repo_id, history_id)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldPurpose {
    ActiveCheckpoint,
    ActiveRestore,
    BackupArchive,
    NamedPin,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinHoldRecord {
    pub hold_id: Uuid,
    pub purpose: HoldPurpose,
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub checkpoint_id: Uuid,
    pub locator_paths: BTreeSet<String>,
    pub released: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GcEligibilityClass {
    ProtectedByHoldOrCheckpoint,
    OrphanGcEligible,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcSweepPlan {
    pub protected_locators: BTreeSet<String>,
    pub gc_eligible_orphan_locators: BTreeSet<String>,
    pub classifications: BTreeMap<String, GcEligibilityClass>,
}

#[derive(Clone, Debug, Default)]
pub struct PinHoldRegistry {
    holds: Arc<Mutex<BTreeMap<Uuid, PinHoldRecord>>>,
}

impl PinHoldRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn acquire_hold(
        &self,
        purpose: HoldPurpose,
        tenant_id: Uuid,
        repo_id: Uuid,
        history_id: Uuid,
        checkpoint_id: Uuid,
        locator_paths: BTreeSet<String>,
    ) -> Result<PinHoldRecord, MerkleSyncError> {
        if tenant_id.is_nil() || repo_id.is_nil() || history_id.is_nil() || checkpoint_id.is_nil() {
            return Err(MerkleSyncError::InvalidInput("pin hold requires non-nil scope identifiers".into()));
        }
        let hold_id = Uuid::new_v4();
        let rec = PinHoldRecord {
            hold_id,
            purpose,
            tenant_id,
            repo_id,
            history_id,
            checkpoint_id,
            locator_paths,
            released: false,
        };
        self.holds.lock().unwrap_or_else(|p| p.into_inner()).insert(hold_id, rec.clone());
        Ok(rec)
    }

    pub fn release_hold(&self, hold_id: Uuid) -> Result<bool, MerkleSyncError> {
        let mut map = self.holds.lock().unwrap_or_else(|p| p.into_inner());
        let Some(rec) = map.get_mut(&hold_id) else {
            return Ok(false);
        };
        rec.released = true;
        Ok(true)
    }

    pub fn is_locator_protected(&self, locator_path: &str) -> bool {
        let map = self.holds.lock().unwrap_or_else(|p| p.into_inner());
        map.values().any(|h| !h.released && h.locator_paths.contains(locator_path))
    }

    pub fn plan_gc_sweep(
        &self,
        all_known_locators: &BTreeSet<String>,
        committed_checkpoint_locators: &BTreeSet<String>,
    ) -> GcSweepPlan {
        let map = self.holds.lock().unwrap_or_else(|p| p.into_inner());
        let mut protected_locators = committed_checkpoint_locators.clone();
        for h in map.values() {
            if !h.released {
                protected_locators.extend(h.locator_paths.iter().cloned());
            }
        }
        let mut gc_eligible_orphan_locators = BTreeSet::new();
        let mut classifications = BTreeMap::new();
        for loc in all_known_locators {
            if protected_locators.contains(loc) {
                classifications.insert(loc.clone(), GcEligibilityClass::ProtectedByHoldOrCheckpoint);
            } else {
                gc_eligible_orphan_locators.insert(loc.clone());
                classifications.insert(loc.clone(), GcEligibilityClass::OrphanGcEligible);
            }
        }
        GcSweepPlan { protected_locators, gc_eligible_orphan_locators, classifications }
    }
}
