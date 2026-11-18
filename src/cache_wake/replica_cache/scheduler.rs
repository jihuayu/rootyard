//! Bounded hot-replica affinity routing, overload fallback, drain/failover,
//! and advisory `RouteDirectory` integration.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::cache_wake::{CacheKey, CacheKeyParts, CacheKind, ServingCache};

pub use super::fair_admission::{
    FairAdmissionPermit, FairnessStatsSnapshot, TenantFairShareConfig, TenantFairShareGate,
};
use super::{
    lease_pin::{AuthTask, LiveAuthorizer, ReplicaViewGuard},
    types::{REPLICA_CACHE_SCHEMA, ReplicaCacheError, ReplicaReadRequest, is_retryable_failover_error},
};

/// Abstract replica node backend implemented by local [`super::ReplicaCacheNode`]
/// or process-isolated replica workers.
pub trait ReplicaBackend: Send + Sync {
    fn node_id(&self) -> &str;
    fn serve_replica_view<'a>(
        &'a self,
        req: &'a ReplicaReadRequest,
        authorizer: &'a dyn LiveAuthorizer,
        deadline: Instant,
    ) -> AuthTask<'a, Result<ReplicaViewGuard, ReplicaCacheError>>;
    fn is_accepting_traffic(&self) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplicaHealthState {
    Active,
    Draining,
    Unhealthy { until: Instant, reason: String },
}

struct ManagedNode {
    backend: Arc<dyn ReplicaBackend>,
    health: ReplicaHealthState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteDirectoryHint {
    pub schema_version: u32,
    pub node_id: String,
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub gate_revision: i64,
    pub membership_digest: String,
}

pub struct ScheduledServeOutcome {
    pub guard: ReplicaViewGuard,
    pub routed_node_id: String,
    pub attempts: usize,
    pub failover_used: bool,
    pub admission_wait_us: u64,
}

pub struct ReplicaScheduler {
    nodes: Arc<Mutex<Vec<ManagedNode>>>,
    fair_gate: TenantFairShareGate,
    route_directory: Option<Arc<ServingCache>>,
    environment: String,
    circuit_cooldown: Duration,
}

impl ReplicaScheduler {
    pub fn new(
        backends: Vec<Arc<dyn ReplicaBackend>>,
        fair_cfg: TenantFairShareConfig,
        route_directory: Option<Arc<ServingCache>>,
        environment: impl Into<String>,
        circuit_cooldown: Duration,
    ) -> Result<Self, ReplicaCacheError> {
        if backends.is_empty() {
            return Err(ReplicaCacheError::InvalidConfig("replica scheduler requires at least one backend"));
        }
        let env = environment.into();
        if env.is_empty() || env.len() > 32 {
            return Err(ReplicaCacheError::InvalidConfig("invalid scheduler environment token"));
        }
        let fair_gate = TenantFairShareGate::new(fair_cfg)?;
        let nodes =
            backends.into_iter().map(|backend| ManagedNode { backend, health: ReplicaHealthState::Active }).collect();
        Ok(Self { nodes: Arc::new(Mutex::new(nodes)), fair_gate, route_directory, environment: env, circuit_cooldown })
    }

    pub fn begin_drain(&self, node_id: &str) -> bool {
        let mut guard = self.nodes.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(node) = guard.iter_mut().find(|n| n.backend.node_id() == node_id) {
            node.health = ReplicaHealthState::Draining;
            true
        } else {
            false
        }
    }

    pub fn restore_active(&self, node_id: &str) -> bool {
        let mut guard = self.nodes.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(node) = guard.iter_mut().find(|n| n.backend.node_id() == node_id) {
            node.health = ReplicaHealthState::Active;
            true
        } else {
            false
        }
    }

    pub fn mark_unhealthy(&self, node_id: &str, reason: impl Into<String>) -> bool {
        let mut guard = self.nodes.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(node) = guard.iter_mut().find(|n| n.backend.node_id() == node_id) {
            node.health =
                ReplicaHealthState::Unhealthy { until: Instant::now() + self.circuit_cooldown, reason: reason.into() };
            true
        } else {
            false
        }
    }

    pub fn node_health(&self, node_id: &str) -> Option<ReplicaHealthState> {
        let guard = self.nodes.lock().unwrap_or_else(|p| p.into_inner());
        guard.iter().find(|n| n.backend.node_id() == node_id).map(|n| n.health.clone())
    }

    pub fn fairness_stats(&self) -> FairnessStatsSnapshot {
        self.fair_gate.stats()
    }

    pub fn affinity_order(&self, tenant_id: Uuid, repo_id: Uuid) -> Vec<String> {
        let now = Instant::now();
        let mut guard = self.nodes.lock().unwrap_or_else(|p| p.into_inner());
        let mut ranked: Vec<(String, Arc<dyn ReplicaBackend>)> = Vec::new();
        for node in guard.iter_mut() {
            if let ReplicaHealthState::Unhealthy { until, .. } = &node.health
                && *until <= now
            {
                node.health = ReplicaHealthState::Active;
            }
            if matches!(node.health, ReplicaHealthState::Active) && node.backend.is_accepting_traffic() {
                ranked.push((hrw_score(node.backend.node_id(), tenant_id, repo_id), Arc::clone(&node.backend)));
            }
        }
        ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.node_id().cmp(b.1.node_id())));
        ranked.into_iter().map(|(_, b)| b.node_id().to_owned()).collect()
    }

    pub async fn route_and_serve(
        &self,
        req: &ReplicaReadRequest,
        authorizer: &dyn LiveAuthorizer,
        deadline: Instant,
    ) -> Result<ScheduledServeOutcome, ReplicaCacheError> {
        let (permit, admission_wait_us) = self.fair_gate.acquire(req.tenant_id, deadline).await?;
        let mut candidates = self.select_candidates(req).await;
        if candidates.is_empty() {
            return Err(ReplicaCacheError::AllReplicasOverloaded);
        }

        let mut attempts = 0usize;
        let mut failover_used = false;
        let mut last_err = ReplicaCacheError::AllReplicasOverloaded;

        for backend in candidates.drain(..) {
            attempts = attempts.saturating_add(1);
            if attempts > 1 {
                failover_used = true;
            }
            let node_id = backend.node_id().to_owned();
            match backend.serve_replica_view(req, authorizer, deadline).await {
                Ok(guard) => {
                    self.record_advisory_hint(guard.view_key(), &node_id).await;
                    return Ok(ScheduledServeOutcome {
                        guard: guard.with_admission_permit(permit),
                        routed_node_id: node_id,
                        attempts,
                        failover_used,
                        admission_wait_us,
                    });
                }
                Err(err) if is_retryable_failover_error(&err) => {
                    if matches!(err, ReplicaCacheError::ReplicaUnhealthy(_)) {
                        self.mark_unhealthy(&node_id, err.to_string());
                    }
                    last_err = err;
                }
                Err(err) => return Err(err),
            }
        }

        if is_retryable_failover_error(&last_err) {
            Err(ReplicaCacheError::AllReplicasOverloaded)
        } else {
            Err(last_err)
        }
    }

    async fn select_candidates(&self, req: &ReplicaReadRequest) -> Vec<Arc<dyn ReplicaBackend>> {
        let preferred_id = self.read_advisory_hint(req).await;
        let now = Instant::now();
        let mut guard = self.nodes.lock().unwrap_or_else(|p| p.into_inner());
        let mut ranked: Vec<(bool, String, Arc<dyn ReplicaBackend>)> = Vec::new();
        for node in guard.iter_mut() {
            if let ReplicaHealthState::Unhealthy { until, .. } = &node.health
                && *until <= now
            {
                node.health = ReplicaHealthState::Active;
            }
            if matches!(node.health, ReplicaHealthState::Active) && node.backend.is_accepting_traffic() {
                let is_hinted = preferred_id.as_deref() == Some(node.backend.node_id());
                let score = hrw_score(node.backend.node_id(), req.tenant_id, req.repo_id);
                ranked.push((is_hinted, score, Arc::clone(&node.backend)));
            }
        }
        ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
        ranked.into_iter().map(|(_, _, b)| b).collect()
    }

    async fn read_advisory_hint(&self, req: &ReplicaReadRequest) -> Option<String> {
        let dir = self.route_directory.as_ref()?;
        let digest = req.known_membership_digest.as_deref()?;
        let key = route_hint_key(&self.environment, req.tenant_id, req.repo_id, digest).ok()?;
        let hint: RouteDirectoryHint = dir.get_json(&key).await?;
        if hint.schema_version != REPLICA_CACHE_SCHEMA
            || hint.tenant_id != req.tenant_id
            || hint.repo_id != req.repo_id
            || hint.membership_digest != digest
        {
            return None;
        }
        Some(hint.node_id)
    }

    async fn record_advisory_hint(&self, view_key: &super::types::ReplicaViewKey, node_id: &str) {
        let Some(dir) = self.route_directory.as_ref() else {
            return;
        };
        let Ok(key) =
            route_hint_key(&self.environment, view_key.tenant_id, view_key.repo_id, &view_key.membership_digest)
        else {
            return;
        };
        let hint = RouteDirectoryHint {
            schema_version: REPLICA_CACHE_SCHEMA,
            node_id: node_id.to_owned(),
            tenant_id: view_key.tenant_id,
            repo_id: view_key.repo_id,
            history_id: view_key.history_id,
            gate_revision: view_key.gate_revision,
            membership_digest: view_key.membership_digest.clone(),
        };
        dir.put_json(&key, &hint, None).await;
    }
}

fn route_hint_key(env: &str, tenant: Uuid, repo: Uuid, membership_digest: &str) -> anyhow::Result<CacheKey> {
    CacheKey::new(CacheKeyParts {
        environment: env,
        authority: "rubicon-replica",
        schema: REPLICA_CACHE_SCHEMA as u16,
        history_incarnation: Uuid::nil(),
        tenant,
        repo,
        kind: CacheKind::RouteDirectory,
        version: 1,
        discriminator: membership_digest,
    })
}

fn hrw_score(node_id: &str, tenant_id: Uuid, repo_id: Uuid) -> String {
    let mut hasher = Sha256::new();
    hasher.update(node_id.as_bytes());
    hasher.update(b"|");
    hasher.update(tenant_id.as_bytes());
    hasher.update(repo_id.as_bytes());
    hex::encode(hasher.finalize())
}
