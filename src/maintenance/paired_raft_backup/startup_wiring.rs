//! Production serving startup wiring for the durable freeze guard and the restored
//! incarnation admission guard (#153).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use anyhow::anyhow;
use deadpool_postgres::Pool;
use serde::Deserialize;
use uuid::Uuid;

use super::admission_guard::IncarnationAdmissionGuard;
use super::mtls_raft::{MtlsLiveRaftBackend, MtlsRaftClusterConfig};
use super::peer_attestation::{PeerAttestationConfig, PeerAttestationDaemon};
use super::pg_cutpoint::pg_err;
use super::pg_freeze_settings::{read_pg_database_freeze_marker, read_pg_database_read_only};
use super::production_runtime::PairedProductionRuntimeGuard;
use super::types::{NewIncarnationAuthority, PairedBackupError};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServingClusterJson {
    group_id: i64,
    local_node_id: u64,
    voter_endpoints: BTreeMap<u64, String>,
    attestor_endpoints: BTreeMap<u64, String>,
    ca_cert_pem: PathBuf,
    client_cert_pem: PathBuf,
    client_key_pem: PathBuf,
    #[serde(default = "default_rpc_timeout_ms")]
    rpc_timeout_ms: u64,
}

fn default_rpc_timeout_ms() -> u64 {
    4_000
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeAttestorStartupJson {
    node_id: u64,
    group_id: i64,
    data_dir: PathBuf,
    raft_node_addr: String,
    #[serde(default)]
    bind_addr: Option<String>,
    ca_cert_pem: PathBuf,
    node_cert_pem: PathBuf,
    node_key_pem: PathBuf,
    raft_client_cert_pem: PathBuf,
    raft_client_key_pem: PathBuf,
    #[serde(default)]
    allowed_caller_cert_sha256s: Vec<String>,
    #[serde(default = "default_rpc_timeout_ms")]
    rpc_timeout_ms: u64,
}

fn peer_attestation_slot() -> &'static Mutex<Option<PeerAttestationDaemon>> {
    static SLOT: OnceLock<Mutex<Option<PeerAttestationDaemon>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

pub fn installed_peer_attestation_daemon_addr() -> Option<String> {
    let slot = peer_attestation_slot().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    slot.as_ref().map(|d| d.addr().to_owned())
}

pub fn shutdown_installed_peer_attestation_daemon() {
    let mut slot = peer_attestation_slot().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(daemon) = slot.take() {
        daemon.shutdown();
    }
}

fn production_guard_slot() -> &'static RwLock<Option<PairedProductionRuntimeGuard>> {
    static SLOT: OnceLock<RwLock<Option<PairedProductionRuntimeGuard>>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(None))
}

pub fn installed_production_runtime_guard() -> Option<PairedProductionRuntimeGuard> {
    production_guard_slot().read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
}

pub fn set_installed_production_runtime_guard(guard: Option<PairedProductionRuntimeGuard>) {
    *production_guard_slot().write().unwrap_or_else(|poisoned| poisoned.into_inner()) = guard;
}

struct PairedWriteBinding {
    serialize: tokio::sync::Mutex<()>,
    raft: Arc<Mutex<MtlsLiveRaftBackend>>,
}

type PairedWriteBindings = RwLock<BTreeMap<String, Arc<PairedWriteBinding>>>;

fn paired_write_raft_map() -> &'static PairedWriteBindings {
    static MAP: OnceLock<PairedWriteBindings> = OnceLock::new();
    MAP.get_or_init(|| RwLock::new(BTreeMap::new()))
}

/// Scope guard that removes one database-keyed paired write binding again on drop.
pub struct PairedWriteRaftScopeGuard {
    db_name: String,
}

impl Drop for PairedWriteRaftScopeGuard {
    fn drop(&mut self) {
        paired_write_raft_map().write().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(&self.db_name);
    }
}

fn database_name_from_url(url: &str) -> Option<String> {
    if let Ok(parsed) = url.parse::<tokio_postgres::Config>()
        && let Some(name) = parsed.get_dbname()
    {
        return Some(name.to_owned());
    }
    let tail = url.rsplit_once('/')?.1.split(['?', '#']).next().unwrap_or_default();
    (!tail.is_empty()).then(|| tail.to_owned())
}

/// Bind this process's live mTLS Raft handle to the *named* PostgreSQL database, so a normal
/// Smart-HTTP push mirrors itself into the exact consensus cluster that owns that database while
/// concurrent fixtures running against other databases can never collide.
pub fn install_paired_write_raft_binding(
    raft: Arc<Mutex<MtlsLiveRaftBackend>>,
    target_database_url: impl AsRef<str>,
) -> Result<PairedWriteRaftScopeGuard, PairedBackupError> {
    let db_name = database_name_from_url(target_database_url.as_ref())
        .ok_or(PairedBackupError::InvalidArgument("paired write raft binding requires a target database name"))?;
    let bound = Arc::new(PairedWriteBinding { serialize: tokio::sync::Mutex::new(()), raft });
    paired_write_raft_map().write().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(db_name.clone(), bound);
    Ok(PairedWriteRaftScopeGuard { db_name })
}

fn bound_paired_write_binding(db_name: &str) -> Option<Arc<PairedWriteBinding>> {
    paired_write_raft_map().read().unwrap_or_else(|poisoned| poisoned.into_inner()).get(db_name).cloned()
}

/// Fail closed when a durable freeze is latched, otherwise install the restored
/// incarnation guard derived from PostgreSQL authority state.
pub async fn install_production_serving_guard(
    barrier_client: &tokio_postgres::Client,
) -> Result<Option<PairedProductionRuntimeGuard>, PairedBackupError> {
    let attestor_json = std::env::var("ROOTYARD_PAIRED_RAFT_ATTESTOR_JSON").ok();
    install_production_serving_guard_with_attestor(barrier_client, attestor_json.as_deref()).await
}

/// Co-located node startup: optionally spawn the voter's mTLS Ed25519 attestor sidecar
/// (`ROOTYARD_PAIRED_RAFT_ATTESTOR_JSON`) before connecting the live mTLS Raft backend.
pub async fn install_production_serving_guard_with_attestor(
    barrier_client: &tokio_postgres::Client,
    attestor_json: Option<&str>,
) -> Result<Option<PairedProductionRuntimeGuard>, PairedBackupError> {
    if read_pg_database_freeze_marker(barrier_client).await?.is_some()
        || read_pg_database_read_only(barrier_client).await?
    {
        return Err(PairedBackupError::FreezeNotHeld(
            "paired backup/restore freeze active on database; refusing serving startup",
        ));
    }
    let tables: bool = barrier_client
        .query_one(
            "SELECT to_regclass('public.cluster_authority') IS NOT NULL \
                    AND to_regclass('public.pando_storage_authorities') IS NOT NULL",
            &[],
        )
        .await
        .map_err(pg_err)?
        .get(0);
    if !tables {
        set_installed_production_runtime_guard(None);
        return Ok(None);
    }
    let cluster_inc: Uuid = barrier_client
        .query_one("SELECT incarnation FROM public.cluster_authority WHERE singleton = true", &[])
        .await
        .map_err(pg_err)?
        .get(0);
    let storage = barrier_client
        .query_one(
            "SELECT authority_id, generation, restore_generation, authority_epoch, remote_delete_fenced \
             FROM public.pando_storage_authorities WHERE singleton = true",
            &[],
        )
        .await
        .map_err(pg_err)?;
    let auth_id: Uuid = storage.get(0);
    let generation: i64 = storage.get(1);
    let restore_gen: i64 = storage.get(2);
    let storage_auth_epoch: i64 = storage.get(3);
    let _remote_delete_fenced: bool = storage.get(4);
    let open_floor: i64 = barrier_client
        .query_one(
            "SELECT COALESCE((SELECT max(version) FROM public.ref_store_decision_scopes WHERE state = 'OPEN'), 1)::bigint",
            &[],
        )
        .await
        .map_err(pg_err)?
        .get(0);
    let has_gates: bool = barrier_client
        .query_one("SELECT to_regclass('public.ref_store_core_gates') IS NOT NULL", &[])
        .await
        .map_err(pg_err)?
        .get(0);
    let gate = if has_gates {
        barrier_client
            .query_opt(
                "SELECT history_incarnation, authority_epoch, group_epoch FROM public.ref_store_core_gates \
                 ORDER BY repository_id LIMIT 1",
                &[],
            )
            .await
            .map_err(pg_err)?
    } else {
        None
    };
    if let Some(raw) = attestor_json.filter(|raw| !raw.trim().is_empty()) {
        let parsed: NodeAttestorStartupJson = serde_json::from_str(raw).map_err(|_| {
            PairedBackupError::InvalidArgument("invalid ROOTYARD_PAIRED_RAFT_ATTESTOR_JSON configuration")
        })?;
        shutdown_installed_peer_attestation_daemon();
        let daemon = PeerAttestationDaemon::spawn(PeerAttestationConfig {
            node_id: parsed.node_id,
            group_id: parsed.group_id,
            data_dir: parsed.data_dir,
            raft_node_addr: parsed.raft_node_addr,
            bind_addr: parsed.bind_addr,
            ca_cert_pem: parsed.ca_cert_pem,
            node_cert_pem: parsed.node_cert_pem,
            node_key_pem: parsed.node_key_pem,
            raft_client_cert_pem: parsed.raft_client_cert_pem,
            raft_client_key_pem: parsed.raft_client_key_pem,
            allowed_caller_cert_sha256s: parsed.allowed_caller_cert_sha256s,
            rpc_timeout: Duration::from_millis(parsed.rpc_timeout_ms.max(1)),
        })?;
        *peer_attestation_slot().lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(daemon);
    }
    if let Ok(raw) = std::env::var("ROOTYARD_PAIRED_RAFT_CLUSTER_JSON")
        && !raw.trim().is_empty()
    {
        let parsed: ServingClusterJson = serde_json::from_str(&raw).map_err(|_| {
            PairedBackupError::InvalidArgument("invalid ROOTYARD_PAIRED_RAFT_CLUSTER_JSON configuration")
        })?;
        let backend = MtlsLiveRaftBackend::connect(MtlsRaftClusterConfig {
            group_id: parsed.group_id,
            local_node_id: parsed.local_node_id,
            voter_endpoints: parsed.voter_endpoints,
            attestor_endpoints: parsed.attestor_endpoints,
            ca_cert_pem: parsed.ca_cert_pem,
            client_cert_pem: parsed.client_cert_pem,
            client_key_pem: parsed.client_key_pem,
            rpc_timeout: Duration::from_millis(parsed.rpc_timeout_ms.max(1)),
        })?;
        if let Some(record) = backend.read_freeze_record()?
            && record.frozen
        {
            return Err(PairedBackupError::FreezeNotHeld(
                "3-voter mTLS Raft freeze record active; refusing serving startup",
            ));
        }
        if let Some(record) = backend.read_incarnation_record()?
            && (record.new_cluster_incarnation != cluster_inc || record.new_storage_authority_id != auth_id)
        {
            return Err(PairedBackupError::StaleIncarnation {
                field: "cluster_incarnation",
                expected: cluster_inc.to_string(),
                got: record.new_cluster_incarnation.to_string(),
            });
        }
        let db_name: String = barrier_client.query_one("SELECT current_database()", &[]).await.map_err(pg_err)?.get(0);
        let bound = Arc::new(PairedWriteBinding {
            serialize: tokio::sync::Mutex::new(()),
            raft: Arc::new(Mutex::new(backend)),
        });
        paired_write_raft_map().write().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(db_name, bound);
    }
    let (new_history_incarnation, new_authority_epoch, new_group_epoch) =
        gate.map(|row| (row.get(0), row.get(1), row.get(2))).unwrap_or((cluster_inc, storage_auth_epoch.max(1), 1));
    let live = NewIncarnationAuthority {
        new_cluster_incarnation: cluster_inc,
        new_storage_authority_id: auth_id,
        new_storage_generation: generation,
        new_history_incarnation,
        new_authority_epoch,
        new_group_epoch,
        new_authz_floor: open_floor.max(1),
        new_deleter_epoch: u64::try_from(restore_gen.max(1)).unwrap_or(1),
        fenced_prior_incarnations: BTreeSet::new(),
        fenced_pre_backup_decision_ids: BTreeSet::new(),
    };
    let guard = PairedProductionRuntimeGuard::from_live_authority(IncarnationAdmissionGuard { live }, false);
    set_installed_production_runtime_guard(Some(guard.clone()));
    Ok(Some(guard))
}

/// Latch the installed guard frozen and drain serving as soon as any durable freeze
/// marker or database read-only fence is observed.
pub async fn ensure_serving_database_unfrozen(barrier_client: &tokio_postgres::Client) -> Result<(), anyhow::Error> {
    if read_pg_database_freeze_marker(barrier_client).await.map_err(|e| anyhow!("{e}"))?.is_some()
        || read_pg_database_read_only(barrier_client).await.map_err(|e| anyhow!("{e}"))?
    {
        if let Some(g) = installed_production_runtime_guard() {
            set_installed_production_runtime_guard(Some(PairedProductionRuntimeGuard::from_live_authority(
                g.admission().clone(),
                true,
            )));
        }
        return Err(anyhow!("paired backup freeze latched; draining serving instance"));
    }
    Ok(())
}

/// Serialize one PostgreSQL snapshot read with its blocking Raft CAS-delta apply per database, so a
/// later read can never overtake an earlier apply.
async fn run_serialized_pg_to_raft_step<T, ReadFut, ReadFn, ApplyFn>(
    serialize: &tokio::sync::Mutex<()>,
    read_pg: ReadFn,
    apply_raft: ApplyFn,
) -> Result<(), PairedBackupError>
where
    T: Send + 'static,
    ReadFn: FnOnce() -> ReadFut,
    ReadFut: std::future::Future<Output = Result<T, PairedBackupError>>,
    ApplyFn: FnOnce(T) -> Result<(), PairedBackupError> + Send + 'static,
{
    let _serial_guard = serialize.lock().await;
    let pg_snapshot = read_pg().await?;
    tokio::task::spawn_blocking(move || apply_raft(pg_snapshot))
        .await
        .map_err(|e| PairedBackupError::StateMachine(format!("paired Raft serialized task failed: {e}")))?
}

/// Resolve the caller database without holding a pooled client while waiting for its serialize lock.
async fn lookup_paired_write_binding(pool: &Pool) -> Result<Option<Arc<PairedWriteBinding>>, PairedBackupError> {
    if paired_write_raft_map().read().unwrap_or_else(|poisoned| poisoned.into_inner()).is_empty() {
        return Ok(None);
    }
    let client = pool.get().await.map_err(|e| PairedBackupError::Postgres(e.to_string()))?;
    let db_name: String = client.query_one("SELECT current_database()", &[]).await.map_err(pg_err)?.get(0);
    drop(client);
    Ok(bound_paired_write_binding(&db_name))
}

/// Refuse a normal paired write while PostgreSQL *or* the database-bound live Raft cluster is frozen.
pub async fn check_paired_write_unfrozen(pool: &Pool) -> Result<(), PairedBackupError> {
    let Some(binding) = lookup_paired_write_binding(pool).await? else {
        return Ok(());
    };
    let raft = binding.raft.clone();
    run_serialized_pg_to_raft_step(
        &binding.serialize,
        || async {
            let client = pool.get().await.map_err(|e| PairedBackupError::Postgres(e.to_string()))?;
            let frozen = read_pg_database_freeze_marker(&**client).await?.is_some()
                || read_pg_database_read_only(&**client).await?;
            drop(client);
            if frozen {
                return Err(PairedBackupError::FreezeNotHeld("paired write refused while PostgreSQL freeze is active"));
            }
            Ok(())
        },
        move |()| {
            let guard = raft.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(record) = guard.read_freeze_record()?
                && record.frozen
            {
                return Err(PairedBackupError::FreezeNotHeld("paired write refused while Raft freeze is active"));
            }
            Ok(())
        },
    )
    .await
}

/// Mirror a committed gateway push into the database-bound live mTLS Raft cluster as an exact CAS
/// delta, so the ordinary Smart-HTTP write path — never a test fixture — owns the consensus floor.
pub async fn mirror_gateway_push_to_paired_raft(pool: &Pool, repository_id: Uuid) -> Result<(), PairedBackupError> {
    let Some(binding) = lookup_paired_write_binding(pool).await? else {
        return Ok(());
    };
    let raft = binding.raft.clone();
    run_serialized_pg_to_raft_step(
        &binding.serialize,
        || async {
            let client = pool.get().await.map_err(|e| PairedBackupError::Postgres(e.to_string()))?;
            let frozen = read_pg_database_freeze_marker(&**client).await?.is_some()
                || read_pg_database_read_only(&**client).await?;
            if frozen {
                return Err(PairedBackupError::FreezeNotHeld("paired write refused while PostgreSQL freeze is active"));
            }
            let floor = super::format30_pg_raft_sync::read_pg_repo_access_floor(&**client, repository_id).await?;
            let (spec, head_ref, pg_refs) =
                super::format30_pg_raft_sync::read_pg_repo_state(&**client, repository_id).await?;
            drop(client);
            Ok((spec, head_ref, pg_refs, floor))
        },
        move |(spec, head_ref, pg_refs, floor)| {
            let mut guard = raft.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(record) = guard.read_freeze_record()?
                && record.frozen
            {
                return Err(PairedBackupError::FreezeNotHeld("paired write refused while Raft freeze is active"));
            }
            super::format30_pg_raft_sync::apply_pg_repo_state_to_raft(&mut guard, &spec, &head_ref, &pg_refs, floor)
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serialized_pg_to_raft_step_prevents_out_of_order_read_before_apply() {
        let serialize = Arc::new(tokio::sync::Mutex::new(()));
        let events = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        let task1_in_apply = Arc::new(tokio::sync::Notify::new());
        let task1 = {
            let (serialize, task1_in_apply) = (serialize.clone(), task1_in_apply.clone());
            let (read_events, apply_events) = (events.clone(), events.clone());
            async move {
                run_serialized_pg_to_raft_step(
                    &serialize,
                    || async move {
                        read_events.lock().unwrap().push("read-1");
                        Ok(())
                    },
                    move |()| {
                        task1_in_apply.notify_one();
                        std::thread::sleep(Duration::from_millis(40));
                        apply_events.lock().unwrap().push("apply-1");
                        Ok(())
                    },
                )
                .await
            }
        };
        let task2 = {
            let (serialize, task1_in_apply) = (serialize.clone(), task1_in_apply.clone());
            let (read_events, apply_events) = (events.clone(), events.clone());
            async move {
                task1_in_apply.notified().await;
                run_serialized_pg_to_raft_step(
                    &serialize,
                    || async move {
                        read_events.lock().unwrap().push("read-2");
                        Ok(())
                    },
                    move |()| {
                        apply_events.lock().unwrap().push("apply-2");
                        Ok(())
                    },
                )
                .await
            }
        };
        let (first, second) = tokio::join!(task1, task2);
        first.expect("task1");
        second.expect("task2");
        assert_eq!(*events.lock().unwrap(), vec!["read-1", "apply-1", "read-2", "apply-2"]);
    }
}
