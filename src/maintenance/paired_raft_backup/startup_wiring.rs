//! Production serving startup wiring for the durable freeze guard and the restored
//! incarnation admission guard (#153).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::Duration;

use anyhow::anyhow;
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
