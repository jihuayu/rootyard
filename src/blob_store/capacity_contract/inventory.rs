//! Structured multi-layer limit inventory distinguishing repository facts,
//! enforced streaming-engine bounds, and measured benchmark baselines.

use serde::{Deserialize, Serialize};

use super::limits::PandoCapacityContract;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractFactStatus {
    CurrentCodeFact,
    EnforcedBoundedEngine,
    MeasuredBenchmarkBaseline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayerLimitFact {
    pub layer: String,
    pub metric: String,
    pub value: u64,
    pub unit: String,
    pub status: ContractFactStatus,
    pub source_ref: String,
    pub note: String,
}

fn fact(
    layer: &str,
    metric: &str,
    value: u64,
    unit: &str,
    status: ContractFactStatus,
    source_ref: &str,
    note: &str,
) -> LayerLimitFact {
    LayerLimitFact {
        layer: layer.to_owned(),
        metric: metric.to_owned(),
        value,
        unit: unit.to_owned(),
        status,
        source_ref: source_ref.to_owned(),
        note: note.to_owned(),
    }
}

pub fn build_fact_inventory(contract: &PandoCapacityContract) -> Vec<LayerLimitFact> {
    vec![
        fact(
            "gateway",
            "max_request_bytes",
            contract.gateway.max_request_bytes,
            "bytes",
            ContractFactStatus::CurrentCodeFact,
            "src/config.rs",
            "Smart HTTP wire/decoded push ceiling; never guarantees verifier acceptance",
        ),
        fact(
            "gateway",
            "max_new_packs_per_push",
            contract.gateway.max_new_packs_per_push as u64,
            "packs",
            ContractFactStatus::CurrentCodeFact,
            "src/blob_git_gateway/receive.rs",
            "Per-push pack pair ceiling matching MAX_BATCH_NEW_PACKS",
        ),
        fact(
            "metadata_ledger",
            "repo_max_logical_bytes",
            contract.metadata_ledger.repo_max_logical_bytes as u64,
            "bytes",
            ContractFactStatus::CurrentCodeFact,
            "src/ref_store/core/pack_commit/contract.rs",
            "Retained DB row/body metadata budget (8 MiB), NOT Blob repository byte capacity",
        ),
        fact(
            "metadata_ledger",
            "repo_max_active_memberships",
            contract.metadata_ledger.repo_max_active_memberships as u64,
            "packs",
            ContractFactStatus::CurrentCodeFact,
            "src/ref_store/core/pack_commit/contract.rs",
            "Uncompacted active serving membership ceiling before compaction rotates frontier",
        ),
        fact(
            "blob_store",
            "max_object_bytes",
            contract.blob.max_object_bytes,
            "bytes",
            ContractFactStatus::CurrentCodeFact,
            "src/blob_store/types.rs",
            "Blob locator object ceiling (1 TiB), independent of 8 MiB metadata ledger budget",
        ),
        fact(
            "verifier",
            "max_total_bytes_per_window",
            contract.verifier.max_total_bytes_per_window,
            "bytes",
            ContractFactStatus::CurrentCodeFact,
            "src/ref_store/core/pack_commit/contract.rs",
            "Single-window verified pack+idx byte ceiling (64 MiB)",
        ),
        fact(
            "verifier",
            "max_objects_per_window",
            contract.verifier.max_objects_per_window,
            "objects",
            ContractFactStatus::CurrentCodeFact,
            "src/ref_store/core/pack_commit/contract.rs",
            "Single-window total object count ceiling across active window pairs",
        ),
        fact(
            "verifier",
            "view_max_logical_bytes",
            contract.verifier.view_max_logical_bytes,
            "bytes",
            ContractFactStatus::CurrentCodeFact,
            "src/ref_store/core/pack_commit/contract.rs",
            "Materialized disposable scratch workspace limit (160 MiB)",
        ),
        fact(
            "verifier",
            "git_nofile",
            contract.verifier.git_nofile,
            "fds",
            ContractFactStatus::CurrentCodeFact,
            "src/ref_store/core/pack_commit/contract.rs",
            "Native Git RLIMIT_NOFILE bounding simultaneous open pack/idx pairs",
        ),
        fact(
            "streaming_engine",
            "compact_trigger_packs",
            contract.streaming.compact_trigger_packs as u64,
            "packs",
            ContractFactStatus::EnforcedBoundedEngine,
            "src/blob_store/capacity_contract/streaming_growth.rs",
            "Triggers no-delete compaction before frontier reaches 16-pack limit",
        ),
        fact(
            "streaming_engine",
            "max_queue_waiters",
            contract.streaming.max_queue_waiters as u64,
            "requests",
            ContractFactStatus::EnforcedBoundedEngine,
            "src/blob_store/capacity_contract/admission.rs",
            "Bounded admission queue depth; excess requests fail closed with QueueFull",
        ),
    ]
}
