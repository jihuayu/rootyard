//! Verifiable causal Git Smart-HTTP push streaming and pack dependency prover (#183).
//!
//! Coordinates shared-deadline Smart HTTP `receive-pack` pkt-line + pack streaming,
//! isolated `0700` quarantine pack ingestion, overlapped OpenDAL `BlobStore` staging and
//! read-back closure verification, recoverable partial/unknown upload reclaim ledgers,
//! stock-Git thin-pack delta/object/LFS/causal ancestry proving over `#180` snapshots,
//! and scoped-decision + durable-hold Ref-CAS commitment across Raft and PostgreSQL.

#[path = "push_causal_stream/closure_prove.rs"]
pub mod closure_prove;
#[path = "push_causal_stream/commit_gate.rs"]
pub mod commit_gate;
#[path = "push_causal_stream/gateway_bridge.rs"]
pub mod gateway_bridge;
#[path = "push_causal_stream/gateway_stream.rs"]
pub mod gateway_stream;
#[path = "push_causal_stream/git_proc.rs"]
mod git_proc;
#[path = "push_causal_stream/git_verify.rs"]
pub mod git_verify;
#[path = "push_causal_stream/lfs_verify.rs"]
mod lfs_verify;
#[path = "push_causal_stream/pg_producer.rs"]
pub mod pg_producer;
#[path = "push_causal_stream/pg_producer_plan.rs"]
mod pg_producer_plan;
#[path = "push_causal_stream/protocol.rs"]
pub mod protocol;
#[path = "push_causal_stream/quarantine.rs"]
pub mod quarantine;
#[path = "push_causal_stream/receipt.rs"]
pub mod receipt;
#[path = "push_causal_stream/reclaim.rs"]
pub mod reclaim;
#[path = "push_causal_stream/sm_commands.rs"]
mod sm_commands;
#[path = "push_causal_stream/sm_executor.rs"]
pub mod sm_executor;
#[path = "push_causal_stream/types.rs"]
pub mod types;

#[cfg(test)]
#[path = "push_causal_stream/unit_tests.rs"]
mod unit_tests;

pub use closure_prove::{prove_streaming_push, verify_base_packs_and_dependencies};
pub use commit_gate::{
    PgScopedPushOutcome, PgScopedPushParams, PushExecutionInput, PushExecutionOutput, build_pg_commit_request,
    commit_push_on_pg, evaluate_push_auth_precheck, report_status_from_pg_receipt, report_status_from_terminal_refs,
};
pub use gateway_bridge::{
    GatewayClosureContext, GatewayPairSummary, GatewayReceiptArgs, finalize_gateway_receipt,
    gateway_reclaim_ledger_dir_for_scratch, open_gateway_reclaim_ledger, recent_gateway_push_receipt,
    record_gateway_reclaim_failure, record_gateway_staging_inflight, verify_gateway_authority_closure,
};
pub use gateway_stream::spool_receive_stream_shared_deadline;
pub use protocol::{
    AdvertisementDecision, AdvertisementRequest, AdvertisementStrategy, ClientPushCapabilityProfile,
    DecodedReceiveStream, VisibleRefEntry, build_push_ref_advertisement, decode_receive_pack_stream,
    encode_receive_pack_report, encode_ref_advertisement,
};
pub use quarantine::{
    CapacityContractBlobCarrier, OperationHoldGuard, PushBlobCarrier, QuarantineArtifactSet, QuarantineSlot,
    QuarantineSweepRecord, UploadedQuarantinePack, ingest_pack_to_quarantine,
};
pub use receipt::{AcceptedRefProof, CausalPushProofReceipt, RejectedRefProof, split_terminal_subset};
pub use reclaim::{BlobUploadReclaimRecord, QuarantineReclaimLedger, StagingUploadIntent, UploadReclaimState};
pub use sm_executor::{CommitBundleCtx, StateMachinePushExecutor};
pub use types::{
    AuthorizedSnapshotState, BasePackRef, BranchPolicy, FaultInjectionHook, GitSubprocessLimits, LfsExpectedBlob,
    LfsPolicy, OperationTicket, PackPipelineMode, PushAuthContext, PushCausalError, PushStageTelemetry,
    PushedRefCommand, ReceiveCapabilities, StreamIngestLimits,
};
