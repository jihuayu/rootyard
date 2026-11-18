//! Verifiable causal Git Smart-HTTP push streaming and pack dependency prover (#183).
//!
//! Coordinates bounded-memory Smart HTTP `receive-pack` command framing, isolated
//! `0700` quarantine pack ingestion, overlapped OpenDAL `BlobStore` staging and
//! read-back closure verification, stock-Git thin-pack delta/object/LFS/causal
//! ancestry proving over `#180` snapshots, and fail-closed Ref-CAS commitment for
//! both `RefCasStateMachine` (Raft) and `PgRefStoreCore` (PostgreSQL).

#[path = "push_causal_stream/closure_prove.rs"]
pub mod closure_prove;
#[path = "push_causal_stream/commit_gate.rs"]
pub mod commit_gate;
#[path = "push_causal_stream/git_proc.rs"]
mod git_proc;
#[path = "push_causal_stream/git_verify.rs"]
pub mod git_verify;
#[path = "push_causal_stream/lfs_verify.rs"]
mod lfs_verify;
#[path = "push_causal_stream/protocol.rs"]
pub mod protocol;
#[path = "push_causal_stream/quarantine.rs"]
pub mod quarantine;
#[path = "push_causal_stream/receipt.rs"]
pub mod receipt;
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
    PushExecutionInput, PushExecutionOutput, build_pg_commit_request, commit_push_on_pg, evaluate_push_auth_precheck,
    report_status_from_pg_receipt,
};
pub use protocol::{
    AdvertisementDecision, AdvertisementRequest, AdvertisementStrategy, ClientPushCapabilityProfile,
    DecodedReceiveStream, VisibleRefEntry, build_push_ref_advertisement, decode_receive_pack_stream,
    encode_receive_pack_report, encode_ref_advertisement,
};
pub use quarantine::{
    CapacityContractBlobCarrier, OperationHoldGuard, PushBlobCarrier, QuarantineArtifactSet, QuarantineSlot,
    QuarantineSweepRecord, UploadedQuarantinePack, ingest_pack_to_quarantine,
};
pub use receipt::{AcceptedRefProof, CausalPushProofReceipt, RejectedRefProof};
pub use sm_executor::StateMachinePushExecutor;
pub use types::{
    AuthorizedSnapshotState, BasePackRef, BranchPolicy, FaultInjectionHook, GitSubprocessLimits, LfsExpectedBlob,
    LfsPolicy, OperationTicket, PackPipelineMode, PushAuthContext, PushCausalError, PushStageTelemetry,
    PushedRefCommand, ReceiveCapabilities, StreamIngestLimits,
};
