//! Verifiable causal ref-version and immutable pack-dependency contract
//! (`docs/ref-version-pack-contract.md` §2-§5, §8).
//!
//! Pure domain modules: canonical operation/version/pack-set/record/commit-set/
//! terminal codecs, closed §2.5.2 reason table, bounded dependency DAG closure
//! verifier, explicit read-mode / session-bound evaluator and retention protector
//! matrix. No PostgreSQL DDL, HTTP routes, background GC or Raft apply runtime
//! lives in this module.
mod closure;
mod commit_set;
mod contract;
mod digest;
mod limits;
pub mod pack_cover;
mod pack_set;
mod read_mode;
mod reasons;
mod record;
mod retention;
mod terminal;
#[cfg(test)]
mod vector_tests;

pub use closure::{
    CausalClosureError, CausalVersionLookup, CausalVersionNode, ClosureDigest, VerifiedDependencyClosure, VersionGraph,
    VersionLookupEntry, select_verifier_dependencies, verify_dependency_closure,
};
pub use commit_set::{CommitSetHead, CommitSetId, CommitSetInput, CommitSetVersionEntry, compute_commit_set_id};
pub use contract::{
    AuthorityKind, BaseRequestSelector, OperationDigest, OperationDigestInput, RefVersionCodecError, RefVersionIntent,
    RefVersionKind, RefVersionRealm, VersionId,
};
pub use digest::{derive_candidate_version_id, operation_digest};
pub use limits::{
    MAX_CLOSURE_ARTIFACTS, MAX_CLOSURE_PACKS, MAX_CLOSURE_VERIFIED_BYTES, MAX_COMMIT_SET_REFS, MAX_OBJECT_DEP_DEPTH,
    MAX_OBJECT_DEPS_PER_VERSION, MAX_OBJECT_DEPS_TOTAL, MAX_OPERATION_PACKS, MAX_OPERATION_PLANNED_BYTES,
    MAX_OPERATION_REFS, MAX_REASON_BYTES, MAX_VERSION_REFS, MAX_VERSION_TERMINAL_BYTES,
};
pub use pack_set::{PackSetDigest, PackSetEntry, VerifiedClosurePack, compute_pack_set_digest};
pub use read_mode::{
    CausalReadError, CausalReadOptions, CausalReadReceipt, ReadConsumer, ReadModeKind, ReadTarget, StrongSnapshotState,
    verify_causal_read,
};
pub use reasons::{CausalRejectCode, is_valid_reason_syntax};
pub use record::{
    BaseCoherenceError, RecordDigest, RefHead, VersionRecord, VersionRecordInput, ensure_immutable_record,
    verify_base_coherence,
};
pub use retention::{RetentionDecision, RetentionProtector, evaluate_pack_retention};
pub use terminal::{
    EncodedTerminal, TerminalDigest, VersionResultEntry, VersionResultOutcome, VersionTerminalInput,
    VersionTerminalKind, encode_terminal, encode_terminal_with_commit_set,
};
