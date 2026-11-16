//! Frozen component bounds and checked integer adapters for the causal
//! ref-version and pack-dependency contract (`docs/ref-version-pack-contract.md`).
//!
//! These are the existing protocol bounds plus the §2.4 dependency closure
//! bounds, not dynamically widenable limits. Every integer that reaches a
//! canonical preimage is converted explicitly; no `as` cast is used.
use super::contract::RefVersionCodecError;
use crate::ref_store::core::MAX_SNAPSHOT_REFS;
use crate::ref_store::core::pack_commit::{MAX_BATCH_NEW_PACKS, VERIFIER_MAX_PAIRS, VERIFIER_MAX_TOTAL_BYTES};
use crate::ref_store::core::types::MAX_REFS_PER_COMMIT;

/// Existing per-commit ref batch bound (`MAX_COMMIT_SET_REFS`).
pub const MAX_OPERATION_REFS: usize = MAX_REFS_PER_COMMIT;
/// Canonical alias matching §2.4 (`MAX_COMMIT_SET_REFS`).
pub const MAX_COMMIT_SET_REFS: usize = MAX_REFS_PER_COMMIT;
/// Existing per-commit new pack bound.
pub const MAX_OPERATION_PACKS: usize = MAX_BATCH_NEW_PACKS;
/// Existing verifier aggregate bound for planned/verified closure artifact bytes.
pub const MAX_OPERATION_PLANNED_BYTES: u64 = VERIFIER_MAX_TOTAL_BYTES;
/// Maximum direct OBJECT edges per version (§2.4).
pub const MAX_OBJECT_DEPS_PER_VERSION: usize = 8;
/// Maximum deduplicated OBJECT edges in one dependency closure (§2.4).
pub const MAX_OBJECT_DEPS_TOTAL: usize = 64;
/// Maximum longest OBJECT dependency path depth (§2.4).
pub const MAX_OBJECT_DEP_DEPTH: usize = 16;
/// Maximum unique pack pairs in one closure (§2.4, matching `VERIFIER_MAX_PAIRS`).
pub const MAX_CLOSURE_PACKS: usize = VERIFIER_MAX_PAIRS;
/// Maximum closure artifacts (exactly 2 per pack, §2.4).
pub const MAX_CLOSURE_ARTIFACTS: usize = MAX_CLOSURE_PACKS * ARTIFACTS_PER_PACK as usize;
/// Maximum verified closure pack+idx bytes (§2.4).
pub const MAX_CLOSURE_VERIFIED_BYTES: u64 = VERIFIER_MAX_TOTAL_BYTES;
/// Maximum version refs in a strong repository snapshot (§2.4).
pub const MAX_VERSION_REFS: usize = MAX_SNAPSHOT_REFS;
/// Canonical ASCII reason code ceiling (§2.5.2).
pub const MAX_REASON_BYTES: usize = 64;
/// Maximum raw canonical terminal bytes `T` accepted by the v2 ref-version codec.
pub const MAX_VERSION_TERMINAL_BYTES: usize = 64 * 1024;
/// Exactly one `.pack` and one `.idx` per planned/registered pack.
pub(super) const ARTIFACTS_PER_PACK: u32 = 2;

pub(super) fn positive_u64(value: i64, field: &'static str) -> Result<u64, RefVersionCodecError> {
    if value < 0 {
        return Err(RefVersionCodecError::NegativeCounter { field });
    }
    if value == 0 {
        return Err(RefVersionCodecError::ZeroCounter { field });
    }
    u64::try_from(value).map_err(|_| RefVersionCodecError::NegativeCounter { field })
}

pub(super) fn nonnegative_u64(value: i64, field: &'static str) -> Result<u64, RefVersionCodecError> {
    if value < 0 {
        return Err(RefVersionCodecError::NegativeCounter { field });
    }
    u64::try_from(value).map_err(|_| RefVersionCodecError::NegativeCounter { field })
}

pub(super) fn count_u32(value: usize, field: &'static str) -> Result<u32, RefVersionCodecError> {
    u32::try_from(value).map_err(|_| RefVersionCodecError::LengthOverflow { field })
}

pub(super) fn length_u64(value: usize, field: &'static str) -> Result<u64, RefVersionCodecError> {
    u64::try_from(value).map_err(|_| RefVersionCodecError::LengthOverflow { field })
}
