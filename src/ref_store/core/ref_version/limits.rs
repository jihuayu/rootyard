//! Frozen component bounds and checked integer adapters for the C1a codec.
//!
//! These are the existing protocol bounds, not new limits: 128 refs per
//! operation and 8 new planned packs. Every integer that reaches the preimage
//! is converted explicitly; no `as` cast is used. The byte writer performs a
//! checked reserve for variable-length fields, so the preimage is bounded by
//! the component caps without inventing a separate encoded-size limit.
use super::contract::RefVersionCodecError;
use crate::ref_store::core::pack_commit::MAX_BATCH_NEW_PACKS;
use crate::ref_store::core::types::MAX_REFS_PER_COMMIT;

/// Existing per-commit ref batch bound.
pub(super) const MAX_OPERATION_REFS: usize = MAX_REFS_PER_COMMIT;
/// Existing per-commit new pack bound.
pub(super) const MAX_OPERATION_PACKS: usize = MAX_BATCH_NEW_PACKS;
/// Exactly one `.pack` and one `.idx` per planned pack.
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
