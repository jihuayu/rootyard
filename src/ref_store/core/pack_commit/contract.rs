//! Bounded values, frozen limits and gate-mode vocabulary for the A4a
//! pack-verified commit slice.
//!
//! Everything in this module is pure: no IO, no PostgreSQL, no Git. The numbers
//! below are logical budgets for retained rows and ACK bodies, **not** database
//! disk/WAL bounds. Every one of them is a fixed literal so a caller cannot
//! widen a bound through configuration, and every arithmetic use goes through a
//! checked helper.
use crate::ref_store::contract::RefStoreError;

/// Planned new packs in one commit (each pack is exactly one pack + one idx).
pub const MAX_BATCH_NEW_PACKS: usize = 8;
/// Artifacts per registered pack: the `.pack` and its `.idx`, nothing else.
pub const ARTIFACTS_PER_PACK: usize = 2;
/// Active memberships at capture and after commit.
pub const MAX_ACTIVE_MEMBERSHIPS: i64 = 16;
/// Complete ref capture bound; an overflow is a typed refusal, never truncation.
pub const MAX_CAPTURE_REFS: i64 = 4096;
/// Active packs observed during capture.
pub const MAX_CAPTURE_ACTIVE_PACKS: i64 = 16;
/// The unchanged migration-139/140 per-commit ref batch bound.
pub const MAX_PLAN_REFS: usize = 128;
/// Widest object id string this slice can ever store (SHA-256 hex).
pub const MAX_OID_HEX: usize = 64;
/// Lowercase SHA-256 hex length.
pub const SHA256_HEX: usize = 64;
/// Fixed per-receipt accounting overhead (ids, tags, field separators).
pub const RECEIPT_OVERHEAD_BYTES: i64 = 256;

// Retained admission budgets. Tenant budgets are exactly four repository
// budgets, matching the A2/A3 shape of this component.
pub const REPO_MAX_REGISTRATIONS: i64 = 128;
pub const REPO_MAX_ARTIFACTS: i64 = 256;
pub const REPO_MAX_MEMBERSHIPS: i64 = 16;
pub const REPO_MAX_LOGICAL_BYTES: i64 = 8 * 1024 * 1024;
pub const REPO_MAX_RECEIPTS: i64 = 2048;
pub const TENANT_MAX_REGISTRATIONS: i64 = 4 * REPO_MAX_REGISTRATIONS;
pub const TENANT_MAX_ARTIFACTS: i64 = 4 * REPO_MAX_ARTIFACTS;
pub const TENANT_MAX_MEMBERSHIPS: i64 = 4 * REPO_MAX_MEMBERSHIPS;
pub const TENANT_MAX_LOGICAL_BYTES: i64 = 4 * REPO_MAX_LOGICAL_BYTES;
pub const TENANT_MAX_RECEIPTS: i64 = 4 * REPO_MAX_RECEIPTS;

/// Individual canonical ACK / registration body bound (also the migration-138
/// terminal body bound this slice must fit inside).
pub const MAX_ACK_BODY_BYTES: usize = 64 * 1024;

// Frozen native-verifier limits. The verifier may not invent larger ones.
pub const VERIFIER_MAX_PAIRS: usize = 16;
pub const VERIFIER_MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
pub const VERIFIER_MAX_OBJECTS: u64 = 16_384;
pub const VERIFIER_MAX_RESULT_REFS: usize = 4096;
/// Process-wide, not per instance: two concurrent native verifiers maximum.
pub const VERIFIER_MAX_CONCURRENT: usize = 2;
pub const VERIFIER_DEADLINE_SECONDS: u64 = 30;
pub const VERIFIER_GIT_CPU_SECONDS: u64 = 20;
pub const VERIFIER_GIT_ADDRESS_SPACE_BYTES: u64 = 512 * 1024 * 1024;
pub const VERIFIER_GIT_FILE_SIZE_BYTES: u64 = 128 * 1024 * 1024;
pub const VERIFIER_GIT_NOFILE: u64 = 64;
pub const VERIFIER_PIPE_BYTES: usize = 2 * 1024 * 1024;

/// Persistent authority fence stored on the core gate.
///
/// The transition is one-way and happens inside the same revision increment
/// that the first verified pack commit performs. `metadata_only` keeps the old
/// A1 commit path available; `pack_verified` refuses every fresh A1 write while
/// immutable terminal replay keeps working.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackMode {
    /// No pack proof has activated this gate: object bytes are unproven.
    MetadataOnly,
    /// Activated by one verified pack commit covering every resulting ref/HEAD.
    PackVerified,
}

impl PackMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MetadataOnly => "metadata_only",
            Self::PackVerified => "pack_verified",
        }
    }

    pub fn parse(value: &str) -> Result<Self, RefStoreError> {
        match value {
            "metadata_only" => Ok(Self::MetadataOnly),
            "pack_verified" => Ok(Self::PackVerified),
            _ => Err(RefStoreError::Database("stored pack mode is not recognized".into())),
        }
    }

    /// Fresh writes of the A1 metadata-only ref path require this mode.
    pub const fn permits_fresh_metadata_write(self) -> bool {
        matches!(self, Self::MetadataOnly)
    }

    /// Only a verified commit may activate, and it can never downgrade.
    pub const fn permits_verified_commit(self) -> bool {
        true
    }
}

/// The two artifact roles of one pack pair. Exactly one of each is required.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PackArtifactRole {
    Pack,
    Idx,
}

impl PackArtifactRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pack => "pack",
            Self::Idx => "idx",
        }
    }

    pub const fn from_slot(slot: usize) -> Self {
        if slot == 0 { Self::Pack } else { Self::Idx }
    }

    pub fn parse(value: &str) -> Result<Self, RefStoreError> {
        match value {
            "pack" => Ok(Self::Pack),
            "idx" => Ok(Self::Idx),
            _ => Err(RefStoreError::Database("stored pack artifact role is not recognized".into())),
        }
    }
}

/// Lowercase SHA-256 hex predicate shared by plan, registration and receipts.
pub fn is_sha256_hex(value: &str) -> bool {
    value.len() == SHA256_HEX && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Checked logical-byte sum; overflow is a typed refusal, never a wrap.
pub fn add_logical_bytes(total: i64, extra: i64) -> Result<i64, RefStoreError> {
    if extra < 0 {
        return Err(RefStoreError::InvalidIdentity("logical byte accounting must not be negative".into()));
    }
    total
        .checked_add(extra)
        .filter(|value| *value <= TENANT_MAX_LOGICAL_BYTES)
        .ok_or_else(|| RefStoreError::InvalidIdentity("logical byte accounting overflowed its bound".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_mode_is_a_one_way_fence() {
        assert!(PackMode::MetadataOnly.permits_fresh_metadata_write());
        assert!(!PackMode::PackVerified.permits_fresh_metadata_write());
        assert_eq!(PackMode::parse("pack_verified").unwrap(), PackMode::PackVerified);
        assert!(PackMode::parse("metadata-only").is_err());
    }

    #[test]
    fn sha_and_arithmetic_bounds_are_exact() {
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(!is_sha256_hex(&"A".repeat(64)));
        assert!(!is_sha256_hex(&"a".repeat(63)));
        assert!(add_logical_bytes(0, 8).is_ok());
        assert!(add_logical_bytes(TENANT_MAX_LOGICAL_BYTES, 1).is_err());
        assert!(add_logical_bytes(0, -1).is_err());
        assert_eq!(TENANT_MAX_LOGICAL_BYTES, 4 * REPO_MAX_LOGICAL_BYTES);
    }
}
