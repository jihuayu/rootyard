//! Bounded, versioned at-close scope-drain acknowledgment.
//!
//! New `CloseAuthScope` applications persist a fixed-size summary of the exact open-decision and
//! pending-operation vectors returned by the successful core response. The summary commits to
//! vector order and duplicates through a domain-separated SHA-256; it is not a historical list and
//! cannot reconstruct the vectors. Current drain must be read through the privileged committed
//! scope-drain query. A close acknowledgment alone is never a drained-revocation proof; the
//! existing evaluator still requires both current vectors to be empty.
//!
//! This adds a new serialized outcome variant. Old binaries do not understand it, so replicas and
//! Rust consumers must be homogeneous before writes resume; it is not a rolling-upgrade protocol.
//! The compact receipt removes cardinality-dependent receipt failure, not Root-state capacity: a
//! close can still legitimately become `StateCapacity` if the required scope floor cannot fit.

use rootyard_refcas_log::state_machine::ApplicationError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::core::state_machine::ScopeLifecycle;

/// Fixed format marker for the compact new close acknowledgment.
pub const SCOPE_CLOSE_DRAIN_FORMAT: &str = "rootyard-refcas-scope-close-drain/v1";
/// Conservative independent bound for the compact acknowledgment. The global 80 KiB receipt
/// admission guard stays in force; this only asserts the new variant's own small shape.
pub const MAX_SCOPE_CLOSE_ACK_BYTES: usize = 2 * 1024;

const DIGEST_DOMAIN: &[u8] = b"rootyard/refcas/auth-scope-close-drain/v1\0";
const OPEN_TAG: &[u8] = b"open";
const PENDING_TAG: &[u8] = b"pending";

/// Fixed-size commitment to the at-close response vectors.
///
/// `open_decision_count` and `pending_operation_count` are the returned element counts, not
/// necessarily unique operations. `ids_digest_hex` preserves returned order and duplicates.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeCloseDrainSummary {
    pub format: String,
    pub open_decision_count: u64,
    pub pending_operation_count: u64,
    pub ids_digest_hex: String,
}

impl ScopeCloseDrainSummary {
    pub(crate) fn from_vectors(
        scope_kind: &str,
        scope_id: Uuid,
        lifecycle: ScopeLifecycle,
        authz_floor: i64,
        open_decision_ids: &[Uuid],
        pending_operation_ids: &[Uuid],
    ) -> Self {
        Self {
            format: SCOPE_CLOSE_DRAIN_FORMAT.to_owned(),
            open_decision_count: count_u64(open_decision_ids.len()),
            pending_operation_count: count_u64(pending_operation_ids.len()),
            ids_digest_hex: scope_close_drain_digest(
                scope_kind,
                scope_id,
                lifecycle,
                authz_floor,
                open_decision_ids,
                pending_operation_ids,
            ),
        }
    }

    /// Restore-time shape and count contract. Counts are explicit `u64` wire values; on this
    /// platform each must be representable for local vector boundary checks. No historical vectors
    /// are promised by this type.
    pub fn validate(&self) -> Result<(), ApplicationError> {
        if self.format != SCOPE_CLOSE_DRAIN_FORMAT {
            return Err(ApplicationError::new("unknown scope close drain summary format"));
        }
        if self.ids_digest_hex.len() != 64
            || !self.ids_digest_hex.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(ApplicationError::new("scope close drain digest is not lowercase SHA-256 hex"));
        }
        if usize::try_from(self.open_decision_count).is_err() || usize::try_from(self.pending_operation_count).is_err()
        {
            return Err(ApplicationError::new("scope close drain count exceeds local vector capacity"));
        }
        Ok(())
    }
}

pub(crate) fn scope_close_drain_digest(
    scope_kind: &str,
    scope_id: Uuid,
    lifecycle: ScopeLifecycle,
    authz_floor: i64,
    open_decision_ids: &[Uuid],
    pending_operation_ids: &[Uuid],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    update_len_prefixed(&mut hasher, scope_kind.as_bytes());
    hasher.update(scope_id.as_bytes());
    hasher.update([lifecycle_tag(lifecycle)]);
    hasher.update(authz_floor.to_be_bytes());
    update_uuid_list(&mut hasher, OPEN_TAG, open_decision_ids);
    update_uuid_list(&mut hasher, PENDING_TAG, pending_operation_ids);
    hex::encode(hasher.finalize())
}

fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(count_u64(bytes.len()).to_be_bytes());
    hasher.update(bytes);
}

fn update_uuid_list(hasher: &mut Sha256, tag: &[u8], ids: &[Uuid]) {
    update_len_prefixed(hasher, tag);
    hasher.update(count_u64(ids.len()).to_be_bytes());
    for id in ids {
        hasher.update(id.as_bytes());
    }
}

fn lifecycle_tag(lifecycle: ScopeLifecycle) -> u8 {
    match lifecycle {
        ScopeLifecycle::Open => 0,
        ScopeLifecycle::Closing => 1,
        ScopeLifecycle::Closed => 2,
    }
}

fn count_u64(count: usize) -> u64 {
    u64::try_from(count).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u128) -> Uuid {
        Uuid::from_u128(byte)
    }

    fn summary(open: &[Uuid], pending: &[Uuid]) -> ScopeCloseDrainSummary {
        ScopeCloseDrainSummary::from_vectors("token", id(9), ScopeLifecycle::Closing, 7, open, pending)
    }

    #[test]
    fn digest_commits_order_duplicates_roles_and_scope_axes() {
        let a = id(1);
        let b = id(2);
        let c = id(3);
        let base = scope_close_drain_digest("token", id(9), ScopeLifecycle::Closing, 7, &[a, b], &[c]);
        assert_eq!(base, scope_close_drain_digest("token", id(9), ScopeLifecycle::Closing, 7, &[a, b], &[c]));
        assert_ne!(base, scope_close_drain_digest("token", id(9), ScopeLifecycle::Closing, 7, &[b, a], &[c]));
        assert_ne!(base, scope_close_drain_digest("token", id(9), ScopeLifecycle::Closing, 7, &[a, a, b], &[c]));
        assert_ne!(base, scope_close_drain_digest("token", id(9), ScopeLifecycle::Closing, 7, &[a, b], &[a, c]));
        assert_ne!(base, scope_close_drain_digest("token", id(10), ScopeLifecycle::Closing, 7, &[a, b], &[c]));
        assert_ne!(base, scope_close_drain_digest("token", id(9), ScopeLifecycle::Closed, 7, &[a, b], &[c]));
        assert_ne!(base, scope_close_drain_digest("token", id(9), ScopeLifecycle::Closing, 8, &[a, b], &[c]));
        assert_ne!(base, scope_close_drain_digest("parent_token", id(9), ScopeLifecycle::Closing, 7, &[a, b], &[c]));
    }

    #[test]
    fn summary_counts_and_validation_match_the_wire_contract() {
        let summary = summary(&[id(1), id(2), id(2)], &[id(3)]);
        assert_eq!(summary.open_decision_count, 3);
        assert_eq!(summary.pending_operation_count, 1);
        assert!(summary.validate().is_ok());

        let mut malformed = summary.clone();
        malformed.format = "rootyard-refcas-scope-close-drain/v2".into();
        assert!(malformed.validate().is_err());
        let mut malformed = summary.clone();
        malformed.ids_digest_hex = "00".repeat(31);
        assert!(malformed.validate().is_err());
        let mut malformed = summary;
        malformed.ids_digest_hex = "AA".repeat(32);
        assert!(malformed.validate().is_err());
    }

    #[test]
    fn compact_summary_size_is_bounded_and_not_linear_in_cardinality() {
        let empty = summary(&[], &[]);
        let one = summary(&[id(1)], &[id(2)]);
        let max = summary(
            &(0_u128..2048).map(|index| id(index + 1)).collect::<Vec<_>>(),
            &(0_u128..2048).map(|index| id(index + 10_000)).collect::<Vec<_>>(),
        );
        let lengths: Vec<usize> = [&empty, &one, &max]
            .into_iter()
            .map(|summary| serde_json::to_vec(summary).expect("summary serializes").len())
            .collect();
        assert!(lengths.iter().all(|length| *length <= MAX_SCOPE_CLOSE_ACK_BYTES), "{lengths:?}");
        let max_len = lengths.iter().copied().max().unwrap();
        let min_len = lengths.iter().copied().min().unwrap();
        assert!(max_len - min_len < 32, "{lengths:?}");
    }
}
