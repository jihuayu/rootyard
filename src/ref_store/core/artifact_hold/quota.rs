//! Exact retained-admission arithmetic for the global hold ledger (A3).
//!
//! Admission is charged for *all retained* ledger state — hold rows, declared
//! artifact bytes, logical ledger bytes and every successful receipt — at shard,
//! tenant and repository scope. Nothing is refunded by an error, timeout,
//! cancellation, unknown completion, release (there is none), expiry (there is
//! none) or owner/repository deletion. Reaching a bound is explicit
//! backpressure, never eviction and never a dynamic cross-shard credit.
//!
//! This module is pure arithmetic; the locked SQL rows live in `super::sql`.
use super::contract::{
    ArtifactHoldError, ArtifactSpec, HoldQuotaResource, HoldQuotaScope, REPO_MAX_DECLARED_BYTES, REPO_MAX_HOLDS,
    REPO_MAX_LOGICAL_BYTES, REPO_MAX_RECEIPTS, SHARD_MAX_DECLARED_BYTES, SHARD_MAX_HOLDS, SHARD_MAX_LOGICAL_BYTES,
    SHARD_MAX_RECEIPTS, TENANT_MAX_DECLARED_BYTES, TENANT_MAX_HOLDS, TENANT_MAX_LOGICAL_BYTES, TENANT_MAX_RECEIPTS,
};

/// Retained counters of one locked scope.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct UsageCounts {
    pub holds: i64,
    pub declared_bytes: i64,
    pub logical_bytes: i64,
    pub receipts: i64,
}

/// One acquire/consume admission delta.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct UsageDelta {
    pub holds: i64,
    pub declared_bytes: i64,
    pub logical_bytes: i64,
    pub receipts: i64,
}

impl UsageCounts {
    fn checked_add(self, delta: UsageDelta) -> Option<Self> {
        Some(Self {
            holds: self.holds.checked_add(delta.holds)?,
            declared_bytes: self.declared_bytes.checked_add(delta.declared_bytes)?,
            logical_bytes: self.logical_bytes.checked_add(delta.logical_bytes)?,
            receipts: self.receipts.checked_add(delta.receipts)?,
        })
    }
}

/// Checked declared-byte total of a bounded batch, computed before any digest
/// or intent is produced.
pub(super) fn declared_bytes(artifacts: &[ArtifactSpec]) -> Result<i64, ArtifactHoldError> {
    let mut total: i64 = 0;
    for artifact in artifacts {
        total = total.checked_add(artifact.declared_bytes()).ok_or_else(|| {
            ArtifactHoldError::InvalidRequest("artifact hold declared-byte total overflows i64".into())
        })?;
    }
    Ok(total)
}

/// Admission delta of one acquire: every hold row, the declared bytes, the
/// retained logical hold bytes plus the bounded ACK receipt body, and the one
/// successful ACK receipt.
pub(super) fn acquire_delta(
    artifacts: &[ArtifactSpec],
    ack_body_bytes: usize,
) -> Result<UsageDelta, ArtifactHoldError> {
    let mut logical: i64 = 0;
    for artifact in artifacts {
        logical = logical.checked_add(artifact.logical_bytes()).ok_or_else(|| {
            ArtifactHoldError::InvalidRequest("artifact hold logical-byte total overflows i64".into())
        })?;
    }
    logical = logical
        .checked_add(
            i64::try_from(ack_body_bytes).map_err(|_| {
                ArtifactHoldError::InvalidRequest("artifact hold ACK body length does not fit i64".into())
            })?,
        )
        .and_then(|value| value.checked_add(128))
        .ok_or_else(|| ArtifactHoldError::InvalidRequest("artifact hold logical-byte total overflows i64".into()))?;
    Ok(UsageDelta {
        holds: i64::try_from(artifacts.len())
            .map_err(|_| ArtifactHoldError::InvalidRequest("artifact hold batch length does not fit i64".into()))?,
        declared_bytes: declared_bytes(artifacts)?,
        logical_bytes: logical,
        receipts: 1,
    })
}

/// Admission delta of one consume: one immutable receipt row per hold. No
/// declared bytes and no new hold are charged; the holds were charged at
/// acquire and are never refunded.
pub(super) fn consume_delta(receipts: usize, body_bytes_total: i64) -> Result<UsageDelta, ArtifactHoldError> {
    let receipts = i64::try_from(receipts)
        .map_err(|_| ArtifactHoldError::InvalidRequest("artifact consume batch length does not fit i64".into()))?;
    Ok(UsageDelta {
        holds: 0,
        declared_bytes: 0,
        logical_bytes: body_bytes_total
            .checked_add(receipts.checked_mul(128).ok_or_else(|| {
                ArtifactHoldError::InvalidRequest("artifact consume receipt overhead overflows i64".into())
            })?)
            .ok_or_else(|| ArtifactHoldError::InvalidRequest("artifact consume logical bytes overflow i64".into()))?,
        receipts,
    })
}

/// Exact admission check against the locked counters. Every scope is checked;
/// the first exhausted bound names the scope/resource explicitly.
pub(super) fn check_admission(
    shard: UsageCounts,
    tenant: UsageCounts,
    repository: UsageCounts,
    delta: UsageDelta,
) -> Result<(), ArtifactHoldError> {
    let shard = shard
        .checked_add(delta)
        .ok_or_else(|| ArtifactHoldError::Database("artifact hold shard counters overflow i64".into()))?;
    let tenant = tenant
        .checked_add(delta)
        .ok_or_else(|| ArtifactHoldError::Database("artifact hold tenant counters overflow i64".into()))?;
    let repository = repository
        .checked_add(delta)
        .ok_or_else(|| ArtifactHoldError::Database("artifact hold repository counters overflow i64".into()))?;
    let refuse = |scope, resource| Err(ArtifactHoldError::QuotaExceeded { scope, resource });
    if repository.holds > REPO_MAX_HOLDS {
        return refuse(HoldQuotaScope::Repository, HoldQuotaResource::Holds);
    }
    if repository.declared_bytes > REPO_MAX_DECLARED_BYTES {
        return refuse(HoldQuotaScope::Repository, HoldQuotaResource::DeclaredBytes);
    }
    if repository.logical_bytes > REPO_MAX_LOGICAL_BYTES {
        return refuse(HoldQuotaScope::Repository, HoldQuotaResource::LogicalBytes);
    }
    if repository.receipts > REPO_MAX_RECEIPTS {
        return refuse(HoldQuotaScope::Repository, HoldQuotaResource::Receipts);
    }
    if tenant.holds > TENANT_MAX_HOLDS {
        return refuse(HoldQuotaScope::Tenant, HoldQuotaResource::Holds);
    }
    if tenant.declared_bytes > TENANT_MAX_DECLARED_BYTES {
        return refuse(HoldQuotaScope::Tenant, HoldQuotaResource::DeclaredBytes);
    }
    if tenant.logical_bytes > TENANT_MAX_LOGICAL_BYTES {
        return refuse(HoldQuotaScope::Tenant, HoldQuotaResource::LogicalBytes);
    }
    if tenant.receipts > TENANT_MAX_RECEIPTS {
        return refuse(HoldQuotaScope::Tenant, HoldQuotaResource::Receipts);
    }
    if shard.holds > SHARD_MAX_HOLDS {
        return refuse(HoldQuotaScope::Shard, HoldQuotaResource::Holds);
    }
    if shard.declared_bytes > SHARD_MAX_DECLARED_BYTES {
        return refuse(HoldQuotaScope::Shard, HoldQuotaResource::DeclaredBytes);
    }
    if shard.logical_bytes > SHARD_MAX_LOGICAL_BYTES {
        return refuse(HoldQuotaScope::Shard, HoldQuotaResource::LogicalBytes);
    }
    if shard.receipts > SHARD_MAX_RECEIPTS {
        return refuse(HoldQuotaScope::Shard, HoldQuotaResource::Receipts);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ref_store::core::artifact_hold::contract::MAX_BATCH_ARTIFACTS;

    fn artifact(length: u64) -> ArtifactSpec {
        ArtifactSpec::new("packs", "a".repeat(64), length).unwrap()
    }

    #[test]
    fn batch_declared_bytes_are_checked() {
        let artifacts = vec![artifact(1), artifact(2)];
        assert_eq!(declared_bytes(&artifacts).unwrap(), 3);
    }

    #[test]
    fn repository_bounds_are_exact() {
        let full = UsageCounts { holds: REPO_MAX_HOLDS - 1, ..Default::default() };
        let delta = UsageDelta { holds: 1, declared_bytes: 1, logical_bytes: 1, receipts: 1 };
        assert!(check_admission(Default::default(), Default::default(), full, delta).is_ok());
        assert!(matches!(
            check_admission(
                Default::default(),
                Default::default(),
                UsageCounts { holds: REPO_MAX_HOLDS, ..Default::default() },
                delta
            ),
            Err(ArtifactHoldError::QuotaExceeded {
                scope: HoldQuotaScope::Repository,
                resource: HoldQuotaResource::Holds
            })
        ));
        assert!(matches!(
            check_admission(
                Default::default(),
                Default::default(),
                UsageCounts { declared_bytes: REPO_MAX_DECLARED_BYTES, ..Default::default() },
                delta
            ),
            Err(ArtifactHoldError::QuotaExceeded {
                scope: HoldQuotaScope::Repository,
                resource: HoldQuotaResource::DeclaredBytes
            })
        ));
        assert!(matches!(
            check_admission(
                Default::default(),
                Default::default(),
                UsageCounts { logical_bytes: REPO_MAX_LOGICAL_BYTES, ..Default::default() },
                delta
            ),
            Err(ArtifactHoldError::QuotaExceeded {
                scope: HoldQuotaScope::Repository,
                resource: HoldQuotaResource::LogicalBytes
            })
        ));
        assert!(matches!(
            check_admission(
                Default::default(),
                Default::default(),
                UsageCounts { receipts: REPO_MAX_RECEIPTS, ..Default::default() },
                UsageDelta { receipts: 1, ..Default::default() }
            ),
            Err(ArtifactHoldError::QuotaExceeded {
                scope: HoldQuotaScope::Repository,
                resource: HoldQuotaResource::Receipts
            })
        ));
    }

    #[test]
    fn tenant_and_shard_bounds_are_exact() {
        let delta = UsageDelta { holds: 1, ..Default::default() };
        assert!(matches!(
            check_admission(
                Default::default(),
                UsageCounts { holds: TENANT_MAX_HOLDS, ..Default::default() },
                Default::default(),
                delta
            ),
            Err(ArtifactHoldError::QuotaExceeded { scope: HoldQuotaScope::Tenant, .. })
        ));
        assert!(matches!(
            check_admission(
                UsageCounts { holds: SHARD_MAX_HOLDS, ..Default::default() },
                Default::default(),
                Default::default(),
                delta
            ),
            Err(ArtifactHoldError::QuotaExceeded { scope: HoldQuotaScope::Shard, .. })
        ));
        assert!(matches!(
            check_admission(
                UsageCounts { logical_bytes: SHARD_MAX_LOGICAL_BYTES, ..Default::default() },
                Default::default(),
                Default::default(),
                UsageDelta { logical_bytes: 1, ..Default::default() }
            ),
            Err(ArtifactHoldError::QuotaExceeded { scope: HoldQuotaScope::Shard, .. })
        ));
    }

    #[test]
    fn consume_delta_charges_one_receipt_per_hold() {
        let delta = consume_delta(3, 300).unwrap();
        assert_eq!(delta.holds, 0);
        assert_eq!(delta.declared_bytes, 0);
        assert_eq!(delta.receipts, 3);
        assert_eq!(delta.logical_bytes, 300 + 3 * 128);
        assert!(i64::try_from(MAX_BATCH_ARTIFACTS).unwrap() <= super::super::contract::SHARD_MAX_RECEIPTS);
    }
}
