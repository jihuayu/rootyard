//! Explicit 3-state retention classification for fetch pack planning and GC (Issue #184).
//!
//! Distinguishes `physically_present`, `plannable_for_fetch`, and `gc_eligible`
//! across active refs, snapshots, CI/CloneKit pins, backups, pending/unknown
//! operations, and historical cover holds. Physical deletion remains strictly
//! owned by `#122/#151/#153` and is never inferred from TTL, cache eviction, or
//! async projection lag.
use super::super::contract::VersionId;
use super::super::retention::RetentionProtector;
use super::model::CoverHierarchyRecord;
use crate::ref_store::core::types::RefName;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// Authoritative GC owner responsible for physical Blob deletion.
pub const PHYSICAL_GC_OWNER: &str = "#122/#151/#153";

/// Explicit 3-state retention classification for physically present packs.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackRetentionState {
    /// Bytes exist in BlobStore, held from deletion (e.g., pending/unknown
    /// operation staging or quarantine), NOT eligible for fetch planning.
    PhysicallyPresent,
    /// Physically present, verified, and protected; eligible for authorized
    /// fetch planning (either active serving or historical/pin reads).
    PlannableForFetch,
    /// Physically present on BlobStore with zero active protectors and retired
    /// from fetch planning; eligible ONLY for `#122/#151/#153` physical GC.
    GcEligible,
}

impl PackRetentionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PhysicallyPresent => "physically_present",
            Self::PlannableForFetch => "plannable_for_fetch",
            Self::GcEligible => "gc_eligible",
        }
    }
}

/// Physical existence status in BlobStore, strictly separate from planning and GC eligibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalBlobStatus {
    Present,
    PhysicallyDeletedByGc { gc_issue: &'static str },
}

/// Kind of authoritative hold/protector retaining a pack or cover.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverHoldKind {
    ActiveRefHead,
    SnapshotPin,
    RetentionRoot,
    CiCloneKitPin,
    BackupManifest,
    PendingOrUnknownOperation,
    HistoricalCoverHold,
    CompactionInputHold,
    QuarantineHold,
}

/// Explicit authoritative protector retaining versions, covers, or packs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoverRetentionHold {
    ActiveRefHead {
        ref_name: RefName,
        version_id: VersionId,
        cover_ids: Vec<Uuid>,
    },
    SnapshotPin {
        pin_id: Uuid,
        version_ids: Vec<VersionId>,
        cover_ids: Vec<Uuid>,
        released: bool,
    },
    RetentionRoot {
        root_id: Uuid,
        version_ids: Vec<VersionId>,
        cover_ids: Vec<Uuid>,
        released: bool,
    },
    CiCloneKitPin {
        job_id: Uuid,
        version_ids: Vec<VersionId>,
        cover_ids: Vec<Uuid>,
        revoked: bool,
    },
    BackupManifest {
        manifest_id: Uuid,
        version_ids: Vec<VersionId>,
        cover_ids: Vec<Uuid>,
        retained: bool,
    },
    PendingOrUnknownOperation {
        operation_id: Uuid,
        target_versions: Vec<VersionId>,
        staged_pack_ids: Vec<Uuid>,
        protected_cover_ids: Vec<Uuid>,
        age_seconds: u64,
        resolved: bool,
    },
    HistoricalCoverHold {
        hold_id: Uuid,
        cover_ids: Vec<Uuid>,
        version_ids: Vec<VersionId>,
        active_readers: u32,
        released: bool,
    },
    CompactionInputHold {
        repack_operation_id: Uuid,
        input_cover_ids: Vec<Uuid>,
        compacted_committed: bool,
        readers_drained: bool,
    },
    QuarantineHold {
        incident_id: Uuid,
        pack_ids: Vec<Uuid>,
        cover_ids: Vec<Uuid>,
        cleared: bool,
    },
}

impl CoverRetentionHold {
    pub const fn kind(&self) -> CoverHoldKind {
        match self {
            Self::ActiveRefHead { .. } => CoverHoldKind::ActiveRefHead,
            Self::SnapshotPin { .. } => CoverHoldKind::SnapshotPin,
            Self::RetentionRoot { .. } => CoverHoldKind::RetentionRoot,
            Self::CiCloneKitPin { .. } => CoverHoldKind::CiCloneKitPin,
            Self::BackupManifest { .. } => CoverHoldKind::BackupManifest,
            Self::PendingOrUnknownOperation { .. } => CoverHoldKind::PendingOrUnknownOperation,
            Self::HistoricalCoverHold { .. } => CoverHoldKind::HistoricalCoverHold,
            Self::CompactionInputHold { .. } => CoverHoldKind::CompactionInputHold,
            Self::QuarantineHold { .. } => CoverHoldKind::QuarantineHold,
        }
    }

    /// Pending/unknown operations NEVER expire on `age_seconds` alone.
    pub const fn is_active(&self) -> bool {
        match self {
            Self::ActiveRefHead { .. } => true,
            Self::SnapshotPin { released, .. } | Self::RetentionRoot { released, .. } => !*released,
            Self::CiCloneKitPin { revoked, .. } => !*revoked,
            Self::BackupManifest { retained, .. } => *retained,
            Self::PendingOrUnknownOperation { resolved, .. } => !*resolved,
            Self::HistoricalCoverHold { active_readers, released, .. } => *active_readers > 0 || !*released,
            Self::CompactionInputHold { compacted_committed, readers_drained, .. } => {
                !(*compacted_committed && *readers_drained)
            }
            Self::QuarantineHold { cleared, .. } => !*cleared,
        }
    }

    /// Map onto `#180` [`RetentionProtector`] where a 1-to-1 bridge applies.
    pub fn to_ref_version_protector(&self) -> Option<RetentionProtector> {
        match self {
            Self::ActiveRefHead { version_id, .. } => Some(RetentionProtector::LiveRefHead { version_id: *version_id }),
            Self::SnapshotPin { pin_id, version_ids, released, .. } => Some(RetentionProtector::SnapshotPin {
                pin_id: *pin_id,
                version_ids: version_ids.clone(),
                expired: *released,
            }),
            Self::RetentionRoot { root_id, version_ids, released, .. } => Some(RetentionProtector::RetentionRoot {
                root_id: *root_id,
                version_ids: version_ids.clone(),
                released: *released,
            }),
            Self::CiCloneKitPin { job_id, version_ids, revoked, .. } => Some(RetentionProtector::CiCheckoutPin {
                job_id: *job_id,
                version_ids: version_ids.clone(),
                revoked: *revoked,
            }),
            Self::BackupManifest { manifest_id, version_ids, retained, .. } => {
                Some(RetentionProtector::BackupManifest {
                    manifest_id: *manifest_id,
                    version_ids: version_ids.clone(),
                    retained: *retained,
                })
            }
            Self::PendingOrUnknownOperation { operation_id, target_versions, staged_pack_ids, age_seconds, .. } => {
                Some(RetentionProtector::PendingOrUnknownOperation {
                    operation_id: *operation_id,
                    target_versions: target_versions.clone(),
                    planned_pack_ids: staged_pack_ids.clone(),
                    age_seconds: *age_seconds,
                })
            }
            Self::QuarantineHold { incident_id, pack_ids, cleared, .. } => Some(RetentionProtector::QuarantineHold {
                incident_id: *incident_id,
                pack_ids: pack_ids.clone(),
                cleared: *cleared,
            }),
            Self::HistoricalCoverHold { .. } | Self::CompactionInputHold { .. } => None,
        }
    }

    fn applies_to(&self, pack_id: Uuid, cover_id: Uuid, covered_versions: &[VersionId]) -> HoldMatch {
        if !self.is_active() {
            return HoldMatch::None;
        }
        match self {
            Self::ActiveRefHead { version_id, cover_ids, .. } => {
                if cover_ids.contains(&cover_id) || covered_versions.contains(version_id) {
                    HoldMatch::Serving
                } else {
                    HoldMatch::None
                }
            }
            Self::SnapshotPin { version_ids, cover_ids, .. }
            | Self::RetentionRoot { version_ids, cover_ids, .. }
            | Self::CiCloneKitPin { version_ids, cover_ids, .. }
            | Self::BackupManifest { version_ids, cover_ids, .. } => {
                if cover_ids.contains(&cover_id) || any_version_intersects(version_ids, covered_versions) {
                    HoldMatch::HistoricalOrPin
                } else {
                    HoldMatch::None
                }
            }
            Self::HistoricalCoverHold { cover_ids, version_ids, .. } => {
                if cover_ids.contains(&cover_id) || any_version_intersects(version_ids, covered_versions) {
                    HoldMatch::HistoricalOrPin
                } else {
                    HoldMatch::None
                }
            }
            Self::CompactionInputHold { input_cover_ids, .. } => {
                if input_cover_ids.contains(&cover_id) {
                    HoldMatch::Serving
                } else {
                    HoldMatch::None
                }
            }
            Self::PendingOrUnknownOperation { target_versions, staged_pack_ids, protected_cover_ids, .. } => {
                if staged_pack_ids.contains(&pack_id) {
                    HoldMatch::QuarantineOrUncommitted
                } else if protected_cover_ids.contains(&cover_id)
                    || any_version_intersects(target_versions, covered_versions)
                {
                    HoldMatch::HistoricalOrPin
                } else {
                    HoldMatch::None
                }
            }
            Self::QuarantineHold { pack_ids, cover_ids, .. } => {
                if pack_ids.contains(&pack_id) || cover_ids.contains(&cover_id) {
                    HoldMatch::QuarantineOrUncommitted
                } else {
                    HoldMatch::None
                }
            }
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum HoldMatch {
    None,
    Serving,
    HistoricalOrPin,
    QuarantineOrUncommitted,
}

/// Non-authoritative signals that MUST NEVER be used to infer pack deletion or planning eligibility.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NonAuthoritativeHint {
    TtlExpired { age_seconds: u64 },
    CacheEvicted { cache_key: String },
    AsyncProjectionMissingOrStale { projection_lag: u64 },
}

impl NonAuthoritativeHint {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::TtlExpired { .. } => "ignored_ttl_expired",
            Self::CacheEvicted { .. } => "ignored_cache_evicted",
            Self::AsyncProjectionMissingOrStale { .. } => "ignored_async_projection_lag",
        }
    }
}

/// Complete retention verdict for one pack/cover pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackRetentionClassification {
    pub pack_id: Uuid,
    pub cover_id: Uuid,
    pub state: Option<PackRetentionState>,
    pub physically_present: bool,
    pub plannable_for_fetch: bool,
    pub gc_eligible: bool,
    pub historical_read_only: bool,
    pub active_protectors: Vec<CoverHoldKind>,
    pub ignored_non_authoritative_hints: Vec<&'static str>,
    pub physical_gc_owner: &'static str,
}

/// Authoritative snapshot completeness & explicit retirement ledger for physical GC gating.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityHoldSnapshot {
    pub authority_epoch: u64,
    pub complete: bool,
    pub explicitly_retired_covers: BTreeSet<Uuid>,
}

/// Ledger of physical Blob states and authoritative retention protectors.
#[derive(Clone, Debug, Default)]
pub struct RetentionClassificationIndex {
    physical_status: BTreeMap<Uuid, PhysicalBlobStatus>,
    holds: Vec<CoverRetentionHold>,
    hints: Vec<NonAuthoritativeHint>,
    authority_snapshot: Option<AuthorityHoldSnapshot>,
}

impl RetentionClassificationIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_physical_status(&mut self, pack_id: Uuid, status: PhysicalBlobStatus) {
        self.physical_status.insert(pack_id, status);
    }

    pub fn set_authority_snapshot(
        &mut self,
        authority_epoch: u64,
        complete: bool,
        retired_cover_ids: impl IntoIterator<Item = Uuid>,
    ) {
        self.authority_snapshot = Some(AuthorityHoldSnapshot {
            authority_epoch,
            complete,
            explicitly_retired_covers: retired_cover_ids.into_iter().collect(),
        });
    }

    pub fn clear_authority_snapshot(&mut self) {
        self.authority_snapshot = None;
    }

    pub fn add_hold(&mut self, hold: CoverRetentionHold) {
        self.holds.push(hold);
    }

    pub fn clear_holds(&mut self) {
        self.holds.clear();
    }

    pub fn add_non_authoritative_hint(&mut self, hint: NonAuthoritativeHint) {
        self.hints.push(hint);
    }

    pub fn classify_cover(&self, record: &CoverHierarchyRecord) -> PackRetentionClassification {
        self.classify_pack(record.pack().entry().pack_id(), record.cover_id(), record.covered_versions())
    }

    /// Evaluate the 3-state retention classification strictly from authoritative holds
    /// and physical status; TTL, cache, and async projection hints are recorded as ignored.
    pub fn classify_pack(
        &self,
        pack_id: Uuid,
        cover_id: Uuid,
        covered_versions: &[VersionId],
    ) -> PackRetentionClassification {
        let ignored_non_authoritative_hints: Vec<&'static str> =
            self.hints.iter().map(NonAuthoritativeHint::label).collect();
        let physical = self.physical_status.get(&pack_id).copied().unwrap_or(PhysicalBlobStatus::Present);
        if matches!(physical, PhysicalBlobStatus::PhysicallyDeletedByGc { .. }) {
            return PackRetentionClassification {
                pack_id,
                cover_id,
                state: None,
                physically_present: false,
                plannable_for_fetch: false,
                gc_eligible: false,
                historical_read_only: false,
                active_protectors: Vec::new(),
                ignored_non_authoritative_hints,
                physical_gc_owner: PHYSICAL_GC_OWNER,
            };
        }

        let mut kinds = BTreeSet::new();
        let mut blocked_from_fetch = false;
        let mut has_serving = false;
        let mut has_historical_or_pin = false;

        for hold in &self.holds {
            match hold.applies_to(pack_id, cover_id, covered_versions) {
                HoldMatch::None => {}
                HoldMatch::Serving => {
                    kinds.insert(hold.kind());
                    has_serving = true;
                }
                HoldMatch::HistoricalOrPin => {
                    kinds.insert(hold.kind());
                    has_historical_or_pin = true;
                }
                HoldMatch::QuarantineOrUncommitted => {
                    kinds.insert(hold.kind());
                    blocked_from_fetch = true;
                }
            }
        }

        let active_protectors: Vec<CoverHoldKind> = kinds.into_iter().collect();
        if blocked_from_fetch {
            return PackRetentionClassification {
                pack_id,
                cover_id,
                state: Some(PackRetentionState::PhysicallyPresent),
                physically_present: true,
                plannable_for_fetch: false,
                gc_eligible: false,
                historical_read_only: false,
                active_protectors,
                ignored_non_authoritative_hints,
                physical_gc_owner: PHYSICAL_GC_OWNER,
            };
        }
        if has_serving || has_historical_or_pin {
            return PackRetentionClassification {
                pack_id,
                cover_id,
                state: Some(PackRetentionState::PlannableForFetch),
                physically_present: true,
                plannable_for_fetch: true,
                gc_eligible: false,
                historical_read_only: !has_serving && has_historical_or_pin,
                active_protectors,
                ignored_non_authoritative_hints,
                physical_gc_owner: PHYSICAL_GC_OWNER,
            };
        }

        let gc_authorized = self.authority_snapshot.as_ref().is_some_and(|snap| {
            snap.complete && snap.authority_epoch > 0 && snap.explicitly_retired_covers.contains(&cover_id)
        });
        if gc_authorized {
            return PackRetentionClassification {
                pack_id,
                cover_id,
                state: Some(PackRetentionState::GcEligible),
                physically_present: true,
                plannable_for_fetch: false,
                gc_eligible: true,
                historical_read_only: false,
                active_protectors,
                ignored_non_authoritative_hints,
                physical_gc_owner: PHYSICAL_GC_OWNER,
            };
        }

        // Missing, incomplete, stale-epoch, or unretired cover fails closed: never authorize GC.
        PackRetentionClassification {
            pack_id,
            cover_id,
            state: Some(PackRetentionState::PhysicallyPresent),
            physically_present: true,
            plannable_for_fetch: false,
            gc_eligible: false,
            historical_read_only: false,
            active_protectors,
            ignored_non_authoritative_hints,
            physical_gc_owner: PHYSICAL_GC_OWNER,
        }
    }
}

fn any_version_intersects(left: &[VersionId], right: &[VersionId]) -> bool {
    left.iter().any(|v| right.contains(v))
}
