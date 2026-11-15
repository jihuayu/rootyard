//! Authoritative retention protector enumeration (§5).
//!
//! Models the eight §5 protector classes (`LiveRefHead`, `SnapshotPin`,
//! `RetentionRoot`, `CiCheckoutPin`, `PrMergeFinalizer`, `BackupManifest`,
//! `PendingOrUnknownOperation`, `CompactionInput`, `QuarantineHold`) so TTL can
//! never collect an unknown/pending operation or supersede a retained pack
//! prematurely during repack/compaction.
use super::closure::VerifiedDependencyClosure;
use super::contract::VersionId;
use super::pack_set::PackSetEntry;
use std::collections::BTreeSet;
use uuid::Uuid;

/// Explicit retention protector enumerated by the authority (§5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetentionProtector {
    LiveRefHead {
        version_id: VersionId,
    },
    SnapshotPin {
        pin_id: Uuid,
        version_ids: Vec<VersionId>,
        expired: bool,
    },
    RetentionRoot {
        root_id: Uuid,
        version_ids: Vec<VersionId>,
        released: bool,
    },
    CiCheckoutPin {
        job_id: Uuid,
        version_ids: Vec<VersionId>,
        revoked: bool,
    },
    PrMergeFinalizer {
        pull_id: Uuid,
        version_ids: Vec<VersionId>,
        settled: bool,
    },
    BackupManifest {
        manifest_id: Uuid,
        version_ids: Vec<VersionId>,
        retained: bool,
    },
    PendingOrUnknownOperation {
        operation_id: Uuid,
        target_versions: Vec<VersionId>,
        planned_pack_ids: Vec<Uuid>,
        age_seconds: u64,
    },
    CompactionInput {
        repack_operation_id: Uuid,
        old_version_ids: Vec<VersionId>,
        committed: bool,
        readers_drained: bool,
    },
    QuarantineHold {
        incident_id: Uuid,
        pack_ids: Vec<Uuid>,
        cleared: bool,
    },
}

impl RetentionProtector {
    /// True when this protector still actively retains referenced versions/packs.
    ///
    /// `PendingOrUnknownOperation` NEVER expires based on `age_seconds` (§5 rule:
    /// no "operation older than N days" deletion rule; delayed/unknown means retain and reconcile).
    pub const fn is_active(&self) -> bool {
        match self {
            Self::LiveRefHead { .. } => true,
            Self::SnapshotPin { expired, .. } => !*expired,
            Self::RetentionRoot { released, .. } => !*released,
            Self::CiCheckoutPin { revoked, .. } => !*revoked,
            Self::PrMergeFinalizer { settled, .. } => !*settled,
            Self::BackupManifest { retained, .. } => *retained,
            Self::PendingOrUnknownOperation { .. } => true,
            Self::CompactionInput { committed, readers_drained, .. } => !(*committed && *readers_drained),
            Self::QuarantineHold { cleared, .. } => !*cleared,
        }
    }

    fn protected_versions(&self) -> &[VersionId] {
        match self {
            Self::LiveRefHead { version_id } => std::slice::from_ref(version_id),
            Self::SnapshotPin { version_ids, .. }
            | Self::RetentionRoot { version_ids, .. }
            | Self::CiCheckoutPin { version_ids, .. }
            | Self::PrMergeFinalizer { version_ids, .. }
            | Self::BackupManifest { version_ids, .. } => version_ids,
            Self::PendingOrUnknownOperation { target_versions, .. } => target_versions,
            Self::CompactionInput { old_version_ids, .. } => old_version_ids,
            Self::QuarantineHold { .. } => &[],
        }
    }

    fn protected_packs(&self) -> &[Uuid] {
        match self {
            Self::PendingOrUnknownOperation { planned_pack_ids, .. } => planned_pack_ids,
            Self::QuarantineHold { pack_ids, .. } => pack_ids,
            _ => &[],
        }
    }
}

/// Retention outcome computed over a set of active protectors and closures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionDecision {
    pub protected_versions: BTreeSet<VersionId>,
    pub protected_pack_ids: BTreeSet<Uuid>,
    pub protected_by_unknown_operation: bool,
    pub collectible: bool,
}

/// Evaluate whether `target_pack` (and `closures` whose packs include it) is
/// protected or collectible under the enumerated authority protectors (§5).
pub fn evaluate_pack_retention(
    target_pack: &PackSetEntry,
    closures: &[&VerifiedDependencyClosure],
    protectors: &[RetentionProtector],
) -> RetentionDecision {
    let mut protected_versions = BTreeSet::new();
    let mut protected_pack_ids = BTreeSet::new();
    let mut protected_by_unknown_operation = false;

    for protector in protectors.iter().filter(|item| item.is_active()) {
        for vid in protector.protected_versions() {
            protected_versions.insert(*vid);
        }
        for pack_id in protector.protected_packs() {
            protected_pack_ids.insert(*pack_id);
        }
        if matches!(protector, RetentionProtector::PendingOrUnknownOperation { .. }) {
            let covers_pack = protector.protected_packs().contains(&target_pack.pack_id());
            let covers_closure = closures.iter().any(|closure| {
                closure_contains_pack(closure, target_pack)
                    && (protector.protected_versions().contains(&closure.root().version_id())
                        || closure
                            .dependencies()
                            .iter()
                            .any(|dep| protector.protected_versions().contains(&dep.version_id())))
            });
            if covers_pack || covers_closure {
                protected_by_unknown_operation = true;
            }
        }
    }

    // Cascade transitive protection from any retained root version to its OBJECT closure packs.
    for closure in closures {
        if protected_versions.contains(&closure.root().version_id()) {
            for dep in closure.dependencies() {
                protected_versions.insert(dep.version_id());
            }
            for pack in closure.packs() {
                protected_pack_ids.insert(pack.entry().pack_id());
            }
        }
    }

    let collectible = !protected_pack_ids.contains(&target_pack.pack_id()) && !protected_by_unknown_operation;
    RetentionDecision { protected_versions, protected_pack_ids, protected_by_unknown_operation, collectible }
}

fn closure_contains_pack(closure: &VerifiedDependencyClosure, target_pack: &PackSetEntry) -> bool {
    closure.packs().iter().any(|pack| pack.entry() == target_pack)
}
