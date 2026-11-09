//! Cycle-free pack commit plan and its canonical parent operation digest.
//!
//! The parent digest is computed **before** the A3 acquire and covers only
//! semantic fields that are known up front: scope, preallocated operation and
//! pack/registration identities, planned content digests and lengths, refs,
//! HEAD/CAS, expected gate revision/digest/mode and the old membership digest.
//! Fresh attempt paths and the actual artifact-set digest are deliberately excluded.
use super::context::{MembershipDigest, PackMembershipEntry};
use super::contract::{
    MAX_ACTIVE_MEMBERSHIPS, MAX_BATCH_NEW_PACKS, MAX_PLAN_REFS, PackArtifactRole, PackMode, VERIFIER_MAX_TOTAL_BYTES,
    is_sha256_hex,
};
use super::error::PackCommitError;
use crate::ref_store::CommitMode;
use crate::ref_store::contract::{OperationIdentity, RequestDigest};
use crate::ref_store::core::types::{GitObjectFormat, GitOid, HeadUpdate, RefUpdate, batch_prefix_conflict};
use std::collections::BTreeSet;
use uuid::Uuid;

/// Validated lowercase SHA-256 hex of one artifact's bytes (declared content,
/// never a server-chosen path or an actual locator).
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ContentDigest(String);

impl ContentDigest {
    pub fn parse(value: impl Into<String>) -> Result<Self, PackCommitError> {
        let value = value.into();
        if !is_sha256_hex(&value) {
            return Err(PackCommitError::Invalid("content digest must be lowercase sha256 hex"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedArtifact {
    role: PackArtifactRole,
    content: ContentDigest,
    length: u64,
}

impl PlannedArtifact {
    pub fn new(role: PackArtifactRole, content: ContentDigest, length: u64) -> Result<Self, PackCommitError> {
        if length == 0 {
            return Err(PackCommitError::Invalid("a planned artifact must be non-empty"));
        }
        Ok(Self { role, content, length })
    }

    pub fn role(&self) -> PackArtifactRole {
        self.role
    }

    pub fn content(&self) -> &ContentDigest {
        &self.content
    }

    pub fn length(&self) -> u64 {
        self.length
    }
}

/// One planned pack pair: exactly one `.pack` and one `.idx`, plus the
/// preallocated pack and global registration identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedPack {
    pack_id: Uuid,
    registration_id: Uuid,
    artifacts: [PlannedArtifact; 2],
}

impl PlannedPack {
    pub fn new(
        pack_id: Uuid,
        registration_id: Uuid,
        pack: PlannedArtifact,
        idx: PlannedArtifact,
    ) -> Result<Self, PackCommitError> {
        if pack_id.is_nil() || registration_id.is_nil() {
            return Err(PackCommitError::Invalid("pack and registration ids must be non-nil"));
        }
        if pack.role != PackArtifactRole::Pack || idx.role != PackArtifactRole::Idx {
            return Err(PackCommitError::Invalid("a pack pair is one pack artifact and one idx artifact"));
        }
        if pack.content == idx.content {
            return Err(PackCommitError::Invalid("pack and idx content digests must differ"));
        }
        Ok(Self { pack_id, registration_id, artifacts: [pack, idx] })
    }

    pub fn pack_id(&self) -> Uuid {
        self.pack_id
    }

    pub fn registration_id(&self) -> Uuid {
        self.registration_id
    }

    pub fn artifact(&self, role: PackArtifactRole) -> &PlannedArtifact {
        &self.artifacts[role as usize]
    }

    pub fn total_bytes(&self) -> u64 {
        self.artifacts.iter().map(|artifact| artifact.length).sum()
    }
}

/// Repository/tenant/format/history/epoch scope of one plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackCommitScope {
    repository_id: Uuid,
    tenant_id: Uuid,
    owner_id: Uuid,
    object_format: GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
}

impl PackCommitScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository_id: Uuid,
        tenant_id: Uuid,
        owner_id: Uuid,
        object_format: GitObjectFormat,
        history_incarnation: Uuid,
        authority_epoch: i64,
        group_epoch: i64,
    ) -> Result<Self, PackCommitError> {
        if repository_id.is_nil() || tenant_id.is_nil() || owner_id.is_nil() || history_incarnation.is_nil() {
            return Err(PackCommitError::Invalid("scope ids must be non-nil"));
        }
        if authority_epoch <= 0 || group_epoch <= 0 {
            return Err(PackCommitError::Invalid("gate epochs must be positive"));
        }
        Ok(Self {
            repository_id,
            tenant_id,
            owner_id,
            object_format,
            history_incarnation,
            authority_epoch,
            group_epoch,
        })
    }

    pub fn repository_id(&self) -> Uuid {
        self.repository_id
    }
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }
    pub fn owner_id(&self) -> Uuid {
        self.owner_id
    }
    pub fn object_format(&self) -> GitObjectFormat {
        self.object_format
    }
    pub fn history_incarnation(&self) -> Uuid {
        self.history_incarnation
    }
    pub fn authority_epoch(&self) -> i64 {
        self.authority_epoch
    }
    pub fn group_epoch(&self) -> i64 {
        self.group_epoch
    }
}

/// Expected gate state frozen by the plan and re-checked by every later step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackCommitExpectation {
    revision: i64,
    gate_digest: RequestDigest,
    mode: PackMode,
}

impl PackCommitExpectation {
    pub fn new(revision: i64, gate_digest: RequestDigest, mode: PackMode) -> Result<Self, PackCommitError> {
        if revision <= 0 {
            return Err(PackCommitError::Invalid("expected gate revision must be positive"));
        }
        Ok(Self { revision, gate_digest, mode })
    }

    pub fn revision(&self) -> i64 {
        self.revision
    }
    pub fn gate_digest(&self) -> &RequestDigest {
        &self.gate_digest
    }
    pub fn mode(&self) -> PackMode {
        self.mode
    }
}

/// Complete pre-A3 plan. `parent_digest` is canonical over known fields only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackCommitPlan {
    scope: PackCommitScope,
    identity: OperationIdentity,
    expected: PackCommitExpectation,
    head: HeadUpdate,
    refs: Vec<RefUpdate>,
    old_membership_digest: MembershipDigest,
    old_memberships: Vec<PackMembershipEntry>,
    packs: Vec<PlannedPack>,
    commit_mode: CommitMode,
    parent_digest: RequestDigest,
}

impl PackCommitPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: PackCommitScope,
        identity: OperationIdentity,
        expected: PackCommitExpectation,
        head: HeadUpdate,
        refs: Vec<RefUpdate>,
        old_membership_digest: MembershipDigest,
        old_memberships: Vec<PackMembershipEntry>,
        packs: Vec<PlannedPack>,
    ) -> Result<Self, PackCommitError> {
        Self::build(
            scope,
            identity,
            expected,
            head,
            refs,
            old_membership_digest,
            old_memberships,
            packs,
            CommitMode::Atomic,
        )
    }

    /// Same plan, explicit commit mode. `Atomic` delegates to the byte-identical
    /// atomic domain (`.new` digest unchanged); `AcceptedSubset` uses the separate
    /// versioned `core-pack-commit-plan-subset-v1` domain that also covers the
    /// mode. The plan stays the ORIGINAL WHOLE BATCH: no caller can derive a
    /// smaller plan or a different parent identity from a selection here.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_mode(
        scope: PackCommitScope,
        identity: OperationIdentity,
        expected: PackCommitExpectation,
        head: HeadUpdate,
        refs: Vec<RefUpdate>,
        old_membership_digest: MembershipDigest,
        old_memberships: Vec<PackMembershipEntry>,
        packs: Vec<PlannedPack>,
        mode: CommitMode,
    ) -> Result<Self, PackCommitError> {
        Self::build(scope, identity, expected, head, refs, old_membership_digest, old_memberships, packs, mode)
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        scope: PackCommitScope,
        identity: OperationIdentity,
        expected: PackCommitExpectation,
        head: HeadUpdate,
        refs: Vec<RefUpdate>,
        old_membership_digest: MembershipDigest,
        old_memberships: Vec<PackMembershipEntry>,
        packs: Vec<PlannedPack>,
        commit_mode: CommitMode,
    ) -> Result<Self, PackCommitError> {
        if identity.repository_id() != scope.repository_id {
            return Err(PackCommitError::Invalid("operation identity belongs to another repository"));
        }
        if refs.is_empty() || refs.len() > MAX_PLAN_REFS {
            return Err(PackCommitError::Capacity {
                limit: "plan_refs",
                bound: MAX_PLAN_REFS as i64,
                actual: refs.len() as i64,
            });
        }
        if packs.len() > MAX_BATCH_NEW_PACKS {
            return Err(PackCommitError::Capacity {
                limit: "batch_new_packs",
                bound: MAX_BATCH_NEW_PACKS as i64,
                actual: packs.len() as i64,
            });
        }
        if old_memberships.len() as i64 > MAX_ACTIVE_MEMBERSHIPS {
            return Err(PackCommitError::Capacity {
                limit: "old_memberships",
                bound: MAX_ACTIVE_MEMBERSHIPS,
                actual: old_memberships.len() as i64,
            });
        }
        if MembershipDigest::of(&old_memberships) != old_membership_digest {
            return Err(PackCommitError::Invalid("old membership digest does not match the captured memberships"));
        }
        let mut names = BTreeSet::new();
        for update in &refs {
            if !names.insert(update.name().as_str()) {
                return Err(PackCommitError::Invalid("a plan must not repeat a ref name"));
            }
            for oid in [update.precondition().oid(), update.target().oid()].into_iter().flatten() {
                if oid.format() != scope.object_format {
                    return Err(PackCommitError::Invalid("plan object id does not match the gate object format"));
                }
            }
        }
        // Atomic keeps the historic whole-batch prefix refusal. AcceptedSubset
        // defers namespace checks to the ordered selection: a non-HEAD parent
        // delete followed by a child create may both be accepted (matching a
        // normal stock-Git push); create-before-delete still rejects the child.
        if commit_mode == CommitMode::Atomic && batch_prefix_conflict(&refs).is_some() {
            return Err(PackCommitError::Invalid("prefix"));
        }
        if let HeadUpdate::Retarget(target) = &head
            && !target.is_branch()
        {
            return Err(PackCommitError::Invalid("HEAD must name a refs/heads/ branch"));
        }
        let mut pack_ids = BTreeSet::new();
        let mut registration_ids = BTreeSet::new();
        let mut total_bytes: u64 = 0;
        for pack in &packs {
            if !pack_ids.insert(pack.pack_id) {
                return Err(PackCommitError::Invalid("a plan must not repeat a pack id"));
            }
            if !registration_ids.insert(pack.registration_id) {
                return Err(PackCommitError::Invalid("a plan must not repeat a registration id"));
            }
            total_bytes = total_bytes
                .checked_add(pack.total_bytes())
                .ok_or(PackCommitError::Invalid("planned artifact bytes overflowed"))?;
        }
        if total_bytes > VERIFIER_MAX_TOTAL_BYTES {
            return Err(PackCommitError::Capacity {
                limit: "planned_pair_bytes",
                bound: VERIFIER_MAX_TOTAL_BYTES as i64,
                actual: total_bytes as i64,
            });
        }
        let parent_digest = match commit_mode {
            CommitMode::Atomic => {
                parent_digest(&scope, &identity, &expected, &head, &refs, old_membership_digest, &packs)
            }
            CommitMode::AcceptedSubset => parent_digest_subset(
                &scope,
                &identity,
                &expected,
                &head,
                &refs,
                old_membership_digest,
                &packs,
                commit_mode,
            ),
        };
        let identity = OperationIdentity::new(
            identity.repository_id(),
            identity.issuer_id(),
            identity.lane().clone(),
            identity.sequence(),
            identity.operation_id(),
            parent_digest,
        )
        .map_err(|_| PackCommitError::Invalid("operation identity is invalid"))?;
        Ok(Self {
            scope,
            identity,
            expected,
            head,
            refs,
            old_membership_digest,
            old_memberships,
            packs,
            commit_mode,
            parent_digest,
        })
    }

    pub fn scope(&self) -> &PackCommitScope {
        &self.scope
    }

    pub fn identity(&self) -> &OperationIdentity {
        &self.identity
    }
    pub fn repository_id(&self) -> Uuid {
        self.scope.repository_id
    }
    pub fn tenant_id(&self) -> Uuid {
        self.scope.tenant_id
    }
    pub fn owner_id(&self) -> Uuid {
        self.scope.owner_id
    }
    pub fn object_format(&self) -> GitObjectFormat {
        self.scope.object_format
    }
    pub fn history_incarnation(&self) -> Uuid {
        self.scope.history_incarnation
    }
    pub fn authority_epoch(&self) -> i64 {
        self.scope.authority_epoch
    }
    pub fn group_epoch(&self) -> i64 {
        self.scope.group_epoch
    }
    pub fn expected(&self) -> &PackCommitExpectation {
        &self.expected
    }
    pub fn head(&self) -> &HeadUpdate {
        &self.head
    }
    pub fn refs(&self) -> &[RefUpdate] {
        &self.refs
    }
    pub fn old_membership_digest(&self) -> MembershipDigest {
        self.old_membership_digest
    }
    pub fn old_memberships(&self) -> &[PackMembershipEntry] {
        &self.old_memberships
    }
    pub fn packs(&self) -> &[PlannedPack] {
        &self.packs
    }
    pub fn parent_digest(&self) -> &RequestDigest {
        &self.parent_digest
    }
    pub fn commit_mode(&self) -> CommitMode {
        self.commit_mode
    }
}

fn parent_digest(
    scope: &PackCommitScope,
    identity: &OperationIdentity,
    expected: &PackCommitExpectation,
    head: &HeadUpdate,
    refs: &[RefUpdate],
    membership: MembershipDigest,
    packs: &[PlannedPack],
) -> RequestDigest {
    let fields = parent_fields(scope, identity, expected, head, refs, membership, packs);
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RequestDigest::of("core-pack-commit-plan-v1", &parts)
}

/// Versioned subset parent digest: separate domain, commit mode covered; the A3 parent stays whole-batch.
#[allow(clippy::too_many_arguments)]
fn parent_digest_subset(
    scope: &PackCommitScope,
    identity: &OperationIdentity,
    expected: &PackCommitExpectation,
    head: &HeadUpdate,
    refs: &[RefUpdate],
    membership: MembershipDigest,
    packs: &[PlannedPack],
    mode: CommitMode,
) -> RequestDigest {
    let mut fields = parent_fields(scope, identity, expected, head, refs, membership, packs);
    fields.push(mode.as_str().as_bytes().to_vec());
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RequestDigest::of("core-pack-commit-plan-subset-v1", &parts)
}

/// Semantic fields known before A3, shared by both plan domains (no attempt paths or artifact-set digest).
#[allow(clippy::too_many_arguments)]
fn parent_fields(
    scope: &PackCommitScope,
    identity: &OperationIdentity,
    expected: &PackCommitExpectation,
    head: &HeadUpdate,
    refs: &[RefUpdate],
    membership: MembershipDigest,
    packs: &[PlannedPack],
) -> Vec<Vec<u8>> {
    let mut fields: Vec<Vec<u8>> = Vec::new();
    for bytes in [
        scope.repository_id.as_bytes().as_slice(),
        scope.tenant_id.as_bytes(),
        scope.owner_id.as_bytes(),
        scope.object_format.as_str().as_bytes(),
        scope.history_incarnation.as_bytes(),
    ] {
        fields.push(bytes.to_vec());
    }
    fields.push(scope.authority_epoch.to_be_bytes().to_vec());
    fields.push(scope.group_epoch.to_be_bytes().to_vec());
    fields.push(identity.issuer_id().as_bytes().to_vec());
    fields.push(identity.lane().as_str().as_bytes().to_vec());
    fields.push(identity.sequence().to_be_bytes().to_vec());
    fields.push(identity.operation_id().as_bytes().to_vec());
    fields.push(expected.revision.to_be_bytes().to_vec());
    fields.push(expected.gate_digest.as_bytes().to_vec());
    fields.push(expected.mode.as_str().as_bytes().to_vec());
    match head {
        HeadUpdate::Keep => fields.push(b"keep".to_vec()),
        HeadUpdate::Retarget(name) => {
            fields.push(b"retarget".to_vec());
            fields.push(name.as_str().as_bytes().to_vec());
        }
    }
    fields.push((refs.len() as u64).to_be_bytes().to_vec());
    for update in refs {
        fields.push(update.name().as_str().as_bytes().to_vec());
        fields.push(update.precondition().canonical_tag().as_bytes().to_vec());
        fields.push(update.precondition().oid().map(GitOid::as_hex).unwrap_or_default().into_bytes());
        fields.push(update.target().canonical_tag().as_bytes().to_vec());
        fields.push(update.target().oid().map(GitOid::as_hex).unwrap_or_default().into_bytes());
    }
    fields.push(membership.digest().as_bytes().to_vec());
    fields.push((packs.len() as u64).to_be_bytes().to_vec());
    for pack in packs {
        fields.push(pack.pack_id.as_bytes().to_vec());
        fields.push(pack.registration_id.as_bytes().to_vec());
        for artifact in &pack.artifacts {
            fields.push(artifact.role.as_str().as_bytes().to_vec());
            fields.push(artifact.content.as_str().as_bytes().to_vec());
            fields.push(artifact.length.to_be_bytes().to_vec());
        }
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ref_store::IssuerLane;
    use crate::ref_store::core::types::{RefName, RefPrecondition, RefTarget};

    fn content(byte: u8) -> ContentDigest {
        ContentDigest::parse(hex::encode([byte; 32])).unwrap()
    }

    fn scope() -> PackCommitScope {
        PackCommitScope::new(
            Uuid::from_bytes([1; 16]),
            Uuid::from_bytes([2; 16]),
            Uuid::from_bytes([3; 16]),
            GitObjectFormat::Sha1,
            Uuid::from_bytes([4; 16]),
            1,
            1,
        )
        .unwrap()
    }

    fn identity() -> OperationIdentity {
        OperationIdentity::new(
            scope().repository_id(),
            Uuid::from_bytes([5; 16]),
            IssuerLane::new("lane").unwrap(),
            1,
            Uuid::from_bytes([6; 16]),
            RequestDigest::from_bytes([0; 32]),
        )
        .unwrap()
    }

    fn pack() -> PlannedPack {
        PlannedPack::new(
            Uuid::from_bytes([7; 16]),
            Uuid::from_bytes([8; 16]),
            PlannedArtifact::new(PackArtifactRole::Pack, content(1), 64).unwrap(),
            PlannedArtifact::new(PackArtifactRole::Idx, content(2), 16).unwrap(),
        )
        .unwrap()
    }

    fn refs() -> Vec<RefUpdate> {
        vec![RefUpdate::new(
            RefName::new("refs/heads/main").unwrap(),
            RefPrecondition::Absent,
            RefTarget::Oid(GitOid::Sha1([9; 20])),
        )]
    }

    fn plan(packs: Vec<PlannedPack>) -> Result<PackCommitPlan, PackCommitError> {
        PackCommitPlan::new(
            scope(),
            identity(),
            PackCommitExpectation::new(1, RequestDigest::from_bytes([4; 32]), PackMode::MetadataOnly).unwrap(),
            HeadUpdate::Keep,
            refs(),
            MembershipDigest::of(&[]),
            Vec::new(),
            packs,
        )
    }

    #[test]
    fn parent_digest_is_deterministic_and_covers_packs() {
        let first = plan(vec![]).unwrap();
        let second = plan(vec![]).unwrap();
        assert_eq!(first.parent_digest(), second.parent_digest());
        let with_pack = plan(vec![pack()]).unwrap();
        assert_ne!(first.parent_digest(), with_pack.parent_digest());
        assert_eq!(with_pack.identity().digest(), with_pack.parent_digest());
        assert_eq!(first.identity().digest(), first.parent_digest());
    }

    #[test]
    fn plans_reject_broken_pairs_and_bounds() {
        assert!(
            PlannedPack::new(
                Uuid::from_bytes([7; 16]),
                Uuid::from_bytes([8; 16]),
                PlannedArtifact::new(PackArtifactRole::Idx, content(1), 1).unwrap(),
                PlannedArtifact::new(PackArtifactRole::Idx, content(2), 1).unwrap(),
            )
            .is_err()
        );
        assert!(plan(vec![pack(); 9]).is_err());
        assert!(plan(vec![pack(), pack()]).is_err());
    }
}
