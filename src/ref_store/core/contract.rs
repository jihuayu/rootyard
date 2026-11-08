//! Gate, commit command and version-check contract for the isolated
//! PostgreSQL metadata core.
//!
//! The operation registry in `src/ref_store/contract.rs` remains the only
//! owner of operation identity, cancellation and terminal replay. This module
//! adds the small typed gate/ref command whose canonical digest is derived
//! from every mutation field, including mode, epochs, expected revision and
//! HEAD. It is not an HTTP contract and does not create a serving authority.
//! Immutable terminals live in [`super::terminal`].
use super::super::contract::{OperationIdentity, RefStoreError, RequestDigest};
use super::terminal::ensure_terminal_budget;
use super::types::{GitObjectFormat, GitOid, HeadUpdate, MAX_REFS_PER_COMMIT, RefName, RefUpdate, batch_prefix_conflict};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreGateInit {
    repository_id: Uuid,
    tenant_id: Uuid,
    object_format: GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
    head_ref: RefName,
}

impl CoreGateInit {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository_id: Uuid,
        tenant_id: Uuid,
        object_format: GitObjectFormat,
        history_incarnation: Uuid,
        authority_epoch: i64,
        group_epoch: i64,
        head_ref: RefName,
    ) -> Result<Self, RefStoreError> {
        if repository_id.is_nil() || tenant_id.is_nil() || history_incarnation.is_nil() {
            return Err(RefStoreError::InvalidIdentity(
                "repository, tenant and history incarnation ids must be non-nil".into(),
            ));
        }
        if authority_epoch <= 0 || group_epoch <= 0 {
            return Err(RefStoreError::InvalidIdentity("gate epochs must be positive".into()));
        }
        if !head_ref.is_branch() {
            return Err(RefStoreError::InvalidIdentity("HEAD must name a refs/heads/ branch".into()));
        }
        Ok(Self {
            repository_id,
            tenant_id,
            object_format,
            history_incarnation,
            authority_epoch,
            group_epoch,
            head_ref,
        })
    }

    pub fn repository_id(&self) -> Uuid {
        self.repository_id
    }
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
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
    pub fn head_ref(&self) -> &RefName {
        &self.head_ref
    }
}

/// Durable gate state. `revision` is advanced only by a committed ref batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreGate {
    repository_id: Uuid,
    tenant_id: Uuid,
    object_format: GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
    head_ref: RefName,
    revision: i64,
    digest: RequestDigest,
}

impl CoreGate {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        repository_id: Uuid,
        tenant_id: Uuid,
        object_format: GitObjectFormat,
        history_incarnation: Uuid,
        authority_epoch: i64,
        group_epoch: i64,
        head_ref: RefName,
        revision: i64,
    ) -> Result<Self, RefStoreError> {
        if revision <= 0 {
            return Err(RefStoreError::Database("stored gate revision must be positive".into()));
        }
        let digest = gate_digest(
            repository_id,
            tenant_id,
            object_format,
            history_incarnation,
            authority_epoch,
            group_epoch,
            head_ref.as_str(),
            revision,
        );
        Ok(Self {
            repository_id,
            tenant_id,
            object_format,
            history_incarnation,
            authority_epoch,
            group_epoch,
            head_ref,
            revision,
            digest,
        })
    }

    pub fn repository_id(&self) -> Uuid {
        self.repository_id
    }
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
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
    pub fn head_ref(&self) -> &RefName {
        &self.head_ref
    }
    pub fn revision(&self) -> i64 {
        self.revision
    }
    pub fn digest(&self) -> &RequestDigest {
        &self.digest
    }

    pub fn version(&self) -> CoreGateVersion {
        CoreGateVersion {
            repository_id: self.repository_id,
            tenant_id: self.tenant_id,
            object_format: self.object_format,
            history_incarnation: self.history_incarnation,
            authority_epoch: self.authority_epoch,
            group_epoch: self.group_epoch,
            head_ref: self.head_ref.clone(),
            revision: self.revision,
            digest: self.digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreGateVersion {
    repository_id: Uuid,
    tenant_id: Uuid,
    object_format: GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
    head_ref: RefName,
    revision: i64,
    digest: RequestDigest,
}

impl CoreGateVersion {
    pub fn repository_id(&self) -> Uuid {
        self.repository_id
    }
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
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
    pub fn head_ref(&self) -> &RefName {
        &self.head_ref
    }
    pub fn revision(&self) -> i64 {
        self.revision
    }
    pub fn digest(&self) -> &RequestDigest {
        &self.digest
    }
}

/// A missing gate is `Unknown`, never "unchanged" and never an aborted commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VersionCheck {
    Unknown,
    Unchanged(CoreGateVersion),
    Changed(CoreGateVersion),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitMode {
    /// All refs apply or none do.
    Atomic,
    /// Typed but fail-closed in this increment: it must never silently degrade
    /// into an atomic commit.
    AcceptedSubset,
}

impl CommitMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Atomic => "atomic",
            Self::AcceptedSubset => "accepted_subset",
        }
    }
}

/// Exact old/new CAS command. Caller-supplied repository/issuer/lane/sequence/
/// operation identity fields and every mutation field are covered by the
/// canonical digest; the adapter never mints a new identity or digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitRefsRequest {
    identity: OperationIdentity,
    tenant_id: Uuid,
    object_format: GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
    expected_revision: i64,
    head: HeadUpdate,
    mode: CommitMode,
    refs: Vec<RefUpdate>,
    digest: RequestDigest,
}

impl CommitRefsRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository_id: Uuid,
        tenant_id: Uuid,
        issuer_id: Uuid,
        lane: super::super::contract::IssuerLane,
        sequence: i64,
        operation_id: Uuid,
        object_format: GitObjectFormat,
        history_incarnation: Uuid,
        authority_epoch: i64,
        group_epoch: i64,
        expected_revision: i64,
        head: HeadUpdate,
        mode: CommitMode,
        refs: Vec<RefUpdate>,
    ) -> Result<Self, RefStoreError> {
        if tenant_id.is_nil() || history_incarnation.is_nil() {
            return Err(RefStoreError::InvalidIdentity("tenant and history incarnation ids must be non-nil".into()));
        }
        if authority_epoch <= 0 || group_epoch <= 0 {
            return Err(RefStoreError::InvalidIdentity("gate epochs must be positive".into()));
        }
        if expected_revision <= 0 {
            return Err(RefStoreError::InvalidIdentity("expected gate revision must be positive".into()));
        }
        if refs.is_empty() || refs.len() > MAX_REFS_PER_COMMIT {
            return Err(RefStoreError::InvalidIdentity(format!(
                "a commit must contain 1..={MAX_REFS_PER_COMMIT} refs"
            )));
        }
        let mut names = BTreeSet::new();
        for update in &refs {
            if !names.insert(update.name().as_str()) {
                return Err(RefStoreError::InvalidIdentity(format!(
                    "duplicate ref {} in one commit",
                    update.name()
                )));
            }
            if let Some(oid) = update.precondition().oid() {
                if oid.format() != object_format {
                    return Err(RefStoreError::InvalidIdentity(
                        "old object id does not match the gate object format".into(),
                    ));
                }
            }
            if let Some(oid) = update.target().oid() {
                if oid.format() != object_format {
                    return Err(RefStoreError::InvalidIdentity(
                        "new object id does not match the gate object format".into(),
                    ));
                }
            }
        }
        if let HeadUpdate::Retarget(target) = &head {
            if !target.is_branch() {
                return Err(RefStoreError::InvalidIdentity("HEAD must name a refs/heads/ branch".into()));
            }
        }
        let identity = OperationIdentity::new(
            repository_id,
            issuer_id,
            lane,
            sequence,
            operation_id,
            RequestDigest::from_bytes([0; 32]),
        )?;
        let digest = commit_digest(
            &identity,
            tenant_id,
            object_format,
            history_incarnation,
            authority_epoch,
            group_epoch,
            expected_revision,
            &head,
            mode,
            &refs,
        );
        let identity = OperationIdentity::new(
            repository_id,
            issuer_id,
            identity.lane().clone(),
            sequence,
            operation_id,
            digest,
        )?;
        Ok(Self {
            identity,
            tenant_id,
            object_format,
            history_incarnation,
            authority_epoch,
            group_epoch,
            expected_revision,
            head,
            mode,
            refs,
            digest,
        })
    }

    /// Construction-level checks that must fail closed before the registry is
    /// touched. `accepted_subset` is intentionally unsupported until its
    /// per-ref terminal semantics and tests exist; it is not downgraded. The
    /// aggregate terminal budget of both possible outcomes is checked here, so
    /// no oversized terminal conversion can happen after `begin` or any write.
    pub fn validate(&self) -> Result<(), RefStoreError> {
        if self.mode == CommitMode::AcceptedSubset {
            return Err(RefStoreError::Unsupported("accepted_subset commit mode"));
        }
        if let Some((left, right)) = batch_prefix_conflict(&self.refs) {
            return Err(RefStoreError::InvalidIdentity(format!(
                "ref prefix conflict inside one commit: {left} vs {right}"
            )));
        }
        ensure_terminal_budget(self.identity.repository_id(), &self.refs)
    }

    pub fn identity(&self) -> &OperationIdentity {
        &self.identity
    }
    pub fn repository_id(&self) -> Uuid {
        self.identity.repository_id()
    }
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
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
    pub fn expected_revision(&self) -> i64 {
        self.expected_revision
    }
    pub fn head(&self) -> &HeadUpdate {
        &self.head
    }
    pub fn mode(&self) -> CommitMode {
        self.mode
    }
    pub fn refs(&self) -> &[RefUpdate] {
        &self.refs
    }
    pub fn digest(&self) -> &RequestDigest {
        &self.digest
    }
}

fn push_bytes(fields: &mut Vec<Vec<u8>>, value: impl AsRef<[u8]>) {
    fields.push(value.as_ref().to_vec());
}

fn push_i64(fields: &mut Vec<Vec<u8>>, value: i64) {
    fields.push(value.to_be_bytes().to_vec());
}

fn gate_digest(
    repository_id: Uuid,
    tenant_id: Uuid,
    object_format: GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
    head_ref: &str,
    revision: i64,
) -> RequestDigest {
    RequestDigest::of(
        "core-gate-version-v1",
        &[
            repository_id.as_bytes(),
            tenant_id.as_bytes(),
            object_format.as_str().as_bytes(),
            history_incarnation.as_bytes(),
            &authority_epoch.to_be_bytes(),
            &group_epoch.to_be_bytes(),
            head_ref.as_bytes(),
            &revision.to_be_bytes(),
        ],
    )
}

fn commit_digest(
    identity: &OperationIdentity,
    tenant_id: Uuid,
    object_format: GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
    expected_revision: i64,
    head: &HeadUpdate,
    mode: CommitMode,
    refs: &[RefUpdate],
) -> RequestDigest {
    let mut fields = Vec::new();
    push_bytes(&mut fields, identity.repository_id().as_bytes());
    push_bytes(&mut fields, identity.issuer_id().as_bytes());
    push_bytes(&mut fields, identity.lane().as_str().as_bytes());
    push_i64(&mut fields, identity.sequence());
    push_bytes(&mut fields, identity.operation_id().as_bytes());
    push_bytes(&mut fields, tenant_id.as_bytes());
    push_bytes(&mut fields, object_format.as_str().as_bytes());
    push_bytes(&mut fields, history_incarnation.as_bytes());
    push_i64(&mut fields, authority_epoch);
    push_i64(&mut fields, group_epoch);
    push_i64(&mut fields, expected_revision);
    match head {
        HeadUpdate::Keep => push_bytes(&mut fields, "keep"),
        HeadUpdate::Retarget(name) => {
            push_bytes(&mut fields, "retarget");
            push_bytes(&mut fields, name.as_str());
        }
    }
    push_bytes(&mut fields, mode.as_str());
    push_i64(&mut fields, refs.len() as i64);
    for update in refs {
        push_bytes(&mut fields, update.name().as_str());
        push_bytes(&mut fields, update.precondition().canonical_tag());
        push_bytes(&mut fields, update.precondition().oid().map(GitOid::as_hex).unwrap_or_default());
        push_bytes(&mut fields, update.target().canonical_tag());
        push_bytes(&mut fields, update.target().oid().map(GitOid::as_hex).unwrap_or_default());
    }
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RequestDigest::of("core-commit-refs-v1", &parts)
}

#[cfg(test)]
mod tests {
    use super::super::contract::IssuerLane;
    use super::super::types::{RefPrecondition, RefTarget};
    use super::*;

    fn format() -> GitObjectFormat {
        GitObjectFormat::Sha1
    }

    fn oid(byte: u8) -> GitOid {
        GitOid::Sha1([byte; 20])
    }

    fn update(name: &str, old: Option<u8>, new: Option<u8>) -> RefUpdate {
        let precondition = match old {
            Some(byte) => RefPrecondition::Present(oid(byte)),
            None => RefPrecondition::Absent,
        };
        let target = match new {
            Some(byte) => RefTarget::Oid(oid(byte)),
            None => RefTarget::Delete,
        };
        RefUpdate::new(RefName::new(name).unwrap(), precondition, target)
    }

    fn request() -> CommitRefsRequest {
        CommitRefsRequest::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            IssuerLane::new("lane").unwrap(),
            1,
            Uuid::new_v4(),
            format(),
            Uuid::new_v4(),
            3,
            4,
            2,
            HeadUpdate::Keep,
            CommitMode::Atomic,
            vec![update("refs/heads/main", None, Some(1))],
        )
        .unwrap()
    }

    #[test]
    fn canonical_digest_covers_every_mutation_field() {
        let base = request();
        let base_digest = *base.digest();
        let another = request();
        assert_ne!(base_digest, *another.digest(), "random identity fields must change the digest");

        let same = CommitRefsRequest::new(
            base.repository_id(),
            base.tenant_id(),
            base.identity().issuer_id(),
            base.identity().lane().clone(),
            base.identity().sequence(),
            base.identity().operation_id(),
            base.object_format(),
            base.history_incarnation(),
            base.authority_epoch(),
            base.group_epoch(),
            base.expected_revision(),
            base.head().clone(),
            base.mode(),
            base.refs().to_vec(),
        )
        .unwrap();
        assert_eq!(base_digest, *same.digest());
        assert_eq!(base.identity(), same.identity());

        let variants = [
            CommitRefsRequest::new(
                base.repository_id(),
                Uuid::new_v4(),
                base.identity().issuer_id(),
                base.identity().lane().clone(),
                base.identity().sequence(),
                base.identity().operation_id(),
                base.object_format(),
                base.history_incarnation(),
                base.authority_epoch(),
                base.group_epoch(),
                base.expected_revision(),
                base.head().clone(),
                base.mode(),
                base.refs().to_vec(),
            )
            .unwrap(),
            CommitRefsRequest::new(
                base.repository_id(),
                base.tenant_id(),
                base.identity().issuer_id(),
                base.identity().lane().clone(),
                base.identity().sequence(),
                base.identity().operation_id(),
                base.object_format(),
                base.history_incarnation(),
                base.authority_epoch(),
                base.group_epoch(),
                base.expected_revision() + 1,
                base.head().clone(),
                base.mode(),
                base.refs().to_vec(),
            )
            .unwrap(),
            CommitRefsRequest::new(
                base.repository_id(),
                base.tenant_id(),
                base.identity().issuer_id(),
                base.identity().lane().clone(),
                base.identity().sequence(),
                base.identity().operation_id(),
                base.object_format(),
                base.history_incarnation(),
                base.authority_epoch(),
                base.group_epoch(),
                base.expected_revision(),
                HeadUpdate::Retarget(RefName::new("refs/heads/main").unwrap()),
                base.mode(),
                base.refs().to_vec(),
            )
            .unwrap(),
            CommitRefsRequest::new(
                base.repository_id(),
                base.tenant_id(),
                base.identity().issuer_id(),
                base.identity().lane().clone(),
                base.identity().sequence(),
                base.identity().operation_id(),
                base.object_format(),
                base.history_incarnation(),
                base.authority_epoch(),
                base.group_epoch(),
                base.expected_revision(),
                base.head().clone(),
                CommitMode::AcceptedSubset,
                base.refs().to_vec(),
            )
            .unwrap(),
            CommitRefsRequest::new(
                base.repository_id(),
                base.tenant_id(),
                base.identity().issuer_id(),
                base.identity().lane().clone(),
                base.identity().sequence(),
                base.identity().operation_id(),
                base.object_format(),
                base.history_incarnation(),
                base.authority_epoch(),
                base.group_epoch(),
                base.expected_revision(),
                base.head().clone(),
                base.mode(),
                vec![update("refs/heads/main", Some(1), Some(2))],
            )
            .unwrap(),
        ];
        for variant in variants {
            assert_ne!(base_digest, *variant.digest());
        }
    }

    #[test]
    fn accepted_subset_fails_closed_instead_of_becoming_atomic() {
        let mut subset = request();
        subset.mode = CommitMode::AcceptedSubset;
        assert!(matches!(subset.validate(), Err(RefStoreError::Unsupported(_))));
        assert_eq!(CommitMode::AcceptedSubset.as_str(), "accepted_subset");
    }

    #[test]
    fn batch_prefix_conflicts_and_duplicates_are_rejected_before_registry_use() {
        let base = request();
        let duplicate = CommitRefsRequest::new(
            base.repository_id(),
            base.tenant_id(),
            base.identity().issuer_id(),
            base.identity().lane().clone(),
            base.identity().sequence(),
            base.identity().operation_id(),
            base.object_format(),
            base.history_incarnation(),
            base.authority_epoch(),
            base.group_epoch(),
            base.expected_revision(),
            base.head().clone(),
            base.mode(),
            vec![update("refs/heads/x", None, Some(1)), update("refs/heads/x", Some(1), Some(2))],
        );
        assert!(duplicate.is_err());

        let prefix = CommitRefsRequest::new(
            base.repository_id(),
            base.tenant_id(),
            base.identity().issuer_id(),
            base.identity().lane().clone(),
            base.identity().sequence(),
            base.identity().operation_id(),
            base.object_format(),
            base.history_incarnation(),
            base.authority_epoch(),
            base.group_epoch(),
            base.expected_revision(),
            base.head().clone(),
            base.mode(),
            vec![update("refs/heads/x", None, Some(1)), update("refs/heads/x/y", None, Some(2))],
        )
        .unwrap();
        assert!(prefix.validate().is_err());
    }

    #[test]
    fn gate_requires_non_nil_identity_and_positive_epochs() {
        let head = RefName::new("refs/heads/main").unwrap();
        assert!(
            CoreGateInit::new(Uuid::nil(), Uuid::new_v4(), format(), Uuid::new_v4(), 1, 1, head.clone()).is_err()
        );
        assert!(
            CoreGateInit::new(Uuid::new_v4(), Uuid::new_v4(), format(), Uuid::new_v4(), 0, 1, head.clone()).is_err()
        );
        assert!(CoreGateInit::new(Uuid::new_v4(), Uuid::new_v4(), format(), Uuid::new_v4(), 1, 1, head).is_ok());
    }

    #[test]
    fn commit_validation_carries_the_terminal_budget() {
        let base = request();
        let long = |index: usize| {
            format!("refs/heads/{index:03}{}", "a".repeat(1024 - "refs/heads/".len() - 3))
        };
        let oversized = CommitRefsRequest::new(
            base.repository_id(),
            base.tenant_id(),
            base.identity().issuer_id(),
            base.identity().lane().clone(),
            base.identity().sequence(),
            base.identity().operation_id(),
            base.object_format(),
            base.history_incarnation(),
            base.authority_epoch(),
            base.group_epoch(),
            base.expected_revision(),
            base.head().clone(),
            base.mode(),
            (0..128).map(|index| update(&long(index), None, Some(1))).collect(),
        )
        .unwrap();
        assert!(matches!(
            oversized.validate(),
            Err(RefStoreError::InvalidIdentity(ref message)) if message.contains("64 KiB")
        ));
    }
}
