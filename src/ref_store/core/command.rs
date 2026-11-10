//! Exact old/new CAS command, canonical request digest and pre-registry
//! validation for the isolated metadata core.
//!
//! Validation here is deliberately pure and happens before `PgRefStore::begin`
//! is called: no request that cannot produce a bounded terminal, a unique batch
//! or a decodable HEAD can reach the operation registry or a ref row.
use super::super::contract::{OperationIdentity, RefStoreError, RequestDigest};
use super::contract::CommitMode;
use super::terminal::{CommitRejectCode, ensure_subset_terminal_budget, ensure_terminal_budget};
use super::types::{GitObjectFormat, GitOid, HeadUpdate, MAX_REFS_PER_COMMIT, RefUpdate, batch_prefix_conflict};
use std::collections::BTreeSet;
use uuid::Uuid;

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
                return Err(RefStoreError::InvalidIdentity(format!("duplicate ref {} in one commit", update.name())));
            }
            if let Some(oid) = update.precondition().oid()
                && oid.format() != object_format
            {
                return Err(RefStoreError::InvalidIdentity(
                    "old object id does not match the gate object format".into(),
                ));
            }
            if let Some(oid) = update.target().oid()
                && oid.format() != object_format
            {
                return Err(RefStoreError::InvalidIdentity(
                    "new object id does not match the gate object format".into(),
                ));
            }
        }
        if let HeadUpdate::Retarget(target) = &head
            && !target.is_branch()
        {
            return Err(RefStoreError::InvalidIdentity("HEAD must name a refs/heads/ branch".into()));
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
        let identity =
            OperationIdentity::new(repository_id, issuer_id, identity.lane().clone(), sequence, operation_id, digest)?;
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
    /// touched. Both commit modes are accepted: the mode is bound into the
    /// canonical digest and can never silently degrade into an atomic commit.
    ///
    /// - `Atomic` keeps the exact historical checks: any intrabatch prefix
    ///   conflict refuses the whole request, and the aggregate 64 KiB budget of
    ///   both possible outcomes is checked before `begin`/writes.
    /// - `AcceptedSubset` keeps the batch shape checks from `new` (1..=128 unique
    ///   names, format-exact oids) but must not reject an intrabatch
    ///   delete-parent/create-child pair up front: deterministic original-order
    ///   per-ref selection (`core::metadata_subset`, and the decided pack path)
    ///   decides it, so the pre-registry 64 KiB budget covers both the
    ///   mixed/committed and the all-rejected terminal shapes.
    pub fn validate(&self) -> Result<(), RefStoreError> {
        match self.mode {
            CommitMode::Atomic => {
                if let Some((left, right)) = batch_prefix_conflict(&self.refs) {
                    return Err(RefStoreError::InvalidIdentity(format!(
                        "ref prefix conflict inside one commit: {left} vs {right}"
                    )));
                }
                ensure_terminal_budget(self.identity.repository_id(), &self.refs)
            }
            CommitMode::AcceptedSubset => {
                ensure_subset_terminal_budget(self.identity.repository_id(), &self.refs, CommitRejectCode::NoRefApplied)
            }
        }
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
    use super::super::types::{RefName, RefPrecondition, RefTarget};
    use super::*;
    use crate::ref_store::IssuerLane;

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
    fn accepted_subset_passes_the_shared_checks_without_degrading_to_atomic() {
        let mut subset = request();
        subset.mode = CommitMode::AcceptedSubset;
        assert!(subset.validate().is_ok());
        assert_eq!(subset.mode(), CommitMode::AcceptedSubset);
        assert_eq!(CommitMode::AcceptedSubset.as_str(), "accepted_subset");
        // Accepted subset no longer blanket-rejects an intrabatch
        // delete-parent/create-child pair here: deterministic original-order
        // selection decides it per ref (`core::metadata_subset`). Atomic keeps
        // the exact historical intrabatch prefix refusal.
        let base = request();
        let prefixed = |mode: CommitMode| {
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
                mode,
                vec![update("refs/heads/x", None, Some(1)), update("refs/heads/x/y", None, Some(2))],
            )
            .unwrap()
        };
        assert!(prefixed(CommitMode::AcceptedSubset).validate().is_ok());
        assert!(prefixed(CommitMode::Atomic).validate().is_err());
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
    fn commit_validation_carries_the_terminal_budget() {
        let base = request();
        let long = |index: usize| format!("refs/heads/{index:03}{}", "a".repeat(1024 - "refs/heads/".len() - 3));
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
