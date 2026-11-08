//! Gate, commit command and version-check contract for the isolated
//! PostgreSQL metadata core.
//!
//! The operation registry in `src/ref_store/contract.rs` remains the only
//! owner of operation identity, cancellation and terminal replay. This module
//! adds the small typed gate/ref command whose canonical digest is derived
//! from every mutation field, including mode, epochs, expected revision and
//! HEAD. It is not an HTTP contract and does not create a serving authority.
//! Immutable terminals live in [`super::terminal`].
use super::super::contract::{RefStoreError, RequestDigest};
use super::types::{GitObjectFormat, RefName};
use serde::{Deserialize, Serialize};
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

/// Canonical digest over every durable gate field. A changed epoch, HEAD or revision
/// is a different gate proof, never an in-place edit.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn format() -> GitObjectFormat {
        GitObjectFormat::Sha1
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
}
