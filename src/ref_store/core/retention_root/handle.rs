//! Root read handles: historical data-only identity, and the current-authority handle required for bytes.
//!
//! * [`RootRef`] is a pure data handle: it names one retained capture and needs no current authority. Metadata
//!   and receipts stay answerable after the source pin expired/was released and after the whole business
//!   repository was deleted.
//! * [`RootReadAuthority`] is the caller's asserted *current* realm for a byte read. It is not trusted: T2
//!   re-reads the live core gate row under `FOR SHARE` and refuses unless the gate still exists and its object
//!   format/history incarnation/authority epoch/group epoch/tenant match this handle and the stored root. A
//!   deleted repository therefore has no byte access, while its metadata stays readable.
use super::error::RootError;
use super::scope::RootsScope;
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use crate::ref_store::core::types::GitObjectFormat;
use std::str::FromStr;
use uuid::Uuid;

/// One retained capture: `(repository, root id, generation)`. Data only, never authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootRef {
    repository_id: Uuid,
    root_id: Uuid,
    generation: i64,
}

impl RootRef {
    pub fn new(repository_id: Uuid, root_id: Uuid, generation: i64) -> Result<Self, RootError> {
        if repository_id.is_nil() || root_id.is_nil() {
            return Err(RootError::Store(RefStoreError::InvalidIdentity(
                "root reference repository/root ids must be non-nil".into(),
            )));
        }
        if generation <= 0 {
            return Err(RootError::Store(RefStoreError::InvalidIdentity(
                "root reference generation must be positive".into(),
            )));
        }
        Ok(Self { repository_id, root_id, generation })
    }

    pub fn repository_id(&self) -> Uuid {
        self.repository_id
    }
    pub fn root_id(&self) -> Uuid {
        self.root_id
    }
    pub fn generation(&self) -> i64 {
        self.generation
    }
}

/// The caller's asserted current realm for a native byte read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootReadAuthority {
    repository_id: Uuid,
    tenant_id: Uuid,
    object_format: GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
}

impl RootReadAuthority {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository_id: Uuid,
        tenant_id: Uuid,
        object_format: GitObjectFormat,
        history_incarnation: Uuid,
        authority_epoch: i64,
        group_epoch: i64,
    ) -> Result<Self, RootError> {
        if repository_id.is_nil() || tenant_id.is_nil() || history_incarnation.is_nil() {
            return Err(RootError::RootAuthorityRequired(
                "a byte read must name the current repository, tenant and history incarnation",
            ));
        }
        if authority_epoch <= 0 || group_epoch <= 0 {
            return Err(RootError::RootAuthorityRequired("current authority epochs must be positive"));
        }
        Ok(Self { repository_id, tenant_id, object_format, history_incarnation, authority_epoch, group_epoch })
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
}

/// One native byte read request: a retained root plus the caller's current realm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootReadRequest {
    root: RootRef,
    authority: RootReadAuthority,
}

impl RootReadRequest {
    pub fn new(root: RootRef, authority: RootReadAuthority) -> Result<Self, RootError> {
        if root.repository_id() != authority.repository_id() {
            return Err(RootError::RootRealmMismatch("read request repository"));
        }
        Ok(Self { root, authority })
    }

    pub fn root(&self) -> RootRef {
        self.root
    }
    pub fn authority(&self) -> &RootReadAuthority {
        &self.authority
    }
}

/// Historical receipt lookup by global request id under the complete trusted scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootReceiptQuery {
    scope: RootsScope,
    request_id: Uuid,
}

impl RootReceiptQuery {
    pub fn new(scope: RootsScope, request_id: Uuid) -> Result<Self, RootError> {
        if request_id.is_nil() {
            return Err(RootError::Store(RefStoreError::InvalidIdentity(
                "root receipt request id must be non-nil".into(),
            )));
        }
        Ok(Self { scope, request_id })
    }

    pub fn scope(&self) -> &RootsScope {
        &self.scope
    }
    pub fn request_id(&self) -> Uuid {
        self.request_id
    }
}

/// Owner-independent helper: a stored root must agree with the queried scope on every trusted field.
pub(super) fn scope_matches(
    scope: &RootsScope,
    tenant_id: Uuid,
    owner_id: Uuid,
    purpose: &str,
    business_intent_digest: &str,
) -> Result<(), RootError> {
    if scope.tenant_id() != tenant_id {
        return Err(RootError::RootRealmMismatch("root tenant"));
    }
    if scope.owner_id() != owner_id {
        return Err(RootError::RootRealmMismatch("root owner"));
    }
    if scope.purpose().as_str() != purpose {
        return Err(RootError::RootRealmMismatch("root purpose"));
    }
    let stored = RequestDigest::from_str(business_intent_digest)
        .map_err(|_| RootError::Store(RefStoreError::Database("stored business intent digest is invalid".into())))?;
    if scope.business_intent_digest() != stored {
        return Err(RootError::RootRealmMismatch("root business intent"));
    }
    Ok(())
}
