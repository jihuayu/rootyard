//! The trusted roots scope and its bounded purpose enumeration.
//!
//! A root scope is a *historical* internal identity, not an HTTP/authorization grant. The owner is always the
//! source pin owner; a caller cannot widen or re-own a root by naming another owner. `business_intent_digest`
//! is mandatory: an operator must state, as a canonical digest, why the bytes are being protected.
//!
//! `purpose` is a bounded enum. It is independent of the source pin purpose (a `verification` pin may anchor a
//! `ci` root): only the owner/tenant/repository must agree with the source snapshot.
use super::error::RootError;
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use crate::ref_store::core::types::GitObjectFormat;
use std::str::FromStr;
use uuid::Uuid;

/// Bounded root purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootPurpose {
    Ci,
    Workspace,
    PullRequest,
    Namespace,
    Backup,
    Export,
    OperatorAudit,
}

impl RootPurpose {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ci => "ci",
            Self::Workspace => "workspace",
            Self::PullRequest => "pull_request",
            Self::Namespace => "namespace",
            Self::Backup => "backup",
            Self::Export => "export",
            Self::OperatorAudit => "operator_audit",
        }
    }

    /// Parse a stored purpose. An unknown value is database corruption, never a caller error.
    pub fn parse(value: &str) -> Result<Self, RootError> {
        match value {
            "ci" => Ok(Self::Ci),
            "workspace" => Ok(Self::Workspace),
            "pull_request" => Ok(Self::PullRequest),
            "namespace" => Ok(Self::Namespace),
            "backup" => Ok(Self::Backup),
            "export" => Ok(Self::Export),
            "operator_audit" => Ok(Self::OperatorAudit),
            _ => {
                Err(RootError::Store(RefStoreError::Database("stored root purpose is not a bounded enum value".into())))
            }
        }
    }
}

/// The complete trusted scope of one root capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootsScope {
    repository_id: Uuid,
    tenant_id: Uuid,
    owner_id: Uuid,
    purpose: RootPurpose,
    business_intent_digest: RequestDigest,
    object_format: GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
}

impl RootsScope {
    /// Build one scope. Every id must be non-nil, both epochs positive, and the business intent digest must be
    /// a canonical lowercase sha256 hex value.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository_id: Uuid,
        tenant_id: Uuid,
        owner_id: Uuid,
        purpose: RootPurpose,
        business_intent_digest: &str,
        object_format: GitObjectFormat,
        history_incarnation: Uuid,
        authority_epoch: i64,
        group_epoch: i64,
    ) -> Result<Self, RootError> {
        if repository_id.is_nil() || tenant_id.is_nil() || owner_id.is_nil() || history_incarnation.is_nil() {
            return Err(RootError::Store(RefStoreError::InvalidIdentity(
                "root scope repository, tenant, owner and history ids must be non-nil".into(),
            )));
        }
        if authority_epoch <= 0 || group_epoch <= 0 {
            return Err(RootError::Store(RefStoreError::InvalidIdentity(
                "root scope gate epochs must be positive".into(),
            )));
        }
        let business_intent_digest = RequestDigest::from_str(business_intent_digest).map_err(|_| {
            RootError::Store(RefStoreError::InvalidIdentity(
                "root business intent digest must be lowercase sha256 hex".into(),
            ))
        })?;
        Ok(Self {
            repository_id,
            tenant_id,
            owner_id,
            purpose,
            business_intent_digest,
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
    pub fn purpose(&self) -> RootPurpose {
        self.purpose
    }
    pub fn business_intent_digest(&self) -> RequestDigest {
        self.business_intent_digest
    }
    pub fn business_intent_hex(&self) -> String {
        self.business_intent_digest.as_hex()
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
