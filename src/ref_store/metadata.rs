//! Shared, bounded metadata snapshot/pin vocabulary.
//!
//! These types are shared by the metadata error/capability contract and the
//! internal core modules. Purpose and quota scope/resource are closed enums:
//! free text is never accepted, and a stored value that is not one of the
//! listed variants is a database-integrity error rather than a silent default.
use super::contract::RefStoreError;
use serde::{Deserialize, Serialize};

/// Bounded, trusted purpose of a metadata snapshot/pin.
///
/// This is an internal, enumerable purpose — never an HTTP authentication
/// substitute and never free text. An unknown purpose is rejected at the
/// contract boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataPinPurpose {
    Verification,
    Maintenance,
    Backup,
    Export,
    OperatorAudit,
}

impl MetadataPinPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verification => "verification",
            Self::Maintenance => "maintenance",
            Self::Backup => "backup",
            Self::Export => "export",
            Self::OperatorAudit => "operator_audit",
        }
    }

    pub fn parse(value: &str) -> Result<Self, RefStoreError> {
        match value {
            "verification" => Ok(Self::Verification),
            "maintenance" => Ok(Self::Maintenance),
            "backup" => Ok(Self::Backup),
            "export" => Ok(Self::Export),
            "operator_audit" => Ok(Self::OperatorAudit),
            _ => Err(RefStoreError::Database("stored metadata pin purpose is not a bounded enum value".into())),
        }
    }
}

/// The single action domain of the successful metadata-mutation receipt ledger.
/// One request-id space covers create/renew/release with identical conflict
/// behaviour; the action is part of every canonical request digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataMutationAction {
    Create,
    Renew,
    Release,
}

impl MetadataMutationAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Renew => "renew",
            Self::Release => "release",
        }
    }

    pub fn parse(value: &str) -> Result<Self, RefStoreError> {
        match value {
            "create" => Ok(Self::Create),
            "renew" => Ok(Self::Renew),
            "release" => Ok(Self::Release),
            _ => Err(RefStoreError::Database("stored metadata receipt action is not a known action".into())),
        }
    }
}

/// Admission-usage scope that refused a metadata mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataQuotaScope {
    Repository,
    Tenant,
}

/// Retained admission resource named by an explicit backpressure error. These
/// are logical admission bounds, never physical disk/WAL/RSS quotas.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataQuotaResource {
    Snapshots,
    SnapshotRefs,
    LogicalBytes,
    Receipts,
}

impl MetadataQuotaScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Repository => "repository",
            Self::Tenant => "tenant",
        }
    }
}

impl MetadataQuotaResource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Snapshots => "snapshots",
            Self::SnapshotRefs => "snapshot_refs",
            Self::LogicalBytes => "logical_bytes",
            Self::Receipts => "receipts",
        }
    }
}
