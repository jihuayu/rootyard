//! Stored root rows and their strict decoding.
//!
//! Every decode validates only *shape* (bounded enum text, canonical digest width, non-nil ids, positive counts).
//! Semantic equality is re-derived by [`super::capture::RootCapture`] from the complete row set, so a partial or
//! inconsistent row set can never be mistaken for a valid capture.
use super::error::RootError;
use super::scope::RootPurpose;
use super::selector::RootSelectorKind;
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use crate::ref_store::core::pack_commit::{
    ArtifactLocator, ArtifactSetDigest, ContentDigest, PackArtifactRole, RegisteredArtifact, RegisteredPack,
};
use crate::ref_store::core::types::{GitObjectFormat, GitOid};
use std::str::FromStr;
use tokio_postgres::Row;
use uuid::Uuid;

fn database(message: &'static str) -> RootError {
    RootError::Store(RefStoreError::Database(message.into()))
}

fn digest(value: &str, what: &'static str) -> Result<RequestDigest, RootError> {
    RequestDigest::from_str(value).map_err(|_| database(what))
}

fn enum_text(value: String) -> Result<String, RootError> {
    if value.is_empty() || value.len() > 64 {
        return Err(database("stored roots enum text is not bounded"));
    }
    Ok(value)
}

/// The live core gate realm (read under `FOR UPDATE` for writes, `FOR SHARE` for byte reads).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct GateRealm {
    pub tenant_id: Uuid,
    pub object_format: GitObjectFormat,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
}

impl GateRealm {
    pub(super) fn from_row(row: &Row) -> Result<Self, RootError> {
        let format: String = row.get("object_format");
        Ok(Self {
            tenant_id: row.get("tenant_id"),
            object_format: GitObjectFormat::parse(&format)
                .map_err(|_| database("stored gate object format is invalid"))?,
            history_incarnation: row.get("history_incarnation"),
            authority_epoch: row.get("authority_epoch"),
            group_epoch: row.get("group_epoch"),
        })
    }
}

/// One root head row: current state, ABA fence and the bound register digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct HeadRow {
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: RootPurpose,
    pub business_intent_digest: String,
    pub register_digest: String,
    pub state: String,
    pub last_generation: i64,
}

impl HeadRow {
    pub(super) fn from_row(row: &Row) -> Result<Self, RootError> {
        let purpose: String = row.get("purpose");
        let state: String = enum_text(row.get("state"))?;
        if state != "active" && state != "released" {
            return Err(database("stored root head state is not active/released"));
        }
        let business_intent_digest: String = row.get("business_intent_digest");
        digest(&business_intent_digest, "stored root head business intent digest is invalid")?;
        let register_digest: String = row.get("register_digest");
        digest(&register_digest, "stored root head register digest is invalid")?;
        Ok(Self {
            tenant_id: row.get("tenant_id"),
            owner_id: row.get("owner_id"),
            purpose: RootPurpose::parse(&purpose)?,
            business_intent_digest,
            register_digest,
            state,
            last_generation: row.get("last_generation"),
        })
    }

    pub(super) fn is_active(&self) -> bool {
        self.state == "active" && self.last_generation == 1
    }

    pub(super) fn is_released(&self) -> bool {
        self.state == "released" && self.last_generation == 2
    }
}

/// One durable release tombstone (written before or after a capture).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TombstoneRow {
    pub generation: i64,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: RootPurpose,
    pub business_intent_digest: String,
    pub expected_register_digest: String,
    pub release_digest: String,
}

impl TombstoneRow {
    pub(super) fn from_row(row: &Row) -> Result<Self, RootError> {
        let purpose: String = row.get("purpose");
        let business_intent_digest: String = row.get("business_intent_digest");
        digest(&business_intent_digest, "stored root tombstone business intent digest is invalid")?;
        let expected_register_digest: String = row.get("expected_register_digest");
        digest(&expected_register_digest, "stored root tombstone register digest is invalid")?;
        let release_digest: String = row.get("release_digest");
        digest(&release_digest, "stored root tombstone release digest is invalid")?;
        Ok(Self {
            generation: row.get("generation"),
            tenant_id: row.get("tenant_id"),
            owner_id: row.get("owner_id"),
            purpose: RootPurpose::parse(&purpose)?,
            business_intent_digest,
            expected_register_digest,
            release_digest,
        })
    }
}

/// One retained mutation receipt row.
#[derive(Clone, Debug)]
pub(super) struct ReceiptRow {
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: RootPurpose,
    pub business_intent_digest: String,
    pub root_id: Uuid,
    pub generation: i64,
    pub action: super::receipt::RootAction,
    pub request_digest: String,
    pub body: serde_json::Value,
    pub created_at_unix_micros: i64,
}

impl ReceiptRow {
    pub(super) fn from_row(row: &Row) -> Result<Self, RootError> {
        let purpose: String = row.get("purpose");
        let action: String = row.get("action");
        let business_intent_digest: String = row.get("business_intent_digest");
        digest(&business_intent_digest, "stored root receipt business intent digest is invalid")?;
        Ok(Self {
            repository_id: row.get("repository_id"),
            tenant_id: row.get("tenant_id"),
            owner_id: row.get("owner_id"),
            purpose: RootPurpose::parse(&purpose)?,
            business_intent_digest,
            root_id: row.get("root_id"),
            generation: row.get("generation"),
            action: super::receipt::RootAction::parse(&action)?,
            request_digest: row.get("request_digest"),
            body: row.get("body"),
            created_at_unix_micros: row.get("created_at_unix_micros"),
        })
    }
}

/// One immutable capture header row (complete retained scope and digests).
#[derive(Clone, Debug)]
pub(super) struct CaptureRow {
    pub repository_id: Uuid,
    pub root_id: Uuid,
    pub generation: i64,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: RootPurpose,
    pub business_intent_digest: String,
    pub operation_id: Uuid,
    pub operation_digest: String,
    pub request_id: Uuid,
    pub selector_kind: RootSelectorKind,
    pub object_format: GitObjectFormat,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub source_snapshot_id: Uuid,
    pub source_pin_id: Uuid,
    pub source_pin_generation: i64,
    pub source_read_digest: String,
    pub gate_revision: i64,
    pub gate_digest: String,
    pub head_ref: String,
    pub head_oid: Option<String>,
    pub refs_digest: String,
    pub ref_count: i64,
    pub membership_digest: String,
    pub pack_set_digest: String,
    pub pack_count: i64,
    pub oid_count: i64,
    pub native_binding_digest: String,
    pub roots_revision: i64,
    pub register_digest: String,
}

impl CaptureRow {
    pub(super) fn from_row(row: &Row) -> Result<Self, RootError> {
        let purpose: String = row.get("purpose");
        let selector_kind: String = row.get("selector_kind");
        let object_format: String = row.get("object_format");
        let business_intent_digest: String = row.get("business_intent_digest");
        let operation_digest: String = row.get("operation_digest");
        let source_read_digest: String = row.get("source_read_digest");
        let gate_digest: String = row.get("gate_digest");
        let refs_digest: String = row.get("refs_digest");
        let membership_digest: String = row.get("membership_digest");
        let pack_set_digest: String = row.get("pack_set_digest");
        let native_binding_digest: String = row.get("native_binding_digest");
        let register_digest: String = row.get("register_digest");
        for (value, what) in [
            (&business_intent_digest, "stored root business intent digest is invalid"),
            (&operation_digest, "stored root operation digest is invalid"),
            (&source_read_digest, "stored root source read digest is invalid"),
            (&gate_digest, "stored root gate digest is invalid"),
            (&refs_digest, "stored root refs digest is invalid"),
            (&membership_digest, "stored root membership digest is invalid"),
            (&pack_set_digest, "stored root pack set digest is invalid"),
            (&native_binding_digest, "stored root native binding digest is invalid"),
            (&register_digest, "stored root register digest is invalid"),
        ] {
            digest(value, what)?;
        }
        Ok(Self {
            repository_id: row.get("repository_id"),
            root_id: row.get("root_id"),
            generation: row.get("generation"),
            tenant_id: row.get("tenant_id"),
            owner_id: row.get("owner_id"),
            purpose: RootPurpose::parse(&purpose)?,
            business_intent_digest,
            operation_id: row.get("operation_id"),
            operation_digest,
            request_id: row.get("request_id"),
            selector_kind: RootSelectorKind::parse(&selector_kind)?,
            object_format: GitObjectFormat::parse(&object_format)
                .map_err(|_| database("stored root object format is invalid"))?,
            history_incarnation: row.get("history_incarnation"),
            authority_epoch: row.get("authority_epoch"),
            group_epoch: row.get("group_epoch"),
            source_snapshot_id: row.get("source_snapshot_id"),
            source_pin_id: row.get("source_pin_id"),
            source_pin_generation: row.get("source_pin_generation"),
            source_read_digest,
            gate_revision: row.get("gate_revision"),
            gate_digest,
            head_ref: row.get("head_ref"),
            head_oid: row.get("head_oid"),
            refs_digest,
            ref_count: i64::from(row.get::<_, i32>("ref_count")),
            membership_digest,
            pack_set_digest,
            pack_count: i64::from(row.get::<_, i32>("pack_count")),
            oid_count: i64::from(row.get::<_, i32>("oid_count")),
            native_binding_digest,
            roots_revision: row.get("roots_revision"),
            register_digest,
        })
    }
}

/// One complete protected pack binding row (pack + both artifacts, fully self-contained locators).
#[derive(Clone, Debug)]
pub(super) struct PackRow {
    pub pack_id: Uuid,
    pub registration_id: Uuid,
    pub artifact_set_digest: String,
    pub joined_revision: i64,
    pub pack: StoredArtifact,
    pub idx: StoredArtifact,
}

/// One stored artifact identity plus its verified read-back result.
#[derive(Clone, Debug)]
pub(super) struct StoredArtifact {
    pub role: PackArtifactRole,
    pub slot: i32,
    pub hold_id: Uuid,
    pub storage_tenant_id: Uuid,
    pub authority_id: Uuid,
    pub authority_generation: i64,
    pub attempt_id: Uuid,
    pub namespace: String,
    pub sha256: String,
    pub length: i64,
    pub provider: String,
    pub backend_identity: String,
    pub verified_sha256: String,
    pub verified_length: i64,
}

impl PackRow {
    pub(super) fn from_row(row: &Row) -> Result<Self, RootError> {
        let artifact_set_digest: String = row.get("artifact_set_digest");
        digest(&artifact_set_digest, "stored root pack artifact set digest is invalid")?;
        let pack = StoredArtifact::from_row(row, PackArtifactRole::Pack, "pack")?;
        let idx = StoredArtifact::from_row(row, PackArtifactRole::Idx, "idx")?;
        Ok(Self {
            pack_id: row.get("pack_id"),
            registration_id: row.get("registration_id"),
            artifact_set_digest,
            joined_revision: row.get("joined_revision"),
            pack,
            idx,
        })
    }

    /// Rebuild the complete read-only registered pack from retained rows.
    ///
    /// [`RegisteredPack::new`] re-derives the artifact-set digest and refuses any identity that does not match,
    /// so a tampered or lossy locator can never become a native read input.
    pub(super) fn registered(&self) -> Result<RegisteredPack, RootError> {
        let artifacts = vec![self.pack.registered()?, self.idx.registered()?];
        let stored = ArtifactSetDigest::from_digest(digest(&self.artifact_set_digest, "pack artifact set digest")?);
        RegisteredPack::new(self.pack_id, self.registration_id, stored, artifacts, Some(self.joined_revision))
            .map_err(RootError::from)
    }
}

impl StoredArtifact {
    fn from_row(row: &Row, role: PackArtifactRole, prefix: &str) -> Result<Self, RootError> {
        let sha256: String = row.get(format!("{prefix}_sha256").as_str());
        let length: i64 = row.get(format!("{prefix}_length").as_str());
        let verified_sha256: String = row.get(format!("{prefix}_verified_sha256").as_str());
        let verified_length: i64 = row.get(format!("{prefix}_verified_length").as_str());
        digest(&sha256, "stored root pack artifact digest is invalid")?;
        digest(&verified_sha256, "stored root pack verified digest is invalid")?;
        if sha256 != verified_sha256 || length != verified_length {
            return Err(database("stored root pack verified read-back disagrees with its locator"));
        }
        let slot: i32 = row.get(format!("{prefix}_slot").as_str());
        let namespace: String = row.get(format!("{prefix}_namespace").as_str());
        let provider: String = row.get(format!("{prefix}_provider").as_str());
        let backend_identity: String = row.get(format!("{prefix}_backend_identity").as_str());
        Ok(Self {
            role,
            slot,
            hold_id: row.get(format!("{prefix}_hold_id").as_str()),
            storage_tenant_id: row.get(format!("{prefix}_storage_tenant_id").as_str()),
            authority_id: row.get(format!("{prefix}_authority_id").as_str()),
            authority_generation: row.get(format!("{prefix}_authority_generation").as_str()),
            attempt_id: row.get(format!("{prefix}_attempt_id").as_str()),
            namespace,
            sha256,
            length,
            provider,
            backend_identity,
            verified_sha256,
            verified_length,
        })
    }

    fn registered(&self) -> Result<RegisteredArtifact, RootError> {
        let length = u64::try_from(self.length).map_err(|_| database("stored root pack length is not positive"))?;
        let verified_length = u64::try_from(self.verified_length)
            .map_err(|_| database("stored root pack verified length is not positive"))?;
        let locator = ArtifactLocator::new(
            self.storage_tenant_id,
            self.authority_id,
            self.authority_generation,
            self.attempt_id,
            self.namespace.clone(),
            ContentDigest::parse(self.sha256.clone()).map_err(RootError::from)?,
            length,
        )
        .map_err(RootError::from)?;
        RegisteredArtifact::new(
            self.role,
            self.slot,
            self.hold_id,
            locator,
            self.provider.clone(),
            self.backend_identity.clone(),
            ContentDigest::parse(self.verified_sha256.clone()).map_err(RootError::from)?,
            verified_length,
        )
        .map_err(RootError::from)
    }
}

/// Parse one stored ref object id against the capture's object format.
pub(super) fn stored_oid(format: GitObjectFormat, oid: &str) -> Result<GitOid, RootError> {
    GitOid::parse(format, oid).map_err(|_| database("stored root object id is not canonical for the capture format"))
}
