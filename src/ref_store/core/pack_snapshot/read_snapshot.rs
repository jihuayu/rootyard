//! The sealed A5a read result: one complete, immutable, registered-membership
//! snapshot value.
//!
//! [`PackReadSnapshot`] has private fields, no public constructor, no
//! `Serialize`/`Deserialize` and no unchecked factory, so it can only be built by
//! the PostgreSQL adapter after it re-derived every digest from the stored rows
//! and proved the live pin generation/lease under the gate lock.
//!
//! What it does claim: the complete captured ref set, HEAD, the exact gate
//! revision/digest/mode and every registered pack membership (full locator,
//! provider, backend identity, verified sha256/length and artifact-set digest)
//! captured atomically under that one gate lock.
//!
//! What it does **not** claim: current Blob bytes, native Git object closure,
//! any serving cutover or write authority. `complete_git_read_snapshot()` stays
//! `false` until A5b performs the verified byte/native read outside every PG
//! lease.
use super::super::pack_commit::{CapturedRef, RegisteredPack, refs_digest};
use super::super::snapshot_contract::{MAX_SNAPSHOT_PACKS, MAX_SNAPSHOT_REFS, MetadataSnapshotScope};
use super::contract::{PACK_MODE_VERIFIED, READ_MATERIALIZATION_DIGEST_DOMAIN, READ_RESULT_DIGEST_DOMAIN};
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use std::collections::BTreeSet;
use std::time::SystemTime;
use uuid::Uuid;

/// Every field needed to build one sealed read result. The adapter fills it from
/// locked/re-derived rows only.
pub(super) struct ReadSnapshotParts {
    pub snapshot_id: Uuid,
    pub pin_id: Uuid,
    pub pin_generation: i64,
    pub scope: MetadataSnapshotScope,
    pub gate_revision: i64,
    pub gate_digest: String,
    pub head_ref: String,
    pub head_oid: Option<String>,
    pub refs: Vec<CapturedRef>,
    pub packs: Vec<RegisteredPack>,
    pub membership_digest: String,
    pub snapshot_digest: String,
    pub logical_bytes: i64,
    pub expires_at_unix_micros: i64,
}

/// One complete registered-membership snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackReadSnapshot {
    snapshot_id: Uuid,
    pin_id: Uuid,
    pin_generation: i64,
    scope: MetadataSnapshotScope,
    gate_revision: i64,
    gate_digest: String,
    head_ref: String,
    head_oid: Option<String>,
    refs: Vec<CapturedRef>,
    packs: Vec<RegisteredPack>,
    membership_digest: String,
    snapshot_digest: String,
    source: ReadSnapshotSourceKind,
    read_digest: RequestDigest,
    logical_bytes: i64,
    expires_at_unix_micros: i64,
}

/// Which pin family produced a [`PackReadSnapshot`].
///
/// The two families are deliberately disjoint: the durable A5a family
/// (`ref_store_core_snapshots`/`ref_store_core_pins`, retained, permanent,
/// 64 per repository) and the transient migration-146 serving read pin (bounded,
/// deleted on release, reclaimed after expiry). The kind is bound into the A5b
/// materialization digest, so a value from one family can never be revalidated,
/// materialized or retained as the other.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadSnapshotSourceKind {
    /// Durable, retained A5a snapshot + durable pin.
    RetainedDurable,
    /// Bounded transient migration-146 serving read pin.
    ServingTransient,
}

impl ReadSnapshotSourceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RetainedDurable => "retained_durable",
            Self::ServingTransient => "serving_transient",
        }
    }
}

impl PackReadSnapshot {
    /// The retained durable A5a constructor (unchanged semantics).
    pub(super) fn new(parts: ReadSnapshotParts) -> Result<Self, RefStoreError> {
        Self::build(parts, ReadSnapshotSourceKind::RetainedDurable)
    }

    /// The bounded transient serving read constructor. Still private to the
    /// pack-snapshot subtree: no adapter outside it can mint a byte proof.
    pub(super) fn new_serving_transient(parts: ReadSnapshotParts) -> Result<Self, RefStoreError> {
        Self::build(parts, ReadSnapshotSourceKind::ServingTransient)
    }

    fn build(parts: ReadSnapshotParts, source: ReadSnapshotSourceKind) -> Result<Self, RefStoreError> {
        if parts.snapshot_id.is_nil() || parts.pin_id.is_nil() || parts.pin_generation <= 0 {
            return Err(RefStoreError::Database("pack read snapshot identity is invalid".into()));
        }
        if parts.refs.len() > MAX_SNAPSHOT_REFS {
            return Err(RefStoreError::MetadataSnapshotTooLarge {
                ref_count: parts.refs.len(),
                max_refs: MAX_SNAPSHOT_REFS,
            });
        }
        if parts.packs.is_empty() || parts.packs.len() > MAX_SNAPSHOT_PACKS {
            return Err(RefStoreError::MetadataSnapshotTooLarge {
                ref_count: parts.packs.len(),
                max_refs: MAX_SNAPSHOT_PACKS,
            });
        }
        let mut refs = parts.refs;
        refs.sort();
        let mut names = BTreeSet::new();
        if !refs.iter().all(|reference| names.insert(reference.name().to_owned())) {
            return Err(RefStoreError::Database("pack read snapshot contains a duplicate ref name".into()));
        }
        let mut packs = parts.packs;
        packs.sort_by_key(RegisteredPack::pack_id);
        let mut pack_ids = BTreeSet::new();
        if !packs.iter().all(|pack| pack_ids.insert(pack.pack_id())) {
            return Err(RefStoreError::Database("pack read snapshot contains a duplicate pack id".into()));
        }
        let read_digest = RequestDigest::of(
            READ_RESULT_DIGEST_DOMAIN,
            &[
                parts.snapshot_id.as_bytes(),
                parts.pin_id.as_bytes(),
                &parts.pin_generation.to_be_bytes(),
                &parts.gate_revision.to_be_bytes(),
                parts.gate_digest.as_bytes(),
                PACK_MODE_VERIFIED.as_bytes(),
                parts.snapshot_digest.as_bytes(),
                parts.membership_digest.as_bytes(),
            ],
        );
        Ok(Self {
            snapshot_id: parts.snapshot_id,
            pin_id: parts.pin_id,
            pin_generation: parts.pin_generation,
            scope: parts.scope,
            gate_revision: parts.gate_revision,
            gate_digest: parts.gate_digest,
            head_ref: parts.head_ref,
            head_oid: parts.head_oid,
            refs,
            packs,
            membership_digest: parts.membership_digest,
            snapshot_digest: parts.snapshot_digest,
            source,
            read_digest,
            logical_bytes: parts.logical_bytes,
            expires_at_unix_micros: parts.expires_at_unix_micros,
        })
    }

    /// Which pin family produced this value. The retained durable path stays
    /// [`ReadSnapshotSourceKind::RetainedDurable`]; the bounded transient serving
    /// path is [`ReadSnapshotSourceKind::ServingTransient`] and must be
    /// revalidated through the migration-146 pin, never the durable pin SQL.
    pub fn source_kind(&self) -> ReadSnapshotSourceKind {
        self.source
    }

    pub fn snapshot_id(&self) -> Uuid {
        self.snapshot_id
    }
    pub fn pin_id(&self) -> Uuid {
        self.pin_id
    }
    pub fn pin_generation(&self) -> i64 {
        self.pin_generation
    }
    pub fn scope(&self) -> &MetadataSnapshotScope {
        &self.scope
    }
    pub fn repository_id(&self) -> Uuid {
        self.scope.repository_id()
    }
    pub fn tenant_id(&self) -> Uuid {
        self.scope.tenant_id()
    }
    pub fn owner_id(&self) -> Uuid {
        self.scope.owner_id()
    }
    pub fn gate_revision(&self) -> i64 {
        self.gate_revision
    }
    pub fn gate_digest_hex(&self) -> &str {
        &self.gate_digest
    }
    pub fn pack_mode(&self) -> &'static str {
        PACK_MODE_VERIFIED
    }
    pub fn head_ref(&self) -> &str {
        &self.head_ref
    }
    pub fn head_oid_hex(&self) -> Option<&str> {
        self.head_oid.as_deref()
    }
    /// The complete captured ref set, sorted by name, unique, `<= 4096` rows.
    pub fn refs(&self) -> &[CapturedRef] {
        &self.refs
    }
    pub fn ref_count(&self) -> i64 {
        i64::try_from(self.refs.len()).unwrap_or(i64::MAX)
    }
    /// The complete registered pack set, sorted by pack id, unique, `1..=16`.
    pub fn packs(&self) -> &[RegisteredPack] {
        &self.packs
    }
    pub fn pack_count(&self) -> i64 {
        i64::try_from(self.packs.len()).unwrap_or(i64::MAX)
    }
    pub fn membership_digest_hex(&self) -> &str {
        &self.membership_digest
    }
    /// The capture-time canonical digest stored on the immutable header.
    pub fn snapshot_digest_hex(&self) -> &str {
        &self.snapshot_digest
    }
    /// The per-read canonical digest: the stored capture digest plus the exact
    /// pin id/generation this value was read under.
    pub fn read_digest_hex(&self) -> String {
        self.read_digest.as_hex()
    }
    /// Complete A5b canonical binding. Unlike the narrower A5a `read_digest`
    /// (which is kept for A5a compatibility and omits scope/expiry), this binds
    /// the full historical scope, snapshot/pin id, generation and expiry,
    /// snapshot digest, refs+HEAD, membership and every full pack identity
    /// digest. T2 recomputes it and requires exact equality before a public
    /// materialized view may exist.
    pub(in crate::ref_store::core) fn materialization_digest(&self) -> RequestDigest {
        let mut fields: Vec<Vec<u8>> = vec![
            self.read_digest.as_bytes().to_vec(),
            self.source.as_str().as_bytes().to_vec(),
            self.scope.repository_id().as_bytes().to_vec(),
            self.scope.tenant_id().as_bytes().to_vec(),
            self.scope.owner_id().as_bytes().to_vec(),
            self.scope.purpose().as_str().as_bytes().to_vec(),
            self.scope.object_format().as_str().as_bytes().to_vec(),
            self.scope.history_incarnation().as_bytes().to_vec(),
            self.scope.authority_epoch().to_be_bytes().to_vec(),
            self.scope.group_epoch().to_be_bytes().to_vec(),
            self.snapshot_id.as_bytes().to_vec(),
            self.pin_id.as_bytes().to_vec(),
            self.pin_generation.to_be_bytes().to_vec(),
            self.expires_at_unix_micros.to_be_bytes().to_vec(),
            self.gate_revision.to_be_bytes().to_vec(),
            self.gate_digest.as_bytes().to_vec(),
            PACK_MODE_VERIFIED.as_bytes().to_vec(),
            self.snapshot_digest.as_bytes().to_vec(),
            self.membership_digest.as_bytes().to_vec(),
            self.head_ref.as_bytes().to_vec(),
            if self.head_oid.is_some() { b"head-oid-present".to_vec() } else { b"head-oid-absent".to_vec() },
            self.head_oid.clone().unwrap_or_default().into_bytes(),
            self.ref_count().to_be_bytes().to_vec(),
            refs_digest(&self.refs).as_bytes().to_vec(),
            self.pack_count().to_be_bytes().to_vec(),
            self.logical_bytes.to_be_bytes().to_vec(),
        ];
        for pack in &self.packs {
            fields.push(pack.pack_id().as_bytes().to_vec());
            fields.push(pack.registration_id().as_bytes().to_vec());
            fields.push(pack.artifact_set_digest().digest().as_bytes().to_vec());
        }
        let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
        RequestDigest::of(READ_MATERIALIZATION_DIGEST_DOMAIN, &parts)
    }

    pub fn logical_bytes(&self) -> i64 {
        self.logical_bytes
    }
    pub fn expires_at_unix_micros(&self) -> i64 {
        self.expires_at_unix_micros
    }
    pub fn expires_at(&self) -> Result<SystemTime, RefStoreError> {
        super::super::snapshot_contract::expires_at_from_micros(self.expires_at_unix_micros)
    }

    /// A5a is a durable metadata foundation: registered membership only.
    pub const fn complete_registered_pack_membership(&self) -> bool {
        true
    }

    /// Never `true` in A5a. A5b must verify current Blob bytes and native Git
    /// closure before any value may claim a complete Git read snapshot.
    pub const fn complete_git_read_snapshot(&self) -> bool {
        false
    }

    pub const fn packs_complete(&self) -> bool {
        true
    }
}
