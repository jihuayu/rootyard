//! Immutable per-ref and per-pack facts produced by the private native facts
//! engine.
//!
//! These values are data only: none of them grants write/publish authority, and
//! none can be turned into a [`super::VerifiedPublicationFacts`] (that type lives
//! in the native engine module and has no external constructor). Every
//! "verified"/"present"/"fast-forward" field is set from an actual native Git or
//! file-bytes observation, never from a caller-supplied boolean.
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::types::RefName;
use uuid::Uuid;

/// The Git object kind native Git reported for one probed object id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GitObjectKind {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl GitObjectKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Tree => "tree",
            Self::Blob => "blob",
            Self::Tag => "tag",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "commit" => Some(Self::Commit),
            "tree" => Some(Self::Tree),
            "blob" => Some(Self::Blob),
            "tag" => Some(Self::Tag),
            _ => None,
        }
    }
}

/// One parsed Git LFS pointer together with the byte evidence the native engine
/// actually gathered for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LfsPointerFact {
    path: String,
    oid_hex: String,
    size: u64,
    durable: bool,
    bytes_verified: bool,
}

impl LfsPointerFact {
    pub(crate) fn new(path: String, oid_hex: String, size: u64, durable: bool, bytes_verified: bool) -> Self {
        Self { path, oid_hex, size, durable, bytes_verified }
    }

    pub(crate) fn oid_hex(&self) -> &str {
        &self.oid_hex
    }
}

/// Native facts for exactly one planned ref update, in original plan order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RefFacts {
    name: RefName,
    old_oid_hex: Option<String>,
    target_oid_hex: Option<String>,
    target_present: Option<bool>,
    target_kind: Option<GitObjectKind>,
    branch_target_is_commit: Option<bool>,
    fast_forward: Option<bool>,
    changed_paths: Vec<String>,
    changed_paths_complete: bool,
    lfs: Vec<LfsPointerFact>,
    lfs_failure: Option<&'static str>,
}

impl RefFacts {
    /// Native-engine constructor. No validation is skipped: the caller must pass
    /// the exact name/oids of the plan ref and the observed native values.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        name: RefName,
        old_oid_hex: Option<String>,
        target_oid_hex: Option<String>,
        target_present: Option<bool>,
        target_kind: Option<GitObjectKind>,
        branch_target_is_commit: Option<bool>,
        fast_forward: Option<bool>,
        changed_paths: Vec<String>,
        changed_paths_complete: bool,
        lfs: Vec<LfsPointerFact>,
        lfs_failure: Option<&'static str>,
    ) -> Self {
        Self {
            name,
            old_oid_hex,
            target_oid_hex,
            target_present,
            target_kind,
            branch_target_is_commit,
            fast_forward,
            changed_paths,
            changed_paths_complete,
            lfs,
            lfs_failure,
        }
    }

    pub(crate) fn name(&self) -> &RefName {
        &self.name
    }

    /// ACTUAL captured old object id from the baseline ref map (`None` when the
    /// ref was absent). The selection compares this with the plan precondition to
    /// derive the per-ref CAS verdict; it is never the caller's expected value.
    pub(crate) fn old_oid_hex(&self) -> Option<&str> {
        self.old_oid_hex.as_deref()
    }

    /// `None` for a delete, otherwise whether native Git could resolve the object.
    pub(crate) fn target_present(&self) -> Option<bool> {
        self.target_present
    }

    /// `None` when the ref is not a branch or has no target.
    pub(crate) fn branch_target_is_commit(&self) -> Option<bool> {
        self.branch_target_is_commit
    }

    /// Verified fast-forward ancestry: `Some(true)` means the captured old object
    /// is an ancestor of (or equal to) the new target.
    pub(crate) fn fast_forward(&self) -> Option<bool> {
        self.fast_forward
    }

    pub(crate) fn changed_paths(&self) -> &[String] {
        &self.changed_paths
    }

    pub(crate) fn changed_paths_complete(&self) -> bool {
        self.changed_paths_complete
    }

    pub(crate) fn lfs_pointers(&self) -> &[LfsPointerFact] {
        &self.lfs
    }

    /// `None` only when every parsed pointer's bytes were verified against a
    /// durable fact. Any other value is a fixed, fail-closed label.
    pub(crate) fn lfs_failure(&self) -> Option<&'static str> {
        self.lfs_failure
    }

    /// Canonical digest of this ref's complete fact set.
    pub(crate) fn digest(&self) -> RequestDigest {
        let mut fields: Vec<Vec<u8>> = vec![
            self.name.as_str().as_bytes().to_vec(),
            self.old_oid_hex.as_deref().unwrap_or("").as_bytes().to_vec(),
            self.target_oid_hex.as_deref().unwrap_or("").as_bytes().to_vec(),
            match self.target_present {
                None => b"none".to_vec(),
                Some(false) => b"absent".to_vec(),
                Some(true) => b"present".to_vec(),
            },
            self.target_kind.map(|kind| kind.as_str().as_bytes().to_vec()).unwrap_or_default(),
            match self.branch_target_is_commit {
                None => b"none".to_vec(),
                Some(false) => b"no".to_vec(),
                Some(true) => b"yes".to_vec(),
            },
            match self.fast_forward {
                None => b"none".to_vec(),
                Some(false) => b"no".to_vec(),
                Some(true) => b"yes".to_vec(),
            },
            if self.changed_paths_complete { b"complete".to_vec() } else { b"partial".to_vec() },
            self.lfs_failure.unwrap_or("").as_bytes().to_vec(),
            (self.changed_paths.len() as u64).to_be_bytes().to_vec(),
        ];
        for path in &self.changed_paths {
            fields.push(path.as_bytes().to_vec());
        }
        fields.push((self.lfs.len() as u64).to_be_bytes().to_vec());
        for pointer in &self.lfs {
            fields.push(pointer.path.as_bytes().to_vec());
            fields.push(pointer.oid_hex.as_bytes().to_vec());
            fields.push(pointer.size.to_be_bytes().to_vec());
            fields.push(if pointer.durable { b"durable".to_vec() } else { b"nodurable".to_vec() });
            fields.push(if pointer.bytes_verified { b"verified".to_vec() } else { b"unverified".to_vec() });
        }
        let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
        RequestDigest::of("core-publication-ref-facts-v1", &parts)
    }
}

/// Full native identity of one verified registered pack pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedPackIdentity {
    pack_id: Uuid,
    registration_id: Uuid,
    artifact_set_digest_hex: String,
    pack_sha256: String,
    pack_length: u64,
    idx_sha256: String,
    idx_length: u64,
}

impl VerifiedPackIdentity {
    pub(crate) fn new(
        pack_id: Uuid,
        registration_id: Uuid,
        artifact_set_digest_hex: String,
        pack_sha256: String,
        pack_length: u64,
        idx_sha256: String,
        idx_length: u64,
    ) -> Self {
        Self { pack_id, registration_id, artifact_set_digest_hex, pack_sha256, pack_length, idx_sha256, idx_length }
    }

    pub(crate) fn digest(&self) -> RequestDigest {
        let parts = [
            self.pack_id.as_bytes().as_slice(),
            self.registration_id.as_bytes(),
            self.artifact_set_digest_hex.as_bytes(),
            self.pack_sha256.as_bytes(),
            &self.pack_length.to_be_bytes(),
            self.idx_sha256.as_bytes(),
            &self.idx_length.to_be_bytes(),
        ];
        RequestDigest::of("core-publication-pack-identity-v1", &parts)
    }
}
