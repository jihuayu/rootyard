//! Pure canonical identity codec for the proposed ref-version contract (C1a).
//!
//! This module is crate-private and unwired. It implements the canonical
//! [`OperationDigest`](contract::OperationDigest) preimage from
//! `docs/ref-version-pack-contract.md` §2.6 and the candidate
//! [`VersionId`](contract::VersionId) preimage from §2.1. It deliberately does
//! not create a version record, register or retain a pack, authorize a
//! mutation, or return any capability.
//!
//! An `OperationDigest` or `VersionId` returned here is only a deterministic
//! value. It does not prove that a request is authorized, that a version was
//! committed or registered, that a record exists, that objects or dependencies
//! are present, or that any data is safe to collect. The legacy base shape is
//! digestible for replay separation, but a candidate `VersionId` is never
//! minted for it. A caller cannot supply a client generation: explicit absent
//! derives generation 1 and a present base uses the supplied authority base
//! generation plus one, checked for overflow.
//!
//! No Cargo dependency, legacy v1 digest, PostgreSQL schema, runtime path,
//! Blob/native Git code or Raft authority is changed by this checkpoint.
//!
//! C1a is intentionally unwired: no crate caller exists until the later C1b/C2
//! checkpoints. Its complete vocabulary is exercised by inline pure tests; the
//! module-level allowance keeps an unwired staging module warning-free without
//! weakening any runtime path.
#![allow(dead_code)]

mod contract;
mod digest;
mod limits;

// These are the C1b/C2 entry points; C1a itself has no crate caller yet.
#[allow(unused_imports)]
pub(crate) use contract::{
    AuthorityKind, BaseRequestSelector, OperationDigest, OperationDigestInput, RefVersionCodecError, RefVersionIntent,
    RefVersionKind, RefVersionRealm, VersionId,
};
#[allow(unused_imports)]
pub(crate) use digest::{derive_candidate_version_id, operation_digest};
