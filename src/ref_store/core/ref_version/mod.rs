//! Pure canonical identity codec for the proposed ref-version contract (C1a).
//!
//! This module is crate-private and unwired. This checkpoint implements only the
//! canonical [`OperationDigest`](contract::OperationDigest) preimage from
//! `docs/ref-version-pack-contract.md` §2.6 and defines the opaque
//! [`VersionId`](contract::VersionId) input type used by the base selector. It
//! does not yet mint a candidate VersionId. It deliberately does not create a
//! version record, register or retain a pack, authorize a mutation, or return
//! any capability.
//!
//! An `OperationDigest` or `VersionId` returned here is only a deterministic
//! value. It does not prove that a request is authorized, that a version was
//! committed or registered, that a record exists, that objects or dependencies
//! are present, or that any data is safe to collect. The legacy base shape is
//! digestible for replay separation. This checkpoint has no generation field
//! and never mints a candidate `VersionId`.
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

pub(crate) use contract::{
    AuthorityKind, BaseRequestSelector, OperationDigest, OperationDigestInput, RefVersionCodecError, RefVersionIntent,
    RefVersionKind, RefVersionRealm, VersionId,
};
pub(crate) use digest::operation_digest;
