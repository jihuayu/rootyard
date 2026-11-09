//! Accepted-subset publication facts (feature 3), crate-private surface.
//!
//! The only way to obtain [`VerifiedPublicationFacts`] is the native engine
//! [`PublicationFactsEngine::facts`]. The type has private fields, no `Clone`, no
//! serde and no external constructor, so no caller can fabricate a per-ref
//! presence/type/ancestry/LFS fact and cannot pass a boolean in place of a real
//! native observation. There is deliberately no "all allowed" default: without
//! durable LFS byte facts, [`NoDurableLfsBytes`] makes every pointer-bearing ref
//! fail closed.
//!
//! This module is `mod facts;` inside `pack_commit`, re-exported `pub(crate)` only:
//! it is not part of any public/HTTP/library surface.
mod types;
mod witness;

pub(crate) use super::proof::verifier::{PublicationFactsEngine, VerifiedPublicationFacts};
pub(crate) use types::{GitObjectKind, LfsPointerFact, RefFacts, VerifiedPackIdentity};
pub(crate) use witness::{LfsByteWitness, NoDurableLfsBytes, verify_local_bytes};
