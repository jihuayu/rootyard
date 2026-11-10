//! Fixtures for `ref_store_decision_subset.rs`.
//!
//! Everything real is reused by `#[path]` from `tests/retention_roots_support`
//! (A3 protected upload, A4 native verified commit, A5 snapshot, PostgreSQL
//! schema + migration 144, fixture Git). This module only adds the pieces that
//! are specific to the decision/accepted-subset pipeline: real API-token actors
//! and RBAC rows, real policy rows, real pending decision plans and read-only
//! PostgreSQL assertions.
//!
//! Nothing here fabricates a token digest, a decision capability, a proof, a
//! selection digest or a caller "authorized" boolean.
pub mod assert;
pub mod auth;
pub mod cases_a;
pub mod cases_b;
pub mod cases_c;
pub mod cases_d;
pub mod common;
pub mod fixture;
pub mod metadata;
pub mod policy;
