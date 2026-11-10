//! Shared real PostgreSQL + S3 + Git fixture for `ref_store_retention_roots.rs`.
//!
//! Every module is a copy of the established A3/A4/A5 fixture mechanics from
//! `ref_store_pack_snapshots.rs` / `ref_store_materialized_reads.rs`, scoped to
//! this suite. Missing services hard-fail; no fixture fabricates a proof,
//! receipt, native closure or SQL acknowledgement.

#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]

pub mod common;
pub mod db;
pub mod git;
pub mod pack;
pub mod roots;
