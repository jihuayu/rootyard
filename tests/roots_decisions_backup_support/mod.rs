//! Real PostgreSQL + S3 + Git fixture support for
//! `tests/ref_store_roots_decisions_backup_fixture.rs`.
//!
//! The A3/A4/A5 and roots request helpers are the *existing* public common
//! fixture (`tests/retention_roots_support`) included here with `#[path]` and
//! not edited. Only the modules owned by this drill live here:
//!
//! * [`db`] — attaches to the **parent-owned, already migrated** database
//!   (never `Db::setup`, `db::migrate`, `CREATE SCHEMA` or `DROP` on a restored
//!   database);
//! * [`decisions`] — the real staged authorized-decision facade;
//! * [`marker`] / [`rows`] — canonical, secret-free marker and row-set capture;
//! * [`seed`] / [`verify`] — the two helper modes.
//!
//! `pack.rs`/`roots.rs` resolve `super::db`/`super::git`/`super::pack` to this
//! module, so the shared helpers work unchanged against the parent database.
#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]

pub mod db;
pub mod decisions;
pub mod marker;
pub mod rows;
pub mod seed;
pub mod verify;

#[path = "../retention_roots_support/git.rs"]
pub mod git;
#[path = "../retention_roots_support/pack.rs"]
pub mod pack;
#[path = "../retention_roots_support/roots.rs"]
pub mod roots;
