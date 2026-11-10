//! Fixtures shared by `tests/blob_git_gateway.rs`.
//!
//! Every fixture is real: a random PostgreSQL schema built only by
//! `db::migrate`, real API tokens created through `db::issue_token`, the actual
//! trusted Git binary and the operator's real S3-compatible Blob profile.
pub mod actor;
pub mod db;
pub mod git;
