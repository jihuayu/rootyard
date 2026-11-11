//! Narrow fixture tree for the `#174` repository-session HTTP acceptance.
//!
//! `src/blob_git_gateway/session_http_acceptance.rs` includes this file (not
//! `tests/blob_gateway_support/mod.rs`) so the library test binary compiles only the real actors,
//! the real PostgreSQL schema fixture and the real Git runner. Every item in
//! these three modules is driven by that harness, so the include needs no
//! `dead_code` suppression. `tests/blob_git_gateway.rs` keeps compiling the
//! whole tree through `tests/blob_gateway_support/mod.rs`, where the
//! integration-only helpers live in sibling modules.
pub mod actor;
pub mod db;
pub mod git;
