//! Fixtures shared by `tests/blob_git_gateway.rs`.
//!
//! Every fixture is real: a random PostgreSQL schema built only by
//! `db::migrate`, real API tokens created through `db::issue_token`, the actual
//! trusted Git binary and the operator's real S3-compatible Blob profile. The
//! service, proxy and capture fixtures never build, patch or replace the
//! service binary.
//!
//! * [`db`] pins the run's schema selector and relative Blob prefix;
//! * [`blob`] opens the production profile and deletes only that owned prefix;
//! * [`service`] launches the already built `rootyard serve-blob` binary;
//! * [`proxy`] is the bounded loopback proxy between stock Git and the service;
//! * [`capture`] reads byte-exact views of the real request bodies it saw;
//! * [`wire`] is the bounded HTTP codec shared by all of the above.
//!
//! The uncommitted `lane/` draft is not linked and stays untracked: its start-up
//! pinned the remote Blob prefix to a local scratch path, which the production
//! profile refuses, and its proxy/server definitions duplicated the modules
//! above. [`service`] is the corrected start-up (relative remote prefix).
pub mod actor;
pub mod blob;
pub mod capture;
pub mod db;
pub mod git;
pub mod preflight;
pub mod proxy;
#[cfg(test)]
mod proxy_reply;
pub mod service;
pub mod wire;
