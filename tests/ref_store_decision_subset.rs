//! Entry point for the decision-gated accepted-subset suite.
//!
//! Cases live in `tests/decision_subset_support/cases_*.rs` so every file stays
//! below the source bound; the shared real fixtures come from
//! `tests/retention_roots_support` (`#[path]`) and `decision_subset_support`.
#![allow(clippy::too_many_arguments)]

#[path = "retention_roots_support/mod.rs"]
mod retention_roots_support;

mod decision_subset_support;
