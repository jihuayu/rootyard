//! Support modules of `tests/ref_store_format22_backup_fixture.rs` (issue #169).
//!
//! Only production APIs create positive state. The shared retention-roots
//! fixture modules (`tests/retention_roots_support/{db,git,pack}`) are included
//! unchanged with `#[path]`; `pack_plan` only re-declares the three helpers of
//! `pack.rs` that hard-code `owner_id == tenant_id`, because issue #169 needs
//! registered packs whose producer owner is a different real user; `roots` only
//! re-declares the scope so a root capture can name that producer.
#![allow(clippy::too_many_arguments)]
#![allow(dead_code)]

pub mod digest_vectors;
pub mod marker;
pub mod pack_plan;
pub mod roots;
pub mod seed;

#[path = "../retention_roots_support/db.rs"]
pub mod db;
#[path = "../retention_roots_support/git.rs"]
pub mod git;
#[path = "../retention_roots_support/pack.rs"]
pub mod pack;

use anyhow::Result;

/// Dispatch one fixture invocation and return the single JSON line to print.
pub fn run(args: &[String]) -> Result<String> {
    if let Some(vector) = digest_vectors::run_if_requested(args) {
        return Ok(serde_json::to_string(&vector)?);
    }
    let options = seed::parse(args)?.ok_or_else(|| {
        anyhow::anyhow!(
            "usage: ref_store_format22_backup_fixture (--digest-vector | --seed M --data-dir D --git G --blob-root R)"
        )
    })?;
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let report = runtime.block_on(seed::run(&options))?;
    Ok(serde_json::to_string(&report)?)
}
