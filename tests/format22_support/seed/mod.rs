//! Seed mode: the real API-produced format22 source for issue #169.
//!
//! Positive state only comes from production APIs: ready `pg_refstore`
//! repositories from the real serving provision path, packs through A3/A4/native
//! verified commits as a producer owner distinct from the repository tenant, an
//! A5 snapshot plus two retention roots owned by that producer, and one live
//! transient serving read owned by a third real user. The only direct writes are
//! the production-issued token rows and the fixture-local offline volume id.
mod identity;
mod packs;
mod run;

pub use run::run;

use anyhow::{Result, anyhow, ensure};
use rootyard::ref_store::GitObjectFormat;
use std::collections::BTreeMap;
use std::path::PathBuf;

const SHA1: GitObjectFormat = GitObjectFormat::Sha1;
const PACKS: i64 = 3;
const ROOT_SLOTS: i64 = 2_000;
/// Bounded transient serving-read lease; the immediate backup runs well inside it.
const SERVING_READ_LEASE_SECONDS: u32 = 300;

#[derive(Clone, Debug)]
pub struct Options {
    pub seed: PathBuf,
    pub data_dir: PathBuf,
    pub git: PathBuf,
    pub blob_root: String,
}

/// Parse `--seed/--data-dir/--git/--blob-root`; `None` means seed mode was not
/// requested (the caller then runs the offline digest-vector mode).
pub fn parse(args: &[String]) -> Result<Option<Options>> {
    if !args.iter().any(|arg| arg == "--seed") {
        return Ok(None);
    }
    let mut values: BTreeMap<&str, String> = BTreeMap::new();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        if !matches!(flag, "--seed" | "--data-dir" | "--git" | "--blob-root") {
            return Err(anyhow!("unknown fixture argument {flag}"));
        }
        let value = args.get(index + 1).cloned().ok_or_else(|| anyhow!("{flag} needs a value"))?;
        ensure!(values.insert(flag, value).is_none(), "{flag} was given twice");
        index += 2;
    }
    let take = |flag: &str| values.get(flag).cloned().ok_or_else(|| anyhow!("{flag} is required in seed mode"));
    let options = Options {
        seed: take("--seed")?.into(),
        data_dir: take("--data-dir")?.into(),
        git: take("--git")?.into(),
        blob_root: take("--blob-root")?,
    };
    ensure!(options.seed.is_absolute(), "--seed must be absolute");
    ensure!(options.data_dir.is_absolute(), "--data-dir must be absolute");
    ensure!(options.git.is_absolute(), "--git must be absolute");
    ensure!(options.blob_root.starts_with("format22-169-"), "--blob-root must be this fixture's own prefix");
    Ok(Some(options))
}
