//! Offline single-node W8-A paired backup/restore entrypoint.
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use rootyard::backup::w8a_paired::{check, create, restore};
use rootyard::config::Config;

fn main() -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the Tokio runtime")?
        .block_on(run())
}

async fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("create") => {
            let destination = required_path(args.next(), "create <destination>")?;
            if args.next().is_some() {
                bail!("create accepts exactly one destination");
            }
            let config = Config::from_env()?;
            let receipt = create(&config, &destination).await?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
            Ok(())
        }
        Some("check") => {
            let source = required_path(args.next(), "check <source>")?;
            if args.next().is_some() {
                bail!("check accepts exactly one source");
            }
            println!("{}", serde_json::to_string_pretty(&check(&source)?)?);
            Ok(())
        }
        Some("restore") => {
            let source = required_path(args.next(), "restore <source> --compute-dir <dir> --trust-backup")?;
            let mut compute_dir = None;
            let mut trusted = false;
            while let Some(flag) = args.next() {
                match flag.as_str() {
                    "--compute-dir" => {
                        compute_dir = Some(required_path(args.next(), "--compute-dir <directory>")?);
                    }
                    "--trust-backup" => trusted = true,
                    other => bail!("unsupported restore argument: {other}"),
                }
            }
            if !trusted {
                bail!("restore requires explicit --trust-backup");
            }
            let compute_dir = compute_dir.context("restore requires --compute-dir <directory>")?;
            let config = Config::from_env()?;
            let receipt = restore(&config, &source, &compute_dir, true).await?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
            Ok(())
        }
        _ => bail!(
            "usage: rootyard-w8a-backup create <destination> | check <source> | restore <source> --compute-dir <directory> --trust-backup"
        ),
    }
}

fn required_path(value: Option<String>, usage: &str) -> Result<PathBuf> {
    match value {
        Some(value) if !value.is_empty() => Ok(PathBuf::from(value)),
        _ => bail!("missing path; usage: {usage}"),
    }
}
