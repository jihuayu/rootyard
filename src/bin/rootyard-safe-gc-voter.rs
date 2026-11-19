//! Standalone production `rootyard-safe-gc-voter` daemon (#122).
//!
//! Loads one JSON `SafeGcVoterServiceConfig`, binds its own mTLS `raft-node` replica, and
//! serves independent Ed25519 cutpoint attestations until SIGTERM/Ctrl-C.

use std::path::Path;

use rootyard::storage_lifecycle::safe_gc::{SafeGcVoterServiceConfig, serve_safe_gc_voter};

const CONFIG_ENV: &str = "ROOTYARD_SAFE_GC_VOTER_CONFIG";
const READY_FILE_ENV: &str = "ROOTYARD_SAFE_GC_VOTER_READY_FILE";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config_path = None;
    let mut ready_file = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config_path = args.next(),
            "--ready-file" => ready_file = args.next(),
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unexpected argument: {other}"),
                )
                .into());
            }
        }
    }
    let config_path = config_path.or_else(|| std::env::var(CONFIG_ENV).ok()).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("--config or {CONFIG_ENV} is required"))
    })?;
    let ready_file = ready_file.or_else(|| std::env::var(READY_FILE_ENV).ok());
    let raw = std::fs::read(&config_path)?;
    let config: SafeGcVoterServiceConfig = serde_json::from_slice(&raw)?;
    serve_safe_gc_voter(config, ready_file.as_deref().map(Path::new)).await?;
    Ok(())
}
