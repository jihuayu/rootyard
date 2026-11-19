//! Standalone production `rootyard-safe-gc-voter` daemon (#122).
//!
//! Loads one JSON `SafeGcVoterServiceConfig`, binds its own mTLS `raft-node` replica, and
//! serves independent Ed25519 cutpoint attestations until SIGTERM/Ctrl-C.

use std::path::Path;

use rootyard::storage_lifecycle::safe_gc::{SafeGcVoterServiceConfig, serve_safe_gc_voter};

const CONFIG_ENV: &str = "ROOTYARD_SAFE_GC_VOTER_CONFIG";
const READY_FILE_ENV: &str = "ROOTYARD_SAFE_GC_VOTER_READY_FILE";

fn invalid(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config_path = None;
    let mut ready_file = None;
    let mut version = false;
    let mut args = std::env::args().skip(1);
    loop {
        let Some(arg) = args.next() else { break };
        match arg.as_str() {
            "--version" => version = true,
            "--config" => config_path = Some(args.next().ok_or_else(|| invalid("--config requires a value"))?),
            "--ready-file" => ready_file = Some(args.next().ok_or_else(|| invalid("--ready-file requires a value"))?),
            other => return Err(invalid(format!("unexpected argument: {other}")).into()),
        }
    }
    if version {
        if config_path.is_some() || ready_file.is_some() {
            return Err(invalid("--version cannot be combined with other flags").into());
        }
        println!("rootyard-safe-gc-voter {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let config_path = config_path
        .or_else(|| std::env::var(CONFIG_ENV).ok())
        .ok_or_else(|| invalid(format!("--config or {CONFIG_ENV} is required")))?;
    let ready_file = ready_file.or_else(|| std::env::var(READY_FILE_ENV).ok());
    let raw = std::fs::read(&config_path)?;
    let config: SafeGcVoterServiceConfig = serde_json::from_slice(&raw)?;
    config.validate()?;
    serve_safe_gc_voter(config, ready_file.as_deref().map(Path::new)).await?;
    Ok(())
}
