//! Production co-located per-voter Ed25519 mTLS attestation sidecar (#153).

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::json;

use rootyard::maintenance::paired_raft_backup::{PeerAttestationConfig, PeerAttestationDaemon};

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|arg| arg == name).and_then(|index| args.get(index + 1)).cloned()
}

fn required(args: &[String], name: &str) -> Result<String> {
    flag(args, name).with_context(|| format!("missing required {name}"))
}

fn parse<T>(args: &[String], name: &str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    required(args, name)?.parse().map_err(|error| anyhow::anyhow!("invalid {name}: {error}"))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let node_id: u64 = parse(&args, "--node-id")?;
    let group_id: i64 = parse(&args, "--group-id")?;
    let rpc_timeout_ms: u64 = flag(&args, "--rpc-timeout-ms").map_or(Ok(4_000), |raw| raw.parse())?;
    let daemon = PeerAttestationDaemon::spawn(PeerAttestationConfig {
        node_id,
        group_id,
        data_dir: PathBuf::from(required(&args, "--dir")?),
        raft_node_addr: required(&args, "--raft-node-addr")?,
        bind_addr: flag(&args, "--listen"),
        ca_cert_pem: PathBuf::from(required(&args, "--tls-ca")?),
        node_cert_pem: PathBuf::from(required(&args, "--tls-cert")?),
        node_key_pem: PathBuf::from(required(&args, "--tls-key")?),
        raft_client_cert_pem: PathBuf::from(required(&args, "--raft-client-cert")?),
        raft_client_key_pem: PathBuf::from(required(&args, "--raft-client-key")?),
        rpc_timeout: Duration::from_millis(rpc_timeout_ms.max(1)),
    })?;
    println!(
        "READY {}",
        json!({
            "node_id": node_id,
            "group_id": group_id,
            "addr": daemon.addr(),
            "voter_id": daemon.voter_id(),
            "ed25519_pubkey_hex": daemon.pubkey_hex(),
        })
    );
    std::io::stdout().flush()?;

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        #[cfg(unix)]
        {
            let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        Ok::<(), std::io::Error>(())
    })?;
    daemon.shutdown();
    Ok(())
}
