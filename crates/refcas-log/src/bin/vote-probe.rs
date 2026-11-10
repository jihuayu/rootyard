//! Local process-recovery probe; no network server or Git/consensus ACK claim.
use openraft::Vote;
use openraft::storage::RaftLogStorage;
use rootyard_refcas_log::PersistentLog;
use std::io::{self, Write};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [mode, path] = args.as_slice() else {
        return Err("usage: vote-probe write|read DIRECTORY".into());
    };
    let mut store = PersistentLog::open(path, 7, true).await?;
    if mode == "write" {
        store.save_vote(&Vote::new(3, 7)).await?;
        println!("ACK {}", serde_json::to_string(&store.read_vote().await?)?);
        io::stdout().flush()?;
        // Keep this process (and the SQLite connection) alive for SIGKILL.
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
    } else if mode == "read" {
        println!("{}", serde_json::to_string(&store.read_vote().await?)?);
    } else {
        return Err("mode must be write or read".into());
    }
    Ok(())
}
