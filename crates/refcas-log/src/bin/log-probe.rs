//! Local acknowledged-log process-recovery probe; no network, state machine or quorum ACK claim.
//!
//! `write` calls openraft's public `RaftLogStorageExt::blocking_append`. That extension is the
//! public path that constructs `LogFlushed`, invokes `RaftLogStorage::append`, and waits for the
//! callback; `LogFlushed::new` itself is private to openraft 0.9.26. This probe therefore cannot
//! acknowledge a merely queued append: if the storage returns `Ok` without completing the
//! callback, `blocking_append` either keeps waiting or reports the dropped sender as an error,
//! and the probe never prints `ACK`.
use std::io::{self, Read, Write};

use openraft::CommittedLeaderId;
use openraft::Entry;
use openraft::EntryPayload;
use openraft::LogId;
use openraft::storage::RaftLogReader;
use openraft::storage::RaftLogStorage;
use openraft::storage::RaftLogStorageExt;
use rootyard_refcas_log::EntryOf;
use rootyard_refcas_log::PersistentLog;
use serde::Serialize;

const NODE_ID: u64 = 7;

#[derive(Serialize)]
struct Report {
    entries: Vec<EntryOf>,
    committed: Option<LogId<u64>>,
    last_purged_log_id: Option<LogId<u64>>,
    last_log_id: Option<LogId<u64>>,
}

fn log_id(term: u64, index: u64) -> LogId<u64> {
    LogId::new(CommittedLeaderId::new(term, NODE_ID), index)
}

/// Exact native entries written by `write` and independently expected by the parent test.
fn entries() -> Vec<EntryOf> {
    vec![
        Entry { log_id: log_id(2, 0), payload: EntryPayload::Blank },
        Entry { log_id: log_id(2, 1), payload: EntryPayload::Normal(b"alpha\0\xff".to_vec()) },
        Entry { log_id: log_id(2, 2), payload: EntryPayload::Normal(b"bravo".to_vec()) },
        Entry { log_id: log_id(3, 3), payload: EntryPayload::Blank },
        Entry { log_id: log_id(3, 4), payload: EntryPayload::Normal(b"charlie\0".to_vec()) },
    ]
}

/// Index 3 is marked committed; index 4 stays uncommitted but must also survive the acknowledged append.
fn committed() -> LogId<u64> {
    log_id(3, 3)
}

async fn write(store: &mut PersistentLog) -> Result<(), Box<dyn std::error::Error>> {
    let expected = entries();
    store.blocking_append(expected.clone()).await?;
    store.save_committed(Some(committed())).await?;
    let saved = store.read_committed().await?;
    let state = store.get_log_state().await?;
    let start = state.last_purged_log_id.map_or(0, |purged| purged.index.saturating_add(1));
    let end = state
        .last_log_id
        .ok_or_else(|| io::Error::other("append left no log tail"))?
        .index
        .checked_add(1)
        .ok_or_else(|| io::Error::other("log tail overflow"))?;
    let readback = store.try_get_log_entries(start..end).await?;
    if readback != expected {
        return Err(io::Error::other("post-append readback mismatch").into());
    }
    if saved != Some(committed()) {
        return Err(io::Error::other("committed metadata mismatch").into());
    }
    if state.last_purged_log_id.is_some() {
        return Err(io::Error::other("unexpected purge boundary").into());
    }
    print_report(
        "ACK",
        &Report {
            entries: readback,
            committed: saved,
            last_purged_log_id: state.last_purged_log_id,
            last_log_id: state.last_log_id,
        },
    )?;
    // Keep this process and its SQLite connection alive for the parent's SIGKILL.
    let mut byte = [0_u8; 1];
    let _ = io::stdin().read(&mut byte);
    Ok(())
}

async fn read_store(store: &mut PersistentLog) -> Result<(), Box<dyn std::error::Error>> {
    let state = store.get_log_state().await?;
    let committed = store.read_committed().await?;
    let start = state.last_purged_log_id.map_or(0, |purged| purged.index.saturating_add(1));
    let end = match state.last_log_id {
        Some(last) => last.index.checked_add(1).ok_or_else(|| io::Error::other("log tail overflow"))?,
        None => start,
    };
    let entries = if start < end { store.try_get_log_entries(start..end).await? } else { Vec::new() };
    for (offset, entry) in entries.iter().enumerate() {
        let offset = u64::try_from(offset).map_err(|_| io::Error::other("entry offset overflow"))?;
        let index = start.checked_add(offset).ok_or_else(|| io::Error::other("index overflow"))?;
        let found = entry.log_id.index;
        if found != index {
            return Err(io::Error::other(format!("non-contiguous log: expected index {index}, found {found}")).into());
        }
    }
    if let Some(last) = state.last_log_id
        && entries.last().map(|entry| entry.log_id.index) != Some(last.index)
    {
        return Err(io::Error::other("read did not reach the stored last log id").into());
    }
    print_report(
        "READ",
        &Report { entries, committed, last_purged_log_id: state.last_purged_log_id, last_log_id: state.last_log_id },
    )?;
    Ok(())
}

fn print_report(prefix: &str, report: &Report) -> Result<(), Box<dyn std::error::Error>> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{prefix} {}", serde_json::to_string(report)?)?;
    stdout.flush()?;
    Ok(())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [mode, path] = args.as_slice() else {
        return Err(io::Error::other("usage: log-probe write|read DIRECTORY").into());
    };
    let mut store = PersistentLog::open(path, NODE_ID, true).await?;
    match mode.as_str() {
        "write" => write(&mut store).await,
        "read" => read_store(&mut store).await,
        _ => Err(io::Error::other("mode must be write or read").into()),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        let message = error.to_string().replace('\n', " ").replace('\r', " ");
        println!("ERR {message}");
        let _ = io::stdout().flush();
        std::process::exit(1);
    }
}
