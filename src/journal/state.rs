//! Terminal markers, canonical operator evidence, and crash-safe retirement.
use super::Operation;
use super::core::{atomic, exists, read, sync_dir};
use super::operation::{op_name, validate};
use super::record::{events, receipts, requests};
use anyhow::{Context, Result, ensure};
use std::fs;

/// Persist that process completion was not observed before startup recovery.
pub fn mark_interrupted(op: &Operation) -> Result<()> {
    validate(op)?;
    atomic(&op.path.join("interrupted"), b"", false)
}
pub fn is_interrupted(op: &Operation) -> Result<bool> {
    validate(op)?;
    let path = op.path.join("interrupted");
    if !exists(&path)? {
        return Ok(false);
    }
    ensure!(read(&path)?.is_empty(), "invalid interrupted marker");
    Ok(true)
}
/// The writer lost its PostgreSQL admission before publishing. Local refs may
/// have advanced inside native Git; reconciliation restores their old OIDs and
/// retires the journal without creating SQL ref history.
pub fn mark_fenced_aborted(op: &Operation) -> Result<()> {
    validate(op)?;
    atomic(&op.path.join("fenced"), b"", false)
}
pub fn is_fenced_aborted(op: &Operation) -> Result<bool> {
    validate(op)?;
    let path = op.path.join("fenced");
    if !exists(&path)? {
        return Ok(false);
    }
    ensure!(read(&path)?.is_empty(), "invalid fenced marker");
    Ok(true)
}
/// Mark verified evidence loss. This is not an inference from Git's exit code.
pub fn mark_corrupt(op: &Operation) -> Result<()> {
    validate(op)?;
    atomic(&op.path.join("corrupt"), b"", false)
}

/// Canonical bounded evidence for operator inspection and immutable resolution.
pub fn evidence(op: &Operation) -> Result<serde_json::Value> {
    Ok(
        serde_json::json!({"operation":op,"reference_events":events(op)?,"requested":requests(op)?,"post_receive":receipts(op)?,"finished":is_finished(op)?,"interrupted":is_interrupted(op)?,"fenced_aborted":is_fenced_aborted(op)?}),
    )
}
pub fn evidence_digest(op: &Operation) -> Result<String> {
    use sha2::Digest;
    Ok(hex::encode(sha2::Sha256::digest(serde_json::to_vec(&evidence(op)?)?)))
}
pub fn finish(op: &Operation) -> Result<()> {
    validate(op)?;
    atomic(&op.path.join("finished"), b"", false)
}
pub fn is_finished(op: &Operation) -> Result<bool> {
    validate(op)?;
    let p = op.path.join("finished");
    if !exists(&p)? {
        return Ok(false);
    }
    ensure!(read(&p)?.is_empty(), "invalid finished marker");
    Ok(true)
}
pub fn retire(op: &Operation) -> Result<()> {
    ensure!(is_finished(op)?, "cannot retire running operation");
    // Caller has committed SQL. Publish retirement before recursive cleanup;
    // interrupted cleanup must not turn already-projected evidence into a
    // corrupt pending operation on restart.
    let parent = op.path.parent().context("operation parent")?;
    let retired = parent.join(format!(".retired-{}", op_name(op)));
    ensure!(!exists(&retired)?, "retirement destination already exists");
    fs::rename(&op.path, &retired)?;
    sync_dir(parent)?;
    fs::remove_dir_all(&retired)?;
    sync_dir(parent)
}
