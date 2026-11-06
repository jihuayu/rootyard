//! Durable discovery of unreachable native objects. Physical unlink stays
//! disabled until every origin reader has a durable shared repository lease.
use super::{gitfs, models::Policy};
use crate::AppState;
use anyhow::{Result, bail};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn candidate(line: &str) -> Option<(&str,&str)> {
    let mut fields=line.split_ascii_whitespace();
    let status=fields.next()?;
    if status!="unreachable" && status!="dangling" { return None; }
    let kind=fields.next()?;
    if !matches!(kind,"blob"|"tree"|"commit"|"tag") { return None; }
    let oid=fields.next()?;
    if fields.next().is_some() || !matches!(oid.len(),40|64)
        || !oid.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return None;
    }
    Some((oid,kind))
}

pub async fn mark(state: &AppState, repo: Uuid, tenant: Uuid, generation: i64,
                  policy: &Policy, cancel: &CancellationToken) -> Result<Value> {
    // Include reflogs as roots. CI retention refs are native refs and therefore
    // roots too. Rows alone never authorize a physical delete.
    let report=gitfs::run_git(state,repo,&["fsck","--unreachable","--no-progress"],cancel,8*1024*1024).await?;
    let mut oids=Vec::<String>::new();
    let mut kinds=Vec::<String>::new();
    for line in report.lines() {
        if let Some((oid,kind))=candidate(line) {
            oids.push(oid.to_owned());
            kinds.push(kind.to_owned());
            if oids.len()>100_000 { bail!("unreachable object inspection exceeded candidate limit"); }
        }
    }
    if oids.is_empty() { return Ok(json!({"candidates":0,"deleted":false})); }
    let client=state.pool.get().await?;
    let inserted=client.execute(
        "INSERT INTO storage_maintenance_tombstones(repository_id,tenant_id,oid,object_kind,repository_generation,delete_after) \
         SELECT $1,$2,u.oid,u.kind,$3,clock_timestamp()+make_interval(secs=>($4::bigint)::double precision) \
         FROM unnest($5::text[],$6::text[]) AS u(oid,kind) \
         ON CONFLICT(repository_id,oid) DO NOTHING",
        &[&repo,&tenant,&generation,&policy.tombstone_grace_seconds,&oids,&kinds],
    ).await?;
    Ok(json!({"candidates":oids.len(),"new_tombstones":inserted,"deleted":false}))
}

#[cfg(test)]
mod tests {
    use super::candidate;
    #[test]
    fn only_native_unreachable_objects_become_tombstones() {
        let oid="a".repeat(40);
        assert_eq!(candidate(&format!("unreachable blob {oid}")),Some((oid.as_str(),"blob")));
        assert_eq!(candidate(&format!("dangling commit {oid}")),Some((oid.as_str(),"commit")));
        assert!(candidate(&format!("reachable blob {oid}")).is_none());
        assert!(candidate("unreachable blob ../../escape").is_none());
        assert!(candidate(&format!("unreachable blob {}", "A".repeat(40))).is_none());
    }
}
