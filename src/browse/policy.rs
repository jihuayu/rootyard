//! Branch policy shared by native receive-pack hooks and server-side ref CAS.
use crate::{Error, journal::RefChange};
use axum::http::StatusCode;
use std::{path::Path, time::Duration};
use tokio_postgres::GenericClient;
use uuid::Uuid;

fn denied() -> Error { Error(StatusCode::FORBIDDEN, "protected branch policy denied") }

pub async fn validate<C: GenericClient + Sync>(
    client: &C,
    repo: Uuid,
    changes: &[RefChange],
    git_bin: &Path,
    git_dir: &Path,
    timeout: Duration,
) -> Result<(), Error> {
    for change in changes {
        if !change.ref_name.starts_with("refs/heads/") { continue; }
        let row = client.query_opt(
            "SELECT required_approvals,required_checks,require_fast_forward,prevent_deletion,prevent_force_push FROM forge_branch_rules WHERE repository_id=$1 AND branch_ref=$2",
            &[&repo, &change.ref_name],
        ).await.map_err(Error::internal)?;
        let Some(row) = row else { continue; };
        let deleting = change.new_oid.bytes().all(|b| b == b'0');
        let creating = change.old_oid.bytes().all(|b| b == b'0');
        if deleting {
            if row.get::<_, bool>("prevent_deletion") { return Err(denied()); }
            continue;
        }
        // Approvals are tied to an authenticated PR merge. A direct push has
        // no pull-request identity and cannot reuse another PR's reviews.
        if row.get::<_, i64>("required_approvals") > 0 { return Err(denied()); }
        let checks: Vec<String> = serde_json::from_value(row.get("required_checks")).map_err(Error::internal)?;
        for context in checks {
            let passed: bool = client.query_one(
                "SELECT EXISTS(SELECT 1 FROM forge_check_runs WHERE repository_id=$1 AND commit_oid=$2 AND context=$3 AND status='completed' AND conclusion='success')",
                &[&repo, &change.new_oid, &context],
            ).await.map_err(Error::internal)?.get(0);
            if !passed { return Err(denied()); }
        }
        if !creating && (row.get::<_, bool>("require_fast_forward") || row.get::<_, bool>("prevent_force_push")) {
            let mut cmd = tokio::process::Command::new(git_bin);
            cmd.arg("--git-dir").arg(git_dir).args(["merge-base", "--is-ancestor", &change.old_oid, &change.new_oid]);
            cmd.env("GIT_NO_REPLACE_OBJECTS", "1");
            cmd.kill_on_drop(true).stderr(std::process::Stdio::null());
            let status = tokio::time::timeout(timeout, cmd.status()).await.map_err(|_| Error::timeout())?
                .map_err(Error::internal)?;
            if !status.success() { return Err(denied()); }
        }
    }
    Ok(())
}

pub fn validate_hook(op: &crate::journal::Operation, changes: &[RefChange]) -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    let url = std::env::var("ROOTYARD_DATABASE_URL").context("missing hook database URL")?;
    let git_bin = std::env::var("ROOTYARD_GIT_PATH").context("missing hook Git path")?;
    let git_dir = std::env::var("ROOTYARD_GIT_DIR").context("missing hook repository path")?;
    let data_root = std::env::var("ROOTYARD_DATA_ROOT").context("missing hook data root")?;
    let timeout = std::env::var("ROOTYARD_GIT_TIMEOUT_SECONDS").ok().and_then(|v| v.parse().ok()).unwrap_or(120);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async {
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
        tokio::spawn(async move { let _ = connection.await; });
        let row = client.query_one("SELECT owner_id,storage_generation FROM repositories WHERE id=$1", &[&op.repository_id]).await?;
        let tenant_id: Uuid = row.get(0);
        let generation: i64 = row.get(1);
        ensure!(generation == op.storage_generation, "repository generation changed");
        crate::sharding::fencing::check_hook_fence(&client, op.repository_id, Path::new(&git_dir), op.storage_generation)
            .await.map_err(|e| anyhow::anyhow!(e.1))?;
        validate(&client, op.repository_id, changes, Path::new(&git_bin), Path::new(&git_dir), Duration::from_secs(timeout)).await
            .map_err(|e| anyhow::anyhow!(e.1))?;
        crate::lfs::publication::validate_new_refs_with_client(
            &client, Path::new(&git_dir), Path::new(&data_root), Path::new(&git_bin),
            Duration::from_secs(timeout), op.repository_id, tenant_id, changes,
        ).await.map_err(|e| anyhow::anyhow!(e.1))?;
        Ok::<(), anyhow::Error>(())
    })
}

pub fn validate_hook_fence(op: &crate::journal::Operation) -> anyhow::Result<()> {
    use anyhow::Context;
    let url = std::env::var("ROOTYARD_DATABASE_URL").context("missing hook database URL")?;
    let git_dir = std::env::var("ROOTYARD_GIT_DIR").context("missing hook repository path")?;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async {
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
        tokio::spawn(async move { let _ = connection.await; });
        crate::sharding::fencing::check_hook_fence(&client, op.repository_id, Path::new(&git_dir), op.storage_generation)
            .await.map_err(|e| anyhow::anyhow!(e.1))
    })
}
