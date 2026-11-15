//! Operator CLI for Pando PITR authority status, verification, isolation and
//! retention root management (#77).
use crate::{
    config::Config,
    pando_gateway::{
        pitr_fence,
        retention_roots::{self, RetentionRootKind},
    },
    storage::{Storage, remote_objects::RemoteObjectStore},
};
use anyhow::{Context, Result, bail, ensure};
use deadpool_postgres::Pool;
use std::time::Duration;
use tokio::time::Instant;
use uuid::Uuid;

const CLI_TIMEOUT: Duration = Duration::from_secs(60);

pub async fn cli(config: &Config, pool: &Pool, args: &[String]) -> Result<()> {
    let deadline = Instant::now() + CLI_TIMEOUT;
    match args.first().map(String::as_str) {
        Some("status") if args.len() == 1 => status(config, pool, deadline).await,
        Some("verify") if args.len() == 1 => verify(config, pool, deadline).await,
        Some("isolate") if args.len() == 2 && args[1] == "--confirm-shared-bucket" => {
            isolate(config, pool, deadline).await
        }
        Some("pin-recovery-point") => pin_cli(config, pool, &args[1..], deadline).await,
        Some("release-recovery-point") if args.len() == 3 && args[1] == "--root" => {
            let root_id: Uuid = args[2].parse().context("invalid --root UUID")?;
            let released = retention_roots::release_recovery_root(pool, root_id).await?;
            ensure!(released, "active retention root not found: {root_id}");
            println!("{}", serde_json::json!({"root_id": root_id, "released": true}));
            Ok(())
        }
        _ => bail!(
            "usage: rootyard pando-authority <status | verify | isolate --confirm-shared-bucket | pin-recovery-point --tenant UUID [--repository UUID] [--kind backup_snapshot|pitr_recovery_point|manual_pin] [--note TEXT] [--ttl-seconds N] | release-recovery-point --root UUID>"
        ),
    }
}

async fn status(config: &Config, pool: &Pool, deadline: Instant) -> Result<()> {
    let client = pool.get().await?;
    let db_coords = pitr_fence::probe_db_coordinates(&**client).await?;
    let auth = pitr_fence::load_authority_state(&**client).await?;
    let active_roots = retention_roots::list_active_roots(pool, None).await?;
    let volume_id = pitr_fence::read_volume_id(&config.data_dir).ok();
    let deployment_id = pitr_fence::read_deployment_id_if_present(&config.data_dir)?;
    let remote = RemoteObjectStore::from_env(config.data_dir.join("pando-pack-work"))?;
    let backend_identity = remote.backend_identity()?;
    let proof_present = remote.authority_proof_exists(auth.authority_id, auth.authority_epoch, deadline).await.ok();
    let next_epoch = auth.authority_epoch.saturating_add(1);
    let successor_present = remote.authority_proof_exists(auth.authority_id, next_epoch, deadline).await.ok();
    let remote_delete_env = crate::storage_lifecycle::pando_delete_gate::remote_delete_env_enabled().ok();

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "authority": auth,
            "local": {
                "volume_id": volume_id,
                "deployment_id": deployment_id,
                "backend_identity": backend_identity,
                "db_system_identifier": db_coords.system_identifier,
                "db_database_oid": db_coords.database_oid,
                "db_schema_oid": db_coords.schema_oid,
                "pg_timeline_id": db_coords.timeline_id,
            },
            "external_bucket": {
                "current_epoch_proof_present": proof_present,
                "successor_epoch_proof_present": successor_present,
            },
            "remote_delete_env_enabled": remote_delete_env,
            "active_retention_roots": active_roots,
        }))?
    );
    Ok(())
}

async fn verify(config: &Config, pool: &Pool, deadline: Instant) -> Result<()> {
    let storage = Storage::open(config)?;
    let remote = RemoteObjectStore::from_env(storage.root.join("pando-pack-work"))?;
    let verified = pitr_fence::verify_or_attest(pool, &storage.root, &remote, deadline, "manual_check").await?;
    println!("{}", serde_json::to_string_pretty(&verified)?);
    Ok(())
}

async fn isolate(config: &Config, pool: &Pool, deadline: Instant) -> Result<()> {
    let storage = Storage::open(config)?;
    let remote = RemoteObjectStore::from_env(storage.root.join("pando-pack-work"))?;
    let isolated = pitr_fence::isolate_cloned_authority(pool, &storage.root, &remote, deadline).await?;
    println!("{}", serde_json::to_string_pretty(&isolated)?);
    Ok(())
}

async fn pin_cli(config: &Config, pool: &Pool, args: &[String], deadline: Instant) -> Result<()> {
    let mut tenant_id: Option<Uuid> = None;
    let mut repository_id: Option<Uuid> = None;
    let mut kind = RetentionRootKind::PitrRecoveryPoint;
    let mut note: Option<String> = None;
    let mut ttl_seconds: Option<i64> = None;

    let mut i = 0;
    while i < args.len() {
        ensure!(i + 1 < args.len(), "missing value for option {}", args[i]);
        match args[i].as_str() {
            "--tenant" => tenant_id = Some(args[i + 1].parse().context("invalid --tenant UUID")?),
            "--repository" => repository_id = Some(args[i + 1].parse().context("invalid --repository UUID")?),
            "--kind" => kind = RetentionRootKind::parse(&args[i + 1])?,
            "--note" => note = Some(args[i + 1].clone()),
            "--ttl-seconds" => ttl_seconds = Some(args[i + 1].parse().context("invalid --ttl-seconds integer")?),
            other => bail!("unknown pin-recovery-point option: {other}"),
        }
        i += 2;
    }

    let tenant = tenant_id.context("--tenant UUID is required")?;
    let storage = Storage::open(config)?;
    let remote = RemoteObjectStore::from_env(storage.root.join("pando-pack-work"))?;
    let summary = retention_roots::pin_recovery_root(
        pool,
        &storage.root,
        &remote,
        tenant,
        repository_id,
        kind,
        note.as_deref(),
        ttl_seconds,
        &[],
        deadline,
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}
