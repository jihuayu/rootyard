//! Validated maintenance configuration and durable job identity.
use anyhow::{Result, bail};
use serde::Serialize;
use std::{env, time::Duration};
use tokio_postgres::Row;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Policy {
    pub enabled: bool,
    pub poll: Duration,
    pub lease_seconds: i64,
    pub loose_threshold: i64,
    pub pack_threshold: i64,
    pub stage_age_seconds: i64,
    pub cache_max_age_seconds: i64,
    pub tombstone_grace_seconds: i64,
    pub scan_period_seconds: i64,
    pub max_attempts: i32,
}

fn number(name: &str, default: i64, min: i64, max: i64) -> Result<i64> {
    let n = env::var(name).ok().map(|v| v.parse::<i64>()).transpose()?.unwrap_or(default);
    if n < min || n > max {
        bail!("{name} is outside the supported range");
    }
    Ok(n)
}
impl Policy {
    pub fn from_env() -> Result<Self> {
        let enabled = match env::var("ROOTYARD_STORAGE_MAINTENANCE").as_deref() {
            Ok("true") => true,
            Ok("false") | Err(_) => false,
            _ => bail!("ROOTYARD_STORAGE_MAINTENANCE must be true or false"),
        };
        Ok(Self {
            enabled,
            poll: Duration::from_secs(number("ROOTYARD_STORAGE_MAINTENANCE_POLL_SECONDS", 5, 1, 3600)? as u64),
            lease_seconds: number("ROOTYARD_STORAGE_MAINTENANCE_LEASE_SECONDS", 30, 5, 300)?,
            loose_threshold: number("ROOTYARD_STORAGE_REPACK_LOOSE_OBJECTS", 1024, 1, 1_000_000)?,
            pack_threshold: number("ROOTYARD_STORAGE_REPACK_PACKS", 8, 1, 10_000)?,
            stage_age_seconds: number("ROOTYARD_STORAGE_STAGE_AGE_SECONDS", 3600, 1, 365 * 24 * 3600)?,
            cache_max_age_seconds: number(
                "ROOTYARD_STORAGE_CACHE_MAX_AGE_SECONDS",
                7 * 24 * 3600,
                60,
                365 * 24 * 3600,
            )?,
            tombstone_grace_seconds: number(
                "ROOTYARD_STORAGE_TOMBSTONE_GRACE_SECONDS",
                7 * 24 * 3600,
                1,
                365 * 24 * 3600,
            )?,
            scan_period_seconds: number("ROOTYARD_STORAGE_SCAN_PERIOD_SECONDS", 3600, 1, 365 * 24 * 3600)?,
            max_attempts: number("ROOTYARD_STORAGE_MAINTENANCE_MAX_ATTEMPTS", 5, 1, 100)? as i32,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Job {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub kind: String,
    pub repository_generation: i64,
    pub attempt: i32,
    pub claim_generation: i64,
    pub lease_owner: Uuid,
}
impl Job {
    pub fn row(row: &Row) -> Self {
        Self {
            id: row.get("id"),
            repository_id: row.get("repository_id"),
            tenant_id: row.get("tenant_id"),
            kind: row.get("kind"),
            repository_generation: row.get("repository_generation"),
            attempt: row.get("attempt"),
            claim_generation: row.get("claim_generation"),
            lease_owner: row.get("lease_owner"),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct JobOutcome {
    pub job_id: Uuid,
    pub kind: String,
    pub repository_id: Uuid,
    pub attempt: i32,
    pub state: String,
}
