//! Shared case helpers (real fixtures only).
use super::fixture::World;
use anyhow::{Result, anyhow, ensure};
use rootyard::ref_store::GitObjectFormat;

pub const SHA1: GitObjectFormat = GitObjectFormat::Sha1;

pub async fn seeded() -> Result<World> {
    let world = World::new(SHA1).await?;
    world.provision().await?;
    Ok(world)
}

pub fn code<'a>(verdicts: &'a [(String, String, Option<String>)], name: &str) -> Result<&'a str> {
    let row = verdicts.iter().find(|row| row.0 == name).ok_or_else(|| anyhow!("no persisted verdict for {name}"))?;
    ensure!(row.1 == "reject", "verdict for {name} is not a rejection");
    row.2.as_deref().ok_or_else(|| anyhow!("rejection for {name} has no stable code"))
}

pub fn accepted(verdicts: &[(String, String, Option<String>)], name: &str) -> bool {
    verdicts.iter().any(|row| row.0 == name && row.1 == "accept")
}
