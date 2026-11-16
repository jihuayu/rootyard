use super::*;
use tokio_postgres::{Client, IsolationLevel};

/// Creates the retained read snapshot and its expiration row on one client.
///
/// Repack and GC take the repository row lock before deciding which old packs
/// may be pruned. Taking `FOR SHARE` as this transaction's first statement and
/// holding it through the `INSERT`/`COMMIT` makes pack selection and retention
/// admission one ordering decision without putting provider, Git or filesystem
/// work inside SQL.
pub(super) async fn snapshot_and_retain(
    client: &mut Client,
    repo: Uuid,
    principal: &str,
) -> Result<Uuid> {
    let t = client
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .read_only(false)
        .start()
        .await?;

    // This must remain the first authoritative statement. No refs or packs are
    // read before the repository ordering fence is held.
    let row = t
        .query_one(
            "SELECT generation,storage_generation FROM pando_lab.repositories WHERE id=$1 FOR SHARE",
            &[&repo],
        )
        .await?;

    let refs = t
        .query(
            "SELECT name,oid FROM pando_lab.refs WHERE repo=$1 ORDER BY name",
            &[&repo],
        )
        .await?
        .into_iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let packs = t
        .query(
            "SELECT pack_id,pack_sha256,idx_sha256 FROM pando_lab.manifests WHERE repo=$1 ORDER BY pack_id",
            &[&repo],
        )
        .await?
        .into_iter()
        .map(|r| Pack {
            id: r.get(0),
            pack_sha256: r.get(1),
            idx_sha256: r.get(2),
        })
        .collect();
    let snapshot = Snapshot {
        repo,
        generation: row.get(0),
        storage_generation: row.get(1),
        refs,
        packs,
    };

    let token = Uuid::new_v4();
    t.execute(
        "INSERT INTO pando_lab.snapshots(id,repo,principal,generation,storage_generation,refs,packs) VALUES($1,$2,$3,$4,$5,$6,$7)",
        &[
            &token,
            &repo,
            &principal,
            &snapshot.generation,
            &snapshot.storage_generation,
            &serde_json::to_value(&snapshot.refs)?,
            &serde_json::to_value(&snapshot.packs)?,
        ],
    )
    .await?;

    t.commit().await?;
    Ok(token)
}
