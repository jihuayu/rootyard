use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::Write,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcReport {
    pub orphan_packs_deleted: usize,
    pub orphan_files_deleted: usize,
    pub orphan_bytes_reclaimed: u64,
    pub expired_snapshots_deleted: u64,
    pub aborted_operations_fenced: u64,
    pub committed_packs_retained: usize,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(super) async fn snapshot(config: &Config, repo: Uuid) -> Result<Snapshot> {
    let mut c = config.db().await?;
    let t = c
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await?;
    let row = t
        .query_one(
            "SELECT generation,storage_generation FROM pando_lab.repositories WHERE id=$1",
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
    t.commit().await?;
    Ok(snapshot)
}

pub(super) async fn init_repo(config: &Config, path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    config
        .git(
            path,
            &[
                "init",
                "--bare",
                "--object-format=sha1",
                "--initial-branch=main",
                ".",
            ],
            b"",
        )
        .await?;
    Ok(())
}

async fn index_pack(config: &Config, repo: &Path, data: &[u8]) -> Result<()> {
    config
        .git(repo, &["index-pack", "--stdin", "--strict"], data)
        .await?;
    Ok(())
}

/// Cold rebuild first validates immutable pack+idx then copies only the chosen
/// roots' reachable closure into an isolated repository. Hidden refs alone are
/// not our access boundary; obsolete and other-repository objects are absent.
pub(super) async fn materialize(
    config: &Config,
    snapshot: &Snapshot,
    base: &Path,
    ctl: &Control,
) -> Result<PathBuf> {
    let staging = base.join("staging.git");
    init_repo(config, &staging).await?;
    for pack in &snapshot.packs {
        object_store::ensure_local_pack_cached(config, snapshot.repo, pack).await?;
        let prefix = config
            .root
            .join("objects")
            .join(snapshot.repo.to_string())
            .join(pack.id.to_string());
        let mut bytes = std::fs::read(prefix.with_extension("pack"))?;
        let idx = std::fs::read(prefix.with_extension("idx"))?;
        if ctl.fault == "corrupt-read" && !bytes.is_empty() {
            bytes[0] ^= 1;
        }
        ensure!(
            digest(&bytes) == pack.pack_sha256 && digest(&idx) == pack.idx_sha256,
            "immutable pack checksum mismatch"
        );
        delta::verify_pack(&bytes, &delta::Limits::default())?;
        config
            .git(&staging, &["index-pack", "--stdin"], &bytes)
            .await?;
    }
    // Only roots in this immutable snapshot are given to pack-objects.
    let roots = snapshot.refs.values().cloned().collect::<Vec<_>>();
    let repo = base.join("repo.git");
    init_repo(config, &repo).await?;
    if !roots.is_empty() {
        let mut args = vec!["fsck", "--full", "--strict", "--no-reflogs"];
        args.extend(roots.iter().map(String::as_str));
        config.git(&staging, &args, b"").await?;
        let input = format!("{}\n", roots.join("\n"));
        let pack = config
            .git(
                &staging,
                &["pack-objects", "--stdout", "--revs"],
                input.as_bytes(),
            )
            .await?;
        index_pack(config, &repo, &pack).await?;
    }
    for (name, oid) in &snapshot.refs {
        config.git(&repo, &["update-ref", name, oid], b"").await?;
    }
    for (key, value) in [
        ("receive.procReceiveRefs", "refs/"),
        ("receive.fsckObjects", "true"),
        ("receive.unpackLimit", "1"),
        ("gc.auto", "0"),
        ("http.getanyfile", "false"),
        ("http.receivepack", "true"),
        ("uploadpack.allowAnySHA1InWant", "false"),
        ("uploadpack.allowReachableSHA1InWant", "false"),
        ("uploadpack.allowTipSHA1InWant", "false"),
    ] {
        config.git(&repo, &["config", key, value], b"").await?;
    }
    std::fs::write(repo.join("git-daemon-export-ok"), b"")?;
    // A symlink avoids shell quoting and uses the current executable exactly.
    std::os::unix::fs::symlink(std::env::current_exe()?, repo.join("hooks/proc-receive"))?;
    std::os::unix::fs::symlink(std::env::current_exe()?, repo.join("hooks/pre-receive"))?;
    Ok(repo)
}

/// Generates an incremental, delta-self-contained pack containing only objects reachable from
/// `roots` that are not already present in the repository's committed manifests, while verifying
/// full object graph closure via `delta::verify_pack` and `graph::walk_reachable`.
pub(super) async fn publish_pack(
    config: &Config,
    repo: Uuid,
    id: Uuid,
    git_dir: &Path,
    roots: &[String],
) -> Result<Option<(Pack, Vec<String>)>> {
    if roots.is_empty() {
        return Ok(None);
    }

    let existing_snap = snapshot(config, repo).await?;
    let existing_refs: Vec<String> = existing_snap
        .refs
        .values()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let mut existing_store = graph::ObjectStore::default();
    for pack in &existing_snap.packs {
        object_store::ensure_local_pack_cached(config, repo, pack).await?;
        let prefix = config
            .root
            .join("objects")
            .join(repo.to_string())
            .join(pack.id.to_string());
        let pack_bytes = std::fs::read(prefix.with_extension("pack"))?;
        let idx_bytes = std::fs::read(prefix.with_extension("idx"))?;
        ensure!(
            digest(&pack_bytes) == pack.pack_sha256 && digest(&idx_bytes) == pack.idx_sha256,
            "committed pack checksum mismatch before incremental pack publication"
        );
        let report = delta::verify_pack(&pack_bytes, &delta::Limits::default())?;
        existing_store.insert_pack(&report);
    }

    let mut rev_input = String::new();
    for r in roots {
        rev_input.push_str(r);
        rev_input.push('\n');
    }
    for old_oid in &existing_refs {
        rev_input.push('^');
        rev_input.push_str(old_oid);
        rev_input.push('\n');
    }

    let incremental_oids: Vec<String> = String::from_utf8(
        config
            .git(
                git_dir,
                &["rev-list", "--objects", "--no-object-names", "--stdin"],
                rev_input.as_bytes(),
            )
            .await?,
    )?
    .lines()
    .filter(|l| !l.is_empty())
    .map(str::to_owned)
    .collect();

    if incremental_oids.is_empty() {
        let full_walk = graph::walk_reachable(&existing_store, roots, &[])?;
        ensure!(
            !full_walk.reachable_oids.is_empty(),
            "reachable object closure for pushed roots is empty"
        );
        return Ok(None);
    }

    let bytes = config
        .git(
            git_dir,
            &["pack-objects", "--stdout", "--revs"],
            rev_input.as_bytes(),
        )
        .await?;
    ensure!(bytes.len() <= LIMIT, "lab pack size limit");

    let pack_report = delta::verify_pack(&bytes, &delta::Limits::default())?;
    existing_store.insert_pack(&pack_report);

    let inc_walk = graph::walk_reachable(&existing_store, roots, &existing_refs)?;
    let full_walk = graph::walk_reachable(&existing_store, roots, &[])?;
    let expected_set: BTreeSet<String> = incremental_oids.iter().cloned().collect();
    let walk_set: BTreeSet<String> = inc_walk.reachable_oids.iter().cloned().collect();
    ensure!(
        walk_set == expected_set && !full_walk.reachable_oids.is_empty(),
        "incremental pack graph walk mismatch against native git rev-list"
    );

    let scratch = Session::new(config)?;
    let pack_path = scratch.0.join("upload.pack");
    std::fs::write(&pack_path, &bytes)?;
    config
        .git(
            git_dir,
            &["index-pack", "--strict", &pack_path.to_string_lossy()],
            b"",
        )
        .await?;
    let idx = std::fs::read(scratch.0.join("upload.idx"))?;
    let dir = config.root.join("objects").join(repo.to_string());
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
        File::open(config.root.join("objects"))?.sync_all()?;
    }
    for (ext, data) in [("pack", &bytes), ("idx", &idx)] {
        let dest = dir.join(format!("{id}.{ext}"));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest)?;
        f.write_all(data)?;
        f.sync_all()?;
        ensure!(std::fs::read(&dest)? == *data, "object read-back mismatch");
    }
    File::open(&dir)?.sync_all()?;
    Ok(Some((
        Pack {
            id,
            pack_sha256: digest(&bytes),
            idx_sha256: digest(&idx),
        },
        inc_walk.reachable_oids,
    )))
}

/// Reclaims unreferenced orphan `.pack`/`.idx` files left by failed/aborted operations,
/// fences non-terminal operations, and purges expired read snapshots.
pub(super) async fn gc(config: &Config, repo_filter: Option<Uuid>) -> Result<GcReport> {
    let mut c = config.db().await?;
    let t = c.transaction().await?;

    let repos: Vec<Uuid> = if let Some(repo) = repo_filter {
        t.query(
            "SELECT id FROM pando_lab.repositories WHERE id=$1 FOR UPDATE",
            &[&repo],
        )
        .await?
        .into_iter()
        .map(|r| r.get(0))
        .collect()
    } else {
        t.query(
            "SELECT id FROM pando_lab.repositories ORDER BY id FOR UPDATE",
            &[],
        )
        .await?
        .into_iter()
        .map(|r| r.get(0))
        .collect()
    };

    let aborted_operations_fenced = if let Some(repo) = repo_filter {
        t.execute(
            "UPDATE pando_lab.operations SET state='ABORTED' WHERE repo=$1 AND state NOT IN ('COMMITTED','REJECTED','ABORTED')",
            &[&repo],
        )
        .await?
    } else {
        t.execute(
            "UPDATE pando_lab.operations SET state='ABORTED' WHERE state NOT IN ('COMMITTED','REJECTED','ABORTED')",
            &[],
        )
        .await?
    };

    let expired_snapshots_deleted = if let Some(repo) = repo_filter {
        t.execute(
            "DELETE FROM pando_lab.snapshots WHERE repo=$1 AND expires_at<=clock_timestamp()",
            &[&repo],
        )
        .await?
    } else {
        t.execute(
            "DELETE FROM pando_lab.snapshots WHERE expires_at<=clock_timestamp()",
            &[],
        )
        .await?
    };

    let committed_rows = if let Some(repo) = repo_filter {
        t.query(
            "SELECT repo,pack_id FROM pando_lab.manifests WHERE repo=$1",
            &[&repo],
        )
        .await?
    } else {
        t.query("SELECT repo,pack_id FROM pando_lab.manifests", &[])
            .await?
    };
    let mut committed: BTreeSet<(Uuid, Uuid)> = committed_rows
        .into_iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let active_snap_rows = if let Some(repo) = repo_filter {
        t.query(
            "SELECT repo,packs FROM pando_lab.snapshots WHERE repo=$1 AND expires_at>clock_timestamp()",
            &[&repo],
        )
        .await?
    } else {
        t.query(
            "SELECT repo,packs FROM pando_lab.snapshots WHERE expires_at>clock_timestamp()",
            &[],
        )
        .await?
    };
    for row in active_snap_rows {
        let srepo: Uuid = row.get(0);
        let spacks: Vec<Pack> = serde_json::from_value(row.get(1))?;
        for sp in spacks {
            committed.insert((srepo, sp.id));
        }
    }
    let committed_packs_retained = committed.len();
    t.commit().await?;

    let mut orphan_packs = BTreeSet::new();
    let mut orphan_files_deleted = 0usize;
    let mut orphan_bytes_reclaimed = 0u64;

    for repo in repos {
        let repo_dir = config.root.join("objects").join(repo.to_string());
        if !repo_dir.is_dir() {
            continue;
        }
        let mut removed_any = false;
        for entry in std::fs::read_dir(&repo_dir)? {
            let entry = entry?;
            let path = entry.path();
            let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
                continue;
            };
            if ext != "pack" && ext != "idx" {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let Ok(pack_id) = stem.parse::<Uuid>() else {
                continue;
            };
            if !committed.contains(&(repo, pack_id)) {
                let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                std::fs::remove_file(&path)?;
                orphan_packs.insert((repo, pack_id));
                orphan_files_deleted += 1;
                orphan_bytes_reclaimed += len;
                removed_any = true;
            }
        }
        if removed_any {
            File::open(&repo_dir)?.sync_all()?;
        }
    }

    Ok(GcReport {
        orphan_packs_deleted: orphan_packs.len(),
        orphan_files_deleted,
        orphan_bytes_reclaimed,
        expired_snapshots_deleted,
        aborted_operations_fenced,
        committed_packs_retained,
    })
}
