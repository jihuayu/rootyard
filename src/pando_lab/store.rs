use super::*;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Write,
};

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
    let packs=t.query("SELECT pack_id,pack_sha256,idx_sha256 FROM pando_lab.manifests WHERE repo=$1 ORDER BY pack_id",&[&repo]).await?.into_iter().map(|r|Pack{id:r.get(0),pack_sha256:r.get(1),idx_sha256:r.get(2)}).collect();
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
        index_pack(config, &staging, &bytes).await?;
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

/// Operation UUID is a never-reused physical key. Failed uploads remain orphans.
/// There is deliberately no GC/DELETE, so late deletion cannot destroy a reuse.
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
    let input = format!("{}\n", roots.join("\n"));
    let bytes = config
        .git(
            git_dir,
            &["pack-objects", "--stdout", "--revs"],
            input.as_bytes(),
        )
        .await?;
    ensure!(bytes.len() <= LIMIT, "lab pack size limit");
    let scratch = Session::new(config)?;
    let pack_path = scratch.0.join("upload.pack");
    std::fs::write(&pack_path, &bytes)?;
    config
        .git(&scratch.0, &["index-pack", "--strict", "upload.pack"], b"")
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
    let oids = String::from_utf8(
        config
            .git(
                git_dir,
                &["rev-list", "--objects", "--no-object-names", "--stdin"],
                input.as_bytes(),
            )
            .await?,
    )?
    .lines()
    .map(str::to_owned)
    .collect();
    Ok(Some((
        Pack {
            id,
            pack_sha256: digest(&bytes),
            idx_sha256: digest(&idx),
        },
        oids,
    )))
}
