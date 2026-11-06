use super::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::Write,
    process::Command as StdCommand,
};

fn default_sync_object_store() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepackOptions {
    #[serde(default)]
    pub prune_superseded: bool,
    #[serde(default)]
    pub pin_oids: Vec<String>,
    #[serde(default = "default_sync_object_store")]
    pub sync_object_store: bool,
}

impl Default for RepackOptions {
    fn default() -> Self {
        Self {
            prune_superseded: false,
            pin_oids: Vec::new(),
            sync_object_store: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepackReport {
    pub repack_id: Uuid,
    pub repo: Uuid,
    pub generation: i64,
    pub storage_generation: i64,
    pub packs_before: usize,
    pub packs_after: usize,
    pub objects_before: usize,
    pub objects_after: usize,
    pub reachable_objects: usize,
    pub unreachable_objects_pruned: usize,
    pub ref_roots_count: usize,
    pub pinned_roots_count: usize,
    pub active_snapshots_count: usize,
    pub compacted_pack_id: Option<Uuid>,
    pub compacted_pack_sha256: Option<String>,
    pub compacted_idx_sha256: Option<String>,
    pub superseded_packs: Vec<Uuid>,
    pub snapshot_retained_packs: Vec<Uuid>,
    pub pruned_pack_files: usize,
    pub reclaimed_bytes: u64,
    pub object_store_synced: bool,
    pub dual_operator_verified: bool,
}

#[derive(Debug, Clone)]
pub struct CompactedPackArtifact {
    pub pack_id: Uuid,
    pub pack_bytes: Vec<u8>,
    pub idx_bytes: Vec<u8>,
    pub pack_sha256: String,
    pub idx_sha256: String,
    pub reachable_oids: Vec<String>,
    pub pruned_oids: Vec<String>,
    pub objects_before: usize,
    pub objects_after: usize,
}

pub fn valid_sha1_oid(oid: &str) -> bool {
    oid.len() == 40 && oid.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn run_sync_git(git_bin: &Path, cwd: &Path, args: &[&str], input: &[u8]) -> Result<Vec<u8>> {
    let mut cmd = StdCommand::new(git_bin);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("GIT_") && k != "GIT_EXEC_PATH" { cmd.env_remove(k); }
    }
    let mut child = cmd.current_dir(cwd).args(args).env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1").env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    if let Some(mut stdin) = child.stdin.take() { stdin.write_all(input)?; }
    let out = child.wait_with_output()?;
    ensure!(out.status.success(), "git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    Ok(out.stdout)
}

pub fn compact_packs_offline(
    git_bin: &Path,
    scratch_dir: &Path,
    input_packs: &[(Uuid, Vec<u8>, Vec<u8>)],
    roots: &[String],
) -> Result<Option<CompactedPackArtifact>> {
    for r in roots { ensure!(valid_sha1_oid(r), "invalid root OID: {r}"); }
    let staging = scratch_dir.join("repack-staging.git");
    std::fs::create_dir_all(&staging)?;
    run_sync_git(git_bin, &staging, &["init", "--bare", "--object-format=sha1", "--initial-branch=main", "."], b"")?;

    let mut before_store = graph::ObjectStore::default();
    for (_id, pack_bytes, _) in input_packs {
        let rep = delta::verify_pack(pack_bytes, &delta::Limits::default())?;
        before_store.insert_pack(&rep);
        run_sync_git(git_bin, &staging, &["index-pack", "--stdin"], pack_bytes)?;
    }
    let objects_before = before_store.objects.len();
    let wants: Vec<String> = roots.iter().cloned().collect::<BTreeSet<_>>().into_iter().collect();
    if wants.is_empty() { return Ok(None); }

    let walk_before = graph::walk_reachable(&before_store, &wants, &[])?;
    let rev_input = format!("{}\n", wants.join("\n"));
    let git_rev_out = String::from_utf8(run_sync_git(git_bin, &staging, &["rev-list", "--objects", "--no-object-names", "--stdin"], rev_input.as_bytes())?)?;
    let git_reachable: BTreeSet<String> = git_rev_out.lines().filter(|l| !l.is_empty()).map(str::to_owned).collect();
    let walk_set: BTreeSet<String> = walk_before.reachable_oids.iter().cloned().collect();
    ensure!(walk_set == git_reachable, "dual-operator reachability mismatch before pack compaction");

    let compacted_pack = run_sync_git(git_bin, &staging, &["pack-objects", "--stdout", "--revs", "--delta-base-offset"], rev_input.as_bytes())?;
    ensure!(compacted_pack.len() <= LIMIT, "compacted pack exceeds size limit");

    let after_rep = delta::verify_pack(&compacted_pack, &delta::Limits::default())?;
    let mut after_store = graph::ObjectStore::default();
    after_store.insert_pack(&after_rep);
    let walk_after = graph::walk_reachable(&after_store, &wants, &[])?;
    let after_set: BTreeSet<String> = walk_after.reachable_oids.iter().cloned().collect();
    ensure!(after_set == walk_set && after_store.objects.len() == walk_set.len(), "compacted pack closure mismatch");
    for oid in &walk_before.reachable_oids {
        ensure!(before_store.objects.get(oid) == after_store.objects.get(oid), "object content mismatch after compaction for {oid}");
    }

    let verify_git = scratch_dir.join("repack-verify.git");
    std::fs::create_dir_all(&verify_git)?;
    run_sync_git(git_bin, &verify_git, &["init", "--bare", "--object-format=sha1", "--initial-branch=main", "."], b"")?;
    let pack_id = Uuid::new_v4();
    let tmp_pack = scratch_dir.join(format!("{pack_id}.pack"));
    std::fs::write(&tmp_pack, &compacted_pack)?;
    run_sync_git(git_bin, &verify_git, &["index-pack", "--strict", &tmp_pack.to_string_lossy()], b"")?;
    let idx_bytes = std::fs::read(scratch_dir.join(format!("{pack_id}.idx")))?;
    run_sync_git(git_bin, &verify_git, &["index-pack", "--stdin"], &compacted_pack)?;
    let mut fsck_args = vec!["fsck", "--full", "--no-reflogs"];
    fsck_args.extend(wants.iter().map(String::as_str));
    run_sync_git(git_bin, &verify_git, &fsck_args, b"")?;

    let pruned_oids: Vec<String> = before_store.objects.keys().filter(|oid| !walk_set.contains(*oid)).cloned().collect();
    Ok(Some(CompactedPackArtifact {
        pack_id, pack_sha256: delta::sha256_hex(&compacted_pack), idx_sha256: delta::sha256_hex(&idx_bytes),
        pack_bytes: compacted_pack, idx_bytes, objects_before, objects_after: after_store.objects.len(),
        reachable_oids: walk_after.reachable_oids, pruned_oids,
    }))
}

pub(super) async fn repack_repo(config: &Config, repo: Uuid, opts: &RepackOptions) -> Result<RepackReport> {
    for pin in &opts.pin_oids { ensure!(valid_sha1_oid(pin), "invalid --pin-oid '{pin}'"); }
    let mut c = config.db().await?;
    let meta = c.query_one("SELECT generation,storage_generation,storage_backend,write_paused FROM pando_lab.repositories WHERE id=$1", &[&repo]).await?;
    let (pre_gen, pre_sgen, backend, paused): (i64, i64, String, bool) = (meta.get(0), meta.get(1), meta.get(2), meta.get(3));
    ensure!(!paused && backend == "pando", "repack requires active pando repository authority");

    let mut ref_roots = BTreeSet::new();
    let mut pinned_roots = BTreeSet::new();
    for r in c.query("SELECT name,oid FROM pando_lab.refs WHERE repo=$1 ORDER BY name", &[&repo]).await? {
        let (name, oid): (String, String) = (r.get(0), r.get(1));
        if name.starts_with("refs/rootyard-ci/") { pinned_roots.insert(oid); } else { ref_roots.insert(oid); }
    }
    for r in c.query("SELECT oid FROM pando_lab.pinned_roots WHERE repo=$1 ORDER BY name", &[&repo]).await? {
        pinned_roots.insert(r.get::<_, String>(0));
    }
    pinned_roots.extend(opts.pin_oids.iter().cloned());

    let mut snapshot_roots = BTreeSet::new();
    for r in c.query("SELECT refs FROM pando_lab.snapshots WHERE repo=$1 AND expires_at>clock_timestamp()", &[&repo]).await? {
        let s_refs: BTreeMap<String, String> = serde_json::from_value(r.get(0))?;
        snapshot_roots.extend(s_refs.into_values());
    }

    let m_rows = c.query("SELECT pack_id,pack_sha256,idx_sha256 FROM pando_lab.manifests WHERE repo=$1 ORDER BY pack_id", &[&repo]).await?;
    let db_objs_before: i64 = c.query_one("SELECT count(*) FROM pando_lab.objects WHERE repo=$1", &[&repo]).await?.get(0);
    let mut input_packs = Vec::with_capacity(m_rows.len());
    for r in &m_rows {
        let pack = Pack { id: r.get(0), pack_sha256: r.get(1), idx_sha256: r.get(2) };
        object_store::ensure_local_pack_cached(config, repo, &pack)?;
        let pfx = config.root.join("objects").join(repo.to_string()).join(pack.id.to_string());
        let (pb, ib) = (std::fs::read(pfx.with_extension("pack"))?, std::fs::read(pfx.with_extension("idx"))?);
        ensure!(delta::sha256_hex(&pb) == pack.pack_sha256 && delta::sha256_hex(&ib) == pack.idx_sha256, "pack checksum mismatch before repack");
        input_packs.push((pack.id, pb, ib));
    }

    let roots_vec: Vec<String> = ref_roots.iter().chain(pinned_roots.iter()).chain(snapshot_roots.iter()).cloned().collect();
    let session = Session::new(config)?;
    let compacted = compact_packs_offline(&config.git, &session.0, &input_packs, &roots_vec)?;

    let repo_obj_dir = config.root.join("objects").join(repo.to_string());
    std::fs::create_dir_all(&repo_obj_dir)?;
    let mut object_store_synced = false;
    if let Some(ref art) = compacted {
        for (ext, data) in [("pack", &art.pack_bytes), ("idx", &art.idx_bytes)] {
            let mut f = OpenOptions::new().write(true).create_new(true).open(repo_obj_dir.join(format!("{}.{ext}", art.pack_id)))?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        File::open(&repo_obj_dir)?.sync_all()?;
        if opts.sync_object_store {
            object_store::put_pack(config, repo, art.pack_id, &object_store::ObjectStorePutOptions::default()).await?;
            object_store_synced = true;
        }
    }

    let t = c.transaction().await?;
    let lk = t.query_one("SELECT generation,storage_generation,storage_backend,write_paused FROM pando_lab.repositories WHERE id=$1 FOR UPDATE", &[&repo]).await?;
    let (cur_gen, cur_sgen, cur_b, cur_p): (i64, i64, String, bool) = (lk.get(0), lk.get(1), lk.get(2), lk.get(3));
    if cur_p || cur_b != "pando" || cur_gen != pre_gen || cur_sgen != pre_sgen {
        if let Some(ref art) = compacted {
            let _ = std::fs::remove_file(repo_obj_dir.join(format!("{}.pack", art.pack_id)));
            let _ = std::fs::remove_file(repo_obj_dir.join(format!("{}.idx", art.pack_id)));
        }
        bail!("concurrent repository state change during repack");
    }

    let live_snaps = t.query("SELECT packs FROM pando_lab.snapshots WHERE repo=$1 AND expires_at>clock_timestamp()", &[&repo]).await?;
    let mut retained_set = BTreeSet::new();
    for r in &live_snaps {
        let spacks: Vec<Pack> = serde_json::from_value(r.get(0))?;
        retained_set.extend(spacks.into_iter().map(|p| p.id));
    }

    t.batch_execute("SET LOCAL pando.allow_repack_mutation = 'on'").await?;
    let (packs_after, objects_after, unreachable_pruned, comp_id, comp_psha, comp_isha) = if let Some(ref art) = compacted {
        t.execute("INSERT INTO pando_lab.manifests(repo,pack_id,pack_sha256,idx_sha256) VALUES($1,$2,$3,$4)", &[&repo, &art.pack_id, &art.pack_sha256, &art.idx_sha256]).await?;
        for oid in &art.reachable_oids {
            t.execute("INSERT INTO pando_lab.objects(repo,oid,pack_id) VALUES($1,$2,$3) ON CONFLICT(repo,oid) DO UPDATE SET pack_id=EXCLUDED.pack_id", &[&repo, oid, &art.pack_id]).await?;
        }
        for pin in &opts.pin_oids {
            let pin_name = format!("pin-{}", &pin[..12]);
            t.execute("INSERT INTO pando_lab.pinned_roots(repo,name,oid) VALUES($1,$2,$3) ON CONFLICT(repo,name) DO UPDATE SET oid=EXCLUDED.oid", &[&repo, &pin_name, pin]).await?;
        }
        let pruned = t.execute("DELETE FROM pando_lab.objects WHERE repo=$1 AND NOT (oid = ANY($2))", &[&repo, &art.reachable_oids]).await? as usize;
        t.execute("DELETE FROM pando_lab.manifests WHERE repo=$1 AND pack_id<>$2", &[&repo, &art.pack_id]).await?;
        if opts.prune_superseded {
            let keep: Vec<Uuid> = retained_set.iter().copied().chain(std::iter::once(art.pack_id)).collect();
            t.execute("DELETE FROM pando_lab.object_store_manifests WHERE repo=$1 AND NOT (pack_id = ANY($2))", &[&repo, &keep]).await?;
        }
        (1usize, art.reachable_oids.len(), pruned.max(art.pruned_oids.len()), Some(art.pack_id), Some(art.pack_sha256.clone()), Some(art.idx_sha256.clone()))
    } else {
        let pruned = t.execute("DELETE FROM pando_lab.objects WHERE repo=$1", &[&repo]).await? as usize;
        t.execute("DELETE FROM pando_lab.manifests WHERE repo=$1", &[&repo]).await?;
        (0usize, 0usize, pruned, None, None, None)
    };

    let (mut superseded_packs, mut snapshot_retained_packs) = (Vec::new(), Vec::new());
    for (old_id, _, _) in &input_packs {
        if retained_set.contains(old_id) { snapshot_retained_packs.push(*old_id); } else { superseded_packs.push(*old_id); }
    }
    let (mut pruned_pack_files, mut reclaimed_bytes) = (0usize, 0u64);
    if opts.prune_superseded {
        for old_id in &superseded_packs {
            for ext in ["pack", "idx"] {
                let p = repo_obj_dir.join(format!("{old_id}.{ext}"));
                if let Ok(m) = std::fs::metadata(&p) { reclaimed_bytes += m.len(); std::fs::remove_file(&p)?; pruned_pack_files += 1; }
            }
        }
        if pruned_pack_files > 0 { File::open(&repo_obj_dir)?.sync_all()?; }
    }

    let repack_id = Uuid::new_v4();
    let packs_before = input_packs.len();
    let objects_before = (db_objs_before as usize).max(compacted.as_ref().map(|a| a.objects_before).unwrap_or(0));
    t.execute(
        "INSERT INTO pando_lab.repacks(id,repo,generation,storage_generation,packs_before,packs_after,objects_before,objects_after,unreachable_objects_pruned,pinned_roots_count,active_snapshots_count,compacted_pack_id,superseded_packs,snapshot_retained_packs,reclaimed_bytes) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
        &[&repack_id, &repo, &cur_gen, &cur_sgen, &(packs_before as i64), &(packs_after as i64), &(objects_before as i64), &(objects_after as i64), &(unreachable_pruned as i64), &(pinned_roots.len() as i64), &(live_snaps.len() as i64), &comp_id, &serde_json::to_value(&superseded_packs)?, &serde_json::to_value(&snapshot_retained_packs)?, &(reclaimed_bytes as i64)],
    ).await?;
    t.commit().await?;

    Ok(RepackReport {
        repack_id, repo, generation: cur_gen, storage_generation: cur_sgen, packs_before, packs_after,
        objects_before, objects_after, reachable_objects: objects_after, unreachable_objects_pruned: unreachable_pruned,
        ref_roots_count: ref_roots.len(), pinned_roots_count: pinned_roots.len(), active_snapshots_count: live_snaps.len(),
        compacted_pack_id: comp_id, compacted_pack_sha256: comp_psha, compacted_idx_sha256: comp_isha,
        superseded_packs, snapshot_retained_packs, pruned_pack_files, reclaimed_bytes, object_store_synced, dual_operator_verified: true,
    })
}

pub(super) async fn pin_root(config: &Config, repo: Uuid, name: &str, oid: &str) -> Result<serde_json::Value> {
    ensure!(!name.is_empty() && name.len() <= 256 && valid_sha1_oid(oid), "invalid pin root parameters");
    config.db().await?.execute("INSERT INTO pando_lab.pinned_roots(repo,name,oid) VALUES($1,$2,$3) ON CONFLICT(repo,name) DO UPDATE SET oid=EXCLUDED.oid", &[&repo, &name, &oid]).await?;
    Ok(serde_json::json!({"repo": repo, "name": name, "oid": oid, "pinned": true}))
}

pub(super) async fn unpin_root(config: &Config, repo: Uuid, name: &str) -> Result<serde_json::Value> {
    let deleted = config.db().await?.execute("DELETE FROM pando_lab.pinned_roots WHERE repo=$1 AND name=$2", &[&repo, &name]).await?;
    Ok(serde_json::json!({"repo": repo, "name": name, "unpinned": deleted > 0}))
}

pub(super) async fn packs_status(config: &Config, repo: Uuid) -> Result<serde_json::Value> {
    let c = config.db().await?;
    let row = c.query_one("SELECT generation,storage_generation,storage_backend,write_paused FROM pando_lab.repositories WHERE id=$1", &[&repo]).await?;
    let packs: Vec<serde_json::Value> = c.query("SELECT pack_id,pack_sha256,idx_sha256 FROM pando_lab.manifests WHERE repo=$1 ORDER BY pack_id", &[&repo]).await?
        .iter().map(|r| serde_json::json!({"pack_id": r.get::<_, Uuid>(0), "pack_sha256": r.get::<_, String>(1), "idx_sha256": r.get::<_, String>(2)})).collect();
    let pinned_roots: Vec<serde_json::Value> = c.query("SELECT name,oid FROM pando_lab.pinned_roots WHERE repo=$1 ORDER BY name", &[&repo]).await?
        .iter().map(|r| serde_json::json!({"name": r.get::<_, String>(0), "oid": r.get::<_, String>(1)})).collect();
    let active_snapshots: i64 = c.query_one("SELECT count(*) FROM pando_lab.snapshots WHERE repo=$1 AND expires_at>clock_timestamp()", &[&repo]).await?.get(0);
    let latest_repack = c.query_opt("SELECT id,packs_before,packs_after,objects_before,objects_after,unreachable_objects_pruned,compacted_pack_id,superseded_packs,snapshot_retained_packs,reclaimed_bytes FROM pando_lab.repacks WHERE repo=$1 ORDER BY created_at DESC LIMIT 1", &[&repo]).await?
        .map(|r| serde_json::json!({"repack_id": r.get::<_, Uuid>(0), "packs_before": r.get::<_, i64>(1), "packs_after": r.get::<_, i64>(2), "objects_before": r.get::<_, i64>(3), "objects_after": r.get::<_, i64>(4), "unreachable_objects_pruned": r.get::<_, i64>(5), "compacted_pack_id": r.get::<_, Option<Uuid>>(6), "superseded_packs": r.get::<_, serde_json::Value>(7), "snapshot_retained_packs": r.get::<_, serde_json::Value>(8), "reclaimed_bytes": r.get::<_, i64>(9)}));
    Ok(serde_json::json!({"repo": repo, "generation": row.get::<_, i64>(0), "storage_generation": row.get::<_, i64>(1), "storage_backend": row.get::<_, String>(2), "write_paused": row.get::<_, bool>(3), "active_pack_count": packs.len(), "pack_count": packs.len(), "packs": packs, "pinned_roots": pinned_roots, "active_snapshots": active_snapshots, "latest_repack": latest_repack}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn multi_pack_compaction_prunes_orphans_and_retains_pinned_roots() {
        let git_bin = Path::new("/usr/bin/git");
        if !git_bin.exists() { return; }
        let tmp = std::env::temp_dir().join(format!("pando-repack-test-{}", Uuid::new_v4()));
        let work = tmp.join("work");
        std::fs::create_dir_all(&work).unwrap();
        run_sync_git(git_bin, &work, &["init", "--initial-branch=main", "."], b"").unwrap();
        run_sync_git(git_bin, &work, &["config", "user.name", "T"], b"").unwrap();
        run_sync_git(git_bin, &work, &["config", "user.email", "t@e.c"], b"").unwrap();
        let commit = |f: &str, msg: &str| -> String {
            std::fs::write(work.join(f), msg).unwrap();
            run_sync_git(git_bin, &work, &["add", f], b"").unwrap();
            run_sync_git(git_bin, &work, &["commit", "-m", msg], b"").unwrap();
            String::from_utf8(run_sync_git(git_bin, &work, &["rev-parse", "HEAD"], b"").unwrap()).unwrap().trim().to_owned()
        };
        let pack = |revs: &str| -> (Uuid, Vec<u8>, Vec<u8>) {
            let pb = run_sync_git(git_bin, &work, &["pack-objects", "--stdout", "--revs"], revs.as_bytes()).unwrap();
            (Uuid::new_v4(), pb, Vec::new())
        };
        let c1 = commit("a.txt", "c1");
        let p1 = pack(&format!("{c1}\n"));
        let c2_pin = commit("p.txt", "c2");
        let p2 = pack(&format!("{c2_pin}\n^{c1}\n"));
        run_sync_git(git_bin, &work, &["reset", "--hard", &c1], b"").unwrap();
        let c3_orp = commit("o.txt", "c3");
        let p3 = pack(&format!("{c3_orp}\n^{c1}\n"));
        run_sync_git(git_bin, &work, &["reset", "--hard", &c1], b"").unwrap();
        let c4_main = commit("m.txt", "c4");
        let p4 = pack(&format!("{c4_main}\n^{c1}\n"));
        let scratch = tmp.join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();
        let art = compact_packs_offline(git_bin, &scratch, &[p1, p2, p3, p4], &[c4_main.clone(), c2_pin.clone()]).unwrap().unwrap();
        assert!(art.reachable_oids.contains(&c4_main) && art.reachable_oids.contains(&c2_pin));
        assert!(art.pruned_oids.contains(&c3_orp));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
