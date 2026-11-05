use super::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::Write,
    os::unix::fs::PermissionsExt,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationReport {
    pub migration_id: Uuid,
    pub repo: Uuid,
    pub direction: String,
    pub step: String,
    pub state: String,
    pub storage_backend: String,
    pub migration_state: String,
    pub write_paused: bool,
    pub gitfs_path: String,
    pub generation: i64,
    pub old_storage_generation: i64,
    pub new_storage_generation: i64,
    pub copied_packs: u64,
    pub copied_objects: u64,
    pub ref_count: usize,
    pub drained_operations: u64,
    pub incremental_objects_synced: usize,
    pub gitfs_fenced_readonly: bool,
    pub diff_report: Option<export::DiffExportReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationStatusReport {
    pub repo: Uuid,
    pub generation: i64,
    pub storage_generation: i64,
    pub storage_backend: String,
    pub migration_state: String,
    pub write_paused: bool,
    pub gitfs_path: Option<String>,
    pub inflight_operations: i64,
    pub latest_migration: Option<serde_json::Value>,
}

const GITFS_PRE_RECEIVE_HOOK: &str = r#"#!/bin/sh
set -eu
paused="$(git config --bool --get rootyard.writePaused 2>/dev/null || echo false)"
backend="$(git config --get rootyard.storageBackend 2>/dev/null || echo gitfs)"
gen="$(git config --get rootyard.storageGeneration 2>/dev/null || echo 1)"
if [ "$paused" = "true" ]; then
  echo "rootyard migration fence: writes are paused on GitFS (storage_generation=$gen)" >&2
  exit 1
fi
if [ "$backend" != "gitfs" ]; then
  echo "rootyard migration fence: GitFS is read-only; authority is $backend (storage_generation=$gen)" >&2
  exit 1
fi
if [ -n "${ROOTYARD_EXPECTED_STORAGE_GENERATION:-}" ] && [ "$ROOTYARD_EXPECTED_STORAGE_GENERATION" != "$gen" ]; then
  echo "rootyard migration fence: stale storage_generation $ROOTYARD_EXPECTED_STORAGE_GENERATION != $gen" >&2
  exit 1
fi
exit 0
"#;

pub(super) async fn validate_gitfs_bare_repo(config: &Config, gitfs_path: &Path) -> Result<()> {
    ensure!(gitfs_path.is_dir(), "GitFS repository path does not exist: {}", gitfs_path.display());
    let is_bare = String::from_utf8(
        config.git(gitfs_path, &["rev-parse", "--is-bare-repository"], b"").await?,
    )?;
    ensure!(is_bare.trim() == "true", "GitFS source must be a bare repository: {}", gitfs_path.display());
    config.git(gitfs_path, &["fsck", "--full", "--strict", "--no-reflogs"], b"").await?;
    Ok(())
}

pub(super) fn ensure_no_gitfs_locks(gitfs_path: &Path) -> Result<()> {
    for lock_name in ["HEAD.lock", "packed-refs.lock", "config.lock"] {
        let p = gitfs_path.join(lock_name);
        ensure!(!p.exists(), "active GitFS lock file detected during migration drain: {}", p.display());
    }
    let refs_dir = gitfs_path.join("refs");
    if refs_dir.is_dir() {
        check_locks_recursive(&refs_dir)?;
    }
    Ok(())
}

fn check_locks_recursive(dir: &Path) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            check_locks_recursive(&path)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("lock") {
            bail!("active GitFS ref lock detected during migration drain: {}", path.display());
        }
    }
    Ok(())
}

pub(super) async fn read_gitfs_refs(config: &Config, gitfs_path: &Path) -> Result<BTreeMap<String, String>> {
    let raw = String::from_utf8(
        config
            .git(gitfs_path, &["for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/tags"], b"")
            .await?,
    )?;
    let mut refs = BTreeMap::new();
    for line in raw.lines().filter(|l| !l.is_empty()) {
        let (name, oid) = line.split_once(' ').context("invalid git for-each-ref line")?;
        refs.insert(name.to_owned(), oid.to_owned());
    }
    for name in refs.keys() {
        for (i, _) in name.match_indices('/') {
            ensure!(!refs.contains_key(&name[..i]), "ref directory/file conflict in GitFS source");
        }
    }
    Ok(refs)
}

pub(super) async fn configure_gitfs_fence(
    config: &Config,
    gitfs_path: &Path,
    write_paused: bool,
    backend: &str,
    storage_gen: i64,
) -> Result<()> {
    let hooks_dir = gitfs_path.join("hooks");
    std::fs::create_dir_all(&hooks_dir)?;
    let tmp_hook = hooks_dir.join(format!(".pre-receive.tmp-{}", Uuid::new_v4()));
    {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp_hook)?;
        f.write_all(GITFS_PRE_RECEIVE_HOOK.as_bytes())?;
        f.set_permissions(std::fs::Permissions::from_mode(0o755))?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp_hook, hooks_dir.join("pre-receive"))?;
    std::fs::File::open(&hooks_dir)?.sync_all()?;

    let receive_pack = if !write_paused && backend == "gitfs" { "true" } else { "false" };
    let paused_str = if write_paused { "true" } else { "false" };
    let gen_str = storage_gen.to_string();
    for (k, v) in [
        ("rootyard.writePaused", paused_str),
        ("rootyard.storageBackend", backend),
        ("rootyard.storageGeneration", gen_str.as_str()),
        ("http.receivepack", receive_pack),
    ] {
        config.git(gitfs_path, &["config", k, v], b"").await?;
    }
    Ok(())
}

pub(super) async fn verify_parity_against_gitfs(
    config: &Config,
    repo: Uuid,
    gitfs_path: &Path,
) -> Result<export::DiffExportReport> {
    let diff_report = export::diff_export(config, repo, &[]).await?;
    ensure!(diff_report.matched && diff_report.bit_for_bit_match, "dual-operator diff_export failed parity verification");

    let snap = store::snapshot(config, repo).await?;
    let gitfs_refs = read_gitfs_refs(config, gitfs_path).await?;
    ensure!(snap.refs == gitfs_refs, "Pando refs do not match GitFS refs");

    let mut obj_store = graph::ObjectStore::default();
    for pack in &snap.packs {
        let prefix = config.root.join("objects").join(repo.to_string()).join(pack.id.to_string());
        let pack_bytes = std::fs::read(prefix.with_extension("pack"))?;
        let report = delta::verify_pack(&pack_bytes, &delta::Limits::default())?;
        obj_store.insert_pack(&report);
    }

    let wants: Vec<String> = gitfs_refs.values().cloned().collect::<BTreeSet<_>>().into_iter().collect();
    let walk = graph::walk_reachable(&obj_store, &wants, &[])?;

    let gitfs_oids: BTreeSet<String> = if wants.is_empty() {
        BTreeSet::new()
    } else {
        let rev_input = format!("{}\n", wants.join("\n"));
        let rev_out = String::from_utf8(
            config.git(gitfs_path, &["rev-list", "--objects", "--no-object-names", "--stdin"], rev_input.as_bytes()).await?,
        )?;
        rev_out.lines().filter(|l| !l.is_empty()).map(str::to_owned).collect()
    };

    let pando_oids: BTreeSet<String> = walk.reachable_oids.iter().cloned().collect();
    ensure!(pando_oids == gitfs_oids, "reachable object closure mismatch between Pando and GitFS");

    for oid in &pando_oids {
        let (pando_type, pando_data) = obj_store.objects.get(oid).context("missing object in Pando ObjectStore")?;
        let git_type = String::from_utf8(config.git(gitfs_path, &["cat-file", "-t", oid], b"").await?)?;
        ensure!(git_type.trim() == pando_type.as_str(), "GitFS object type mismatch for {oid}");
        let git_raw = config.git(gitfs_path, &["cat-file", pando_type.as_str(), oid], b"").await?;
        ensure!(git_raw == *pando_data, "GitFS byte-for-bit content mismatch for {oid}");
    }
    Ok(diff_report)
}

async fn count_packs_and_objects(t: &tokio_postgres::Transaction<'_>, repo: Uuid) -> Result<(i64, i64)> {
    let packs: i64 = t.query_one("SELECT count(*) FROM pando_lab.manifests WHERE repo=$1", &[&repo]).await?.get(0);
    let objs: i64 = t.query_one("SELECT count(*) FROM pando_lab.objects WHERE repo=$1", &[&repo]).await?.get(0);
    Ok((packs, objs))
}

async fn latest_or_new_migration_id(
    t: &tokio_postgres::Transaction<'_>,
    repo: Uuid,
    gitfs_str: &str,
    storage_gen: i64,
    state: &str,
) -> Result<(Uuid, i64)> {
    if let Some(row) = t
        .query_opt(
            "SELECT id, old_storage_generation FROM pando_lab.migrations WHERE repo=$1 AND direction='gitfs_to_pando' ORDER BY created_at DESC LIMIT 1 FOR UPDATE",
            &[&repo],
        )
        .await?
    {
        Ok((row.get(0), row.get(1)))
    } else {
        let id = Uuid::new_v4();
        t.execute(
            "INSERT INTO pando_lab.migrations(id,repo,direction,state,gitfs_path,old_storage_generation) VALUES($1,$2,'gitfs_to_pando',$3,$4,$5)",
            &[&id, &repo, &state, &gitfs_str, &storage_gen],
        )
        .await?;
        Ok((id, storage_gen))
    }
}

pub(super) async fn step_copy(config: &Config, repo: Uuid, gitfs_path: &Path) -> Result<MigrationReport> {
    let gitfs_abs = std::fs::canonicalize(gitfs_path)?;
    let gitfs_str = gitfs_abs.to_string_lossy().into_owned();
    validate_gitfs_bare_repo(config, &gitfs_abs).await?;

    let mut c = config.db().await?;
    let storage_gen: i64 = {
        let t = c.transaction().await?;
        let row = t
            .query_one(
                "INSERT INTO pando_lab.repositories(id, storage_backend, migration_state, write_paused, gitfs_path) \
                 VALUES($1, 'gitfs', 'copying', false, $2) \
                 ON CONFLICT(id) DO UPDATE SET storage_backend='gitfs', migration_state='copying', write_paused=false, gitfs_path=excluded.gitfs_path \
                 RETURNING storage_generation",
                &[&repo, &gitfs_str],
            )
            .await?;
        t.execute(
            "INSERT INTO pando_lab.acl(repo, principal, write_allowed) VALUES($1, 'alice', true) ON CONFLICT(repo, principal) DO NOTHING",
            &[&repo],
        )
        .await?;
        t.commit().await?;
        row.get(0)
    };

    configure_gitfs_fence(config, &gitfs_abs, false, "gitfs", storage_gen).await?;

    let gitfs_refs = read_gitfs_refs(config, &gitfs_abs).await?;
    let roots: Vec<String> = gitfs_refs.values().cloned().collect::<BTreeSet<_>>().into_iter().collect();
    let published = store::publish_pack(config, repo, Uuid::new_v4(), &gitfs_abs, &roots).await?;
    let synced_count = published.as_ref().map(|(_, oids)| oids.len()).unwrap_or(0);

    let t = c.transaction().await?;
    let row = t.query_one("SELECT generation, storage_generation FROM pando_lab.repositories WHERE id=$1 FOR UPDATE", &[&repo]).await?;
    let generation: i64 = row.get(0);
    let old_storage_gen: i64 = row.get(1);

    if let Some((pack, oids)) = &published {
        t.execute(
            "INSERT INTO pando_lab.manifests(repo,pack_id,pack_sha256,idx_sha256) VALUES($1,$2,$3,$4) ON CONFLICT(repo,pack_id) DO NOTHING",
            &[&repo, &pack.id, &pack.pack_sha256, &pack.idx_sha256],
        )
        .await?;
        for oid in oids {
            t.execute("INSERT INTO pando_lab.objects(repo,oid,pack_id) VALUES($1,$2,$3) ON CONFLICT(repo,oid) DO NOTHING", &[&repo, oid, &pack.id]).await?;
        }
    }

    t.execute("DELETE FROM pando_lab.refs WHERE repo=$1", &[&repo]).await?;
    for (name, oid) in &gitfs_refs {
        t.execute("INSERT INTO pando_lab.refs(repo,name,oid) VALUES($1,$2,$3)", &[&repo, name, oid]).await?;
    }

    let next_gen = generation.checked_add(1).context("generation exhausted")?;
    t.execute(
        "UPDATE pando_lab.repositories SET generation=$2, storage_backend='gitfs', migration_state='copying', write_paused=false, gitfs_path=$3 WHERE id=$1",
        &[&repo, &next_gen, &gitfs_str],
    )
    .await?;

    let (packs_cnt, objs_cnt) = count_packs_and_objects(&t, repo).await?;
    let mig_id = Uuid::new_v4();
    t.execute(
        "INSERT INTO pando_lab.migrations(id,repo,direction,state,gitfs_path,old_storage_generation,copied_packs,copied_objects) VALUES($1,$2,'gitfs_to_pando','COPYING',$3,$4,$5,$6)",
        &[&mig_id, &repo, &gitfs_str, &old_storage_gen, &packs_cnt, &objs_cnt],
    )
    .await?;
    t.commit().await?;

    Ok(MigrationReport {
        migration_id: mig_id,
        repo,
        direction: "gitfs_to_pando".to_owned(),
        step: "copy".to_owned(),
        state: "COPYING".to_owned(),
        storage_backend: "gitfs".to_owned(),
        migration_state: "copying".to_owned(),
        write_paused: false,
        gitfs_path: gitfs_str,
        generation: next_gen,
        old_storage_generation: old_storage_gen,
        new_storage_generation: old_storage_gen,
        copied_packs: packs_cnt as u64,
        copied_objects: objs_cnt as u64,
        ref_count: gitfs_refs.len(),
        drained_operations: 0,
        incremental_objects_synced: synced_count,
        gitfs_fenced_readonly: false,
        diff_report: None,
    })
}

pub(super) async fn step_verify(config: &Config, repo: Uuid, gitfs_path: &Path) -> Result<MigrationReport> {
    let gitfs_abs = std::fs::canonicalize(gitfs_path)?;
    let gitfs_str = gitfs_abs.to_string_lossy().into_owned();
    validate_gitfs_bare_repo(config, &gitfs_abs).await?;
    let diff_report = verify_parity_against_gitfs(config, repo, &gitfs_abs).await?;

    let mut c = config.db().await?;
    let t = c.transaction().await?;
    let row = t
        .query_one("SELECT generation, storage_generation, storage_backend, migration_state, write_paused FROM pando_lab.repositories WHERE id=$1 FOR UPDATE", &[&repo])
        .await?;
    let generation: i64 = row.get(0);
    let storage_gen: i64 = row.get(1);
    let backend: String = row.get(2);
    let mig_state: String = row.get(3);
    let write_paused: bool = row.get(4);
    ensure!(matches!(mig_state.as_str(), "copying" | "verified"), "verify requires migration_state in copying|verified, got {mig_state}");

    t.execute("UPDATE pando_lab.repositories SET migration_state='verified', gitfs_path=$2 WHERE id=$1", &[&repo, &gitfs_str]).await?;
    let (packs_cnt, objs_cnt) = count_packs_and_objects(&t, repo).await?;
    let (mig_id, old_storage_gen) = latest_or_new_migration_id(&t, repo, &gitfs_str, storage_gen, "VERIFIED").await?;
    t.execute(
        "UPDATE pando_lab.migrations SET state='VERIFIED', copied_packs=$2, copied_objects=$3, diff_report=$4, updated_at=clock_timestamp() WHERE id=$1",
        &[&mig_id, &packs_cnt, &objs_cnt, &serde_json::to_value(&diff_report)?],
    )
    .await?;
    t.commit().await?;

    Ok(MigrationReport {
        migration_id: mig_id,
        repo,
        direction: "gitfs_to_pando".to_owned(),
        step: "verify".to_owned(),
        state: "VERIFIED".to_owned(),
        storage_backend: backend,
        migration_state: "verified".to_owned(),
        write_paused,
        gitfs_path: gitfs_str,
        generation,
        old_storage_generation: old_storage_gen,
        new_storage_generation: storage_gen,
        copied_packs: packs_cnt as u64,
        copied_objects: objs_cnt as u64,
        ref_count: diff_report.ref_count,
        drained_operations: 0,
        incremental_objects_synced: 0,
        gitfs_fenced_readonly: false,
        diff_report: Some(diff_report),
    })
}

pub(super) async fn step_drain(config: &Config, repo: Uuid, gitfs_path: &Path) -> Result<MigrationReport> {
    let gitfs_abs = std::fs::canonicalize(gitfs_path)?;
    let gitfs_str = gitfs_abs.to_string_lossy().into_owned();
    validate_gitfs_bare_repo(config, &gitfs_abs).await?;

    let mut c = config.db().await?;
    let (storage_gen, drained_ops) = {
        let t = c.transaction().await?;
        let row = t.query_one("SELECT storage_generation, migration_state FROM pando_lab.repositories WHERE id=$1 FOR UPDATE", &[&repo]).await?;
        let sgen: i64 = row.get(0);
        let mstate: String = row.get(1);
        ensure!(matches!(mstate.as_str(), "copying" | "verified" | "draining"), "drain requires migration_state in copying|verified|draining, got {mstate}");
        t.execute("UPDATE pando_lab.repositories SET write_paused=true, migration_state='draining', storage_backend='gitfs', gitfs_path=$2 WHERE id=$1", &[&repo, &gitfs_str]).await?;
        let drained = t
            .execute("UPDATE pando_lab.operations SET state='ABORTED', result=jsonb_build_object('error','aborted by migration drain') WHERE repo=$1 AND state NOT IN ('COMMITTED','REJECTED','ABORTED')", &[&repo])
            .await?;
        t.commit().await?;
        (sgen, drained)
    };

    configure_gitfs_fence(config, &gitfs_abs, true, "gitfs", storage_gen).await?;
    ensure_no_gitfs_locks(&gitfs_abs)?;

    let gitfs_refs = read_gitfs_refs(config, &gitfs_abs).await?;
    let roots: Vec<String> = gitfs_refs.values().cloned().collect::<BTreeSet<_>>().into_iter().collect();
    let published = store::publish_pack(config, repo, Uuid::new_v4(), &gitfs_abs, &roots).await?;
    let inc_objects = published.as_ref().map(|(_, oids)| oids.len()).unwrap_or(0);

    {
        let t = c.transaction().await?;
        let generation: i64 = t.query_one("SELECT generation FROM pando_lab.repositories WHERE id=$1 FOR UPDATE", &[&repo]).await?.get(0);
        let existing_refs: BTreeMap<String, String> = t
            .query("SELECT name, oid FROM pando_lab.refs WHERE repo=$1", &[&repo])
            .await?
            .into_iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();

        if let Some((pack, oids)) = &published {
            t.execute("INSERT INTO pando_lab.manifests(repo,pack_id,pack_sha256,idx_sha256) VALUES($1,$2,$3,$4) ON CONFLICT(repo,pack_id) DO NOTHING", &[&repo, &pack.id, &pack.pack_sha256, &pack.idx_sha256]).await?;
            for oid in oids {
                t.execute("INSERT INTO pando_lab.objects(repo,oid,pack_id) VALUES($1,$2,$3) ON CONFLICT(repo,oid) DO NOTHING", &[&repo, oid, &pack.id]).await?;
            }
        }
        if existing_refs != gitfs_refs || published.is_some() {
            t.execute("DELETE FROM pando_lab.refs WHERE repo=$1", &[&repo]).await?;
            for (name, oid) in &gitfs_refs {
                t.execute("INSERT INTO pando_lab.refs(repo,name,oid) VALUES($1,$2,$3)", &[&repo, name, oid]).await?;
            }
            let next_gen = generation.checked_add(1).context("generation exhausted")?;
            t.execute("UPDATE pando_lab.repositories SET generation=$2 WHERE id=$1", &[&repo, &next_gen]).await?;
        }
        t.commit().await?;
    }

    let diff_report = verify_parity_against_gitfs(config, repo, &gitfs_abs).await?;
    let t = c.transaction().await?;
    let row = t.query_one("SELECT generation, storage_generation FROM pando_lab.repositories WHERE id=$1 FOR UPDATE", &[&repo]).await?;
    let generation: i64 = row.get(0);
    let sgen: i64 = row.get(1);
    let (packs_cnt, objs_cnt) = count_packs_and_objects(&t, repo).await?;
    let (mig_id, old_storage_gen) = latest_or_new_migration_id(&t, repo, &gitfs_str, sgen, "DRAINED").await?;
    t.execute(
        "UPDATE pando_lab.migrations SET state='DRAINED', copied_packs=$2, copied_objects=$3, diff_report=$4, updated_at=clock_timestamp() WHERE id=$1",
        &[&mig_id, &packs_cnt, &objs_cnt, &serde_json::to_value(&diff_report)?],
    )
    .await?;
    t.commit().await?;

    Ok(MigrationReport {
        migration_id: mig_id,
        repo,
        direction: "gitfs_to_pando".to_owned(),
        step: "drain".to_owned(),
        state: "DRAINED".to_owned(),
        storage_backend: "gitfs".to_owned(),
        migration_state: "draining".to_owned(),
        write_paused: true,
        gitfs_path: gitfs_str,
        generation,
        old_storage_generation: old_storage_gen,
        new_storage_generation: sgen,
        copied_packs: packs_cnt as u64,
        copied_objects: objs_cnt as u64,
        ref_count: gitfs_refs.len(),
        drained_operations: drained_ops,
        incremental_objects_synced: inc_objects,
        gitfs_fenced_readonly: true,
        diff_report: Some(diff_report),
    })
}

pub(super) async fn step_fence(config: &Config, repo: Uuid, gitfs_path: &Path) -> Result<MigrationReport> {
    let gitfs_abs = std::fs::canonicalize(gitfs_path)?;
    let gitfs_str = gitfs_abs.to_string_lossy().into_owned();
    ensure_no_gitfs_locks(&gitfs_abs)?;

    let mut c = config.db().await?;
    let t = c.transaction().await?;
    let row = t
        .query_one("SELECT generation, storage_generation, storage_backend, migration_state, write_paused FROM pando_lab.repositories WHERE id=$1 FOR UPDATE", &[&repo])
        .await?;
    let generation: i64 = row.get(0);
    let cur_storage_gen: i64 = row.get(1);
    let backend: String = row.get(2);
    let mstate: String = row.get(3);
    let write_paused: bool = row.get(4);
    ensure!(write_paused && matches!(mstate.as_str(), "draining" | "fenced"), "fence requires write_paused=true and migration_state in draining|fenced");

    let new_gen = generation.checked_add(1).context("generation exhausted")?;
    let new_storage_gen = cur_storage_gen.checked_add(1).context("storage_generation exhausted")?;

    t.execute("UPDATE pando_lab.repositories SET generation=$2, storage_generation=$3, migration_state='fenced', write_paused=true, gitfs_path=$4 WHERE id=$1", &[&repo, &new_gen, &new_storage_gen, &gitfs_str]).await?;
    t.execute("DELETE FROM pando_lab.snapshots WHERE repo=$1 AND storage_generation < $2", &[&repo, &new_storage_gen]).await?;
    let aborted = t
        .execute("UPDATE pando_lab.operations SET state='ABORTED', result=jsonb_build_object('error','fenced by storage_generation bump') WHERE repo=$1 AND state NOT IN ('COMMITTED','REJECTED','ABORTED')", &[&repo])
        .await?;
    let ref_count: i64 = t.query_one("SELECT count(*) FROM pando_lab.refs WHERE repo=$1", &[&repo]).await?.get(0);
    let (packs_cnt, objs_cnt) = count_packs_and_objects(&t, repo).await?;
    let (mig_id, old_storage_gen) = latest_or_new_migration_id(&t, repo, &gitfs_str, cur_storage_gen, "FENCED").await?;
    t.execute(
        "UPDATE pando_lab.migrations SET state='FENCED', new_storage_generation=$2, copied_packs=$3, copied_objects=$4, updated_at=clock_timestamp() WHERE id=$1",
        &[&mig_id, &new_storage_gen, &packs_cnt, &objs_cnt],
    )
    .await?;
    t.commit().await?;

    configure_gitfs_fence(config, &gitfs_abs, true, &backend, new_storage_gen).await?;

    Ok(MigrationReport {
        migration_id: mig_id,
        repo,
        direction: "gitfs_to_pando".to_owned(),
        step: "fence".to_owned(),
        state: "FENCED".to_owned(),
        storage_backend: backend,
        migration_state: "fenced".to_owned(),
        write_paused: true,
        gitfs_path: gitfs_str,
        generation: new_gen,
        old_storage_generation: old_storage_gen,
        new_storage_generation: new_storage_gen,
        copied_packs: packs_cnt as u64,
        copied_objects: objs_cnt as u64,
        ref_count: ref_count as usize,
        drained_operations: aborted,
        incremental_objects_synced: 0,
        gitfs_fenced_readonly: true,
        diff_report: None,
    })
}

pub(super) async fn step_switchover(config: &Config, repo: Uuid, gitfs_path: &Path) -> Result<MigrationReport> {
    let gitfs_abs = std::fs::canonicalize(gitfs_path)?;
    let gitfs_str = gitfs_abs.to_string_lossy().into_owned();
    ensure_no_gitfs_locks(&gitfs_abs)?;

    let snap = store::snapshot(config, repo).await?;
    configure_gitfs_fence(config, &gitfs_abs, true, "pando", snap.storage_generation).await?;

    let session = Session::new(config)?;
    let ctl = Control::default();
    let materialized = store::materialize(config, &snap, &session.0, &ctl).await?;
    config.git(&materialized, &["fsck", "--full", "--strict", "--no-reflogs"], b"").await?;
    let diff_report = verify_parity_against_gitfs(config, repo, &gitfs_abs).await?;

    let mut c = config.db().await?;
    let t = c.transaction().await?;
    let row = t.query_one("SELECT generation, storage_generation, migration_state, write_paused FROM pando_lab.repositories WHERE id=$1 FOR UPDATE", &[&repo]).await?;
    let generation: i64 = row.get(0);
    let storage_gen: i64 = row.get(1);
    let mstate: String = row.get(2);
    let write_paused: bool = row.get(3);
    ensure!(mstate == "fenced" && write_paused, "switchover requires migration_state=fenced and write_paused=true");

    let next_gen = generation.checked_add(1).context("generation exhausted")?;
    t.execute("UPDATE pando_lab.repositories SET generation=$2, storage_backend='pando', migration_state='switched_over', write_paused=false, gitfs_path=$3 WHERE id=$1", &[&repo, &next_gen, &gitfs_str]).await?;

    let (packs_cnt, objs_cnt) = count_packs_and_objects(&t, repo).await?;
    let (mig_id, old_storage_gen) = latest_or_new_migration_id(&t, repo, &gitfs_str, storage_gen, "SWITCHED_OVER").await?;
    t.execute(
        "UPDATE pando_lab.migrations SET state='SWITCHED_OVER', new_storage_generation=$2, copied_packs=$3, copied_objects=$4, diff_report=$5, updated_at=clock_timestamp() WHERE id=$1",
        &[&mig_id, &storage_gen, &packs_cnt, &objs_cnt, &serde_json::to_value(&diff_report)?],
    )
    .await?;
    t.commit().await?;

    Ok(MigrationReport {
        migration_id: mig_id,
        repo,
        direction: "gitfs_to_pando".to_owned(),
        step: "switchover".to_owned(),
        state: "SWITCHED_OVER".to_owned(),
        storage_backend: "pando".to_owned(),
        migration_state: "switched_over".to_owned(),
        write_paused: false,
        gitfs_path: gitfs_str,
        generation: next_gen,
        old_storage_generation: old_storage_gen,
        new_storage_generation: storage_gen,
        copied_packs: packs_cnt as u64,
        copied_objects: objs_cnt as u64,
        ref_count: diff_report.ref_count,
        drained_operations: 0,
        incremental_objects_synced: 0,
        gitfs_fenced_readonly: true,
        diff_report: Some(diff_report),
    })
}

pub(super) async fn migrate_step(config: &Config, repo: Uuid, gitfs_path: &Path, step: &str) -> Result<MigrationReport> {
    match step {
        "copy" => step_copy(config, repo, gitfs_path).await,
        "verify" => step_verify(config, repo, gitfs_path).await,
        "drain" => step_drain(config, repo, gitfs_path).await,
        "fence" => step_fence(config, repo, gitfs_path).await,
        "switchover" => step_switchover(config, repo, gitfs_path).await,
        other => bail!("unknown migration step '{other}' (expected copy|verify|drain|fence|switchover)"),
    }
}

pub(super) async fn migrate_full(config: &Config, repo: Uuid, gitfs_path: &Path) -> Result<MigrationReport> {
    let copy_rep = step_copy(config, repo, gitfs_path).await?;
    step_verify(config, repo, gitfs_path).await?;
    let drain_rep = step_drain(config, repo, gitfs_path).await?;
    let fence_rep = step_fence(config, repo, gitfs_path).await?;
    let mut final_rep = step_switchover(config, repo, gitfs_path).await?;
    final_rep.step = "full".to_owned();
    final_rep.drained_operations = drain_rep.drained_operations + fence_rep.drained_operations;
    final_rep.incremental_objects_synced = copy_rep.incremental_objects_synced + drain_rep.incremental_objects_synced;
    Ok(final_rep)
}

pub(super) async fn status(config: &Config, repo: Uuid) -> Result<MigrationStatusReport> {
    let c = config.db().await?;
    let row = c
        .query_one("SELECT generation, storage_generation, storage_backend, migration_state, write_paused, gitfs_path FROM pando_lab.repositories WHERE id=$1", &[&repo])
        .await?;
    let inflight: i64 = c
        .query_one("SELECT count(*) FROM pando_lab.operations WHERE repo=$1 AND state NOT IN ('COMMITTED','REJECTED','ABORTED')", &[&repo])
        .await?
        .get(0);
    let latest = c
        .query_opt(
            "SELECT id, direction, state, gitfs_path, old_storage_generation, new_storage_generation, copied_packs, copied_objects, post_switchover_commits, diff_report \
             FROM pando_lab.migrations WHERE repo=$1 ORDER BY updated_at DESC, created_at DESC LIMIT 1",
            &[&repo],
        )
        .await?
        .map(|r| {
            serde_json::json!({
                "id": r.get::<_, Uuid>(0),
                "direction": r.get::<_, String>(1),
                "state": r.get::<_, String>(2),
                "gitfs_path": r.get::<_, String>(3),
                "old_storage_generation": r.get::<_, i64>(4),
                "new_storage_generation": r.get::<_, Option<i64>>(5),
                "copied_packs": r.get::<_, i64>(6),
                "copied_objects": r.get::<_, i64>(7),
                "post_switchover_commits": r.get::<_, i64>(8),
                "diff_report": r.get::<_, Option<serde_json::Value>>(9),
            })
        });

    Ok(MigrationStatusReport {
        repo,
        generation: row.get(0),
        storage_generation: row.get(1),
        storage_backend: row.get(2),
        migration_state: row.get(3),
        write_paused: row.get(4),
        gitfs_path: row.get(5),
        inflight_operations: inflight,
        latest_migration: latest,
    })
}
