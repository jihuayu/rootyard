use super::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffExportReport {
    pub repo: Uuid,
    pub generation: i64,
    pub storage_generation: i64,
    pub ref_count: usize,
    pub pack_count: usize,
    pub total_pack_objects: usize,
    pub reachable_objects: usize,
    pub excluded_objects: usize,
    pub commits: usize,
    pub trees: usize,
    pub blobs: usize,
    pub tags: usize,
    pub max_delta_depth: usize,
    pub matched: bool,
    pub bit_for_bit_match: bool,
}

/// Dual-operator differential verifier comparing Operator A (Pando native Rust `delta` + `graph`)
/// against Operator B (materialized native `git` via `for-each-ref`, `rev-list --objects`, and
/// `cat-file`) bit-for-bit across all reachable commits, trees, blobs, and tags.
pub(super) async fn diff_export(
    config: &Config,
    repo: Uuid,
    haves: &[String],
) -> Result<DiffExportReport> {
    let snapshot = store::snapshot(config, repo).await?;

    // Operator A: Pando native Rust pack delta inflation & object graph reachability walker
    let mut obj_store = graph::ObjectStore::default();
    let mut total_pack_objects = 0usize;
    let mut max_delta_depth = 0usize;
    for pack in &snapshot.packs {
        let prefix = config
            .root
            .join("objects")
            .join(snapshot.repo.to_string())
            .join(pack.id.to_string());
        let pack_bytes = std::fs::read(prefix.with_extension("pack"))?;
        let idx_bytes = std::fs::read(prefix.with_extension("idx"))?;
        ensure!(
            delta::sha256_hex(&pack_bytes) == pack.pack_sha256
                && delta::sha256_hex(&idx_bytes) == pack.idx_sha256,
            "immutable pack checksum mismatch during differential export"
        );
        let report = delta::verify_pack(&pack_bytes, &delta::Limits::default())?;
        total_pack_objects += report.object_count;
        max_delta_depth = max_delta_depth.max(report.max_delta_depth_observed);
        obj_store.insert_pack(&report);
    }

    let wants_set: BTreeSet<String> = snapshot.refs.values().cloned().collect();
    let wants: Vec<String> = wants_set.into_iter().collect();
    let walk = graph::walk_reachable(&obj_store, &wants, haves)?;

    // Operator B: Materialized native Git repository verification
    let session = Session::new(config)?;
    let ctl = Control::default();
    let repo_git = store::materialize(config, &snapshot, &session.0, &ctl).await?;
    let staging_git = session.0.join("staging.git");

    let git_refs_raw = String::from_utf8(
        config
            .git(
                &repo_git,
                &["for-each-ref", "--format=%(refname) %(objectname)"],
                b"",
            )
            .await?,
    )?;
    let mut git_refs = BTreeMap::new();
    for line in git_refs_raw.lines().filter(|l| !l.is_empty()) {
        let (name, oid) = line
            .split_once(' ')
            .context("invalid git for-each-ref line")?;
        git_refs.insert(name.to_owned(), oid.to_owned());
    }
    ensure!(
        git_refs == snapshot.refs,
        "differential export ref mismatch between Pando PG and materialized Git"
    );

    let git_oids: BTreeSet<String> = if wants.is_empty() {
        BTreeSet::new()
    } else {
        let mut rev_input = String::new();
        for w in &wants {
            rev_input.push_str(w);
            rev_input.push('\n');
        }
        for h in haves {
            rev_input.push('^');
            rev_input.push_str(h);
            rev_input.push('\n');
        }
        let rev_out = String::from_utf8(
            config
                .git(
                    &staging_git,
                    &["rev-list", "--objects", "--no-object-names", "--stdin"],
                    rev_input.as_bytes(),
                )
                .await?,
        )?;
        rev_out
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect()
    };

    let pando_oids: BTreeSet<String> = walk.reachable_oids.iter().cloned().collect();
    ensure!(
        pando_oids == git_oids,
        "differential export reachable OID set mismatch: pando={} vs git={}",
        pando_oids.len(),
        git_oids.len()
    );

    for oid in &pando_oids {
        let (pando_type, pando_data) = obj_store
            .objects
            .get(oid)
            .context("missing object in Pando ObjectStore")?;
        let git_type = String::from_utf8(
            config
                .git(&staging_git, &["cat-file", "-t", oid], b"")
                .await?,
        )?;
        ensure!(
            git_type.trim() == pando_type.as_str(),
            "differential export object type mismatch for {oid}: pando={} vs git={}",
            pando_type.as_str(),
            git_type.trim()
        );
        let git_raw = config
            .git(&staging_git, &["cat-file", pando_type.as_str(), oid], b"")
            .await?;
        ensure!(
            git_raw == *pando_data,
            "differential export byte-for-bit content mismatch for {oid}"
        );
    }

    Ok(DiffExportReport {
        repo,
        generation: snapshot.generation,
        storage_generation: snapshot.storage_generation,
        ref_count: snapshot.refs.len(),
        pack_count: snapshot.packs.len(),
        total_pack_objects,
        reachable_objects: walk.reachable_count,
        excluded_objects: walk.excluded_count,
        commits: walk.commits,
        trees: walk.trees,
        blobs: walk.blobs,
        tags: walk.tags,
        max_delta_depth,
        matched: true,
        bit_for_bit_match: true,
    })
}
