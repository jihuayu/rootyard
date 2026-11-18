//! Projected copy/drain parity verification.
//!
//! The final migration transaction must not perform Git work. This module
//! verifies the exact snapshot that transaction intends to publish, using the
//! already staged immutable packs, before the short authority transaction
//! opens. The final transaction only re-checks that no authority moved and
//! commits the same projected rows.

use super::super::{Config, Control, Session, Snapshot, delta, export, graph, store};
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;
use std::path::Path;
use uuid::Uuid;

/// Compare a projected Pando snapshot bit-for-bit with the GitFS source.
pub(super) async fn verify_projected_parity(
    config: &Config,
    repo: Uuid,
    gitfs_path: &Path,
    snapshot: &Snapshot,
) -> Result<export::DiffExportReport> {
    ensure!(snapshot.repo == repo, "projected snapshot repo mismatch");

    let mut obj_store = graph::ObjectStore::default();
    let mut total_pack_objects = 0usize;
    let mut max_delta_depth = 0usize;
    for pack in &snapshot.packs {
        let prefix = config.root.join("objects").join(repo.to_string()).join(pack.id.to_string());
        let pack_bytes = std::fs::read(prefix.with_extension("pack"))?;
        let idx_bytes = std::fs::read(prefix.with_extension("idx"))?;
        ensure!(
            delta::sha256_hex(&pack_bytes) == pack.pack_sha256 && delta::sha256_hex(&idx_bytes) == pack.idx_sha256,
            "projected pack checksum mismatch during migration parity"
        );
        let report = delta::verify_pack(&pack_bytes, &delta::Limits::default())?;
        total_pack_objects += report.object_count;
        max_delta_depth = max_delta_depth.max(report.max_delta_depth_observed);
        obj_store.insert_pack(&report);
    }

    let wants: Vec<String> = snapshot.refs.values().cloned().collect::<BTreeSet<_>>().into_iter().collect();
    let walk = graph::walk_reachable(&obj_store, &wants, &[])?;

    // Materialize the projected snapshot through the same Pando pack reader
    // used by the post-publication verifier. Existing packs may be rehydrated
    // before the final transaction; the new pack is already staged locally.
    let session = Session::new(config)?;
    let ctl = Control::default();
    let repo_git = store::materialize(config, snapshot, &session.0, &ctl).await?;
    let git_refs_raw =
        String::from_utf8(config.git(&repo_git, &["for-each-ref", "--format=%(refname) %(objectname)"], b"").await?)?;
    let mut git_refs = std::collections::BTreeMap::new();
    for line in git_refs_raw.lines().filter(|l| !l.is_empty()) {
        let (name, oid) = line.split_once(' ').context("invalid projected for-each-ref line")?;
        git_refs.insert(name.to_owned(), oid.to_owned());
    }
    ensure!(git_refs == snapshot.refs, "projected migration ref mismatch between Pando PG and materialized Git");

    let gitfs_refs = super::read_gitfs_refs(config, gitfs_path).await?;
    ensure!(gitfs_refs == snapshot.refs, "projected migration refs do not match GitFS");

    let gitfs_oids: BTreeSet<String> = if wants.is_empty() {
        BTreeSet::new()
    } else {
        let rev_input = format!("{}\n", wants.join("\n"));
        String::from_utf8(
            config
                .git(gitfs_path, &["rev-list", "--objects", "--no-object-names", "--stdin"], rev_input.as_bytes())
                .await?,
        )?
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
    };
    let pando_oids: BTreeSet<String> = walk.reachable_oids.iter().cloned().collect();
    ensure!(pando_oids == gitfs_oids, "projected migration reachable object closure mismatch between Pando and GitFS");

    for oid in &pando_oids {
        let (pando_type, pando_data) = obj_store.objects.get(oid).context("missing projected object")?;
        let git_type = String::from_utf8(config.git(gitfs_path, &["cat-file", "-t", oid], b"").await?)?;
        ensure!(git_type.trim() == pando_type.as_str(), "projected migration object type mismatch for {oid}");
        let git_raw = config.git(gitfs_path, &["cat-file", pando_type.as_str(), oid], b"").await?;
        ensure!(git_raw == *pando_data, "projected migration byte-for-bit mismatch for {oid}");
    }

    Ok(export::DiffExportReport {
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
