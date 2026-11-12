//! Unit coverage for snapshot materialization, hydrated verification, symlink
//! hop bounds, no-replace publication, and visible raw-layer file reads.
use super::{
    Workspace, directory_names, file, link, merged, mode_of, selected,
    snapshot::{self, Origin, Raw},
    write,
};
use crate::{Error, workspace_lab::core};
use std::{
    fs::{self, File},
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
};

#[test]
fn materialize_copies_selected_origins_and_requires_hydration() {
    let workspace = Workspace::new();
    let lower = workspace.lower();
    write(&lower, ".git/HEAD", b"ref: refs/heads/main\n");
    write(&lower, ".git/index", b"lower-index");
    write(&lower, "build/out.o", b"ignored binary");
    write(&lower, "bin/tool.sh", b"#!/bin/sh\n");
    fs::set_permissions(lower.join("bin/tool.sh"), fs::Permissions::from_mode(0o755)).expect("chmod");
    symlink("bin/tool.sh", lower.join("link")).expect("symlink");
    write(&workspace.upper(), ".git/index", b"upper-index");
    write(&workspace.upper(), "extra.txt", b"extra");

    let raw = workspace.raw();
    let dest = workspace.root.path().join("checkpoint");
    fs::create_dir(&dest).expect("dest");
    snapshot::materialize(&raw, &dest, &mut |_, _, _, _| panic!("no lazy entry may be hydrated")).expect("copy");
    assert_eq!(core::inventory(&dest).expect("inventory"), selected(&raw));
    assert_eq!(fs::read(dest.join(".git/index")).expect("index"), b"upper-index");
    assert_eq!(mode_of(&dest.join("bin/tool.sh")), 0o755);
    assert_eq!(fs::read_link(dest.join("link")).expect("link"), Path::new("bin/tool.sh"));
    assert_eq!(fs::read(dest.join("build/out.o")).expect("ignored"), b"ignored binary");

    // A lazy entry without a reader is an error, never a zero-filled fallback.
    let lazy = Workspace::new();
    write(&lazy.lower(), "data.bin", &[0_u8; 12]);
    lazy.write_manifest(&[file("data.bin", 0o644, b"remote-bytes")]);
    let raw = lazy.raw();
    let dest = lazy.root.path().join("checkpoint");
    fs::create_dir(&dest).expect("dest");
    let error = snapshot::materialize(&raw, &dest, &mut |_, _, _, _| Err(Error::internal("hydrate failed")));
    assert!(error.is_err());
    assert!(!dest.join("data.bin").exists());
}

#[test]
fn hydrated_copies_verify_length_digest_and_mode() {
    let workspace = Workspace::new();
    let source = workspace.root.path().join("remote.bin");
    fs::write(&source, b"remote bytes").expect("source");
    let entry = file("data.bin", 0o640, b"remote bytes");
    let dest = workspace.root.path().join("dest");
    fs::create_dir(&dest).expect("dest");
    let mut total = 0_u64;
    snapshot::copy_hydrated(&dest, Path::new("data.bin"), &entry, File::open(&source).expect("open"), &mut total)
        .expect("copy");
    assert_eq!(fs::read(dest.join("data.bin")).expect("bytes"), b"remote bytes");
    assert_eq!(mode_of(&dest.join("data.bin")), 0o640);
    assert_eq!(total, 12);

    // A digest mismatch is refused instead of publishing different bytes.
    let corrupt = file("bad.bin", 0o644, b"other bytes");
    let error =
        snapshot::copy_hydrated(&dest, Path::new("bad.bin"), &corrupt, File::open(&source).expect("open"), &mut 0);
    assert!(error.is_err());
    // The length promise is enforced before the digest is trusted.
    let truncated = file("short.bin", 0o644, b"remote bytes!");
    let error =
        snapshot::copy_hydrated(&dest, Path::new("short.bin"), &truncated, File::open(&source).expect("open"), &mut 0);
    assert!(error.is_err());
    let oversized = file("huge.bin", 0o644, b"x");
    let mut total = core::MAX_BYTES;
    let error = snapshot::copy_hydrated(
        &dest,
        Path::new("huge.bin"),
        &oversized,
        File::open(&source).expect("open"),
        &mut total,
    );
    assert!(error.is_err(), "the 1 GiB copy bound still applies");
    assert_eq!(total, core::MAX_BYTES, "the bound is rejected before any byte is written");
}

#[test]
fn merged_symlink_targets_may_not_escape_the_workspace() {
    let workspace = Workspace::new();
    let lower = workspace.lower();
    write(&lower, "d/real.txt", b"real");
    fs::create_dir_all(lower.join("a/b")).expect("link parent");
    symlink("../../d", lower.join("a/b/link")).expect("lower symlink");
    assert!(Raw::load(&workspace.mount()).is_ok(), "a single layer stays inside its own root");

    let upper = workspace.upper();
    fs::create_dir_all(&upper).expect("upper");
    symlink("a/b/link/../../../outside", upper.join("escape")).expect("upper symlink");
    assert!(Raw::load(&workspace.mount()).is_err(), "a cross-layer escape is rejected");
    assert!(snapshot::fingerprint(&workspace.mount()).is_err(), "the fingerprint never publishes it");
}

#[test]
fn merged_symlink_chains_stay_inside_and_are_bounded() {
    let workspace = Workspace::new();
    let lower = workspace.lower();
    write(&lower, "d/real.txt", b"real");
    fs::create_dir_all(lower.join("a/b")).expect("link parent");
    symlink("../../d", lower.join("a/b/link")).expect("lower symlink");
    let upper = workspace.upper();
    fs::create_dir_all(&upper).expect("upper");
    symlink("a/b/link", upper.join("chain")).expect("upper symlink");
    symlink("chain", upper.join("safe")).expect("upper symlink");
    let entries = merged(&workspace.raw());
    assert_eq!(entries["safe"].0, Origin::Upper);
    assert_eq!(entries["chain"].1.kind, "symlink");
    assert_eq!(entries["chain"].1.sha256, link("chain", "a/b/link").sha256, "the fingerprint keeps the raw target");

    // 41 links are 40 hops and still resolve; 42 links exceed the bound.
    for count in [41_usize, 42] {
        let workspace = Workspace::new();
        write(&workspace.lower(), "keep.txt", b"keep");
        let upper = workspace.upper();
        fs::create_dir_all(&upper).expect("upper");
        for index in 0..count {
            let target = if index + 1 == count { "keep.txt".to_owned() } else { format!("l{}", index + 1) };
            symlink(target, upper.join(format!("l{index}"))).expect("chain symlink");
        }
        let loaded = Raw::load(&workspace.mount());
        if count == 41 {
            assert!(loaded.is_ok(), "40 hops are allowed");
        } else {
            assert!(loaded.is_err(), "more than 40 hops is refused");
        }
    }
}

#[test]
fn copy_never_replaces_or_deletes_a_preexisting_destination() {
    let workspace = Workspace::new();
    write(&workspace.lower(), "keep.txt", b"keep");
    let raw = workspace.raw();
    let mut no_lazy = |_: &Path, _: &Path, _: &core::Entry, _: &mut u64| panic!("no lazy entry may be hydrated");

    let dest = workspace.root.path().join("checkpoint");
    fs::create_dir(&dest).expect("dest");
    fs::write(dest.join("sentinel"), b"sentinel").expect("sentinel");
    let error = snapshot::copy_into(&raw, &dest, &mut no_lazy);
    assert!(error.is_err(), "an existing destination is never published over");
    assert_eq!(fs::read(dest.join("sentinel")).expect("sentinel bytes"), b"sentinel");
    assert_eq!(fs::read_dir(&dest).expect("dest entries").count(), 1, "nothing is written into the existing tree");
    let names = directory_names(workspace.root.path());
    assert!(!names.iter().any(|name| name.starts_with(".snapshot-")), "a failed publication leaves no staging tree");

    // A destination this call published is owned by the guard: dropping it
    // before the commit removes exactly that directory.
    let owned = workspace.root.path().join("owned");
    let published = snapshot::copy_into(&raw, &owned, &mut no_lazy).expect("copy");
    assert_eq!(fs::read(owned.join("keep.txt")).expect("copied"), b"keep");
    drop(published);
    assert!(!owned.exists(), "an uncommitted publication is removed");

    // `keep` disarms the guard once the publication is committed.
    let committed = workspace.root.path().join("committed");
    snapshot::copy_into(&raw, &committed, &mut no_lazy).expect("copy").keep();
    assert_eq!(fs::read(committed.join("keep.txt")).expect("copied"), b"keep");
    assert_eq!(
        fs::read(dest.join("sentinel")).expect("sentinel bytes"),
        b"sentinel",
        "the sentinel is still untouched"
    );
}

#[test]
fn raw_file_reads_only_the_visible_merged_regular_entry() {
    let workspace = Workspace::new();
    write(&workspace.lower(), ".git/HEAD", b"ref: refs/heads/main\n");
    write(&workspace.lower(), ".git/index", b"lower-index");
    let upper = workspace.upper();
    fs::create_dir_all(&upper).expect("upper");
    fs::write(upper.join(".rootyard-whiteouts.json"), serde_json::to_vec(&[".git/index"]).expect("whiteouts"))
        .expect("whiteout file");
    let raw = workspace.raw();
    assert!(raw.raw_file(Path::new(".git/index")).expect("hidden index").is_empty());

    fs::remove_file(upper.join(".rootyard-whiteouts.json")).expect("drop whiteout");
    write(&upper, ".git/index", b"upper-index");
    let raw = workspace.raw();
    assert_eq!(raw.raw_file(Path::new(".git/index")).expect("upper index"), b"upper-index");

    fs::remove_file(upper.join(".git/index")).expect("drop upper index");
    write(&upper, ".git/index/extra", b"extra");
    let raw = workspace.raw();
    assert!(raw.raw_file(Path::new(".git/index")).expect("masked index").is_empty());
    assert!(raw.raw_file(Path::new(".git/absent")).expect("absent").is_empty());
}

#[test]
fn raw_file_refuses_a_symlink_ancestor() {
    let workspace = Workspace::new();
    let upper = workspace.upper();
    write(&upper, ".git/index", b"upper-index");
    let raw = Raw::fixture(
        workspace.lower(),
        upper.clone(),
        vec![(Origin::Upper, file(".git/index", 0o644, b"upper-index"))],
    );
    assert_eq!(raw.raw_file(Path::new(".git/index")).expect("visible index"), b"upper-index");
    fs::remove_dir_all(upper.join(".git")).expect("remove git dir");
    symlink("../elsewhere", upper.join(".git")).expect("symlink git dir");
    assert!(raw.raw_file(Path::new(".git/index")).is_err(), "a symlinked ancestor is never followed");

    let workspace = Workspace::new();
    let upper = workspace.upper();
    write(&upper, "sub/index", b"index");
    symlink("sub", upper.join("link")).expect("symlink");
    let raw = Raw::fixture(
        workspace.lower(),
        upper,
        vec![(Origin::Upper, link("link", "sub")), (Origin::Upper, file("link/index", 0o644, b"index"))],
    );
    assert!(raw.raw_file(Path::new("link/index")).is_err(), "a merged symlink ancestor is never traversed");
}
