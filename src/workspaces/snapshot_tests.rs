//! Unit coverage for the mount-free raw workspace snapshot.
//!
//! Every fixture deliberately never creates `workspace-service/mounts/<id>`:
//! the snapshot must work from service-owned lower/upper/lazy state alone. The
//! live FUSE reproduction (mounted workspace frozen, parked write holding an
//! inode lock, SIGKILL, `D` state) is *not* covered here and has not been
//! re-run; it needs the separate native-API phase.
use super::snapshot::{self, Origin, Raw};
use crate::{Error, workspace_lab::core};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
};
use uuid::Uuid;

struct Workspace {
    root: tempfile::TempDir,
    id: Uuid,
}

impl Workspace {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("temp dir");
        let id = Uuid::new_v4();
        fs::create_dir_all(root.path().join("workspace-service/workspaces").join(id.to_string())).expect("lower root");
        Self { root, id }
    }

    fn service(&self) -> PathBuf {
        self.root.path().join("workspace-service")
    }

    fn lower(&self) -> PathBuf {
        self.service().join("workspaces").join(self.id.to_string())
    }

    fn upper(&self) -> PathBuf {
        self.service().join("uppers").join(self.id.to_string())
    }

    /// Never created on purpose: a raw snapshot must not need the mount.
    fn mount(&self) -> PathBuf {
        self.service().join("mounts").join(self.id.to_string())
    }

    fn raw(&self) -> Raw {
        Raw::load(&self.mount()).expect("raw snapshot").expect("workspace layout")
    }

    fn fingerprint(&self) -> String {
        snapshot::fingerprint(&self.mount()).expect("fingerprint")
    }

    fn write_manifest(&self, entries: &[core::Entry]) {
        let directory = self.service().join("lazy");
        fs::create_dir_all(&directory).expect("lazy dir");
        let manifest = serde_json::json!({
            "schema": 1,
            "checkpoint_id": Uuid::new_v4(),
            "tenant_id": Uuid::new_v4(),
            "entries": entries,
        });
        fs::write(directory.join(format!("{}.json", self.id)), serde_json::to_vec(&manifest).expect("manifest"))
            .expect("manifest write");
    }
}

/// Deterministic fixture bytes. The explicit mode keeps entry modes (and thus
/// fingerprints) stable on hosts whose umask is 077 instead of 022; production
/// still hashes whatever mode the workspace actually has.
fn write(root: &Path, name: &str, bytes: &[u8]) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(&path, bytes).expect("write");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("mode");
}

fn entry(relative: &str, kind: &str, mode: u32, bytes: &[u8]) -> core::Entry {
    core::Entry {
        path_base64: STANDARD.encode(relative.as_bytes()),
        kind: kind.into(),
        mode,
        size: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}

fn file(relative: &str, mode: u32, bytes: &[u8]) -> core::Entry {
    entry(relative, "file", mode, bytes)
}

fn link(relative: &str, target: &str) -> core::Entry {
    entry(relative, "symlink", 0o777, target.as_bytes())
}

fn hash(entries: &[core::Entry]) -> String {
    hex::encode(Sha256::digest(serde_json::to_vec(entries).expect("json")))
}

fn relative(entry: &core::Entry) -> String {
    String::from_utf8(STANDARD.decode(&entry.path_base64).expect("base64")).expect("utf-8")
}

fn merged(raw: &Raw) -> BTreeMap<String, (Origin, core::Entry)> {
    raw.items().into_iter().map(|(origin, entry)| (relative(&entry), (origin, entry))).collect()
}

fn selected(raw: &Raw) -> Vec<core::Entry> {
    raw.items().into_iter().map(|(_, entry)| entry).collect()
}

fn directory_names(root: &Path) -> Vec<String> {
    fs::read_dir(root)
        .expect("read dir")
        .map(|child| child.expect("dir entry").file_name().to_string_lossy().into_owned())
        .collect()
}

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).expect("metadata").permissions().mode() & 0o777
}

#[test]
fn raw_snapshot_merges_upper_over_lower_and_keeps_native_state() {
    let workspace = Workspace::new();
    let lower = workspace.lower();
    write(&lower, ".git/HEAD", b"ref: refs/heads/main\n");
    write(&lower, ".git/index", b"lower-index");
    write(&lower, "a.txt", b"lower");
    write(&lower, "sub/b.txt", b"b");
    write(&lower, "gone.txt", b"gone");
    write(&lower, ".gitignore", b"build/\n");
    write(&lower, "build/out.o", b"ignored binary");
    write(&lower, "bin/tool.sh", b"#!/bin/sh\n");
    fs::set_permissions(lower.join("bin/tool.sh"), fs::Permissions::from_mode(0o755)).expect("chmod");
    symlink("a.txt", lower.join("link")).expect("symlink");
    let upper = workspace.upper();
    write(&upper, "a.txt", b"upper");
    write(&upper, "new/c.txt", b"new");
    write(&upper, ".rootyard-whiteouts.tmp", b"junk");
    fs::write(upper.join(".rootyard-whiteouts.json"), serde_json::to_vec(&["gone.txt"]).expect("whiteouts"))
        .expect("whiteout file");

    let raw = workspace.raw();
    let entries = merged(&raw);
    assert_eq!(entries["a.txt"].0, Origin::Upper, "upper overrides lower");
    assert_eq!(relative(&entries["a.txt"].1), "a.txt");
    assert_eq!(entries["a.txt"].1.sha256, file("a.txt", 0o644, b"upper").sha256);
    assert_eq!(entries["new/c.txt"].0, Origin::Upper);
    assert!(!entries.contains_key("gone.txt"), "a whiteout hides its exact path");
    assert!(!entries.contains_key(".rootyard-whiteouts.json"), "internal bookkeeping never enters a snapshot");
    assert!(!entries.contains_key(".rootyard-whiteouts.tmp"));
    assert_eq!(entries["build/out.o"].0, Origin::Lower, "ignored files stay, they are not filtered");
    assert_eq!(entries["sub/b.txt"].1.size, 1);
    assert_eq!(entries["bin/tool.sh"].1.mode, 0o755, "executable bit is preserved");
    assert_eq!(entries["link"].1.kind, "symlink");
    assert_eq!(entries["link"].1.sha256, link("link", "a.txt").sha256);
    assert!(entries.contains_key(".git/index"), "native Git index is part of the snapshot");
    // The hash is the documented format: SHA-256 over the JSON of the
    // path-ordered entry list, so stored capture baselines stay comparable.
    assert_eq!(workspace.fingerprint(), hash(&selected(&raw)));
}

#[test]
fn fingerprint_uses_merged_bytes_not_timestamps() {
    let workspace = Workspace::new();
    write(&workspace.lower(), "a.txt", b"one");
    let first = workspace.fingerprint();
    // Same bytes written again (new mtime) is not a change.
    write(&workspace.lower(), "a.txt", b"one");
    assert_eq!(workspace.fingerprint(), first);
    // An upper override with identical bytes keeps every entry identical.
    write(&workspace.upper(), "a.txt", b"one");
    assert_eq!(workspace.fingerprint(), first);
    // A real upper edit changes the fingerprint.
    write(&workspace.upper(), "a.txt", b"two");
    assert_ne!(workspace.fingerprint(), first);
}

#[test]
fn upper_type_changes_hide_the_replaced_lower_subtree() {
    let workspace = Workspace::new();
    let lower = workspace.lower();
    write(&lower, "file_x", b"x");
    write(&lower, "dir_y/child", b"child");
    write(&lower, "dir_y/more/leaf", b"leaf");
    symlink("file_x", lower.join("link_z")).expect("symlink");
    let upper = workspace.upper();
    // A file replaces a lower directory: its children must disappear.
    write(&upper, "dir_y", b"now a file");
    // A directory replaces a lower file.
    write(&upper, "file_x/inner", b"inner");
    // A directory replaces a lower symlink (CoW of a child under it).
    write(&upper, "link_z/inner", b"inner");

    let entries = merged(&workspace.raw());
    assert_eq!(entries["dir_y"].0, Origin::Upper);
    assert_eq!(entries["dir_y"].1.kind, "file");
    assert!(!entries.contains_key("dir_y/child"));
    assert!(!entries.contains_key("dir_y/more/leaf"));
    assert!(!entries.contains_key("file_x"), "an upper directory hides a lower file");
    assert!(entries.contains_key("file_x/inner"));
    assert!(!entries.contains_key("link_z"), "an upper directory hides a lower symlink");
    assert!(entries.contains_key("link_z/inner"));
}

#[test]
fn empty_upper_directory_hides_a_lower_file_and_symlink() {
    let workspace = Workspace::new();
    let lower = workspace.lower();
    write(&lower, "file_target", b"x");
    symlink("file_target", lower.join("link_target")).expect("symlink");
    let upper = workspace.upper();
    fs::create_dir_all(upper.join("file_target")).expect("upper dir");
    fs::create_dir_all(upper.join("link_target")).expect("upper dir");

    let entries = merged(&workspace.raw());
    assert!(!entries.contains_key("file_target"), "an empty upper directory hides a lower file");
    assert!(!entries.contains_key("link_target"), "an empty upper directory hides a lower symlink");
    assert!(entries.is_empty(), "an empty upper directory contributes no entries of its own");
}

#[test]
fn whiteouts_hide_descendants_and_reject_traversal() {
    let workspace = Workspace::new();
    let lower = workspace.lower();
    write(&lower, "tree/keep.txt", b"keep");
    write(&lower, "tree/gone/deep.txt", b"deep");
    write(&workspace.upper(), ".git/HEAD", b"ref: refs/heads/main\n");
    fs::write(
        workspace.upper().join(".rootyard-whiteouts.json"),
        serde_json::to_vec(&["tree/gone"]).expect("whiteouts"),
    )
    .expect("whiteout file");
    let entries = merged(&workspace.raw());
    assert!(entries.contains_key("tree/keep.txt"));
    assert!(!entries.contains_key("tree/gone/deep.txt"), "descendants of a whiteout are hidden");

    fs::write(
        workspace.upper().join(".rootyard-whiteouts.json"),
        serde_json::to_vec(&["../escape"]).expect("whiteouts"),
    )
    .expect("whiteout file");
    assert!(Raw::load(&workspace.mount()).is_err(), "whiteout paths with .. are rejected");
}

#[test]
fn paths_through_a_symlink_ancestor_are_rejected_not_followed() {
    let workspace = Workspace::new();
    write(&workspace.lower(), "keep.txt", b"keep");
    // A lazy manifest that claims a file below a symlink would make the
    // destination tree traverse the link; that is refused.
    workspace.write_manifest(&[link("s", "keep.txt"), file("s/x", 0o644, b"x")]);
    assert!(Raw::load(&workspace.mount()).is_err());

    // An upper symlink with an absolute target is refused by the shared rule.
    let workspace = Workspace::new();
    write(&workspace.lower(), "keep.txt", b"keep");
    let upper = workspace.upper();
    fs::create_dir_all(&upper).expect("upper");
    symlink("/etc/passwd", upper.join("evil")).expect("symlink");
    assert!(Raw::load(&workspace.mount()).is_err());
}

#[test]
fn git_index_is_read_from_raw_layers_upper_first() {
    let workspace = Workspace::new();
    let lower = workspace.lower();
    write(&lower, ".git/index", b"lower-index");
    let raw = workspace.raw();
    assert_eq!(raw.raw_file(Path::new(".git/index")).expect("raw index"), b"lower-index");
    // Native Git writes go through the CoW upper layer.
    write(&workspace.upper(), ".git/index", b"upper-index");
    let raw = workspace.raw();
    assert_eq!(raw.raw_file(Path::new(".git/index")).expect("raw index"), b"upper-index");
    assert!(raw.raw_file(Path::new(".git/absent")).expect("absent").is_empty());
}

#[test]
fn lazy_manifest_metadata_is_authoritative_and_hash_compatible() {
    let workspace = Workspace::new();
    let lower = workspace.lower();
    // Sparse placeholder with the right length but the wrong bytes: hashing it
    // would produce the zeroes digest, so the manifest must win.
    write(&lower, "data.bin", &[0_u8; 12]);
    write(&lower, "tree/nested.txt", &[0_u8; 6]);
    write(&lower, "tree/other.txt", &[0_u8; 5]);
    symlink("data.bin", lower.join("link")).expect("symlink");
    workspace.write_manifest(&[
        file("data.bin", 0o644, b"remote-bytes"),
        file("tree/nested.txt", 0o644, b"nested"),
        file("tree/other.txt", 0o644, b"other"),
        link("link", "data.bin"),
    ]);
    let upper = workspace.upper();
    write(&upper, "tree/nested.txt", b"local");
    fs::write(upper.join(".rootyard-whiteouts.json"), serde_json::to_vec(&["tree/other.txt"]).expect("whiteouts"))
        .expect("whiteout file");

    let raw = workspace.raw();
    let entries = merged(&raw);
    assert_eq!(entries["data.bin"].0, Origin::Lazy);
    assert_eq!(entries["data.bin"].1.sha256, file("data.bin", 0o644, b"remote-bytes").sha256);
    assert_eq!(entries["tree/nested.txt"].0, Origin::Upper, "upper wins over the lazy baseline");
    assert!(!entries.contains_key("tree/other.txt"), "a whiteout hides a lazy baseline entry");
    assert_eq!(entries["link"].0, Origin::Lazy);
    // Byte compatibility with the former `lazy::fingerprint`: manifest entries
    // filtered by whiteouts, overridden by upper entries, path-ordered.
    let expected = vec![
        file("data.bin", 0o644, b"remote-bytes"),
        link("link", "data.bin"),
        file("tree/nested.txt", 0o644, b"local"),
    ];
    assert_eq!(workspace.fingerprint(), hash(&expected));
}

#[test]
fn lazy_fingerprint_matches_the_former_merge() {
    let workspace = Workspace::new();
    let lower = workspace.lower();
    write(&lower, "data.bin", &[0_u8; 12]);
    workspace.write_manifest(&[file("data.bin", 0o644, b"remote-bytes"), link("link", "data.bin")]);
    let upper = workspace.upper();
    write(&upper, "extra.txt", b"extra");
    let mut expected = BTreeMap::new();
    expected.insert("data.bin".to_owned(), file("data.bin", 0o644, b"remote-bytes"));
    expected.insert("link".to_owned(), link("link", "data.bin"));
    expected.insert("extra.txt".to_owned(), file("extra.txt", 0o644, b"extra"));
    // The former implementation sorted decoded paths in a `BTreeMap` before
    // serialising, which is exactly path order.
    let order = ["data.bin", "extra.txt", "link"];
    let expected: Vec<core::Entry> = order.into_iter().map(|name| expected[name].clone()).collect();
    assert_eq!(workspace.fingerprint(), hash(&expected));
}

#[test]
fn snapshot_limits_fail_closed() {
    // Duplicate paths in the manifest are rejected by `core::validate_entries`.
    let workspace = Workspace::new();
    workspace.write_manifest(&[file("dup", 0o644, b"a"), file("dup", 0o644, b"b")]);
    assert!(Raw::load(&workspace.mount()).is_err());

    // The merged tree keeps the 1 GiB bound instead of silently dropping data.
    let workspace = Workspace::new();
    let manifest = |entries: serde_json::Value| {
        let directory = workspace.service().join("lazy");
        fs::create_dir_all(&directory).expect("lazy dir");
        fs::write(
            directory.join(format!("{}.json", workspace.id)),
            serde_json::to_vec(&serde_json::json!({
                "schema": 1,
                "checkpoint_id": Uuid::new_v4(),
                "tenant_id": Uuid::new_v4(),
                "entries": entries,
            }))
            .expect("manifest"),
        )
        .expect("manifest write");
    };
    let huge = |name: &str| {
        serde_json::json!({
            "path_base64": STANDARD.encode(name.as_bytes()),
            "kind": "file",
            "mode": 0o644,
            "size": 600 * 1024 * 1024,
            "sha256": "0".repeat(64),
        })
    };
    manifest(serde_json::json!([huge("a"), huge("b")]));
    assert!(Raw::load(&workspace.mount()).is_err(), "merged size over 1 GiB must fail");

    // Paths with `..` or an empty component are rejected before any read.
    manifest(serde_json::json!([{
        "path_base64": STANDARD.encode(b"../escape"),
        "kind": "file",
        "mode": 0o644,
        "size": 1,
        "sha256": "0".repeat(64),
    }]));
    assert!(Raw::load(&workspace.mount()).is_err());
}

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
    // Per layer this target is harmless: `a/b/link` is popped by the two `..`
    // components and the target lands on the lower root's `d`.
    symlink("../../d", lower.join("a/b/link")).expect("lower symlink");
    assert!(Raw::load(&workspace.mount()).is_ok(), "a single layer stays inside its own root");

    // In the merged namespace the same target is a hop: the upper entry walks
    // into the lower link first, applies `../../d`, and the trailing `..`
    // then leaves the workspace. Only merged resolution sees that.
    let upper = workspace.upper();
    fs::create_dir_all(&upper).expect("upper");
    symlink("a/b/link/../../../outside", upper.join("escape")).expect("upper symlink");
    assert!(Raw::load(&workspace.mount()).is_err(), "a cross-layer escape is rejected");
    assert!(snapshot::fingerprint(&workspace.mount()).is_err(), "the fingerprint never publishes it");
}

#[test]
fn merged_symlink_chains_stay_inside_and_are_bounded() {
    // A hop through another layer is legal while it stays inside the workspace.
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
    assert_eq!(fs::read(dest.join("sentinel")).expect("sentinel bytes"), b"sentinel", "the sentinel is still untouched");
}

#[test]
fn raw_file_reads_only_the_visible_merged_regular_entry() {
    let workspace = Workspace::new();
    write(&workspace.lower(), ".git/HEAD", b"ref: refs/heads/main\n");
    write(&workspace.lower(), ".git/index", b"lower-index");
    let upper = workspace.upper();
    fs::create_dir_all(&upper).expect("upper");
    // A whiteout hides the lower index: the overlay exposes no index at all, so
    // reading one out of the lower tree would report a file that is not there.
    fs::write(upper.join(".rootyard-whiteouts.json"), serde_json::to_vec(&[".git/index"]).expect("whiteouts"))
        .expect("whiteout file");
    let raw = workspace.raw();
    assert!(raw.raw_file(Path::new(".git/index")).expect("hidden index").is_empty());

    // The visible upper index wins over the lower one.
    fs::remove_file(upper.join(".rootyard-whiteouts.json")).expect("drop whiteout");
    write(&upper, ".git/index", b"upper-index");
    let raw = workspace.raw();
    assert_eq!(raw.raw_file(Path::new(".git/index")).expect("upper index"), b"upper-index");

    // An upper directory replacing the lower file masks it as well.
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
    let raw =
        Raw::fixture(workspace.lower(), upper.clone(), vec![(Origin::Upper, file(".git/index", 0o644, b"upper-index"))]);
    assert_eq!(raw.raw_file(Path::new(".git/index")).expect("visible index"), b"upper-index");
    // A `.git` symlink on disk is refused instead of followed out of the layer.
    fs::remove_dir_all(upper.join(".git")).expect("remove git dir");
    symlink("../elsewhere", upper.join(".git")).expect("symlink git dir");
    assert!(raw.raw_file(Path::new(".git/index")).is_err(), "a symlinked ancestor is never followed");

    // A merged symlink ancestor is refused before the filesystem is consulted.
    let workspace = Workspace::new();
    let upper = workspace.upper();
    write(&upper, "sub/index", b"index");
    symlink("sub", upper.join("link")).expect("symlink");
    let raw = Raw::fixture(
        workspace.lower(),
        upper,
        vec![
            (Origin::Upper, link("link", "sub")),
            (Origin::Upper, file("link/index", 0o644, b"index")),
        ],
    );
    assert!(raw.raw_file(Path::new("link/index")).is_err(), "a merged symlink ancestor is never traversed");
}
