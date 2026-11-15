use super::compat::{
    is_gitattributes_path, validate_config_bytes, validate_gitattributes_bytes, validate_head_bytes, validate_raw,
    validate_repo, validate_tree_listing_no_gitlinks,
};
use super::snapshot::{Origin, Raw};
use crate::workspace_lab::core;
use axum::http::StatusCode;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::symlink, path::Path};

const OID_A: &str = "1111111111111111111111111111111111111111";

fn write(root: &Path, rel: &str, bytes: &[u8]) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, bytes).unwrap();
}

fn dirc(mode: u32, flags: u16, extended: Option<u16>, path: &[u8], ext: Option<&[u8; 4]>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"DIRC");
    out.extend_from_slice(&(if extended.is_some() { 3u32 } else { 2u32 }).to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    let start = out.len();
    out.extend_from_slice(&[0u8; 24]);
    out.extend_from_slice(&mode.to_be_bytes());
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&flags.to_be_bytes());
    if let Some(ext_flags) = extended {
        out.extend_from_slice(&ext_flags.to_be_bytes());
    }
    out.extend_from_slice(path);
    out.push(0);
    let aligned = start + (out.len() - start).div_ceil(8) * 8;
    out.resize(aligned, 0);
    if let Some(name) = ext {
        out.extend_from_slice(name);
        out.extend_from_slice(&0u32.to_be_bytes());
    }
    out.extend_from_slice(&[0u8; 20]);
    out
}

fn make_valid_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let cfg = concat!(
        "[core]\n",
        "\trepositoryformatversion = 0\n",
        "\tfilemode = true\n",
        "\tbare = false\n",
        "\tlogallrefupdates = true\n",
        "[remote \"origin\"]\n",
        "\turl = /var/lib/rootyard/repos/1\n",
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
        "[branch \"main\"]\n",
        "\tremote = origin\n",
        "\tmerge = refs/heads/main\n",
        "[user]\n",
        "\tname = \"Workspace Agent\"\n",
        "\temail = agent@example.invalid\n"
    );
    write(dir.path(), ".git/HEAD", b"ref: refs/heads/main\n");
    write(dir.path(), ".git/refs/heads/main", format!("{OID_A}\n").as_bytes());
    write(dir.path(), ".git/config", cfg.as_bytes());
    write(dir.path(), ".git/index", &dirc(0o100644, 9, None, b"hello.txt", Some(b"TREE")));
    write(dir.path(), ".git/hooks/pre-commit.sample", b"#!/bin/sh\n");
    write(dir.path(), "hello.txt", b"hello\n");
    dir
}

fn file_entry(rel: &str, bytes: &[u8]) -> core::Entry {
    core::Entry {
        path_base64: STANDARD.encode(rel.as_bytes()),
        kind: "file".to_owned(),
        mode: 0o644,
        size: bytes.len() as u64,
        target_base64: None,
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}

#[test]
fn valid_cloned_branch_and_detached_head_repos_pass() {
    let branch_repo = make_valid_repo();
    validate_repo(branch_repo.path()).expect("branch clone repo supported");

    // Packed refs resolve cleanly when loose branch file does not exist.
    fs::remove_file(branch_repo.path().join(".git/refs/heads/main")).unwrap();
    write(
        branch_repo.path(),
        ".git/packed-refs",
        format!("# pack-refs with: peeled fully-peeled sorted\n{OID_A} refs/heads/main\n").as_bytes(),
    );
    validate_repo(branch_repo.path()).expect("packed-refs branch resolves");

    // Detached HEAD is explicitly supported.
    write(branch_repo.path(), ".git/HEAD", format!("{OID_A}\n").as_bytes());
    validate_repo(branch_repo.path()).expect("detached HEAD supported");

    // Benign .gitattributes, # filter comments, filter filenames, and inert filter=lfs pass.
    write(
        branch_repo.path(),
        ".gitattributes",
        b"# filter note\nsrc/filter_core.rs text eol=lf\n*.dat filter=lfs diff=lfs merge=lfs -text\n",
    );
    validate_repo(branch_repo.path()).expect("inert filter=lfs and safe attributes allowed");
}

#[test]
fn unborn_head_and_sha256_are_rejected_as_conflict() {
    let repo = make_valid_repo();
    fs::remove_file(repo.path().join(".git/refs/heads/main")).unwrap();
    let err = validate_repo(repo.path()).expect_err("unborn HEAD rejected");
    assert_eq!(err.0, StatusCode::CONFLICT);

    let sha256_oid = "a".repeat(64);
    assert_eq!(validate_head_bytes(sha256_oid.as_bytes(), |_| Ok(false)).unwrap_err().0, StatusCode::CONFLICT);

    let sha256_cfg = "[core]\n\trepositoryformatversion = 1\n\tbare = false\n[extensions]\n\tobjectformat = sha256\n";
    assert_eq!(validate_config_bytes(sha256_cfg.as_bytes()).unwrap_err().0, StatusCode::CONFLICT);
}

#[test]
fn submodules_gitlinks_and_nested_git_are_rejected() {
    let tree_err = validate_tree_listing_no_gitlinks(
        b"100644 blob 1111111111111111111111111111111111111111\thello.txt\0160000 commit 2222222222222222222222222222222222222222\tvendor/lib\0",
    )
    .unwrap_err();
    assert_eq!(tree_err.0, StatusCode::CONFLICT);

    let with_modules = make_valid_repo();
    write(with_modules.path(), ".git/modules/vendor/HEAD", b"ref: refs/heads/main\n");
    assert_eq!(validate_repo(with_modules.path()).unwrap_err().0, StatusCode::CONFLICT);

    let with_index_gitlink = make_valid_repo();
    write(with_index_gitlink.path(), ".git/index", &dirc(0o160000, 6, None, b"vendor", None));
    assert_eq!(validate_repo(with_index_gitlink.path()).unwrap_err().0, StatusCode::CONFLICT);

    let with_nested_pointer = make_valid_repo();
    write(with_nested_pointer.path(), "vendor/.git", b"gitdir: ../.git/modules/vendor\n");
    assert_eq!(validate_repo(with_nested_pointer.path()).unwrap_err().0, StatusCode::CONFLICT);
}

#[test]
fn linked_worktrees_and_external_git_storage_are_rejected() {
    let file_git = make_valid_repo();
    fs::remove_dir_all(file_git.path().join(".git")).unwrap();
    write(file_git.path(), ".git", b"gitdir: /tmp/elsewhere/.git/worktrees/wt1\n");
    assert_eq!(validate_repo(file_git.path()).unwrap_err().0, StatusCode::CONFLICT);

    for bad_path in [
        ".git/commondir",
        ".git/gitdir",
        ".git/worktrees/wt1/gitdir",
        ".git/objects/info/alternates",
        ".git/objects/info/http-alternates",
        ".git/shallow",
        ".git/info/grafts",
        ".git/refs/replace/1111111111111111111111111111111111111111",
        ".git/hooks/post-checkout",
        ".git/index.lock",
    ] {
        let repo = make_valid_repo();
        write(repo.path(), bad_path, b"marker\n");
        assert_eq!(validate_repo(repo.path()).unwrap_err().0, StatusCode::CONFLICT, "{bad_path} must reject");
    }

    let symlink_git = make_valid_repo();
    fs::remove_file(symlink_git.path().join(".git/HEAD")).unwrap();
    symlink("/etc/passwd", symlink_git.path().join(".git/HEAD")).unwrap();
    assert_eq!(validate_repo(symlink_git.path()).unwrap_err().0, StatusCode::CONFLICT);
}

#[test]
fn split_sparse_and_filter_config_or_attributes_are_rejected() {
    for bad_index in [
        dirc(0o100644, 0x4005, Some(0x4000), b"a.txt", None),
        dirc(0o100644, 5, None, b"a.txt", Some(b"link")),
        dirc(0o100644, 5, None, b"a.txt", Some(b"sdir")),
        dirc(0o100644, 5, None, b"a.txt", Some(b"FSMN")),
        dirc(0o100644, 5, None, b"a.txt", Some(b"UNTR")),
    ] {
        let repo = make_valid_repo();
        write(repo.path(), ".git/index", &bad_index);
        assert_eq!(validate_repo(repo.path()).unwrap_err().0, StatusCode::CONFLICT);
    }

    for admin in [".git/sharedindex.0123", ".git/info/sparse-checkout", ".git/config.worktree"] {
        let repo = make_valid_repo();
        write(repo.path(), admin, b"/*\n");
        assert_eq!(validate_repo(repo.path()).unwrap_err().0, StatusCode::CONFLICT, "{admin} must reject");
    }

    assert!(is_gitattributes_path(".gitattributes"));
    assert!(is_gitattributes_path("sub/.gitattributes"));
    assert!(!is_gitattributes_path("sub/gitattributes.txt"));
    assert!(validate_gitattributes_bytes(b"*.dat filter=lfs diff=lfs -text\n", true).is_ok());
    assert_eq!(validate_gitattributes_bytes(b"*.txt filter=custom\n", true).unwrap_err().0, StatusCode::CONFLICT);
    assert_eq!(validate_gitattributes_bytes(b"*.dat filter=lfs\n", false).unwrap_err().0, StatusCode::CONFLICT);

    let info_attr = make_valid_repo();
    write(info_attr.path(), ".git/info/attributes", b"*.dat filter=lfs\n");
    assert_eq!(validate_repo(info_attr.path()).unwrap_err().0, StatusCode::CONFLICT);

    for bad_cfg in [
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n",
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tsparseCheckout = true\n",
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tsplitIndex = true\n",
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tfsmonitor = true\n",
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n\thooksPath = /tmp/hooks\n",
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[include]\n\tpath = /etc/gitconfig\n",
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\tuploadpack = /tmp/evil\n",
    ] {
        assert_eq!(validate_config_bytes(bad_cfg.as_bytes()).unwrap_err().0, StatusCode::CONFLICT);
    }
}

#[test]
fn validate_raw_skips_unhydrated_lazy_worktree_while_rejecting_upper_filter() {
    let dir = tempfile::tempdir().unwrap();
    let lower = dir.path().join("lower");
    let upper = dir.path().join("upper");
    fs::create_dir_all(&lower).unwrap();
    fs::create_dir_all(&upper).unwrap();

    let head = b"ref: refs/heads/main\n";
    let main_ref = format!("{OID_A}\n").into_bytes();
    let cfg = b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n";
    let idx = dirc(0o100644, 5, None, b"a.txt", Some(b"TREE"));
    write(&lower, ".git/HEAD", head);
    write(&lower, ".git/refs/heads/main", &main_ref);
    write(&lower, ".git/config", cfg);
    write(&lower, ".git/index", &idx);
    // Unhydrated lazy placeholder on disk contains zeroes and differs in SHA-256 from entry.
    write(&lower, ".gitattributes", &[0u8; 32]);

    let lazy_attr_entry = file_entry(".gitattributes", b"*.dat filter=lfs\n");
    let raw_lazy_ok = Raw::fixture(
        lower.clone(),
        upper.clone(),
        vec![
            (Origin::Lower, file_entry(".git/HEAD", head)),
            (Origin::Lower, file_entry(".git/refs/heads/main", &main_ref)),
            (Origin::Lower, file_entry(".git/config", cfg)),
            (Origin::Lower, file_entry(".git/index", &idx)),
            (Origin::Lazy, lazy_attr_entry),
        ],
    );
    validate_raw(&raw_lazy_ok).expect("unhydrated lazy .gitattributes skips zero placeholder read");

    let bad_upper = b"*.txt filter=evil\n";
    write(&upper, ".gitattributes", bad_upper);
    let raw_bad_upper = Raw::fixture(
        lower,
        upper,
        vec![
            (Origin::Lower, file_entry(".git/HEAD", head)),
            (Origin::Lower, file_entry(".git/refs/heads/main", &main_ref)),
            (Origin::Lower, file_entry(".git/config", cfg)),
            (Origin::Lower, file_entry(".git/index", &idx)),
            (Origin::Upper, file_entry(".gitattributes", bad_upper)),
        ],
    );
    assert_eq!(validate_raw(&raw_bad_upper).unwrap_err().0, StatusCode::CONFLICT);
}
