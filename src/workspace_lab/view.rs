use super::core::{
    Entry, MAX_BYTES, MAX_MANIFEST, SCHEMA, Store, copy_all, decode_path, display_path,
    no_symlink_components, private_dir, publish, read_regular, require_directory, sync_tree,
    text_arg, valid_id, validate_index, validate_symlink, walk,
};
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    os::unix::{
        ffi::OsStringExt,
        fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadonlyViewReport {
    pub schema: u32,
    pub checkpoint_id: String,
    pub base_oid: String,
    pub view_path: String,
    pub verified: bool,
    pub readonly: bool,
    pub entries: usize,
    pub state: String,
}

pub fn cmd_verify_readonly_view(
    store: &Store,
    checkpoint_arg: &OsStr,
    view_arg: Option<&OsStr>,
) -> Result<serde_json::Value> {
    let checkpoint_id = text_arg(checkpoint_arg)?;
    valid_id(&checkpoint_id)?;
    let (checkpoint_dir, manifest) = store.read_checkpoint(&checkpoint_id)?;
    let checkpoint_repo = checkpoint_dir.join("repo");

    let view_repo = if let Some(arg) = view_arg {
        let requested = Path::new(arg);
        let absolute = if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            std::env::current_dir()?.join(requested)
        };
        no_symlink_components(&absolute)?;
        let checkpoints_root = store.root.join("checkpoints");
        let workspaces_root = store.root.join("workspaces");
        ensure!(
            !absolute.starts_with(&checkpoints_root) && !absolute.starts_with(&workspaces_root),
            "readonly view path must not overlap checkpoints or workspaces"
        );
        absolute
    } else {
        let view_parent = store.root.join("views").join(&checkpoint_id);
        if !view_parent.exists() {
            private_dir(&view_parent)?;
        }
        require_directory(&view_parent)?;
        view_parent.join("repo")
    };

    if !view_repo.exists() {
        ensure!(
            fs::symlink_metadata(&view_repo).is_err(),
            "readonly view path cannot be a dangling symlink"
        );
        if let Some(parent) = view_repo.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
            require_directory(parent)?;
        }
        let staging = store.stage()?;
        let staging_repo = staging.0.join("repo");
        copy_all(&checkpoint_repo, &staging_repo)?;
        for (rel, meta) in walk(&staging_repo)? {
            if meta.is_file() {
                let full = staging_repo.join(&rel);
                let ro_mode = (meta.permissions().mode() & 0o555) | 0o400;
                fs::set_permissions(&full, fs::Permissions::from_mode(ro_mode))?;
            }
        }
        sync_tree(&staging_repo)?;
        publish(&staging_repo, &view_repo)?;
    }

    require_directory(&view_repo)?;
    let view_files = walk(&view_repo)?;
    let mut expected_map: BTreeMap<PathBuf, Entry> = BTreeMap::new();
    for entry in &manifest.entries {
        expected_map.insert(decode_path(&entry.path_base64)?, entry.clone());
    }

    for path in view_files.keys() {
        if !expected_map.contains_key(path) {
            bail!("unexpected file in readonly view: {}", display_path(path));
        }
    }
    for path in expected_map.keys() {
        if !view_files.contains_key(path) {
            bail!("missing file in readonly view: {}", display_path(path));
        }
    }

    for (path, meta) in &view_files {
        let expected = expected_map.get(path).expect("checked key existence");
        let full = view_repo.join(path);
        let cp_meta = fs::symlink_metadata(checkpoint_repo.join(path))?;

        if meta.file_type().is_symlink() {
            ensure!(
                expected.kind == "symlink",
                "file kind mismatch in readonly view for {}",
                display_path(path)
            );
            let target = fs::read_link(&full)?;
            validate_symlink(&view_repo, path, &target)?;
            let bytes = target.into_os_string().into_vec();
            let sha = hex::encode(Sha256::digest(&bytes));
            ensure!(
                bytes.len() as u64 == expected.size && sha == expected.sha256,
                "symlink target tampered in readonly view: {}",
                display_path(path)
            );
        } else {
            ensure!(
                meta.is_file() && expected.kind == "file",
                "file kind mismatch in readonly view for {}",
                display_path(path)
            );
            ensure!(
                (meta.dev(), meta.ino()) != (cp_meta.dev(), cp_meta.ino()),
                "readonly view shares hardlink inode with checkpoint: {}",
                display_path(path)
            );
            let mode = meta.permissions().mode();
            ensure!(
                mode & 0o7000 == 0,
                "special permission bits in readonly view: {}",
                display_path(path)
            );
            ensure!(
                mode & 0o222 == 0,
                "writable file detected in readonly view: {}",
                display_path(path)
            );
            ensure!(
                mode & 0o444 != 0,
                "unreadable file in readonly view: {}",
                display_path(path)
            );
            ensure!(
                (mode & 0o111) == (expected.mode & 0o111),
                "executable permission bit mismatch in readonly view: {}",
                display_path(path)
            );
            let bytes = read_regular(&full, MAX_BYTES)?;
            let sha = hex::encode(Sha256::digest(&bytes));
            ensure!(
                bytes.len() as u64 == expected.size && sha == expected.sha256,
                "file content tampered in readonly view: {}",
                display_path(path)
            );
        }
    }

    let index_path = view_repo.join(".git/index");
    if index_path.try_exists()? {
        validate_index(&read_regular(&index_path, MAX_MANIFEST)?)?;
    }

    let canonical_view = fs::canonicalize(&view_repo)?;
    let report = ReadonlyViewReport {
        schema: SCHEMA,
        checkpoint_id,
        base_oid: manifest.workspace.base_oid,
        view_path: canonical_view.to_string_lossy().into_owned(),
        verified: true,
        readonly: true,
        entries: manifest.entries.len(),
        state: "verified".into(),
    };
    Ok(serde_json::to_value(report)?)
}
