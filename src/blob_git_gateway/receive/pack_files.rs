use std::path::{Path, PathBuf};

use super::GatewayError;

pub(super) fn pack_stems(repo: &Path) -> Result<std::collections::BTreeSet<String>, GatewayError> {
    let directory = repo.join("objects").join("pack");
    let mut stems = std::collections::BTreeSet::new();
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(_) => return Ok(stems),
    };
    for entry in entries {
        let entry = entry.map_err(|_| GatewayError::Internal("temporary pack directory is unreadable"))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Some(stem) = name.strip_suffix(".pack")
            && stem.starts_with("pack-")
        {
            stems.insert(stem.to_owned());
        }
    }
    Ok(stems)
}

pub(super) fn collect_pairs(
    repo: &Path,
    before: &std::collections::BTreeSet<String>,
) -> Result<Vec<(PathBuf, PathBuf)>, GatewayError> {
    let directory = repo.join("objects").join("pack");
    let mut pairs = Vec::new();
    let entries =
        std::fs::read_dir(&directory).map_err(|_| GatewayError::Internal("temporary pack directory is unreadable"))?;
    let mut names = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .collect::<Vec<_>>();
    names.sort();
    for name in names {
        let Some(stem) = name.strip_suffix(".pack") else { continue };
        if !stem.starts_with("pack-") || before.contains(stem) {
            continue;
        }
        let pack = directory.join(&name);
        let idx = directory.join(format!("{stem}.idx"));
        if !idx.is_file() {
            return Err(GatewayError::Internal("native receive-pack produced a pack without an index"));
        }
        pairs.push((pack, idx));
    }
    Ok(pairs)
}
