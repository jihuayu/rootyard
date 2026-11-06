//! CI pin store implementation.
use super::*;
pub(super) fn directory(root: &FsPath, repo: Uuid) -> PathBuf {
    root.join("ci-pins").join(repo.to_string())
}
pub(crate) fn load_intent(root: &FsPath, repo: Uuid, job: Uuid) -> Result<Intent> {
    let intent: Intent = serde_json::from_slice(&journal::read(
        &directory(root, repo).join(format!("{job}.json")),
    )?)?;
    intent.validate()?;
    ensure!(
        intent.repository_id == repo && intent.job_id == job,
        "CI intent path mismatch"
    );
    Ok(intent)
}
pub(super) fn receipt(root: &FsPath, intent: &Intent) -> Result<()> {
    journal::atomic(
        &directory(root, intent.repository_id).join(format!("{}.pinned.json", intent.job_id)),
        &serde_json::to_vec(intent)?,
        false,
    )
}
pub(super) fn intents(root: &FsPath, repo: Uuid) -> Result<HashMap<String, Intent>> {
    let path = directory(root, repo);
    if !journal::exists(&path)? {
        return Ok(HashMap::new());
    }
    let mut result = HashMap::new();
    let mut entries = 0;
    for entry in std::fs::read_dir(&path)? {
        entries += 1;
        ensure!(
            entries <= 3 * MAX_PINS + 16,
            "CI metadata directory exceeds limit"
        );
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("invalid CI filename"))?;
        if name.starts_with(".tmp-") {
            continue;
        }
        let suffix = if name.ends_with(".pinned.json") {
            ".pinned.json"
        } else {
            ".json"
        };
        let job: Uuid = name
            .strip_suffix(suffix)
            .context("invalid CI record")?
            .parse()?;
        let intent = load_intent(root, repo, job)?;
        if suffix == ".pinned.json" {
            ensure!(
                journal::read(&entry.path())? == serde_json::to_vec(&intent)?,
                "CI pinned receipt changed"
            );
        } else {
            ensure!(name == format!("{job}.json"), "noncanonical CI identity");
            result.insert(intent.retention_ref.clone(), intent);
            ensure!(result.len() <= MAX_PINS, "CI plan admission limit reached");
        }
    }
    Ok(result)
}
