//! CI pin native implementation.
use super::*;
pub(super) fn git(state: &AppState, repo: Uuid) -> Result<tokio::process::Command> {
    let mut cmd = crate::mirror::mirror_git(state);
    cmd.arg("--git-dir").arg(state.storage.verify_path(repo)?);
    Ok(cmd)
}
pub(super) async fn run(state: &AppState, repo: Uuid, args: &[&str], limit: usize) -> Result<Vec<u8>> {
    let mut cmd = git(state, repo)?;
    cmd.args(args);
    git_http::collect_git_output(cmd, limit, state.config.git_timeout).await
}
// Include symbolic targets so a symbolic ref cannot masquerade as immutable.
pub(super) async fn roots(state: &AppState, repo: Uuid) -> Result<HashMap<String, String>> {
    let bytes = run(
        state,
        repo,
        &[
            "for-each-ref",
            "--count=1026",
            "--format=%(refname)%00%(objectname)%00%(symref)",
            NAMESPACE,
        ],
        256 * 1024,
    )
    .await?;
    let mut result = HashMap::new();
    for line in std::str::from_utf8(&bytes)?.lines() {
        let fields: Vec<_> = line.split('\0').collect();
        ensure!(
            fields.len() == 3
                && reserved(fields[0])
                && valid_oid(fields[1])
                && fields[2].is_empty(),
            "unsupported CI retention ref"
        );
        result.insert(fields[0].to_owned(), fields[1].to_owned());
        ensure!(
            result.len() <= MAX_PINS,
            "CI retention namespace exceeds limit"
        );
    }
    // for-each-ref omits broken symbolic refs. Inspect the loose reserved tree
    // too: an unlisted/dangling ref, lock or symlink must never be overwritten
    // by the first create-only CAS (including --no-deref on a symbolic ref).
    let repo_path = state.storage.verify_path(repo)?;
    let reserved_path = repo_path.join(NAMESPACE);
    if journal::exists(&reserved_path)? {
        let mut pending = vec![reserved_path];
        let mut count = 0;
        while let Some(path) = pending.pop() {
            count += 1;
            ensure!(count <= 3 * MAX_PINS + 16, "CI loose refs exceed bound");
            journal::safe_path(&path)?;
            let meta = std::fs::symlink_metadata(&path)?;
            if meta.is_dir() {
                for entry in std::fs::read_dir(&path)? {
                    pending.push(entry?.path());
                }
            } else {
                ensure!(meta.is_file(), "unsupported CI loose ref");
                let name = path
                    .strip_prefix(&repo_path)?
                    .to_str()
                    .context("invalid CI ref path")?;
                let bytes = journal::read(&path)?;
                let value = std::str::from_utf8(&bytes)?
                    .strip_suffix('\n')
                    .context("invalid CI ref content")?;
                ensure!(
                    valid_oid(value) && result.get(name).is_some_and(|oid| oid == value),
                    "unlisted or symbolic CI ref collision"
                );
            }
        }
    }
    Ok(result)
}
pub(super) async fn commit(state: &AppState, repo: Uuid, oid: &str) -> Result<()> {
    ensure!(
        run(state, repo, &["rev-parse", "--show-object-format"], 128).await?
            == if oid.len()==40 {b"sha1\n".as_slice()} else {b"sha256\n".as_slice()},
        "CI object format differs from target"
    );
    ensure!(
        run(state, repo, &["cat-file", "-t", oid], 128).await? == b"commit\n",
        "target is not an actual commit"
    );
    Ok(())
}

/// Recover only a typed exact maintenance operation. Caller proves child completion
/// (or startup volume ownership) and holds the writer lock. Native refs remain truth.
/// This is explicitly observed retention evidence, never a fabricated push receipt.
pub(crate) async fn observed_operation(
    state: &AppState,
    operation: &journal::Operation,
) -> Result<Option<Vec<journal::RefChange>>> {
    let Some(intent) = &operation.ci_pin else {
        return Ok(None);
    };
    ensure!(
        load_intent(&state.storage.root, intent.repository_id, intent.job_id)? == *intent,
        "CI intent changed"
    );
    let owner = state
        .pool
        .get()
        .await?
        .query_one(
            "SELECT owner_id,storage_generation FROM repositories WHERE id=$1",
            &[&intent.repository_id],
        )
        .await?;
    ensure!(
        owner.get::<_, Uuid>(0) == intent.owner_id
            && owner.get::<_, i64>(1) == intent.storage_generation,
        "CI authority changed"
    );
    let events = journal::events(operation)?;
    ensure!(
        events
            .iter()
            .all(|event| event.changes == [intent.change()]),
        "CI maintenance evidence changed"
    );
    ensure!(
        journal::requests(operation)?.is_none() && journal::receipts(operation)?.is_none(),
        "CI operation is not receive-pack"
    );
    let current = roots(state, intent.repository_id).await?;
    match current.get(&intent.retention_ref) {
        Some(oid) => {
            ensure!(oid == &intent.target_oid, "retention root changed");
            commit(state, intent.repository_id, oid).await?;
            Ok(Some(vec![intent.change()]))
        }
        None => {
            ensure!(
                !events
                    .iter()
                    .any(|event| event.phase == journal::HookPhase::Committed),
                "committed retention root is missing"
            );
            ensure!(
                !journal::exists(
                    &directory(&state.storage.root, intent.repository_id)
                        .join(format!("{}.pinned.json", intent.job_id))
                )?,
                "pinned retention root is missing"
            );
            Ok(Some(Vec::new()))
        }
    }
}

