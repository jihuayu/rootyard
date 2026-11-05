# Phase-five Namespace, Git View and cross-repository ChangeSet foundation: local experiment

## Decision and scope

This opt-in binary (`rootyard-view-lab`) is an executable semantics experiment for company Namespace mounts (`BaseVector`), deterministic subdirectory history projection, composite multi-repository task snapshot views, and two-phase cross-repository ChangeSet integration. It leaves the production HTTP server (`rootyard`), PostgreSQL `schema008` catalog, paired offline backup format 5, and native GitFS hosting paths untouched.

Each registered repository in the private store (`0700`) remains an independent authoritative bare Git repository. Namespace revisions and views never merge underlying repositories into a single global monorepo `HEAD`.

## Commands

Build and invoke explicitly:

```sh
cargo build --locked --bin rootyard-view-lab
LAB=target/debug/rootyard-view-lab
$LAB register-repo /private/view-store proto /path/to/proto --quiescent
$LAB register-repo /private/view-store search /path/to/search --quiescent
$LAB create-namespace /private/view-store corp libs/proto=proto@$B1 services/search=search@$B2
$LAB project-subdir /private/view-store search-sub search services/search
$LAB create-task-view /private/view-store agent-view $REVISION_UUID
$LAB project-history /private/view-store search-hist search --strategy deterministic_history --subdir services/search
$LAB project-history /private/view-store search-snap search --strategy task_snapshot --subdir services/search
$LAB verify-view /private/view-store $VIEW_UUID
$LAB integrate-changeset /private/view-store $VIEW_UUID refs/heads/task/feature-1
$LAB recover-changeset /private/view-store $CHANGESET_UUID
```

## Invariants and two-phase cross-repository integration contract

1. **Non-overlapping Namespace mounts and `BaseVector` retention**:
   `create-namespace` normalizes relative mount paths, rejects overlapping path prefixes (such as `libs` and `libs/proto`), rejects `.git` or `..` traversal, verifies that each `BASE_OID` is a complete commit in its source repository, and writes `refs/rootyard/namespace-pins/<revision_id>` in each mounted repository.
2. **Deterministic subdirectory history projection with unreachable-object pruning**:
   `project-subdir` walks `refs/heads/main` in topological order, rewrites trees to the target subdirectory, folds commits that leave the subdirectory tree unchanged, preserves exact author/committer identities and timestamps, and runs `git repack -adq` and `git prune --expire=now` before `git fsck --full --strict`. Objects outside the projected subdirectory closure are physically removed.
3. **Composite task snapshot views and proposal branch separation**:
   `create-task-view` synthesizes a single composite root tree from all mounted `(mount_path, base_oid)` entries via `git mktree -z` and publishes a deterministic synthetic root commit to `refs/heads/main` and `refs/rootyard/view-base`. Writable pushes target `refs/heads/task/<name>`; commits modifying paths outside declared mount prefixes are rejected.
4. **Zero partial success across repositories (`integrate-changeset` & `recover-changeset`)**:
   - **Stage 1 (`preparing -> staged`)**: Reverse-maps view tree deltas back to each modified repository, performs a 3-way tree merge (`git merge-tree --write-tree`) when a source repository's `refs/heads/main` advanced past its `BaseVector` commit, writes candidate commit $c_i'$ to `refs/rootyard/changesets/<cs_id>/candidate`, and validates each repository with `git fsck --full --strict`. Any merge conflict or validation failure aborts in Stage 1 (`aborted_conflict`) with **zero mutations to any repository's `refs/heads/main`**.
   - **Stage 2 (`staged -> committing`)**: Acquires durable per-repository ref write leases (`leases/<repo_id>.json`) in deterministic `repo_id` order, re-verifies every target repository's `refs/heads/main == expected_old_oid`, and atomically fsyncs `state = "committing"` (the **irreversible Commit Point**). A crash before this point (`ROOTYARD_VIEW_TEST_FAILPOINT=before_commit_point`) leaves all `refs/heads/main` untouched and is cleanly aborted (`aborted_pre_commit`) by `recover-changeset`.
   - **Stage 3 (`committing -> integrated`, Roll-Forward Only)**: Updates each target repository's `refs/heads/main` from `expected_old_oid` to `candidate_oid`, re-projects the view's `refs/heads/main` and `refs/rootyard/view-base` to the new synthetic commit (`projected_view_oid`), records `refs/rootyard/integrated/<cs_id>`, and releases all leases. If a crash occurs mid-Stage 3 (`ROOTYARD_VIEW_TEST_FAILPOINT=mid_commit_after_first_repo`), active leases block concurrent `advance-repo` writes, and `recover-changeset` **rolls forward** all remaining repositories to `candidate_oid`.
5. **Long-term history projection strategies and epoch commit mapping (`project-history`)**:
   `project-history` supports both `--strategy deterministic_history` (topological commit rewriting with no-op folding, merge parent preservation, and incremental epoch advancement that reuses prior epoch projected commit OIDs without rewriting history) and `--strategy task_snapshot` (single synthetic root commit with `rewritten_history_commits == 0`), persisting per-epoch `(source_oid, view_epoch) -> projected_oid` mappings in `views/<view_id>/epoch_commit_map.json`.
6. **Cryptographic commit signature & provenance verification (`verify-view`)**:
   Projected views inspect source commits for `gpgsig` / `gpgsig-sha256` headers (`source_signed`, `source_signature_type` in `gpg` | `ssh` | `none`), record `original_signature_covers_projected_oid = false` because tree/parent projection invalidates raw source commit signatures over projected OIDs, attach a platform HMAC-SHA256 provenance attestation (`Rootyard-View-Signature: hmac-sha256:rootyard-local-v1:<hex>`) over `(view_id, strategy, view_epoch, source_commit_oid, projected_tree_oid, projected_parent_oids)` in `views/<view_id>/provenance.json`, and fail closed on `verify-view` if any reachable commit, tree, parent link, or signature record is tampered with.

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --bin rootyard-view-lab
python3 tests/git_views.py --binary target/debug/rootyard-view-lab --report test-results/git-views.json
python3 -m unittest discover -s tests -p "test_view_lab.py" -v
```
