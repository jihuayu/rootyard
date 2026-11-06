# Independent native review: issue #41 Git LFS locks

- Reviewed commit: `21588b3abb02d32d2382663c7ac3d029a818aeff`; exact service binary `/workspace/shared/rootyard-acceptance-13b28dd`, SHA-256 `ec62504f2c699874fa78a336c9185aba75ade1969a029cabcd786a161a0a31b7`.
- Live suite actually run: `source /workspace/shared/rootyard-env.sh && python3 tests/lfs.py --binary /workspace/shared/rootyard-acceptance-13b28dd --report /workspace/shared/reviews/lfs-41-independent.json`. PASS 10/10 against the native Rust service and PostgreSQL 17, including stock Git LFS lock/list/unlock, restart, concurrent same-path create, role checks, and backup/restore preservation.
- Additional adversarial request tests actually run against the same native service are captured in `/workspace/shared/reviews/lfs-41-independent-repro.json`.

## Findings

1. **A new branch can bypass another user’s lock.** With `docs/locked.txt` locked by Alice, Bob created a commit changing that path, then a second tip commit changing only `unlocked.txt`. Bob pushed the tip as a new ref, `refs/heads/lock-bypass`. The native push returned exit 0, the ref was published, and reading the pushed tip returned `unauthorized edit\n`. `validate_new_refs_with_client` handles zero old OIDs by running `git diff-tree --root ... <new_oid>`, which sees only the tip/root commit’s diff and misses the locked-path change in an earlier newly reachable commit.

2. **`locks/verify` ignores protocol pagination in its POST body.** After creating three locks, a live `POST /git/alice/demo.git/info/lfs/locks/verify` with `Content-Type: application/vnd.git-lfs+json` and body `{"limit":1}` returned all three entries in `ours` and `next_cursor: null`. The handler reads `cursor` and `limit` from URL query parameters and ignores the JSON body.

The executor and parent received both reproductions. Existing stock-client/basic lock coverage is useful but does not exercise pagination or pushing an ancestor path change under a newly created ref. Issue #41 remains open until both defects are fixed and the native regressions pass.
