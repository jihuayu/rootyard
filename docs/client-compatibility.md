# Executed client compatibility

`tests/client_compatibility.py` starts the actual Rust service with an isolated
PostgreSQL schema. It fails if a required client is absent, and records the
server binary hash, exact client artifacts, HTTP observations, OIDs, file hashes,
fsck results, status and redacted client output. Each new version needs a new run.

Initial local run, 2026-11-06: Git 2.52.0, JGit 7.8.1.202611041320-r,
pygit2 1.19.0 / libgit2 1.9.1, PostgreSQL 17.11. The tested Rust binary includes
the overlay fix on integration commit `fd7727f`; full receipts are retained in
`test-results/client-compatibility.json` and its adjacent evidence directory.

| Path | Observed result | Boundary |
| --- | --- | --- |
| JGit and libgit2 clone/fetch/push over authenticated HTTP | Passed; fresh objects transferred in both directions, content verified with stock Git | SHA-1 repositories |
| Non-member independent-client clone | Both rejected | Private repository authorization |
| Stock Git protocol versions 0/1/2, shallow then unshallow | Passed with matching HEAD/content and clean fsck | Client request versions; no inferred SSH support |
| Annotated tags, stale force-with-lease and atomic multi-ref failure | Passed; failed transaction left refs unchanged | Actual observed native refs |
| Detached HEAD with staged and untracked files across fetch | Passed; index/worktree status preserved | Stock Git worktree |
| SHA-256 end-to-end, LFS locking and partial-clone filters | Pending | No passed label; dependent capabilities still under delivery |

Reproduce with a Java 21 runtime, Python and PostgreSQL tools:

```sh
python3 scripts/prepare_git_clients.py test-results/ci-tools/clients
python3 -m venv test-results/ci-tools/client-venv
test-results/ci-tools/client-venv/bin/pip install pygit2==1.19.0 cffi==2.1.1 pycparser==3.12
export ROOTYARD_JGIT_CLASSPATH="$PWD/test-results/ci-tools/clients/jgit-libs/*"
export ROOTYARD_PYGIT2_PYTHON="$PWD/test-results/ci-tools/client-venv/bin/python"
# Set ROOTYARD_TEST_DATABASE_URL to an owned disposable PostgreSQL database.
python3 tests/client_compatibility.py --binary target/debug/rootyard --report test-results/client-compatibility.json
```

The JGit download is pinned by SHA-256 and checked before execution. Client
credentials are passed through child environments, never repository URLs or
report command arguments. These functional tests are not cluster performance or
production durability measurements. Issue #45 remains open until its full
matrix and independent review are complete.
