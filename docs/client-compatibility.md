# Executed client compatibility

`tests/client_compatibility.py` starts the actual Rust service with an isolated
PostgreSQL schema. It fails if a required client is absent, and records the
server binary hash, exact client artifacts, HTTP observations, OIDs, file hashes,
fsck results, status and redacted client output. Each new version needs a new run.

Latest executed matrix, 2026-11-06: Git 2.52.0, git-lfs 3.6.1,
JGit 7.8.1.202611041320-r, pygit2 1.19.0 / libgit2 1.9.1,
PostgreSQL 17.11. Nine native cases passed on the build bound to source inputs
at integration commit `6c30bc3`; the receipt records the source-input digest,
compiler, unstripped and executed binary hashes. Removing debug symbols is
recorded as a build transformation. Durable raw results, observed OIDs/content,
client failures and packet transcript are in `evidence/client-compatibility.json`.

| Path | Observed result | Boundary |
| --- | --- | --- |
| JGit and libgit2 clone/fetch/push over authenticated HTTP | Passed; fresh objects transferred in both directions, content verified with stock Git | SHA-1 repositories |
| Non-member independent-client clone | Both rejected | Private repository authorization |
| Stock Git protocol versions 0/1/2, shallow then unshallow | Passed with matching HEAD/content and clean fsck | Client request versions; no inferred SSH support |
| Annotated tags, stale force-with-lease and atomic multi-ref failure | Passed; failed transaction left refs unchanged | Actual observed native refs |
| Detached HEAD with staged and untracked files across fetch | Passed; index/worktree status preserved | Stock Git worktree |
| Stock Git SHA-256 create/push/clone/fsck | Passed with exact 64-hex tip/content | SHA-256 Forge/CI behavior is separately tested under #38 |
| JGit/libgit2 SHA-256 | Explicitly unsupported; both real clone attempts failed | SHA-1 probes passed; stock Git continued reading the same SHA-256 repository after each failure |
| Thin push / delta objects | Passed, native repack produced delta objects; receiver clone/fsck/content matched | Transcript records actual receive-pack; no inferred wire-level compression ratio |
| Stock git-lfs upload/pull/fsck/lock/unlock | Passed, 1 MiB exact payload | Independent clients' additional LFS extensions are not supported by this matrix |
| Partial-clone filter | Explicitly unsupported | Capability not advertised; Git warning and full-object fallback verified, not counted as filtered success |
| SSH | Unsupported | No SSH service endpoint |

Reproduce with a Java 21 runtime, Python and PostgreSQL tools:

```sh
python3 scripts/prepare_git_clients.py test-results/ci-tools/clients
python3 -m venv test-results/ci-tools/client-venv
test-results/ci-tools/client-venv/bin/pip install pygit2==1.19.0 cffi==2.1.1 pycparser==3.12
export ROOTYARD_JGIT_CLASSPATH="$PWD/test-results/ci-tools/clients/jgit-libs/*"
export ROOTYARD_PYGIT2_PYTHON="$PWD/test-results/ci-tools/client-venv/bin/python"
# Set ROOTYARD_TEST_DATABASE_URL to an owned disposable PostgreSQL database.
python3 scripts/build_native.py
python3 tests/client_compatibility.py --binary target/debug/rootyard --report test-results/client-compatibility.json
```

The JGit download is pinned by SHA-256 and checked before execution. Client
credentials are passed through child environments, never repository URLs or
report command arguments. These functional tests are not cluster performance or
production durability measurements. Issue #45 remains open until independent review, final combined regression and
merge evidence are complete. A new binary or client version requires a new run.
