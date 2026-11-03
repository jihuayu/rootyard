# Development and verification

## Build

Use Linux, stable Rust, Git >= 2.43, Python 3, the `psql`, `pg_dump` and `pg_restore` clients and PostgreSQL 17. Commit `Cargo.lock` for reproducible dependency resolution. Containers use moving official image tags; deployments needing reproducible base images should pin reviewed image digests.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked
```

## End-to-end tests

Provision a **disposable dedicated PostgreSQL database**, never a production or shared application database. The harness exercises migrations and creates test identities/repositories. It creates a random schema and drops only that schema afterward. It needs permission to create the schema. Connection URLs with existing `options` are rejected to preserve search-path isolation. Use local-only credentials and do not put real tokens into test output.

```sh
export ROOTYARD_TEST_DATABASE_URL='postgresql://rootyard:LOCAL_TEST_PASSWORD@127.0.0.1:5432/rootyard_test'
python3 tests/e2e.py --binary target/debug/rootyard --report test-results/e2e.json
```

Add `--keep` to retain temporary storage for debugging; treat retained data as private. The JSON report can be retained as a verification artifact; CI uploads it even when a test step fails.

The harness is the executable source of truth for covered cases. Review its output and the exact tested versions before describing compatibility or reliability. GitHub Actions runs formatting, linting, Rust tests and the Python harness against a PostgreSQL 17 service on Ubuntu 24.04.

Important acceptance areas include real client clone/commit/push/fetch, file modes and symlinks, ref updates and conflicts, protocol negotiation, atomic pushes, invalid authentication, owner isolation, malformed paths, read-only/revoked tokens, stream limits, interrupted operations, concurrency, restart survival and provisioning recovery. A checklist item is not proof it has been executed: report unsupported or untested cases explicitly.

See [the verification record](verification.md) for the tested versions, confirmed results and pending checks.

## Scope of verification

Process restart and injected provisioning interruptions can establish recovery for those boundaries. The harness also exercises an offline paired backup/restore: stop writes, dump the owned schema, copy the full data tree, restore the schema, and verify refs, a fresh clone, fsck and read-only/revoked-token behavior. This is not a full deployment restore into a new external database. These tests do not establish hard power-loss safety, cross-store push atomicity, full audit completeness, high availability, production disaster recovery, or a throughput SLA. A rejected client request can have an unknown result if ref updates occurred before the connection failed.

Do not run benchmark or failure-injection tests against real repositories. Keep local database credentials, tokens, test reports with sensitive data, build output and repository volumes out of version control. Review `git diff` and `git status` before committing.
