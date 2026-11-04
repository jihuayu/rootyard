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

The harness is the executable source of truth for covered cases. Review its output and the exact tested versions before describing compatibility or reliability. GitHub Actions runs formatting, linting, Rust tests and the Python harness inside an official Rust Debian 13 container against a PostgreSQL 17 service (on an Ubuntu runner). The job enables Docker's init reaper, matching Compose, so orphaned Git grandchildren are reaped after timeout cleanup. It installs PostgreSQL 17 client tools explicitly; an older `pg_dump` cannot dump a newer server.

Important acceptance areas include real client clone/commit/push/fetch, file modes and symlinks, ref updates and conflicts, protocol negotiation, atomic pushes, invalid authentication, owner isolation, malformed paths, read-only/revoked tokens, stream limits, interrupted operations, concurrency, restart survival and provisioning recovery. A checklist item is not proof it has been executed: report unsupported or untested cases explicitly.

See [the verification record](verification.md) for the tested versions, confirmed results and pending checks.

## Scope of verification

Process restart and injected provisioning interruptions can establish recovery for those boundaries. The harness also exercises an offline paired backup/restore: stop writes, dump the owned schema, copy the full data tree, restore the schema, and verify refs, a fresh clone, fsck and read-only/revoked-token behavior. This is not a full deployment restore into a new external database. These tests do not establish hard power-loss safety, cross-store push atomicity, full audit completeness, high availability, production disaster recovery, or a throughput SLA. A rejected client request can have an unknown result if ref updates occurred before the connection failed.

Do not run benchmark or failure-injection tests against real repositories. Keep local database credentials, tokens, test reports with sensitive data, build output and repository volumes out of version control. Review `git diff` and `git status` before committing.

## Durable reliability tests

With `ROOTYARD_TEST_DATABASE_URL` pointing at a disposable PostgreSQL database, run `cargo test --test outbox -- --ignored` and `python3 tests/reliability.py --binary target/debug/rootyard --report test-results/reliability.json`. Both own random schemas and clean only their fixtures. CI runs these explicitly; a default cargo test alone does not execute the ignored PostgreSQL test. See [phase-two verification](phase-two-verification.md) for injected boundaries and untested infrastructure assumptions.

## Offline backup and isolated restore tests

`python3 tests/backup.py --binary target/debug/rootyard --report test-results/backup.json` needs a **synthetic PostgreSQL test administrator** with CREATEDB and permission for catalog-lock fault injection. It creates/drops only run-owned random databases, unlike the schema-only e2e harness. Optionally set `ROOTYARD_RESTORE_TEST_DATABASE_URL` for a separate disposable PostgreSQL server. Never run this against production. See [the contract](backup-restore.md) and [integrated test record](integration-verification.md).

`python3 tests/schema_contract.py --binary target/debug/rootyard` compares pristine migrations and their PostgreSQL dump/restore round trip and restored003/restored006-to007 upgrades to all three reviewed schema-007 catalog fixtures. `--write` is only a development aid; inspect every fixture change before accepting it. `python3 tests/backup_recovery.py --binary target/debug/rootyard --report test-results/backup-recovery.json` verifies exact fifteen-table restoration, volume identity, recovery protection and authenticated new-generation pushes. Run `cargo test --test outbox --test resolution_fences -- --ignored`, `tests/recovery_ops.py` and `tests/metrics.py` as well; CI runs these alongside the original suites. All database tests require isolated synthetic resources, not production.

`tests/restored_workers.py` adds fresh-database restore followed by real standalone workers with pending/expired leases, stale-generation retirement and a native post-restore push. `tests/cross_process.py` uses a run-owned Redis server when `ROOTYARD_TEST_REDIS_SERVER` is explicitly provided; CI requires the real Redis case and preserves its multicall executable name. See [worker integration verification](workers-integration-verification.md).

## Private-owner Issue API tests

With the same disposable PostgreSQL database, run
`python3 tests/forge.py --binary target/debug/rootyard --report test-results/forge.json`.
This is required in addition to the Git/reliability/recovery suites; default
`cargo test` does not run these real HTTP/PostgreSQL cases. See the
[Forge slice contract](forge-issues.md) for exact scope and remaining work.

`tests/forge_idempotency.py` adds optional-key replay, conflict, concurrency,
rollback, response-loss and authorization-race coverage. Run it with the same
isolated database and `--binary`/`--report` arguments.

`tests/backup_forge.py` verifies populated Forge content, counters, versions and permissions across a fresh PostgreSQL/volume restore, including the write barrier and finite recovery point. Use the same synthetic CREATEDB administrators as the other backup suites. See [Forge backup verification](forge-backup-verification.md).

`tests/backup_upgrade.py` exercises actual schema003 logical restore, migrations006/007, populated Git/Forge backup and a fresh final restore. It does not manufacture the upgrade shape by editing CHECK constraints. CI runs the default successful path, never its local-only regression-rejection diagnostic.

## Exact-commit CI mirror tests

`python3 tests/ci_mirror.py --binary target/debug/rootyard --report test-results/ci-mirror.json`
uses the same disposable schema-only PostgreSQL fixture as the original Git
suite. It starts separate primary and mirror processes/volumes on the same host.
It checks pinned clone/fetch, source unavailability, retained snapshots, replacement
refs, authorization and role/generation fences. See [the mirror contract](ci-mirror.md).
Rust unit tests additionally exercise native Git pinned views without PostgreSQL;
those do not replace the authenticated HTTP integration suite.
