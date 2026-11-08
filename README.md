# Rootyard

## Round-4 browser + LFS (current)

Integrated source `4c5bcfe` (base main `a91c93f`; immutable binary `c0049c3a…`, production input `8f399a06…`/331) passed all 11 native coordinator jobs: real Chromium sign-in/discovery/Issue+PR/merge/logout with the stale cookie rejected, revocable browser sessions with CSRF/Origin/expiry enforcement, remote-only LFS recovery by real stock `git-lfs` against actual Garage after the source data directory was deleted (second process, new data directory, shared PostgreSQL), pointer normalization and validation of 12 bad kinds across 4 publication paths (48 rejected combinations) plus 18 official `git-lfs` client probes, 4000 real staging-cleanup deletions blocked by the native data `ShareLock`, and an offline format-8/schema-132 restore that revokes old browser sessions and serves LFS bytes with the target endpoint absent. The independent review is `APPROVED` (0 P1), so #39/#40/#47 are close-eligible after the primary's publication review and PR merge. Counts are kept apart: 145 Rust unit tests and 25 cases across 9 JSON reports. Four production files changed in browser and LFS areas with no DDL; the adapter was already atomic, so this is hydration hardening, not a truncate fix, and the old CRLF pointer bypass was the genuine prior failure (kept as labeled old evidence). No production-HA, vendor, cloud or cross-host claim is made; physical #26/#43/#44 and umbrella #48 stay open. See the [round-4 acceptance](docs/acceptance/round4-browser-lfs.md) and the [evidence bundle](evidence/round4/browser-lfs-4c5bcfe/README.md).

Git hosting and collaborative workspaces in Rust. PostgreSQL holds identities, repository metadata, permissions and durable jobs. **Native bare Git repositories on a durable local volume are authoritative for refs and objects.** Clients create commits locally and use Git Smart HTTP to clone, fetch and push.

Round-3 integrated production source `1061a8e` (test-only harness `750ccce`; production input `9e33859…`; immutable local binary `6f76d70…`) adds opt-in authority-scoped Pando remote retention on backup format 8 / schema 132 and passes all 10 combined acceptance jobs, including a real Garage/S3 + Vault + PostgreSQL Pando deletion test, GitFS lifecycle 3/3 and physical GC 8/8. Independent acceptance is `ACCEPT_FOR_DOCUMENTED_MODE` with `closable_23=true`; #23 is completed for the documented mode in [PR #61](https://github.com/jihuayu/rootyard/pull/61). That mode requires `ROOTYARD_PANDO_REMOTE_DELETE=true` and deletes only registered current-authority, unreferenced obsolete artifacts: legacy/unregistered/foreign objects stay protected, raw metadata-only PostgreSQL/PITR copies against the shared bucket are unsupported, undetected and not fail-closed, only a paired Rootyard archive restore rotates authority, and no per-OID, hardware-power-loss or cross-host HA claim is made. #32 is closed via PR #60 and #38 via PR #57. #25 is completed for the accepted one-host separate-volume mode via PR #63 (final merge step pending at publication time); #26, #43, #44 and roadmap #48 remain open, and merged HA profile PR [#62](https://github.com/jihuayu/rootyard/pull/62) closes no issue. A final combined HA/CI compatibility run on the same current `157748add`/`0f865a0…`/331-input identity passed (6 ACK, 0 lost; write RTO 20762.3 ms; old grant 401/fresh checkout; format-8/schema-132 restore). This is not a production HA qualification. The round-2 baseline `f319100`/`35d01` (merged main `5fa4854`/PR #56) remains historical. See the [delivery ledger](docs/registered-task-delivery.md), [round-3 Pando acceptance](docs/acceptance/round3-pando23.md) and [round-2 delivery](docs/acceptance/round2-delivery.md).

## Round-4 webhook candidate (current)

Test-only candidate `cff5ddb` (base main `53e7776`; compiled production source `cb8d1b9`, immutable binary `157748a`, production input `0f865a0…`/331) passed both native coordinator jobs: a manual-dispatch regression (201-event batches, concurrent claim fence, verified TLS plus plaintext rejection, and an unrelated-CA TLS receiver rejected with 0 requests) and an automatic-worker report (lost wakeup recovered by scanning, SIGKILL after a receiver `204`, live-lease retry 409, automatic backoff into dead letter, and a stock push auto-updating an open PR 1 → 2 with a queued check and a receiver delivery) with `manual_dispatch_calls=0`. The independent review is `approved` with 0 P1 and 5 non-blocking P2, so #33/#3/#16/#19 are close-eligible after the primary's final publication review and the PR #64 merge. This publication is docs/evidence only and did not compile `cff5ddb`; the retry deadline is an integer unix due field (now+2) with an observed ≈1.9 s wall interval, not a guaranteed 2 s minimum. See the [round-4 acceptance](docs/acceptance/round4-webhooks33.md) and the [evidence bundle](evidence/round4/webhooks33-cff5ddb/README.md). No production HA, cross-host or external-endpoint claim is made, and browser #47 and LFS #39/#40 remain open pending separate work.

## Issue 25 current status (round 3)

Issue #25 durable shard-data migration and CI sidecar handoff is `ACCEPT_FOR_DOCUMENTED_MODE` / `closable_25=true` on compiled source `cb8d1b9`, production input `0f865a0…` and immutable local binary `157748add` with harness `9f85c5a`: all four current main native jobs (sidecar-crash, migration, takeover, partition) and all four extra jobs (Rust lib 145, real S3/Vault Pando 1, schema 132, exact 5-phase SIGKILL 5/5 all returncode -9) passed. Accepted mode is one trusted Linux host, separate Rust nodes/volumes, one PostgreSQL authority and a local process-session fence. #26 physical cross-host fencing, #43/#44 and roadmap #48 remain open; PR #62 is the HA profile PR and closes nothing. The historical old 16 MiB takeover generic 409 stays unclassified, 13 registered hooks are not 13 SIGKILLs, the 34-row reconcile fixture is metadata-only, and the 1024-intent/2 MiB cap is a deliberate fail-closed bound with no capacity claim. See the [round-3 #25 acceptance](docs/acceptance/round3-migration25.md) and [evidence bundle](evidence/round3/migration25-ci-handoff-cb8d1b9/README.md). The issue is completed for the accepted one-host separate-volume mode via PR #63 (final merge step pending at publication time). An additional final combined HA/CI compatibility run on the same current binary `157748add`/input `0f865a0…`/331 files with harness-deployment `0d9f4821…` passed: 6 ACK / 0 lost on promotion, write RTO 20762.3 ms, old grant 401 with fresh checkout at the exact retained OID, and format-8/schema-132 restore; this is not the older `6f76d70` HA report. See the [final combined bundle](evidence/round3/final-combination-157748add/README.md).

Round-3 HA reference profile (issues #43/#44, still **open**): an actual native run of `tests/cluster_patroni_native.py` on composed source `1061a8e`/harness `300c6c9` passed with 3 mutual-TLS etcd members, 3 Patroni-managed PostgreSQL 17 nodes (`verify-full` TLS + SCRAM-SHA-256, strict `remote_apply` synchronous replication), a stable HAProxy primary endpoint and an offline format-8/schema-132 restore. The whole old leader was killed and Patroni promoted automatically with no manual `pg_ctl promote`; the same Rootyard PID reconnected, lost 0 acknowledged commits as measured, and the measured RTO was 18519.1 ms read / 19896.9 ms write. With 2 of 3 etcd members stopped, all PostgreSQL roles stopped accepting writes and 4/4 durable probes were rejected after demotion; the restore path intentionally loses one post-backup acknowledged OID (no zero-RPO DR claim). Scope is one physical Linux host: no cross-host storage fencing, hardware watchdog/power-loss/rack/zone/Kafka HA, HAProxy HA or Git-volume replication, and the backup fixture is a local, unencrypted trusted closure (`authenticity_verified=false`). The production profile rejects this host. See [HA acceptance](docs/acceptance/round3-ha43.md), [evidence](evidence/round3/ha43-patroni-300c6c9/README.md) and [operations: HA](docs/operations-HA.md).

## Requirements

- Linux (64-bit), Rust 1.88 or newer (declared `rust-version`, required for edition 2024 let-chains), Git 2.43 or newer, PostgreSQL 17. The gates and acceptance evidence use the pinned 1.99.1 toolchain; see [development](docs/development.md) and `rust-toolchain.toml`.
- A durable, private local filesystem for `ROOTYARD_DATA_DIR`; one serving process per directory.
- TLS termination in front of HTTP outside localhost. The app does not terminate TLS.
- PostgreSQL 17: use `sslmode=require` plus `ROOTYARD_PG_CA_PEM` for certificate/hostname verification outside local development. Optional client certificate/key variables support mutual TLS. Supplying a CA with a weaker mode is rejected; credentials belong in the trusted runtime environment.

These are baseline requirements, not a claim that every version or storage device has been qualified. See [verification](docs/development.md).

## Known open gaps (not claimed)

- Physical HA stays open: #26 (physical cross-host fencing), #43/#44 (HA reference profile) and roadmap #48 are not closed by this tree. Accepted evidence covers one trusted Linux host with separate Rust nodes/volumes, PostgreSQL and a local process-session fence; there is no cross-host storage fencing, hardware watchdog/power-loss, rack/zone, Kafka HA, HAProxy HA or Git-volume replication claim.
- Pando remote retention is limited to the documented `ROOTYARD_PANDO_REMOTE_DELETE=true` mode that deletes only registered current-authority, unreferenced obsolete artifacts, and is re-keyed only by a paired Rootyard archive restore. A raw metadata-only PostgreSQL copy or PITR snapshot taken against the same object-store bucket is undetected, unsupported and **not fail-closed** until the tracked #77 hardening lands; never treat it as a recovery path.

## Local quick start

Start PostgreSQL with a dedicated database and role, then run from this checkout:

```sh
export DATABASE_URL='postgresql://rootyard:YOUR_LOCAL_PASSWORD@127.0.0.1:5432/rootyard'
export ROOTYARD_DATA_DIR="$PWD/data"
export ROOTYARD_BIND='127.0.0.1:8080'
cargo build --locked
./target/debug/rootyard migrate
./target/debug/rootyard create-user alice
./target/debug/rootyard serve
```

`create-user` prints JSON containing a new token and token ID. Save the token in a password manager: it is displayed once and only its digest is stored. Do not paste it into source files, URLs, logs, or shell history. In a second terminal, read it privately and create a repository:

```sh
read -r -s -p 'Token: ' ROOTYARD_TOKEN; echo
export ROOTYARD_TOKEN
# Feed the authorization header via stdin, not a literal shell-history entry.
printf 'header = "Authorization: Bearer %s"\n' "$ROOTYARD_TOKEN" | \
  curl --fail-with-body --config - -H 'Content-Type: application/json' \
  -d '{"name":"demo"}' http://127.0.0.1:8080/api/repos
unset ROOTYARD_TOKEN

git clone http://alice@127.0.0.1:8080/git/alice/demo.git
# Enter the token at Git's password prompt; use a secure credential helper if desired.
cd demo
git switch -c main
printf 'Hello Rootyard\n' > README.md
git add README.md
git -c user.name=Alice -c user.email=alice@example.invalid commit -m 'Initial commit'
git push -u origin main
```

Creating the same repository again is idempotent by owner and name. Names contain 1–63 lowercase ASCII letters, digits, `_` or `-`, beginning with a letter or digit. Do not include `.git` in the API name.

## API and access

- `POST /api/repos`, JSON `{"name":"demo"}`: provision your repository.
- `GET /api/repos`: list up to 1,000 repositories visible to your identity, ordered by name; pagination is not implemented.
- `GET /api/repos/alice/demo`: inspect your own repository.
- `/git/alice/demo.git`: authenticated Smart HTTP endpoint, not a browsable directory.
- `GET /health/live`: process liveness; `GET /health/ready`: database reachability and repository-directory presence, not a full integrity scan.

Create returns `201` for a new ready repository, `200` for an existing ready one, or `202` while provisioning remains pending. Startup and a periodic scan resume pending provisioning in batches of at most 64, with persisted attempt counts and a 30-second retry backoff. Inspect the repository state before cloning. `serve` applies migrations automatically before recovery and accepting requests.

Use Bearer tokens for REST, or Basic authentication with username and token as password. Read-only tokens can clone/fetch and read metadata, but cannot create repositories or push.

Access is not owner-only. A repository can be reached through direct organization membership, organization teams, repository collaborators or repository teams, with the five-level role ladder `read` < `triage` < `write` < `maintain` < `admin`; the strongest effective grant wins and removing a membership or team removes inherited access immediately. A personal repository stays private to its owner until such a grant exists. Numbering, organization ownership, last-administrator protection and the immutable-ownership rule are described in [organizations](docs/organizations.md); the API surface is in `src/members.rs`. Roles are per repository, not per branch.

```sh
./target/debug/rootyard create-token alice --read-only
./target/debug/rootyard revoke-token TOKEN_UUID
```

The repository is the security boundary. A reader may obtain historical or unreachable objects; there is no branch-level confidentiality. Non-fast-forward branch pushes are rejected, including force pushes. New repositories default to SHA-1 objects and `HEAD` to `main`; creation also accepts an explicit `object_format` of `sha256`. Tags and non-default branch deletion use native Git semantics; deleting the branch named by `HEAD` is denied. Native Git manages ref locking, quarantine and push results. A disconnected push can have an unknown outcome: fetch/check refs before retrying.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `DATABASE_URL` | required | PostgreSQL metadata connection; verified TLS through `sslmode=require` plus `ROOTYARD_PG_CA_PEM` |
| `ROOTYARD_DATA_DIR` | `data` | Durable repository volume |
| `ROOTYARD_BIND` | `127.0.0.1:8080` | HTTP listening address |
| `ROOTYARD_GIT` | Git found in `PATH` | Native Git executable |
| `ROOTYARD_MAX_REQUEST_BYTES` | `134217728` | Request stream limit, 128 MiB |
| `ROOTYARD_MAX_OUTPUT_BYTES` | `536870912` | Git output stream limit, 512 MiB |
| `ROOTYARD_MAX_CONCURRENT_GIT` | `8` | Concurrent Git process bound |
| `ROOTYARD_GIT_TIMEOUT_SECONDS` | `120` | Git request deadline |
| `ROOTYARD_GIT_MEMORY_BYTES` | `1073741824` | Per-child address-space resource limit |
| `ROOTYARD_MAX_REPO_BYTES` | `1073741824` | Repository size admission threshold |
| `ROOTYARD_PG_CA_PEM` | unset | CA bundle used with `sslmode=require` for certificate/hostname verification |
| `ROOTYARD_PG_CLIENT_CERT_PEM` / `ROOTYARD_PG_CLIENT_KEY_PEM` | unset | Optional PostgreSQL client certificate and key for mutual TLS |

Smart HTTP accepts streaming `gzip`/`x-gzip` request bodies; both wire bytes and expanded bytes are bounded by the request limit. Other content encodings are rejected. The Git transfer deadline continues even when a client stops reading. If a timeout, cap or child failure occurs after response headers have been sent, the response stream fails or is truncated; an initial HTTP `200` alone does not mean the Git operation succeeded.

`sslmode=require` without `ROOTYARD_PG_CA_PEM` is rejected, as is a CA supplied together with a weaker mode; credentials belong in the trusted runtime environment. The HTTP listener itself stays plaintext and must sit behind your TLS terminator.

Numeric limits must be positive. Repository size checks are not filesystem quotas; concurrent writes and temporary packs can require extra disk. Use a dedicated filesystem quota and headroom where a hard disk limit is needed. Process limits and stream bounds do not establish a total service RSS bound. See [operations](docs/operations.md).

## Container development

The provided Compose stack is local development only. It publishes HTTP exclusively on `127.0.0.1` and keeps PostgreSQL private to its network. It builds from source using official Rust and Debian images and persists both database and Git data in named volumes.

```sh
# Generate a local hexadecimal password; keep the file outside version control.
umask 077
printf 'POSTGRES_PASSWORD=%s\n' "$(openssl rand -hex 24)" > .env
docker compose up --build -d
docker compose exec rootyard rootyard create-user alice
```

Never run `docker compose down -v` unless you intend to destroy the development data. Do not expose this development stack directly to the internet.

## Further reading

- [Complete design documents, implementation status and architecture diagrams](docs/design/README.md)
- [All documentation and verification records](docs/README.md)
- [Architecture and phase-one decisions](docs/architecture.md)
- [Operations, recovery and coordinated backup/restore](docs/operations.md)
- [Development and verification](docs/development.md)
- [Verification record and remaining limits](docs/verification.md)

Licensed under Apache-2.0.

## Phase-two reliability increment

GitFS writes now retain durable operation evidence and post-receive receipts, with explicit unknown/recovering states. PostgreSQL atomically stores audit evidence and durable events; fenced local consumers maintain audit and ref projections. This does not replace Git refs with PostgreSQL refs or enable HA. See [reliability contract and operations](docs/reliability.md) and [phase-two verification](docs/phase-two-verification.md).

Run the added tests against an isolated test database:

```sh
export ROOTYARD_TEST_DATABASE_URL=postgresql://localhost/rootyard_test
cargo test --test outbox -- --ignored
python3 tests/reliability.py --binary target/debug/rootyard --report test-results/reliability.json
```

Offline backup and isolated restore are available as a phase-two increment. See [the backup/restore contract](docs/backup-restore.md) and [integrated verification evidence](docs/integration-verification.md) before using the maintenance commands. This is not online replication or a zero-loss guarantee.

## Explicit incident recovery and metrics

The follow-on recovery increment supports offline inspection and explicit acknowledgment of an unknown-push audit gap without rewriting its outcome. It preserves immutable history, establishes an observed new-generation snapshot, and fences old ref-index effects. Read [the maintenance contract](docs/manual-recovery.md) before use. Optional [loopback-only metrics](docs/metrics.md) expose fixed-cardinality service health and durable backlog without repository or user labels. This is not distributed fencing or a substitute for verified backups.

PG-only `rootyard worker` processes can drain durable deliveries independently of Git storage. Optional Redis wake hints are advisory; periodic PostgreSQL scanning remains mandatory. The bounded advisory cache boundary is available with Memory bounds and an optional mature Redis cache/wake adapter; dispatch keeps local Notify/Redis hints and PostgreSQL scanning. Full production cache-consumer wiring (#110) is still pending, and PG/RefStore authority is unchanged. See [the bounded cache/wake contract](docs/state-cache-wake.md). See [cross-process workers](docs/cross-process-workers.md) for role separation, limits, and the separate Kafka profile and limits.

The [Kafka wake adapter](docs/kafka-wakes.md) adds optional hint transport for a controlled local broker. It does not replace PostgreSQL deliveries or provide storage-node takeover.

The backup/recovery and standalone-worker increments are integrated and tested together. See [fresh-restore worker verification](docs/workers-integration-verification.md), including the requirement to keep database-only workers stopped while a restore target is incomplete.

## Initial private-owner Issue API

The phase-six foundation adds owner-private Issues and comments with bounded
keyset pagination, transactional local numbering, explicit token authorization
and optimistic update versions. Optional bounded `Idempotency-Key` headers make
Issue/comment creation retries replay the original response. Issue lists support
optional open/closed state filters with number-keyset pagination. This does not add organization sharing, PRs,
LFS, CI or a Web UI. See [the API and integration contract](docs/forge-issues.md).

Private-owner Issues/comments are included in the exact schema008 backup contract, including durable creation retry records. See [populated Forge restore verification](docs/forge-backup-verification.md) for content, numbering, authorization and recovery-state checks after a fresh-cluster restore.

## Exact-commit CI read mirrors

An opt-in `serve-mirror` process can serve CI clones from a separate private local
volume while the primary remains the only writer. Explicit sync uses native Git
transport, validates a complete snapshot, and publishes it atomically. Exact-OID
URLs clone a fixed commit and reject missing data instead of silently building an
old branch value. The mirror checks authoritative PostgreSQL permissions for every
Git request. See [the read-mirror contract](docs/ci-mirror.md) for configuration,
retained pins, verification and current limits. This is not automatic replication,
a CI scheduler, multi-writer support or high availability.

## Workspace foundation experiment

An opt-in `rootyard-workspace-lab` binary tests independent Linux agent directories, fixed base OIDs and local full-copy checkpoints preserving HEAD/index/worktree. It does not change the hosting service or provide FUSE, live capture, remote durability or multi-tenant isolation. Read the [scope, caller-quiescence requirement and recovery limits](docs/workspace-foundation.md) before use.

## Namespace, Git View and cross-repository ChangeSet experiment

An opt-in `rootyard-view-lab` binary tests company Namespace `BaseVector` mounts, deterministic subdirectory history projection with unreachable-object pruning, composite multi-repository task snapshot views, and two-phase cross-repository ChangeSet integration (candidate staging, ordered per-repository ref leases, zero partial updates on conflict, and crash roll-forward recovery). See [the Git View and ChangeSet contract](docs/git-view-foundation.md).

