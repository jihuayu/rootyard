# Pando lab: PG refs and immutable local packs

**Experimental phase-three slice, not a production backend or completed migration.**
This opt-in Rust executable does not import the serving `Storage` implementation,
change GitFS routes, migrate an existing repository, or select a new authority.
The ordinary Rootyard binary and its migration runner do not load this schema.

## What is implemented

- Real native Git Smart HTTP receive-pack/upload-pack behind a loopback gateway.
- PostgreSQL authoritative refs, object locators, generation, operation result and
  change record, committed together in one transaction.
- Native `proc-receive` adapts writes. Every HTTP request creates a disposable
  bare repository. No persistent bare repository is authoritative.
- Self-contained immutable `.pack` and `.idx` files in a separate local store,
  with incremental delta-self-contained pack publication (`store::publish_pack`)
  and pure-Rust streaming pack/delta verification (`delta::verify_pack`) enforcing
  `OFS_DELTA`/`REF_DELTA` cycle, depth, and decompressed object size guards.
- Native Rust commit, tree, and tag graph reachability walker (`graph::walk_reachable`)
  supporting `want` roots and `have` exclusion closures, plus dual-operator
  differential verification (`export::diff_export` / `diff-export`) comparing Pando
  native Rust operators bit-for-bit against native `git`.
- Read-only and compaction HTTP endpoints (`GET /repos/{id}.git/refs`,
  `GET /repos/{id}.git/operations/{op_id}`, `GET /repos/{id}.git/migration`,
  `GET /repos/{id}.git/packs`, `POST /repos/{id}.git/repack`, and
  `GET /repos/{id}.git/object-store`) with principal ACL verification, plus CLI
  subcommands (`verify-delta`, `walk-graph`, `diff-export`, `gc`, `migrate`,
  `migrate-step`, `rollback`, `migration-status`, `repack`, `pin-root`,
  `unpin-root`, `object-store-put`, `object-store-get`, `object-store-verify`,
  `object-store-status`).
- Content-addressable S3-compatible immutable Pack/Idx object storage backend
  (`object_store.rs`) under `buckets/<bucket>/repos/<repo_id>/packs/<pack_id>.{pack,idx}`
  with multipart chunk staging (`multipart/<upload_id>/part-<part_number>`),
  per-chunk and full-object SHA-256 & byte-size verification, write-once `0o444`
  immutability, signed CAS manifests (`manifests/<repo_id>/<pack_id>.json`),
  fault-injection protection (`--fail-after-chunks`, `--corrupt-chunk`), and
  transparent local cache miss read-through re-hydration.
- Online multi-pack compaction (`repack.rs`: `repack <repo_id> [--prune-superseded] [--pin-oid <oid>...]`)
  consolidating incremental `.pack` files into a single self-contained `.pack` + `.idx`
  with reachability GC, strict protection of pinned roots (`pando_lab.pinned_roots`,
  `refs/rootyard-ci/*`, `--pin-oid`) and active read snapshots (`pando_lab.snapshots`),
  dual-operator verification, atomic `FOR UPDATE` manifest replacement, and safe
  retirement of superseded pack files.
- Repository-level 5-step online migration state machine (`migration.rs`:
  `copy` -> `verify` -> `drain` -> `fence` -> `switchover`) from a GitFS bare
  repository to Pando with incremental delta capture during drain, `storage_generation`
  epoch fencing, and executable GitFS `hooks/pre-receive` read-only fencing.
- Safe post-switchover rollback with new commits (`rollback.rs`: `rollback <repo> <gitfs_path>`)
  that pauses Pando writes, reverse-synchronizes all committed Pando packs and
  post-switchover commits/ref updates back to GitFS (`git index-pack --stdin --strict`
  and `git update-ref`), verifies dual-operator parity and `git fsck --full --strict`,
  bumps `storage_generation`, and cuts write authority back to GitFS.
- Old-OID CAS, atomic multi-ref publication, final ref directory/file validation,
  commit-time repository ACL validation, and storage-generation fencing.
- PG-persisted five-minute read snapshots spanning advertisement and subsequent
  HTTP requests, bound to repository and synthetic principal. Every request
  rechecks current repository access.
- Cold reconstruction, four hook-exit failure points, and deterministic writer
  barriers for tests. Missing/corrupt committed pack bytes fail closed.

## Run only with synthetic data

Prerequisites: Linux, Rust stable, native Git 2.43 or newer, and
PostgreSQL server/client binaries on PATH. The recorded run uses Git 2.56.0 and
PostgreSQL 17.11. No new Rust dependency is added.

```sh
cargo build --locked --features pando-lab --bin rootyard-pando-lab
# Creates its own temporary cluster, database, object store, clients, and server.
# Never uses an inherited production DATABASE_URL. Run as a non-root user.
./scripts/test-pando-lab.sh
```

If PostgreSQL is unpacked rather than installed, set `PG_SHARE` to its matching
share directory; set PATH and LD_LIBRARY_PATH for that installation. The runner
also accepts `ROOTYARD_TOOLS_ENV`, `ROOTYARD_GIT_ENV`, `PANDO_BINARY`, and
`PANDO_SKIP_BUILD=1` for an already-built binary. It always stops its owned PG
cluster in `finally`, and prints the retained evidence directory.

Manual synthetic API example, using an **already-created disposable** database
and an existing disposable directory:

```sh
export PANDO_SYNTHETIC_ONLY=1
export PANDO_DATABASE_URL=postgresql://lab@127.0.0.1:55459/pando_lab
export PANDO_ROOT=/tmp/my-disposable-pando-store
export PANDO_GIT=/absolute/path/to/git
export PANDO_LISTEN=127.0.0.1:0
mkdir -p "$PANDO_ROOT"
BIN=target/debug/rootyard-pando-lab
"$BIN" init
"$BIN" create-repo 11111111-1111-4111-8111-111111111111 alice
"$BIN" serve  # Prints LISTEN http://127.0.0.1:<allocated-port>
git -c 'http.extraHeader=X-Pando-Principal: alice' clone \
  http://127.0.0.1:<allocated-port>/repos/11111111-1111-4111-8111-111111111111.git
```

`X-Pando-Principal` is a **spoofable synthetic test identity, not authentication**.
The executable refuses non-loopback listen addresses, non-literal-loopback
database hosts, and non-loopback `hostaddr` overrides, and requires the explicit
synthetic-only gate. These checks do
not make it safe to point at a production database reachable on localhost.
Do not expose this server through a proxy or use real repositories/secrets.

## Correctness contract and linearization points

### Receive and publish

1. Capture current PG refs and committed pack identities in REPEATABLE READ.
   Reconstruct the authorized repository view, enabling native receive fsck and
   routing all supported refs through proc-receive.
2. Native receive-pack ingests the client's pack. A `pre-receive` hook persists
   the **complete** old/new/name command group for this operation. Native Git can
   omit failed commands from `proc-receive`, even for an atomic push. The proc
   hook must match the saved complete group exactly; it refuses a filtered subset
   before object publication. Without this check, PG could commit only the valid
   half of an atomic push while native Git rejects another command.
   The hook separately validates
   supported namespaces, branch target types, fast-forward policy, full strict
   fsck and reachable object closure. Only SHA-1 is supported here.
3. Generate a non-thin, self-contained pack and index. Create files with
   `create_new` at `objects/<repository>/<operation UUID>.{pack,idx}`. UUIDs are
   never reused. Write, fsync each file, read back, and sync the object directory
   before any committed locator or ref can reference those bytes.
4. Begin the final PG transaction. Lock the repository row; compare storage
   generation; lock/check the principal's write ACL; compare **all** old OIDs
   against current authoritative refs; validate the final set of names.
5. Insert immutable manifests and object locators; update all refs; increment
   generation; insert one change record; store the COMMITTED operation result.
   COMMIT is the publication linearization point. The connection explicitly uses
   synchronous_commit=on. Any earlier failure leaves no published ref mutation.
6. Only after successful COMMIT does proc-receive report success. Exiting after
   COMMIT can still cause the Git client to report failure. PG remains the outcome
   authority and the next clone sees committed state.

Same-repository final publications are conservatively serialized, including
independent refs. This is a correctness baseline, **not the later parallel-ref
performance design**. A non-atomic push is also handled as an atomic hook batch;
the prototype deliberately offers stricter all-or-nothing behavior.

`changes` is a durable transactional change log. This slice has no delivery
worker, replay consumer, cache invalidation fanout, or end-to-end outbox delivery
claim. It is independent of the existing GitFS outbox tables.

### Read isolation

The first upload-pack advertisement redirects the standard client to a random
snapshot URL. Snapshot refs, generation and immutable pack identities are stored
in PG, not process memory. Subsequent advertisement/ls-refs/fetch requests check
the same snapshot ID, repository, principal, expiry, and current ACL.

Cold reconstruction first checks all captured pack/index digests. It then builds
a **second** repository containing only the closure reachable from snapshot refs.
That second repository is the only one exposed to upload-pack. Historical
unreachable objects and other repositories' objects are not merely hidden behind
unadvertised refs; they are absent from the serving object database. A live old
snapshot intentionally retains its original reachable objects until expiry.

No committed object is deleted in this slice. Snapshot retention therefore does
not prove a GC pin/lease implementation. Every snapshot currently lists all of
the repository's historical committed packs, so a missing obsolete pack can
conservatively fail an otherwise possible read. This favors fail-closed behavior
over availability and is not an efficient read plan.

### Failure and recovery meaning

`PANDO_ROOT/control.json` is a local test-only control, never an HTTP parameter:

```json
{"fault":"before-objects"}
```

Other fault values are `after-objects`, `before-commit`, `after-commit`, and
`corrupt-read`. A `barrier` absolute directory writes `<operation>.ready` after
pack persistence and waits for a `release` file before final CAS.

- Before objects, after objects, and before COMMIT: hook process exits, client
  fails, authoritative refs/locators/generation/change log remain unchanged.
  Durable unreferenced files may remain and are **not** automatically reclaimed.
- After COMMIT: client may fail although refs and objects are committed. The
  ordinary retry in the test becomes a Git no-op because remote refs already
  match. **This is not idempotent operation replay.**
- A fresh gateway process reconstructs both new reads and persisted old snapshots
  after its entire sessions cache is deleted.

Each receive POST gets a new server-generated operation UUID in the
`X-Pando-Operation` response header. There is no client-supplied idempotency key,
operation-replay protocol, or operation-status HTTP API. An interrupted client may
not receive that header. Operators can inspect `pando_lab.operations` and
`pando_lab.changes`; nonterminal rows remain evidence of uncertain/interrupted
attempts, not automatically declared failures. Do not infer idempotent retry
guarantees from the earlier standalone research prototype.

## Acceptance evidence

`evidence/results.json` records the latest actual run. The harness retains exact
Git commands, stdout/stderr, packet traces, CGI replies, generated thin pack,
server logs and PostgreSQL logs in its printed run directory. Tests check:

- Native v0/v2 clone and fetch with packet-level v2 negotiation proof, exact OIDs,
  strict fsck, annotated tags and deletions.
- Atomic success, DB-constraint rejection rollback, D/F rejection, raw-protocol
  valid-plus-missing-OID/invalid-ref/outside-refs batches with no partial commit,
  and two
  overlapping atomic pushes: one commit, one CAS rejection, no losing extra ref.
- Four publication failure windows and stale storage-generation rejection.
- Repository permissions on advertisement and RPC, commit-time ACL revocation,
  same-repository principal binding and cross-repository snapshot binding/expiry,
  snapshot continuity across writes and a fresh process, and cold reconstruction.
- Foreign-repository and deleted-branch raw-OID requests rejected.
- An actual thin pack verified to require a missing delta base: accepted against
  its existing base, rejected in an empty authorized repo with no publication.
- Committed pack/index SHA-256 checks, corrupt bytes and missing-file rejection,
  followed by a restored clone/fsck.
- Configuration rejection before connection for non-loopback `hostaddr`, plus
  Rust tests for IPv4, IPv6, mixed address lists and valid loopback addresses.
- Online GitFS-to-Pando 5-step migration (`copy` -> `verify` -> `drain` ->
  `fence` -> `switchover`), incremental drain delta capture, GitFS read-only
  `hooks/pre-receive` fencing, `GET /repos/{id}.git/migration`, and safe
  post-switchover rollback with new commits (`rollback`) back to GitFS.

## Hosted qualification evidence (#21)

The historical hosted `verify` job passed all five real Vault cases, all 17
Local PostgreSQL producer cases, and all seven PITR cases for PR #283's synthetic
merge `2b8da9d52602839d27075b249d5b36c487a97808`. The evidence is in artifact
`14422436208` from [run 44284634068](https://github.com/jihuayu/rootyard/actions/runs/44284634068).
Later compositions require fresh exact-head hosted verification.

The required gate is an exact clean source commit/tree, the actual
`rootyard-pando-lab` product artifact and its native-build receipt, no skip path,
and a separate source-bound run of the Local-provider PostgreSQL producer cases.
The report/projection adapter, the 17-case runner and the workflow wiring are
integrated in this source and required by the existing `verify` job.

### Five real derived-Vault cases

The actual fixture CLI on this source is `tests/pando_vault_rotation.py`. Its
help accepts exactly these inputs:

```sh
python3 tests/pando_vault_rotation.py \
  --binary "$ROOTYARD_PANDO_LAB_BIN" \
  --receipt "$ROOTYARD_PANDO_BUILD_RECEIPT" \
  --source-root "$PWD" \
  --expected-commit "$(git rev-parse HEAD)" \
  --report test-results/pando-vault-rotation.json
```

`--expected-binary-sha256` is optional. The flags are `--receipt` and
`--expected-commit`, not `--build-receipt` or `--expect-commit`. The harness
loads the native receipt with implicit builds forbidden, proves the exact source
commit/tree/clean state, binary and receipt identity, and rehashes source,
binary, receipt and harness after execution. The canonical report schema is
`rootyard/issue21-derived-vault-rotation/v1`; its `binding` field is nested and
its cases use `id`, not `name`.

The five authored IDs are mandatory and ordered:

1. `vault_fixture_and_app_capability_boundary` — pinned derived
   `aes256-gcm96` Vault key, app wrap/unwrap/rewrap works, app rotate/delete/
   config/token/policy administration is denied, and the app cannot change the
   master version.
2. `authentic_envelope_digest_and_cold_read` — exact `PANDOENC` ciphertext,
   manifest/DB envelope digest and length equality, no known plaintext marker,
   evicted plaintext cache, cold `object-store-get`/`object-store-verify`/
   `kms-verify`, and a cold stock-Git clone.
3. `admin_rotated_target_interrupted_resume_and_new_write` — admin-created
   existing Transit version 2, interrupted `--target-version 2` checkpoint,
   version-1 readability at the midpoint, latest version 3 appearing during the
   run, version-2 writes despite latest 3, `--resume`, completion, unchanged
   ciphertext, and a post-completion version-2 write pin.
4. `wrong_key_ciphertext_envelope_and_provider_revocation_fail_closed` — a
   usable wrong scoped key, one-byte ciphertext tamper, DB MAC-only and
   ciphertext-digest-only tamper, mirror corruption/removal repair from the DB
   envelope, and final app-token revocation all fail closed without plaintext
   cache or CAS/DB replacement.
5. `owned_resource_cleanup` — stop and remove only the exact owned server,
   Vault container, random database and private root, with identity verification
   and no global prune/kill; unresolved cleanup fails the run.

The fixture uses the pinned real Vault image with expected version 2.2.2 and a
derived `aes256-gcm96` key. Its admin fixture alone creates master versions; the
application token is scoped to key-metadata read plus encrypt/decrypt/rewrap.
`min_decryption_version` remains 1 for the run, so the unrewrapped version-1
pack must stay readable at the interrupted midpoint. The fixture creates version
2, then latest version 3 while the checkpoint still targets 2.

### Existing-target rotation and version pinning

The Vault rotation contract is `existing-vault-version/v1`. It targets an
already existing Transit version; the product and application do not call
Transit rotate. The actual existing-target commands exercised by the authored
case are:

```sh
"$ROOTYARD_PANDO_LAB_BIN" kms-status "$REPO"
"$ROOTYARD_PANDO_LAB_BIN" kms-rotate "$REPO" --target-version 2 --fail-after-packs 1
"$ROOTYARD_PANDO_LAB_BIN" kms-rotate "$REPO" --resume
"$ROOTYARD_PANDO_LAB_BIN" kms-verify "$REPO"
```

The interruption must return nonzero and leave a DB-backed `IN_PROGRESS`
checkpoint with `from_key_id == to_key_id`, target and expected version 2, the
existing-target contract, positive `write_epoch`, one completed original pack
and a different failed remaining pack. `kms-status` in Vault mode reports
`policy: null`, `provider_latest_version` and the active rotation; it does not
fabricate Local key entries.

Both a remaining version-1 pack and a completed version-2 pack are cold-read at
the midpoint. After another administrator rotation makes latest version 3, a new
real push must use version 2, not 3. `--resume` must keep the same rotation
identity/target, verify all current packs, include the new writer in the
completed/target sets, and mark the checkpoint `COMPLETED`. A further push after
completion must still use version 2 while latest remains 3. That durable pin is
the single completed checkpoint with the highest positive `write_epoch`; an
ambiguous maximum completed epoch fails closed. Legacy Local epoch-0 completion
rows are not positive Vault pins.

Only wrapping metadata changes during rotation. The exact stored ciphertext
SHA-256 and length of every pre-existing and newly written pack must remain
unchanged. Vault `--revoke-previous` is refused as unimplemented; the app never
rotates the master key, so the administrator-created latest version must remain
exactly 3.

### DB envelope authority, mirror repair and cold-cache checks

The complete pair of `pando_lab.object_store_manifests` and
`pando_lab.kms_envelopes` rows is checked as authority for DB-backed
publication/recovery and remote S3 reads. The local CAS path is narrower: a
digest-matching warm pack/index cache returns `verified` before any DB envelope
lookup. On a cold cache it reads and validates the local CAS manifest plus the
exact stored ciphertext SHA-256/length, then loads the DB `kms_envelopes` record
through the repository pack/index digests; it does not query
`object_store_manifests`. The per-pack JSON at
`$PANDO_ROOT/object_store/envelopes/<repo>/<pack>.json` is a post-commit mirror,
not a fallback authority. The missing-DB-envelope/no-mirror-fallback failure
applies to cold hydration (cache miss), where the DB envelope is loaded and a
damaged or missing mirror is repaired best-effort; the verified file-only mirror
path exists only for raw helpers without a DB client.

Every cold negative probe evicts only the exact owned pack/index cache and
asserts it remains absent after the failure. A cold read validates the immutable
manifest digest, compares the exact stored ciphertext bytes to the manifest
SHA-256/length, loads the authoritative DB envelope, validates its MAC and
wrapped-key identity, decrypts, then rechecks plaintext SHA-256/length and pack
object count before writing the cache. Corrupting only `envelope_mac`, changing
only the DB ciphertext digest, flipping stored ciphertext, using a usable wrong
scoped key, or revoking the app token must not create a plaintext cache, replace
CAS bytes, or mutate committed DB authority. Because the fixture evicts before
every provider probe, its cache/provider failure evidence is cold-hydration
only; it does not establish warm-cache provider revocation or whole-KMS
access-control runtime behavior.

### Separate 17 Local PostgreSQL producer cases

These are separate Local-provider PG contract tests, not additional Vault cases
and not part of the Vault report. Exactly 17 ignored tests live in the
existing `rootyard-pando-lab` bin unit-test harness; the normal CLI executable
and the library-test target cannot select them. The mandatory gate runs
each fully qualified name serially in the same PG17 job, in a separately owned
random database initialized from `experimental/pando/schema.sql`, with
`PANDO_OBJECT_STORE_ROOT`, `PANDO_KMS_KEYRING_DIR`, `PANDO_KMS_PROVIDER` and
`ROOTYARD_OBJECT_STORE_ENDPOINT` absent before any DB/root creation. The
existing Cargo bin-test executable is selected directly; no new Rust target is
invented.

Migration family (7):

- `pando_lab::migration::pg_tests::pg_copy_authenticated_publication_commits_pair_rows_and_mirror_together`
- `pando_lab::migration::pg_tests::pg_drain_authenticated_incremental_publication_is_atomic_and_targeted`
- `pando_lab::migration::pg_tests::pg_publication_rollback_leaves_no_authority_rows_or_mirror`
- `pando_lab::migration::pg_tests::pg_exact_preparation_retry_returns_same_physical_winner`
- `pando_lab::migration::pg_tests::pg_stale_repository_generation_fails_before_commit`
- `pando_lab::migration::pg_tests::pg_shared_gate_blocks_exclusive_rotation_and_stale_target_fails_cleanly`
- `pando_lab::migration::pg_tests::pg_local_default_and_legacy_completed_epoch_zero_keep_raw_behavior`

Repack family (5):

- `pando_lab::repack::pg_tests::pg_repack_default_local_publishes_one_authority_and_retains_pinned_data`
- `pando_lab::repack::pg_tests::pg_repack_generation_race_fails_cleanly_without_authority`
- `pando_lab::repack::pg_tests::pg_repack_forced_final_failure_rolls_back_authority_and_mirror`
- `pando_lab::repack::pg_tests::pg_repack_rotation_barrier_keeps_exact_target_and_shared_gate`
- `pando_lab::repack::pg_tests::pg_repack_no_sync_local_legacy_and_active_target_narrow_reject`

Snapshot family (5):

- `pando_lab::store::snapshot_pg_tests::pg_snapshot_wins_retains_old_pack_before_insert`
- `pando_lab::store::snapshot_pg_tests::pg_repack_wins_snapshot_selects_replacement_after_commit`
- `pando_lab::store::snapshot_race_pg_tests::pg_snapshot_fault_rolls_back_without_token_and_releases_lock`
- `pando_lab::store::snapshot_race_pg_tests::pg_snapshot_retention_uses_live_expiry_not_expired_rows`
- `pando_lab::store::snapshot_race_pg_tests::pg_ordinary_snapshot_still_does_not_retain`

One exact-name manual invocation on the existing Cargo target is:

```sh
cargo test --locked --features pando-lab --bin rootyard-pando-lab \
  pando_lab::migration::pg_tests::pg_copy_authenticated_publication_commits_pair_rows_and_mirror_together \
  -- --exact --ignored --test-threads=1
```

Repeat for each name. The CI gate resolves the same bin-test executable once
from Cargo JSON and executes all 17 serially, then emits a source-bound report.
The runner and its report are integrated in this source and wired as a mandatory
step in the existing `verify` job. A zero-test or missing-report run fails the
gate. The tests cover the DB manifest/envelope pair, rollback and exact retry,
generation/shared-gate fencing, completed-epoch behavior, repack authority/mirror
rollback, pinned data, snapshot retention races and expiry. Remote S3, Vault
and production behavior are outside this case inventory.

### Resource and credential boundary

The Vault fixture owns exactly one digest-pinned container with a random nonce,
ownership labels, exact container ID/image reconciliation, a loopback-only
ephemeral port and no persisted server logs. The admin root token stays in
fixture memory; the app gets only its scoped Transit token. No token, DSN or
password is placed in argv, ownership state or sanitized evidence. PostgreSQL
uses a random owned database prechecked absent, the CI bootstrap DSN only for
creation/bootstrap, and drops only the exact owned name/OID/owner. The private
`PANDO_ROOT` is exact-owned and inode-verified before removal.

The harness shares one absolute monotonic deadline from before input validation
through the final report write. The CI step uses `--timeout-seconds 1080` under
a 1200-second step and the default 90-second cleanup reserve, so work may use
990 seconds and cleanup the full 1080 seconds; no case or phase resets it.
Docker inspect/pull/run, HTTP health/capability calls, PostgreSQL children,
Git/CLI/server children, wait/drain and cleanup are each clamped to the
remaining budget with a late recheck. Source Git/receipt binding reads run in a
bounded owned child. Existing per-operation caps are never increased. A timeout
or late completion is failure, cleanup cannot replace a primary failure, and an
expired deadline reports a failed/unresolved cleanup instead of passing.

The stock Git client runs with a filtered environment that excludes Vault
variables, DB DSNs/passwords, admin tokens and injected Git/proxy/trace settings.
The Pando server and native hooks retain only their own required app Vault/DB
configuration; do not strip the server environment to imitate the Git-client
filter. Psql uses its own connection environment and SQL stdin. Cleanup or
identity uncertainty, an unknown create outcome, or a hard kill is unresolved
failure, not cleanup success, and authorizes no global deletion.

No raw server/container logs, `commands.json`, SQL result rows, environment
dumps, provider bodies, tracebacks or pack/plaintext bytes are report artifacts.
The report keeps only the fixed sanitized fields and rechecked binding hashes.

### Remote S3 and claims boundary

The five authored Vault cases exercise local CAS only; their report limitations
include `local_cas_only` and `s3_rotation_unsupported`. This is not a blanket
ban on S3. Normal standalone remote S3-compatible `object-store-put`,
`object-store-get` and `object-store-verify` remain implemented, including
verified remote manifest retrieval, DB envelope authority and best-effort
mirror repair. The unsupported part is composition: `kms-rotate` refuses while
`ROOTYARD_OBJECT_STORE_ENDPOINT` is enabled, the encrypted prepared Git-hook
publication rejects the remote backend, and the migration prepared-publication
and a compacted repack with object-store sync fail closed instead of mixing a
remote staging step with local authority in one SQL transaction.

No CloudHSM/HSM service, FIPS 140 validation, production durability/HA or
security, or cross-process GC/destructive collection guarantee is claimed.
Source-level zeroization is not an all-disk-at-rest or plaintext-erasure proof.

### Not covered by the five authored cases

The five IDs do not cover the original missing-DB-envelope-row probe: retain a
valid mirror, remove the authoritative DB envelope row, and prove that a fresh
cold consumer fails without mirror fallback. They also do not cover a valid
scoped token that can read key metadata but is denied decrypt. The broader
Astra matrix, every migration/repack/snapshot producer, remote S3 composition and
a production environment remain outside these five cases.

See the [KeyProvider and envelope contract](../../docs/key-provider.md) for the
key-provider, DB-authority and envelope details.

## Online migration and rollback state machine

1. `copy` (`migrate-step <repo> <gitfs_path> copy`): validates the source GitFS
   bare repository (`git fsck --full --strict`), packages reachable objects into
   an immutable Pando `.pack`/`.idx`, and populates `pando_lab.manifests`,
   `pando_lab.objects`, and `pando_lab.refs` while keeping `storage_backend = 'gitfs'`.
2. `verify` (`migrate-step <repo> <gitfs_path> verify`): runs dual-operator
   `export::diff_export` and directly compares Pando refs and reachable object
   closure byte-for-byte against the GitFS source repository.
3. `drain` (`migrate-step <repo> <gitfs_path> drain`): sets `write_paused = true`,
   installs the GitFS `hooks/pre-receive` write fence (`rootyard.writePaused = true`),
   aborts non-terminal Pando operations, syncs any final incremental delta commits
   created on GitFS since `copy`, and re-verifies dual-operator parity.
4. `fence` (`migrate-step <repo> <gitfs_path> fence`): atomically increments
   `storage_generation`, expires prior read snapshots, and updates
   `rootyard.storageGeneration` on GitFS so stale writers fail closed.
5. `switchover` (`migrate-step <repo> <gitfs_path> switchover`): keeps GitFS
   fenced read-only (`rootyard.storageBackend = pando`, `rootyard.writePaused = true`),
   verifies materialized `git fsck --full --strict`, and switches
   `storage_backend = 'pando'`, `write_paused = false`, `migration_state = 'switched_over'`.
6. `rollback` (`rollback <repo> <gitfs_path>`): pauses Pando writes, streams all
   committed Pando packs into GitFS via `git index-pack --stdin --strict`,
   reconciles updated and deleted refs in GitFS, verifies dual-operator `diff_export`
   and `git fsck --full --strict`, increments `storage_generation`, and restores
   `storage_backend = 'gitfs'` with GitFS unfenced and Pando write-fenced.

## Not implemented or not verified

- Production main-server routing switchover (`rootyard::Storage` remains untouched
  by this isolated lab binary).
- Real S3/R2/MinIO consistency/durability, multi-host deployment, PG replication,
  failover, network partitions, disk power loss, media failure, or PITR coordination.
- Cross-repository pack deduplication, pack compaction, or capacity benchmarks.
- Production authentication/TLS, branch-level authorization, LFS, SHA-256 repos,
  partial/shallow clone guarantees, push-options, arbitrary ref namespaces, force
  updates to branches, compressed HTTP request bodies, or full Git compatibility.
- Hardened cancellation of all descendant processes and decompressed object/disk
  quotas. HTTP and pack fixture limits are 32 MiB; stdout/stderr are incrementally
  bounded at 128 MiB/1 MiB, concurrency at eight, command deadline at 45 seconds.
  Those are lab limits, not a hostile-tenant resource-isolation certificate.
- Abrupt in-flight gateway/PG process termination. The current fault cases are
  explicit hook exits; restart testing is a clean idle gateway restart.

The existing GitFS backend remains the only default implementation. Do not merge
this prototype's tables or enable it automatically based on these tests.

## References

- [Native proc-receive contract](https://git-scm.com/docs/githooks#_proc_receive)
- [Git pack-objects](https://git-scm.com/docs/git-pack-objects)
- [PostgreSQL transaction isolation](https://www.postgresql.org/docs/17/transaction-iso.html)
- [PostgreSQL explicit locking](https://www.postgresql.org/docs/17/explicit-locking.html)
