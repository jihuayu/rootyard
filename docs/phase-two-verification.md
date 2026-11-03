# Durable push evidence and outbox verification

`tests/reliability.py` is an integration suite layered on the existing `tests/e2e.py` harness. Every run owns a random PostgreSQL schema and temporary storage directory. Cleanup removes only that schema and, unless `--keep` is passed, its own files. Use a disposable/dedicated test database.

```sh
cargo build --locked
ROOTYARD_TEST_DATABASE_URL=postgresql://localhost/rootyard_test \
  python3 tests/reliability.py --binary target/debug/rootyard \
  --report test-results/reliability.json
```

Set `ROOTYARD_GIT` to select the server Git executable and `PATH` to select the client. The report records both actual versions and the tested binary's SHA-256. Do not claim compatibility from a requested version without checking the report.

## Observed runs

On 2026-11-03, all 18 cases passed with Git 2.52.0 and Git 2.56.0, each as both client and server. The two reports are `test-results/reliability-git-2.52.json` and `test-results/reliability-git-2.56.json`. They exercised the same debug binary, SHA-256 `9a1688c3934656cd110dc17ce85243ad62dce6a1a666f18cae2ddd6b5fd70957`. Later source changes require rerunning the suite.

The first run caught empty prepared/committed diagnostic callbacks on a native non-fast-forward rejection. The implementation was corrected to classify finished operations whose callbacks all contain empty change lists as `no_ref_changes`; nonempty ambiguous evidence remains `unknown`. Both complete reruns above include this regression.

## Executable cases

- Fresh migration and idempotent upgrade of existing migration-001 user/repository data.
- Real clone, push, independent clone, fetch and fsck. Successful pushes produce immutable successful-ref events; a server-rejected non-fast-forward push produces no successful-ref event.
- A non-atomic push containing a rejected branch rewrite and successful branch creation publishes only the successful subset, even though the Git client exits nonzero.
- Real loose-ref and packed-ref deletion. Packing runs with the server stopped.
- Owner-only operation/event APIs, including read-only owner tokens and cross-owner denial.
- SQL final-settlement failure after a real push: retain the actual post-receive receipt, hard-stop the service, remove the injected SQL fault, remove the completion marker and seed a matching SQL unknown/recovering state, restart, and verify recorded recovery, restored ready state and stable event identities on another restart. The receipt is actual Git output; the interruption/SQL state is an explicit recovery fixture.
- Transient final-settlement SQL failure with no restart: remove the injected fault, require periodic ingestion to publish and retire the actual retained receipt within 15 seconds, confirm the same service PID, then verify another push succeeds. Outbox delivery is disabled during this check, so ingestion retry is independently exercised.
- Local audit/ref-index consumers, repeated delivery, projection rebuild and native Git authority after deleting the SQL projection.
- Admission backlog rejection before starting another Git operation, restored admission after draining, and enabled background delivery.
- Explicit synthetic interrupted-operation journals: prepared-only evidence, and identical old/new ref values in an earlier prepared/committed pair followed by another prepared event. Both must remain unknown and block new pushes even when the native current OID equals the requested new OID.

- A synthetic duplicate-ref post-receive receipt describing A → B → A must remain unknown and publish no events, deliveries or consumer effects.
- A real push to a valid segmented Git ref longer than 1024 bytes must fail before the native ref is written; no successful event may be published. The operation must settle as `no_ref_changes` and the repository must remain ready.
- A real non-atomic push of 4097 short refs must be rejected as a whole before any native ref is created, with no events and a `no_ref_changes` operation.

- An unrelated operator recovery reason must remain blocked after restart; successful journal reconciliation must not clear it.

The large batch produced two HTTP operation records in each tested Git version, both `no_ref_changes`. The test does not assume that one client push always means one HTTP RPC. Both oversized-input tests require Git’s explicit pre-receive-hook rejection, rather than accepting any transport failure as success.

A raw pkt-line receive-pack test also sends an actual stale old-OID compare-and-swap alongside a valid new branch. Native Git rejects the stale ref and accepts the other branch; only the accepted branch gets an event. Repeating exactly the stale old/new pair leaves the operation `unknown` on both tested versions, with no new event despite the current ref already equaling the requested new OID. The unknown settlement terminates HTTP after Git emits its rejection report; the test preserves and checks that partial rejection report without treating it as a successful push.

The deployment-hook fixture starts the service from a private copied executable, removes that deployment path while it is live, and requires a successful recorded push using the persistent hook runner. Removing the managed pre-receive hook must reject a new RPC with HTTP 503 before starting a Git operation; restarting must reinstall the hook and restore successful pushes.

## Fault-injection boundary

The SQL trigger deliberately rejects only terminal operation settlement, not initial unknown insertion. The test checks the actual on-disk successful-ref receipt before restarting. It does not infer successful refs from the client exit code or from current ref equality.

The ambiguity fixtures deliberately write synthetic diagnostic journals while the server is stopped. They test recovery policy, not whether a particular kernel/process crash can generate the exact fixture. These fixtures are labeled separately in the report.

No kernel/power-loss durability, production throughput, multi-node fencing, online backup consistency, or external exactly-once side-effect guarantee is established by this suite. GitFS remains the authoritative source for refs and objects; the SQL ref index is disposable derived state.

## Build, worker and baseline checks

The same final debug binary also passed all 15 baseline `tests/e2e.py` cases with both Git 2.52.0 and 2.56.0. The baseline CAS race uses its own repository because a conservatively unknown rejected request may isolate that repository; it still requires exactly one native `ok`, one `ng`, the final expected OID and fsck. Reports are `test-results/phase-two-baseline-git-2.52.json` and `phase-two-baseline-git-2.56.json`.

`cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, 19 Rust unit tests, the explicitly enabled PostgreSQL outbox integration test, and debug/release builds passed. The PostgreSQL integration test covers claim concurrency, unknown barriers, expiry and generation fencing, expiry while waiting on delivery/projection locks, replay identity/evidence validation, per-ref order, retries, deletion projection and ownership constraints.

CI explicitly executes both Python suites and `cargo test --test outbox -- --ignored`. A default cargo test without that explicit command does not run the PostgreSQL integration test.

Actual noexec-mounted storage was not available for this test run. Startup executable self-checks, real X_OK checks and non-executable/missing-file capability tests are implemented, but these are not reported as a successful noexec-mount deployment test. No container runtime or multi-node deployment has been verified here.
