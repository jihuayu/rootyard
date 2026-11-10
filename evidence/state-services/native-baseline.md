# Bounded native baseline: legacy Pando

Status: **PASS within the workload below; #106 remains open.** This receipt is bound to the historical pre-evolution `d689bf8` source/binary inputs. It is **not** a qualification of the rebased security/token/membership parent, a new RefStore/Blob backend, or a new deployment profile. DeepSeek implemented W0 contracts and inventory; the root agent integrated and ran this service baseline. Luna Max reviewed the runner and its evidence boundaries. No new backend or multi-host qualification is implied.

| Binding | Value |
| --- | --- |
| Compiled source | `d689bf8062a73cfadbc0a72abf3f1546d992e09c` |
| Binary SHA-256 | `f39838f139e27d6f00a55a88c7ef98974c993f2da3139e0eb3b4e04b05ff8e0b` |
| Source inputs SHA-256 | `6225c08c28ace0bc45c4e6810e0e8642ee4215a9cb0bc930b87d5fa3eab7fb10` |
| Cargo.lock SHA-256 | `1d463290291864226a654eb509bb81e095dd4c1e1a109254b670fbd0c4342034` |
| Runner SHA-256 | `8a36ccc9e8db2ac7a79425ee4af8a0c979d80992d44bb1bf93c82042650bed01` |
| Harness SHA-256 | `c5a2964e687b4c10b77f548defd0f25407e42c0a57a64ffaddc7bb7b2a128dbc` |
| Versions | PostgreSQL 17.11 (Debian 17.11-0+deb13u1); git version 2.52.0 |
| Owned PG sessions | 160 samples; peak 15 connections |
| Idle Pando RSS | 31808 KiB |
| Final RSS | 40856 KiB |

[Raw report](w0-native-legacy-pando-v5.json) embeds the build receipt, host-visible resources, individual durations and small-sample nearest-rank percentiles. [Runner](../../scripts/state_services_native_baseline.py) uses the repository Harness by default; `ROOTYARD_BASELINE_HARNESS_ROOT` explicitly selects another checkout and its exact Harness hash is recorded. `--source-root` must match the binary receipt's compiled-input hash before and after the workload. Python optimization mode is rejected because it would remove acceptance assertions.

The workload uses two repositories with deterministic 256 KiB initial payloads, legacy GitFS seed pushes and offline Pando cutover, six serial Pando pushes, eight different-ref pushes, two concurrent cross-repository new-pack pushes, two competing same-ref pushes, one successful atomic two-ref push with readback, cold/warm clones after deleting only owned disposable Pando caches, closure fsck and twelve API list requests. Competing same-ref pushes produced one accepted update and one rejection, with winner readback; their advertisements are **not synchronized to an identical old OID**, so this is not an exact-CAS race proof. Atomic push covers the successful case; rejection atomicity remains separate.

This is one physical host using real loopback PostgreSQL, Garage and Vault. Provider versions remain null because executable inspection was unavailable to the test user. The 250 ms socket-scoped PG sampler can miss short waits; zero observed lock waiters does not establish zero contention. Internal pool/semaphore/ref/repository/singleton-lock phase times, Git CPU, Blob bytes/latency, peak temporary disk, maintenance contention and production budgets remain unmeasured. The peak connection count is an observation, not proof that the pool is the dominant bottleneck.

## Reproduce

Use an isolated test database and real S3-compatible/Vault fixture. Supply the standard Harness variables: `ROOTYARD_TEST_DATABASE_URL`, `ROOTYARD_OBJECT_STORE_ENDPOINT/BUCKET/REGION/ACCESS_KEY/SECRET_KEY` and `ROOTYARD_KMS_VAULT_URL/TOKEN/KEY`. Do not put credentials in reports. Build with `python3 scripts/build_native.py`; copy the binary and its `.build.json` receipt to an immutable location before another Cargo command. Then run:

```sh
python3 scripts/state_services_native_baseline.py --binary /absolute/immutable/rootyard --source-root /absolute/compiled-checkout --report /absolute/report.json
```

Add `--keep` only when the owned fixture must be inspected after a passed run;
failed runs retain it automatically as recorded in `fixture_retention`.

The runner stops only its owned process group and drops only its random SQL
schema. A passed run removes its owned temporary fixture directory by default.
`--keep` retains it explicitly; any failed run also retains the owned fixture for
diagnosis. The JSON report records `fixture_retention.requested`,
`retained`, `root` and `reason`, so an unexpected leftover is visible rather
than silent. Operators may remove that exact owned directory afterwards. It
does not modify host FUSE, kernel, PostgreSQL or provider configuration.

This cleanup change applies only to future runner invocations. The historical
v4/v5 reports and their recorded `fixture_root` paths remain immutable; the
rebased head is still unqualified until the root agent runs the fresh
feature-enabled binary and 32-case native workload.

## Earlier measurements

Local scratch v1 was rejected for PG measurements because it selected an application name overridden by the service. Scratch v2 corrected this by matching actual API-owned TCP socket client ports. Scratch v3 added source/lock/hardware binding and extra workloads. The v4 report captured the portable runner and same-ref limitation. This v5 report additionally validates API-returned repository UUIDs and exact same-origin clone paths before authenticated Git or descriptor-safe cache cleanup, and supersedes those runs and binds the checked-in portable runner with its optimization guard and explicit same-ref limitation. The local Git smoke report is a separate tooling smoke test and does not qualify the service architecture.
