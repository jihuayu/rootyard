# Blob-only baseline evidence — 2026-11-14

Root-owned, credential-free baseline report for issue #106. This evidence comes
from root integration commit `ce1aaa3caccb6e9bca73cd960e4803aac8dfd862` and is
distinct from the feature branch that produced the runner. Do not relabel it as
a current-branch test result.

The exact report is [`report.json`](report.json) (sha256
`42788ad969397baa5beaf150a03a35f9c7098bd10bf6271773fe8d5037e9cc5d`).
It is report version 3, status `passed`, with all five cases passed:
provision, seed_push, concurrent_read_clones, restart, and cold_clone.
Report metadata: `qualification_kind=clean-candidate`,
`measurement_kind=native_execution`, `simulated_fields=false`.

## Provenance

| Field | Value |
| --- | --- |
| Source head | `ce1aaa3caccb6e9bca73cd960e4803aac8dfd862` |
| Binary sha256 | `66fdfba3b7c55d9ceb659afc86d806a74b1336e0c1ee63904f6f17c82ee06cb3` |
| Source inputs sha256 | `25ca6845620267c131d50f91d32f0a50d5e8266157722598cd413fe44286a678` |
| Runner sha256 | `c274c81d015f80f5f21e6a487bc726e87e15aee50f90ca17e09072eec031f5d7` |
| Harness sha256 | `dd29e6c3f60795309eabefb775a7573152489ab056d7dee899cef518d4966bdc` |
| Build receipt sha256 | `53d6b3c0a94995195daec1fcfc77cb38827a4438caf5792e2bd7a877941af25e` |
| Trusted Git sha256 | `a0e562e4bd3c4c79379e91d8c07a10104b2cefe8fac966dc6bd4874a57a807f3` |
| Rustc | `rustc 1.99.1 (58cf8f9c3 2026-10-13)` |
| Report sha256 | `42788ad969397baa5beaf150a03a35f9c7098bd10bf6271773fe8d5037e9cc5d` |

The report's `input_sha256` also records the exact hashes of the runner,
`scripts/build_native.py`, and the reused harness/helper files.

## Runtime

- Linux `aarch64`, kernel `7.2.12-orbstack-00394-gbecdd6130068`, Python 3.13.5,
  Git 2.47.3, PostgreSQL 17.11 (Debian 17.11-1.pgdg13+2).
- 12 logical CPUs; host `MemTotal` 49,315,216 KiB. CPU model `unavailable`.
- cgroup v2: `cpu.max=max 100000` (unlimited), `cpuset.cpus.effective=0-11`
  (12 CPUs), `memory.max=max` (unlimited). Host shared; not isolated performance
  hardware.
- Root reports Garage 2.1.0 for the profile; the redacted report records the
  OpenDAL S3 profile facts, not the Garage version.
- Root used a task-owned host-network runtime so Garage’s host-published endpoint
  was the actual `127.0.0.1` loopback endpoint, satisfying the runner’s
  HTTPS-outside-loopback rule. No remote, cloud, or independent-host
  qualification is claimed.

## Measured workload and boundaries

- One deterministic repository of exactly 262,144 file bytes (four files;
  fingerprint `554e7b78f5f19bc227bc3c106af23cdbecf45bdc7b5b6dc02a1c8c6e3616cabd`).
- One push, then two concurrent read-only clones of that same repository. Two
  read clones only; receive-pack writes are not measured.
- Setup (schema migration, fixture accounts, serve-blob readiness) `0.729686` s.
  Case wall seconds: provision `0.058323`; seed_push `1.601852` (push
  `0.739071`; separate ls-remote `0.655786`); concurrent_read_clones `1.003734`
  (workers `0.907927`/`0.951724`; aggregate `0.952046`); restart `0.372328`;
  cold_clone `1.053514` (clone `1.010170`).
- PostgreSQL was sampled at 250 ms intervals. Reported per-case peaks are 4
  sessions and 0 lock waiters; `exact_lock_wait_ms` is null. Counts are observed
  lower bounds; short waits can be missed. The restart case is unsampled, and cold
  samples do not cross the restart.
- Cold means a process-local materialized view after the graceful restart with an
  emptied and freshly recreated service-local scratch root, verified empty before
  and after. Provider cache state is unknown; this is not provider-cold.
- HTTP request/response wire bytes, OpenDAL GET bytes/phases, throughput,
  percentiles, capacity, and SLOs are not measured. `payload_bytes=262144` is the
  deterministic file payload, not wire bytes. Configured admission was read, never
  overridden, and its report facts are not a capacity claim.

## Commands

Required public-schema prerequisite before the runner (the random-schema Harness
setup alone does not create `public.cluster_authority`):

```sh
DATABASE_URL="$ROOTYARD_TEST_DATABASE_URL" /absolute/path/to/rootyard migrate
```

Runner invocation:

```sh
python3 scripts/state_services_blob_baseline.py \
  --binary /absolute/path/to/rootyard \
  --git /absolute/path/to/git \
  --report /absolute/path/to/report.json
```

Root first hit the 503/preflight path because `public.cluster_authority` was
absent, then used the existing CI initialization path and reran. This report is
from that successful rerun, not a fabricated clean first attempt.

## Cleanup and scope

- Report cleanup fields: `fixture_retention.retained=false`, `root=null`,
  `cleanup_error=null`. The random schema is always dropped and the owned
  temporary fixture was removed on the passed run.
- Blob deletion remains disabled. Uploaded S3 objects stay in the caller-owned,
  whole-instance disposable Garage until root removes that instance.
- Single host, one PostgreSQL server, one OpenDAL S3 provider, loopback HTTP
  origin. No HA, multi-host, physical-durability, provider-cold, exact-lock-wait,
  GET-metric, throughput, percentile, capacity, or SLO claim.
- The report itself says `issue_complete=false`, `budgets_frozen=false`, and
  `claim=baseline_entry_only`. #106 remains open.
