# HA #43/#44 — bounded Patroni/etcd/HAProxy reference profile (composed source `1061a8e`, harness `300c6c9`)

Permanent evidence for issues [#43](https://github.com/jihuayu/rootyard/issues/43)
and [#44](https://github.com/jihuayu/rootyard/issues/44). This bundle records one
**actual native run** of `tests/cluster_patroni_native.py` on a composed
production source (HA profile + Pando schema 132 / backup format 8) and the
honest ledger of the failed attempts that preceded it.

**#43 and #44 remain OPEN.** This is a reproducible reference profile plus
single-host measurements. It is **not** a production HA/DR certification and it
does not close either issue.

## Read this scope first

- **One physical Linux host** runs all three etcd members, all three Patroni
  PostgreSQL 17 nodes and the single HAProxy process. There is **no** cross-host
  storage fencing, **no** hardware watchdog qualification, **no** power-loss,
  rack, zone or kernel network-partition test. Injection is process/port/session
  crash, not power loss.
- **HAProxy's own HA/failover is out of scope**: it is a single local
  stable-endpoint process.
- The production profile **rejects this host** (`production_certified=false`,
  `hardware_watchdog=false`). The current local fixture therefore runs with the
  explicit allow-unfenced single-host flag; a production render without a real,
  kernel-registered watchdog device is refused.
- The backup fixture is a **local, unencrypted, trusted-closure** backup:
  `checksums_verified=true` but `authenticity_verified=false`. It is **not** an
  authenticated-archive or tamper-proof proof.
- **No zero-RPO DR claim.** Automatic promotion lost 0 acknowledged commits as
  measured (6/6 retained). The *restore* path intentionally loses exactly one
  post-backup acknowledged OID (`52f47a5…`, not present in the paired archive).
- No multi-broker Kafka HA, no Git-volume replication (only PostgreSQL metadata
  is synchronously replicated). The GitFS volume stays node-local and needs the
  restore path.

## Source, input and harness identity

| Item | Value |
| --- | --- |
| Compiled production source | `1061a8ee9d1ecc783189d33949980eac6b3bd6ea` |
| Production input digest | `9e33859aad991589c57863af6f6b46fe42290071b3e271f90eda44f6d707feac` (329 files) |
| Immutable local binary | `6f76d70966473cd4bc956bc6a6cff792191664dba3516736b5d50cb92e156eba` |
| Deployment HEAD (`codex/deepseek-round3-ops`) | `ac54f7163561ad98fb83e4c5f45cd2e1f7151f74` |
| Merged main in lineage | `9a27f4a` (Pando schema132/format8 composition), HA delta `300c6c9` |
| Native harness commit (`tests/cluster_patroni_native.py`) | `300c6c93cc054fbd723af2243a8f321307835cbc` |
| Harness file hash | `07c5265aa0f3ec7c7ccb963fea7648e5c0bd8ba8fd17d4f6ade3b81c10feb9e1` |
| `tests/ha_fixture.py` / `deployment/ha/render.py` hash | `ef14ad39…dff7bc7b` / `95dd01fb…22db4b` (last changed at `0223b24`) |

`source-equivalence.json` records that **all 329 production paths and SHA-256
digests are identical** to the certified Pando61 compile
(`production_inputs_identical=true`), i.e. the HA deployment/test delta is
outside the production input set. The published `production-inputs.json` is that
exact path/digest map; recomputing it today with `source_digest.py` on the
current tree still yields `9e33859…` over the same 329 files (verified, see
`manifest.json` → `checks.current_tree_reproduces_certified_production_input_digest`).
The test harness and the profile worktree HEAD are distinct commits, and the tree
was clean before and after the run (`source_worktree_dirty=false`).

## Gate check before publishing

- `status.json` (copied from `scratchops43/coordinator-status.json`) has
  `state=passed`, `exit_code=0`, and records `report_sha256 =
  43655b1a59fc49aeac2049010a9ed022c5832daf9db5d09a8f568680f9ad9dea`.
- `report.json` is the byte-exact coordinator report; its published SHA-256 is
  the same value. `measurement_kind=native_execution`, `simulated_fields=false`.

## What actually ran

Topology: 3 etcd v3.5.17 members with mutual TLS; 3 Patroni 4.0.4-managed
PostgreSQL 17 nodes with `verify-full` TLS + SCRAM-SHA-256, `synchronous_commit
= remote_apply`, `synchronous_standby_names=*`, one synchronous standby; one
HAProxy 3.0.11 stable primary endpoint plus one replica endpoint; one Rootyard
server on the stable endpoint. Tool versions in the report: git 2.52.0, Python
3.12.14, OpenSSL 3.5.7, psql 17.11, kernel 6.18.57, 5 logical CPUs, 18.4 GB RAM.

Workload: native Git clone/push/fetch/fsck and HTTP browse through the stable
endpoint, a hard kill of the whole old leader (Patroni **and** the unmanaged
postmaster), an automatic Patroni promotion, a two-of-three etcd quorum-loss
drill, then an offline backup into a fresh deployment restore with ingress held
until the offline checks passed. Baseline counts: 1 repository, 1 ref,
4 tokens, 2 outbox events, 4 event deliveries; leader `pg3`, server port 29033.

### Automatic failover (whole old leader killed)

| Measurement | Value |
| --- | --- |
| Old primary / successor | `pg3` / `pg1` |
| Manual `pg_ctl promote` invoked | `false` (Patroni "promoted self to leader by acquiring session lock") |
| Old-node processes alive after crash / old PG port | `0` / closed |
| Crash → successor elected | **18480.3 ms** |
| Acknowledged commits checked / missing after promotion | **6 / 0** (`missing_acked_oids=[]`) |
| Post-promotion OID | `d8de49433e2cb8be1c03c1bb9524978e12a34b28` |
| Rootyard PID before / after | `357650` / **same `357650`** — the application reconnected, it was not restarted |
| Stable endpoint primary backend | `29033` → `29031` (same host:port for clients) |
| Replica endpoint | `t:29031` → `t:29032`, TLS+SCRAM verified, primary excluded |
| Worker drains | 12/12 pre-failure `(event_id,consumer)` deliveries delivered; global pending total deliberately excluded |

### RTO / RPO (from this current report, not the archived 85 checkpoint)

| Metric | Value |
| --- | --- |
| RTO read | 18519.1 ms |
| RTO write | 19896.9 ms |
| RTO Rootyard ready | 18596.6 ms |
| RPO — acknowledged commits lost on automatic promotion | **0** (6 verified) |
| Total pipeline | 141.0 s |

### Two-of-three etcd quorum loss

`etcd1` and `etcd2` were stopped, leaving one member (no quorum). All three
PostgreSQL nodes were sampled 13 times:

- Healthy baseline first: a write through the stable endpoint succeeded with a
  real `UPDATE 1` result (so "no write" later is not an artifact of a broken
  client).
- 2.15 s after the stop the old primary was still `primary` (its leader lease
  was still valid, so **writes can still be acknowledged inside the valid lease
  interval** — recorded separately, not counted as a violation).
- Demotion detected at 6.69 s; the old primary then stayed `unavailable`/
  `standby`, the other standby stayed `standby`, and the stopped node stayed
  `unavailable` (`standby_nodes_promoted_without_quorum=[]`,
  `promotion_without_quorum=false`).
- **4/4 durable write probes were rejected** over an observed 6.25 s window
  (target ≥ 5 s, ≥ 3 probes) — `endpoint_writes_rejected=true`. The last probe's
  failure is a closed connection, recorded verbatim.
- 8 probes were accepted while the leader lease was still valid (see above).
- Quorum loss detection 12.94 s; writable again after 17195.9 ms on `pg1`
  (`f:29031`), post-recovery OID `637d25d048a3f011a4bc7946a6478b46cdb07f4e`.
- `api_during_quorum_loss=200`: the Rootyard health/read API answered while the
  database correctly refused writes; this is not a writable-DB claim.

### Backup / restore, CI authority rotation, refs

| Measurement | Value |
| --- | --- |
| Backup closure / restore | 41.79 s / 25.75 s |
| Backup manifest read from the actual archive | **format 8**, schema end **132** (`backup_id 12085b3a-fb24-490e-84f1-29045156d50a`) |
| Backup verify | `checksums_verified=true`, **`authenticity_verified=false`** (local trusted closure, not authenticated archive) |
| Source vs restored counts | equal: 1 repository, 9 Git operations, 4 tokens, 9 outbox events, 18 deliveries, 1 CI checkout job |
| Authority | rotated automatically by the restore CLI (incarnation `4dd246da…` → `c630f695…`); no SQL rewrite of authority or grants |
| Pre-backup CI job | `70c15fd7…`, target OID `865d4bb…`, grant active, expiry still in the future, same mirror audience, real token clone baseline `HEAD=865d4bb…` |
| After restore | old token rejected with **HTTP 401**, old grant revoked by the CLI restore, historical pin descriptor and receipt **byte-identical** to source (full JSON equal, canonical SHA `a2af3f5f…`) and the restored retention ref still points at the same OID |
| Fresh restored-authority job | `76194c33…` cloned exactly `865d4bb…` with `git fsck` passed |
| Ordinary user tokens | preserved through the backup (reader, token-revocation and tenant-denial checks passed); only a token revoked *before* backup stays denied |
| Refs | source map `{main: 637d25d, refs/rootyard-ci/jobs/70c15fd7: 865d4bb}` equals restored map; 2 vs 3 refs is a legitimate post-boundary add |
| Post-boundary write | `main` `637d25d` → `52f47a5` (direct child, ref count unchanged) — intentionally **absent** from the paired archive, hence the one-OID restore loss |
| Retained acknowledged OIDs | 8 (all pre-boundary ACKs) |
| Worker drains | 6/6 pre-backup `(event_id,consumer)` deliveries delivered on the restored authority |
| Restored push | `eb58dca215464cca8b2c74e6859bb3ce81abb2dc` with `git_fsck=passed` |

### Security boundaries (honest)

- PostgreSQL TLS `verify-full` + SCRAM-SHA-256 for service and replication;
  plaintext and untrusted-CA runtime connections rejected. DCS is mutual TLS
  with client-certificate authentication; missing/world-readable server key and
  client-without-certificate renders are rejected.
- Patroni REST is loopback-only on all three nodes. Its health/GET endpoints are
  unauthenticated **by design** (`read_only_health_http=200`), management
  endpoints require basic auth (`unauthenticated_management=401`,
  `authenticated_management=404`). The loopback binding is the real boundary;
  HAProxy sends basic credentials on role checks anyway.
- Role separation: `repl|false|false|true` (replication only) and
  `rootyard|false|true|false` (no superuser/replication).
- **Safe watchdog gate**: `deployment/ha/render.py:125-178` resolves the
  configured watchdog device through kernel `/sys/class/watchdog` sysfs
  identity and major/minor **without opening it or issuing ioctls** (opening can
  reset an armed watchdog), and refuses unregistered devices, `/dev/null` and
  `/dev/urandom`. This is configuration compatibility only — **no hardware
  watchdog proof** and no arming.
- `tests/ha_reaper.py` is a child-subreaper wrapper for the fixture only: it
  reaps **owned reparented descendants** so PID 1 zombie accumulation in the
  container does not deadlock Patroni's offline demotion. It changes no
  production code or configuration.

## What this proves / does not prove

Proved here (actual execution): external DCS election, automatic role promotion
with no manual step, stable-endpoint reconnect with an unchanged Rootyard PID,
measured RTO/RPO on acknowledgement, all PG roles refusing writes without
quorum, an offline format-8/schema-132 restore with authority rotation, real CI
grant revocation + fresh checkout of the exact retained OID, ref map equality at
the backup boundary, and retained ACK content.

Not proved: cross-host fencing, hardware watchdog arming, power loss, rack/zone
failure, HAProxy HA, Kafka HA, Git-volume replication, authenticated-archive
authenticity, or zero-RPO disaster recovery.

## Failed-attempt ledger (all failures preserved, no invented reports)

| Attempt | Source | Error (verbatim summary) | Correction | Retained log |
| --- | --- | --- | --- | --- |
| Old `be247` / composed prior 85 HA attempt | `be24759b9541e8a56dd9466c9b859b817fe9ca5e` (with composed main `a36f32a3b64a04cc520c7f205cc5db368f442085`) | Last line failed committing the **restored** clone: `Command failed (128): Author identity unknown … fatal: unable to auto-detect email address` | test-only `85b8a2f` adds per-repository `user.name`/`user.email` to the restored clone (same pattern as the first clone); no global config, no weakened assertion | `attempts/pre-restored-git-identity-a36f32a3/native.log` (published sha256 `f5da52cc6739ea6e73bb2f11061ace263d16e6d8451686e2ede3efeda9a51ce0`; scratch original `3bd0c36c…` differed only by one trailing blank line) |
| `579` pin-content attempt | `a8ea22e17454de0a7df14042c6710fce929fc758` | `AssertionError: {'version': 1, …}` at `assert source_descriptor.get("state") == "pinned"` — the fixture invented a non-existent `Intent.state` field; the real `PinIntent` has no `state` | test-only `300c6c9` validates `version==1` plus job/repo/target/storage/format/retention_ref, compares the durable `<job>.pinned.json` receipt to the Intent (before and after restore) by canonical hash, and checks the retention ref with real `git rev-parse`/`cat-file` | `attempts/failed-579-pin-state-a8ea22e/native.log` (published sha256 `f9615694737bc2e66f9748af23fe182909e3bc36b4ab4cbf1c5dde0ff8b091c2`, byte-identical to the scratch log) |
| Pre-`be247`/earlier fixture gaps (DCS reaper deadlock, profile startup, a false refcount assertion) | explained in the earlier `scratchops43` reviews/attempts | — | `c03e7c9` (reaper + watchdog identity + evidence gaps), `0223b24` (quorum/lease evidence and docs), `be247` (CLI authority rotation, real CI revocation) | see the earlier review artifacts; not re-published here |

`checkpoint-85/` is the archived **`cfa89ce` full pass** (report sha `62f607a5…`,
RTO write 20991.2 ms, failover 19.69 s). It is a valid checkpoint for that
test-only 85 tree and **not** a qualification of the current `300c6c9` run; the
current numbers are the ones in the tables above.

## Files, hashes and reproduction

`manifest.json` lists every published file with its SHA-256 and byte size, the
gate checks, the run summary and the secret-scan result. The run is reproducible
with the certified binary:

```sh
python3 tests/cluster_patroni_native.py \
  --binary /path/to/1061a8e/rootyard \
  --report /tmp/ha43/cluster-patroni.json
```

**Not published** (deliberately): the Rootyard binary, build archives/ZIPs, TLS
CA/certificates/private keys or any PKI material, env/config credential files,
backup byte sets or database data directories, raw service/PostgreSQL logs, and
private backup contents. Every published text file was scanned for password
assignments, passphrases, private-key blocks, API keys and non-placeholder
bearer tokens: **0 hits** (`report.json` only contains the benign JSON flag names
`weak_password_rejected`/`shared_password_rejected`).

`source-review.json`/`.md` are the independent source review of the **current
`300c6c9`** delta (0 P1, 0 P2). Their `native_status` block was written **before**
this run finished and therefore says pending/running; the actual post-review
result is the `passed` status/report published here. The earlier `579` review
(`source-review-579.json`/`.md`, which failed) is intentionally **not** part of
this bundle.

Issue links: [#43](https://github.com/jihuayu/rootyard/issues/43),
[#44](https://github.com/jihuayu/rootyard/issues/44); roadmap #48 stays open.
Acceptance summary: [`docs/acceptance/round3-ha43.md`](../../../docs/acceptance/round3-ha43.md).
