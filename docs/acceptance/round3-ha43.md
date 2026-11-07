# Round-3 issues #43/#44 acceptance — bounded Patroni/etcd/HAProxy reference profile

Status: **ACCEPT_FOR_BOUNDED_SINGLE_HOST_PROFILE** — actual native run passed on
the composed round-3 source; **#43 and #44 remain OPEN**. This delivers a
reproducible external-HA reference profile and real single-host measurements, not
a production HA/DR qualification. Permanent evidence:
[`evidence/round3/ha43-patroni-300c6c9/`](../../evidence/round3/ha43-patroni-300c6c9/README.md).

## Source and result

- Compiled production source `1061a8ee9d1ecc783189d33949980eac6b3bd6ea`
  (Pando schema 132 / backup format 8) composed with merged main `9a27f4a` and
  the HA delta `300c6c9`; deployment HEAD `ac54f7163561ad98fb83e4c5f45cd2e1f7151f74`.
- `source-equivalence.json`: **all 329 production paths and digests equal the
  certified Pando61 compile** (`production_inputs_sha256 = 9e33859…`, still
  reproducible from the current tree); immutable local binary `6f76d70…`.
  Test harness/profile HEAD is a distinct commit and the tree was clean before
  and after the run.
- `status.json`: `state=passed`, `exit_code=0`; `report.json` is the actual
  coordinator report (SHA-256 `43655b1a…` matches the recorded hash),
  `measurement_kind=native_execution`, `simulated_fields=false`.
- Topology: 3 etcd v3.5.17 members with mutual TLS; 3 Patroni 4.0.4 PostgreSQL
  17 nodes with `verify-full` TLS + SCRAM-SHA-256, `remote_apply` strict
  synchronous replication; one HAProxy 3.0.11 stable primary endpoint plus a
  replica endpoint; one Rootyard server on the stable endpoint.
- Failover: the **whole old leader** (`pg3`: Patroni + unmanaged postmaster)
  was hard-killed. Patroni promoted `pg1` automatically, **no manual
  `pg_ctl promote`**. The same Rootyard PID `357650` reconnected through the
  stable endpoint; 6/6 acknowledged commits survived (`missing_acked_oids=[]`),
  post-promotion OID `d8de494…`.
- RTO from this report: read **18519.1 ms**, write **19896.9 ms**, Rootyard
  ready **18596.6 ms**. RPO: **0** acknowledged commits lost on automatic
  promotion (as measured). No zero-RPO DR claim: the *restore* path
  intentionally loses one post-backup acknowledged OID (`52f47a5…`, absent from
  the paired archive).
- Quorum loss (2 of 3 etcd stopped): a healthy baseline wrote `UPDATE 1` first;
  within the still-valid leader lease the old primary could acknowledge (8
  probes, recorded separately). After demotion (6.69 s) **4/4 durable probes
  over 6.25 s were rejected**, all nodes were `standby`/`unavailable`, and
  `standby_nodes_promoted_without_quorum=[]`. Writable again after 17195.9 ms.
- Restore: offline backup **format 8, schema 132** read from the actual
  manifest; `checksums_verified=true`, **`authenticity_verified=false`** (local
  trusted closure, not an authenticated archive). Source and restored counts are
  equal; source/restored ref maps are equal at the backup boundary; 8 retained
  ACK OIDs verified; `git fsck` passed.
- Authority: the restore **CLI** rotated the deployment authority and revoked
  the pre-backup CI grant (no SQL rewrite). The old grant was active with a
  future expiry and the same audience *before* backup and did a real checkout;
  after restore the old token returned **401**, while a fresh restored-authority
  grant checked out exactly the retained OID `865d4bb…` with `fsck` passed.
  Pin descriptor + receipt remained byte-identical to the source. Ordinary user
  tokens were preserved by the trusted backup; only a pre-revoked token stayed
  denied.
- CI/worker accounting uses exact `(event_id,consumer)` identity sets
  (6/6 pre-backup drained before ingress, 12/12 pre-failure deliveries
  delivered); global pending totals are excluded because later acknowledged
  writes legitimately add new deliveries and the final ref count may differ.

## Scope explicitly accepted

- A supported *external* stack (Patroni + etcd + HAProxy), reproducible with
  `deployment/ha/render.py` and `tests/cluster_patroni_native.py`.
- The safe watchdog gate checks the configured device through kernel
  `/sys/class/watchdog` sysfs identity and major/minor **without opening it or
  issuing ioctls**; a production render without a registered device is rejected.
  `softdog` is configuration compatibility only — no hardware proof.
- Patroni REST is loopback-only; unauthenticated health GETs are by design
  (200) while management requires basic auth (401 unauthenticated / 404
  authenticated). TLS `verify-full` + SCRAM and server-key permission rejects
  were exercised. `tests/ha_reaper.py` is a test-only child-subreaper that
  reaps owned descendants to avoid PID 1 zombie deadlock; it changes no
  production code.

## Explicit non-claims

- Single physical Linux host: **no** physical cross-host storage fence, hardware
  watchdog arming, power loss, rack, zone, kernel network partition or Kafka HA.
- HAProxy's own HA/failover is out of scope; the GitFS data volume is not
  replicated (only PostgreSQL metadata).
- The current local fixture uses the explicit allow-unfenced single-host flag;
  the production profile **rejects this host**.
- The backup fixture is local, unencrypted and trusted-closure
  (`authenticity_verified=false`); it is not an authenticated-archive or
  tamper-proof proof.
- No zero-RPO disaster-recovery claim (see the one-OID restore loss above).
- #43, #44, #26, #48 remain open; nothing is closed by this evidence. The failed
  attempts are preserved in the evidence bundle (old `be247`/`a36f32a3` Git
  identity failure, `579`/`a8ea22e` nonexistent `Intent.state` fixture failure);
  the archived `85`/`cfa89ce` full pass is a valid checkpoint, not a
  qualification of the current `300c6c9` run.

## Delivery

Source review of the current `300c6c9` delta: `source-review.json` (0 P1,
0 P2; its `native_status` block predates this run and says pending — the actual
result is the `passed` status/report above). Evidence only: no production,
schema or test change in this delivery. See also
[operations: HA profile](../operations-HA.md).

The [final publication review](../../evidence/round3/ha43-publication-review.json) allows merge with zero P1/P2. Its two wording observations are clarified in the bundle publication-provenance note; the copied raw source-equivalence record is preserved.
