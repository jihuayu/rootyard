# Final combined HA/CI restore compatibility — current `157748add` binary

Additional **current-binary** proof for the combined PR63 migration runtime and
merged PR62 HA profile. It is **not** the older `6f76d70` PR62 HA report; the two
runs and identities are kept separate. This bundle records only actual native
compatibility evidence and makes no production/cross-host claim.

## Identity (distinct from the older `6f76d70` HA report)

| Item | Value |
| --- | --- |
| Harness source / deployment content commit | `0d9f48211e8e05ba02d402c920d397e1e1c117ac` |
| Compiled production source | `cb8d1b915a3c1e12990c038b7a43e2b7e891ff5f` |
| Immutable binary | `157748addd3ad1cc67e9aa5fc2c60b76b524de4f6a09ae65bedfdea26f17958f` |
| Production inputs | `0f865a04763c5be077e15151143554b191f8ad8a84462f6746d045eabea3bc90` (331 files) |
| Coordinator | `state=passed`, `exit_code=0`, `report_sha256=efcfd7e4…` matches `report.json` |

`source-equivalence.json` and `production-inputs.json` show all 331 production
paths/digests equal the certified compile; PR62 HA-profile and PR63 migration
runtime files are combined without a production-input change. No binary, env,
PKI, private credential or backup set is stored.

## Actual compatibility results

- Automatic Patroni failover on the combined stack: 6 acknowledged commits,
  **0 lost** after promotion; measured RTO read **19522.7 ms**, write
  **20762.3 ms**, Rootyard ready 19597.6 ms.
- Offline backup format **8** / schema **132** restored; source and restored
  counts equal at the boundary; pin receipt matched intent before and after.
- Restore rotated authority by CLI, revoked the real pre-backup CI grant: old
  token HTTP **401**, while a fresh grant checked out the exact retained OID
  `deac9589…` with `fsck=passed`; new grant not revoked.
- Retained ACK OIDs verified, one post-boundary OID intentionally absent (no
  zero-RPO DR claim); restored endpoint served a new push OID.
- The coordinator-native log records `ha_endpoint_repository_api: passed`,
  `ha_git_roundtrip: passed`, and a final `result: passed` with write RTO
  20762.3 ms / failover 19.08 s.

The coordinator report has **no top-level `result` field** (known presentation
nit); the pass is established by coordinator `exit_code: 0` and the native log
result, not by inventing a field. One trailing blank line, if any, was removed
from the stdout log; all other bytes are preserved and the manifest hashes are
post-normalization.

## Scope and non-claims

Single Linux host, 3 mutual-TLS etcd members, 3 Patroni-managed PostgreSQL 17
nodes (`remote_apply`), one HAProxy stable endpoint, one Rootyard server. No
second physical host, hardware watchdog, power-loss, rack/zone, cross-host
storage fence, HAProxy HA, Kafka HA or Git-volume replication claim. #26/#43/#44
and roadmap #48 remain OPEN; PR62 closes no issue. The older `6f76d70` HA
metrics remain recorded in their own bundle/acceptance document and are not
overwritten here.
