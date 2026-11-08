# PostgreSQL RefStore metadata core: executed evidence

This is an internal, unserved increment toward #107/#105. Real DeepSeek
subagents implemented the core and test fixtures; Luna Max reviewed the
transaction/budget/fence/deadline and backup boundaries; root integrated and
executed qualification. It does not activate a serving backend.

Application and library qualification uses clean source
`0bb2b6c8c6587d6f3a88100d309bb98126d833f1`. The application SHA-256 is
`d19daacca4629e60d1109ccb36bcc883c792155b91367d71715e23be98b7fbe2`.
Build receipts retain the actual Cargo commands, input hashes and Fresh=false
artifacts. Subsequent evidence-only commits do not relabel those receipts.

| Executed check | Result | Evidence |
| --- | --- | --- |
| Real PostgreSQL metadata-core contract | 12 passed, 0 failed, 0 ignored | `core-12-pg.json`, `core-12-pg.log` |
| Library, pando-lab | 281 passed, 8 existing service-dependent ignored | `library.json`, `library.log` |
| Selected Python source/unit suites | 286 run, no failures/errors, 6 existing skips | `source-units.json`, `source-units.log` |
| Actual binary schema139 migration | Fresh, dump/restore, restored003/006/007 upgrades, upgraded roundtrip, custom search_path and idempotence passed; 93 tables / 16 functions / 36 triggers | `binary-schema139.json` |
| Nonempty format15 backup and fresh restore | All 7 native cases passed | `backup15-populated.json`, `.log` |
| Genuine format14/schema138 archive upgrade | All 7 native cases passed | `legacy-format14.json`, `.log`, `legacy-producer.build.json` |
| All-target pando-lab Clippy, warnings denied | Passed | `clippy.log`, `checks.json` |
| Formatting and diff whitespace | Passed | `checks.json` |

The 12 PostgreSQL cases include real gate-lock synchronization between two
connections, immutable replay/digest conflict, cancellation before registration,
atomic multi-ref rejection, HEAD/format/tenant/epoch/history/prefix checks,
rollback after a body error, aggregate terminal budget rejection before writes,
authority changes, queued BEGIN expiry and deferred-trigger COMMIT timeout
followed by same-identity query/retry. A sent COMMIT can be unknown; the test
does not turn that into a claimed rollback.

The integration executable was freshly compiled at `58c22ea`, SHA-256
`6078da4cecfca970a26d3f1026e6ed993f924f1d72190b14ff1dec5d566ed147`.
The later `0bb2b6c` changes only two Python files. Before and after the accepted
run, all compiled inputs and the explicit integration-test source matched that
original build receipt, and the tested checkout stayed fixed. Both commits are
recorded; this is source equivalence, not a claimed rebuild at the later commit.

The backup15 fixture directly seeds SQL metadata on a distinct provisioning
GitFS repository. Gate/ref/event/operation/cancellation/lane tables are all
nonempty. It compares exact global and fixture-scoped rows, timestamps and the
whole repository row after actual offline backup/fresh restore; rejected
terminal/event/cancellation updates leave the rows unchanged. The repository
remains unserved, without a bare directory, Pando authority or legacy ref
projection. This proves metadata preservation, not an adapter or protocol ACK;
the separate PostgreSQL cases test the adapter. JSON timestamp comparisons use
UTC. Encoded credentials/URI-option portability is an inherited harness limit.

The legacy producer is the unmodified, source-bound schema138 executable with
SHA-256 `9f861ff7b098836fc9b80bba945545c4e9b2fb1e78fe5136c76c316a91fda8db`.
It creates a genuine format14 archive. The candidate rejects missing, wrong or
mixed opt-ins, then explicitly upgrades with `--allow-legacy-schema138` and
checks new core tables/constraints, authority rotation, Git clone/fsck and
session/access boundaries. Its source has no core rows; this is not a nonempty
core-data roundtrip. The independent format15 fixture provides that proof.

`history/` retains failed runs: two initial test defects (wrong cancellation
table name and a missed durable rejection event), an ENOSPC run, the run made
while fixtures had not restarted after environment recovery, and the exact-FK
inventory failure. None is counted as qualification. The successful retry
used restored task-owned services and sufficient disk space. A restarted dev
Vault was bootstrapped only for fresh synthetic objects; its restart is not
key durability evidence. Qualified binaries are retained locally as verified
gzip artifacts rather than committed to Git.

Reproduction needs dedicated synthetic PostgreSQL17 with CREATEDB, a real S3
fixture and a dev Vault for legacy Pando archive fixtures, with credentials
injected privately. Select the ignored core suite explicitly; a default run
that ignores it is not a pass. The exact root-runner scripts are included for
provenance; their local paths must be adapted to another checkout.

```sh
python3 tests/schema_contract.py --binary /absolute/qualified/rootyard
python3 tests/backup_refstore_core139.py --binary /absolute/qualified/rootyard --report /absolute/report15.json
python3 tests/backup_legacy138_core.py --binary /absolute/qualified/rootyard --legacy-binary /absolute/trusted/schema138-rootyard --report /absolute/report14.json
```

No HTTP activation/cutover, Blob membership, snapshot pins, roots, holds,
decision bridge, Raft or GC integration is qualified here. Existing legacy
authorities remain in use. #107/#105 stay open. Full dependency-stack CI is
separately blocked by Sharding fixture issue #134; its Browse step passed.
One physical loopback host is not power-loss, production HA, latency or RPO/RTO
qualification. No new MSRV1.88 or Azure runtime qualification is claimed.
