# Cluster local profile independent review

Reviewed commits: `ffec1ed28835ee8f9d94a9340ea7ff782d0fae13` and `c8406cbeef618e429c8bc4bbdba5b18bb25bc580` in `/workspace/rootyard-cluster`.

The reported native acceptance evidence in `evidence/cluster-local-profile.json` binds binary SHA-256 `27203db5f8f6cac103ef61e06867b205f718b4325a98367c3cc15769e24d6b70` and launcher SHA-256 `3facd3b64c0b1a52d46ec30c44cc15707953bd800d598fd2d2f7bf337c3be0d6`. It reports two Rust nodes, distinct PostgreSQL/Kafka roles, TLS/SCRAM PostgreSQL, Kafka 4.4 SASL/PLAIN over TLS, a successful wrong-password rejection followed by retry, equal pushed/cloned/browsed OIDs, and Kafka offset 0→1. I inspected the committed launcher and test; I did not rerun the full Kafka/PostgreSQL profile suite in this review.

## Finding: shutdown can leave same-session children alive

`deployment/local_cluster.py:184-199` sends SIGTERM to each process group and then waits only for the recorded session leaders. It sends SIGKILL only if a leader still matches. A leader can exit on SIGTERM while a child in the same session ignores SIGTERM; then the wait loop considers the group finished and never escalates to SIGKILL. `run_down` removes the manifest after this call, so that surviving process becomes untracked.

Independent reproduction imported `stop_entries`, started a new-session bash leader with a same-session `sleep` child ignoring SIGTERM, and passed the leader's `proc_identity` to `stop_entries`. Result: `child_alive_after_stop_entries True`. I manually killed the test child after observing the defect. This is an operational cleanup defect; fix group quiescence/escalation independent of leader lifetime and add a regression with a stubborn child.

## Finding: environment validation helper is unused

`validate_env` at line 68 checks the required SASL_SSL/PLAIN settings, safely serializable SASL username/password, and HMAC key encoding/length. There are no call sites (`rg validate_env` finds only its definition). `_run_up` calls `pg_preflight` and then `kafka_preflight`, which hardcodes SASL_SSL/PLAIN while writing the credential fields directly into JAAS properties; it never validates the configured wake protocol/mechanism, HMAC key, or JAAS-safe credential characters before running migrations and starting services. Misconfiguration therefore passes preflight and fails later after partial setup, while characters rejected by the intended validator are accepted by this launcher. Call the helper on each role environment and add preflight rejection coverage.

## Review status

Not ready for approval pending process-group cleanup fix. `c8406cb` does correct same-node-count failed preflight cleanup and its report/test covers wrong Kafka password → no remaining `.kafka.properties` → corrected retry; cross-node-count stale preflight cleanup was not covered. Scope remains single-host local profile; no cross-host HA claim.

## Re-review of `7c048c6`

Reviewed follow-up `7c048c677b88cc1ff58d7b8829205d7c5eb3e733`. Both findings above are fixed in source: `_run_up` calls `validate_env` for each data/worker role before migration, and `stop_entries` scans the whole recorded session (including separate process groups), escalates TERM to KILL, waits for quiescence, and retains the manifest on uncertainty. The native test adds a SIGTERM-ignoring descendant regression. I independently reran the descendant test and invalid Kafka protocol rejection; both passed.

I also reran full native acceptance with actual PostgreSQL 17 TLS/SCRAM, official Kafka 4.4 SASL_SSL, and the two Rust service processes:

```
source /workspace/shared/rootyard-env.sh
python3 tests/cluster_local_profile_native.py --binary target-cluster/debug/rootyard --kafka-home .profile-deps/kafka_2.13-4.4.0 --report /workspace/shared/reviews/cluster-local-profile-7c048c6-independent.json
```

PASS. Independent report is `/workspace/shared/reviews/cluster-local-profile-7c048c6-independent.json`; it records matching launcher hash `1d8096be2c44096da540c4323454d3c9d3e6a29e52e7905ea9b615c9b8d00390`, binary hash `02a4b3d5f78ca05c136e869c0469dfbb0a27f05c58c6f9686db62adc03fb2e25`, rejected wrong Kafka password before process start and cleaned preflight property files, successful retry, equal push/owner-clone/routed-browse OIDs, Kafka offset 0→1, and resistant descendant cleanup. The target binary path has since changed to SHA `be6c3730…`; this review’s report preserves the binary SHA observed by the profile run. The profile remains limited to one trusted Linux host and does not establish cross-host HA.

Status: profile shutdown and environment-validation findings are addressed; independent full native profile pass. Cross-node-count stale preflight artifacts after an abrupt launcher kill remain untested; files stay under the required 0700 state directory.
