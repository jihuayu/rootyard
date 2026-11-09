# Paired PostgreSQL and Blob pack archive qualification

Candidate source: `1d1ce6276b806b0aa0fbf4fd5ae02050a6211bf0`.
Production inputs SHA-256: `941eccc8b92e792b723b1c65c02bcf396d12a49b64545140f72f99cf348a7053`.
Executable SHA-256: `bc0abc3ed0ac2c5690581480456532eca17ffbbcb5a2667d10e0a1366845c03b`.
`build.json` is the real clean native build receipt. This evidence commit changes
no production inputs.

## Behaviour

Offline format22 archives include the fresh PG RefStore pack/index closure,
not just locators. Backup takes the same database-wide exclusive advisory
barrier that standalone serving holds shared, then fixes one PostgreSQL
snapshot. A closed write cut, validated ConsumeAck/hold rows, physical backend
identity, checksummed bytes and bounded streamed immutable-row digests bind the
archive. Restoring into an empty database and absent data directory preserves
original immutable locators and ledger rows, verifies/rebuilds bytes at those
coordinates on the same physical backend, and keeps serving fenced until
publication and fsync finish. Losing the serving barrier stops admission and
the owned worker. A persistent database marker also blocks alternate data
paths during incomplete restore. No DDL or frozen catalog fixture changes.

Legacy format21 archives remain available for legacy repositories. Format22
currently rejects mixed legacy/PG repositories and does not remap to a different
Blob backend. Nonterminal writes and unsupported/missing backend configuration
are refused. Physical product GC remains disabled.

## Actual verification

- Seven real PG17.11/Garage2.1 paired archive cases passed, zero skips. These
  cover SHA-1/SHA-256 pushes without persistent bare storage, lost serving
  barriers, offline/snapshot barriers, six damaged archives refused before SQL,
  existing-target refusal, exclusion of a post-backup ACK, deleting every exact
  original pack/index object before fresh restore, authenticated clone/content/
  refs/fsck, and exact receive replay without another ledger effect.
- Existing standalone history (7), HTTP/Git (11) and tree/blob (7) cases passed,
  zero skips. Together with the paired archive suite, 32 native cases use the
  identical executable hash above. History/HTTP/paired reports retain their
  honest original source commit `4c4abe1`; subsequent commits changed only tests,
  workflow and evidence. The clean final build is byte-identical and has the
  same production input hash. Final browse ran against clean `1d1ce62`.
- Legacy format21 backup/restore: seven cases passed. This includes interrupted
  restore handling, corruption/barrier refusals and fresh clone verification.
- Rust library: 464 passed, nine existing service-dependent tests ignored.
  Strict all-target minimal-profile Clippy and formatting passed.
- Python suite: 336 tests, 331 passed and five skipped. Three S3-dependent
  workspace cases were then run against the owned live Garage fixture and all
  passed (`s3-supplement.log`); the two remaining cgroup entrypoint cases require
  their separate native preflight and are not claimed here.
- All 591 explicitly labelled reference-model cases passed after the merged
  route audit and lifecycle/catalog wiring updates. They are not native proof.
- The real database guard/auto-start probe passed (`database-guard.json`).

The complete RefStore integration-service suite is not claimed by the nine
ignored library tests. Existing protocol CI owns those separate checks.

## Review and retained failures

Development and separate source review used the official DeepSeek dsh CLI via
[jihuayu/skills deepseek-subagent](https://github.com/jihuayu/skills/tree/main/deepseek-subagent).
Root checked findings against real source and PostgreSQL behaviour, rejected
unsubstantiated findings, corrected actual errors and ran every recorded gate.
The final scoped review found no confirmed format22 restore/replay blocker.
Review itself did not execute the tests. Private connection settings and model
session state are excluded.

Failed paired runs are retained in `failed-attempts/`: v1 missed intermediate
private directories, v2 omitted Blob inventory before full comparison, and v3
counted directories as artifacts at import completion. All were fixed before
the passing v4. The earlier browse receipt refusal executed zero cases after
a test-only commit changed the candidate head; final browse used a fresh clean
receipt. Failures were not reclassified as passes.

## Limits

This is fresh PG pack-closure qualification for format22/schema147 on the same
physical Blob backend. Full LFS, workspace/checkpoint closure, legacy upgrades,
interrupted format22 restore recovery, HA, multi-host failure, physical
power-loss and production RPO/RTO qualification remain. The generic legacy21
interruption drill does not prove interruption recovery for format22. It does
not complete issue #120. A legacy Pando-stage timeout-window inconsistency is
outside this change and has not been presented as fixed. Nothing is merged or
released by this evidence.
