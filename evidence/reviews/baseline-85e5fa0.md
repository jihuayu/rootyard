# Independent baseline review — 85e5fa0

Scope: registered issues #2–47; initial audit focused on test integrity (#10), live evidence, and cross-cutting correctness/security acceptance. This is a baseline snapshot, not a completion sign-off.

## Tests actually run

- `python3 tests/e2e_tiers.py --feature F24 --binary /tmp/rootyard-review-nonexistent-binary --report /tmp/rootyard-review-model-only.json -v` (from review worktree). Exit 0; 19/19 passed, 0 skipped, 1.825s. The target path did not exist.
- `source /workspace/shared/rootyard-env.sh; python3 tests/members.py --binary /workspace/rootyard/target/debug/rootyard --report /tmp/rootyard-review-members-baseline.json`. Exit 0 against PostgreSQL 17 and native Rust binary SHA-256 `cb5837964c5d53a66dc073282333cede28e74213d3a32d63c4c385e5054a857f`; all nine live cases passed, including schema migration, RBAC, audit pagination, concurrent writes/idempotency, and server restart. This exercises `tests/members.py` from this commit against its isolated non-public schema.

## Findings

- **#10 remains open at baseline.** `e2e_tiers.py` accepts `--binary` but does not read `args.binary`; it builds/runs its Python reference engines. A nonexistent binary still gives a green 19-test report. That report cannot be accepted as Rust service evidence.
- **#6 and #11 appear fixed before this baseline, with live evidence above.** Commit `014c528` changed schema detection to search-path-relative `to_regclass` and repaired the members harness argument wiring. Do not count these as newly implemented work or claim broader role behavior from a smoke test; the run did exercise the named live suite.
- **Mapping rule for #10:** GitHub issue numbers must map to explicit service harness cases and acceptance IDs. The original `F##` labels in `e2e_tiers.py` refer to feature-inventory IDs, not registered GitHub issue numbers; e.g. feature F24 means RBAC, whereas issue #24 is shard request routing. Passing a generic service smoke or unrelated suite must not produce an issue-level pass.
- **Evidence rule for #45/#44 and distributed claims:** source inspection, reference-model tests, synthetic benchmark values, readiness health checks, or caller-supplied receipts do not complete these requirements. The issue acceptance calls for actual clients/processes/database/repository bytes and retained evidence with versions, binary identity, topology/workload, and observed refs/content/fsck. Limit claims to what each run actually exercised.
- **Security regression paths to require in review:** #2 needs parent-component and external-target symlink cases with unchanged lower/external bytes and modes (and race-resistant traversal); #12 must cover personal tokens across repository roles plus operator access and the repository-admin-to-global-node fencing path; #18 must exercise stock Git push plus ref transaction for non-FF, protected deletion and required checks/approvals; #40 must gate every publication path and cover LFS ready/missing/wrong-size and concurrent cleanup.

## Status

#10 baseline: failing acceptance gate, independently reproduced. #6/#11: live suite passed on baseline; retain as already addressed. Other issues remain subject to per-batch review; no completeness claim is made from this audit.
