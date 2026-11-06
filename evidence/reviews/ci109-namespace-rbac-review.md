# Independent CI service principal and namespace RBAC review

## Source and evidence

Reviewed the native integration source in `/workspace/rootyard` through integration commit `82e8fdf`. The binary used for the completed focused runs was SHA-256 `f1e5f82640e5c3c5e9a058a07de00df68a32cdbd88d08e8e9ee4f6db2bf13489`; it predates the `ci_pull_sync_progress` table present in current source, so it is not a current-source acceptance build.

- `tests/ci_source_pins.py --binary /tmp/rootyard-review-ci-6c30bc3 --report /workspace/shared/reviews/ci-source-pins-recheck.json` — PASS, 16 cases. Covers exact CI retention refs, authorization, collisions, push rejection, immutable replay/recovery, generation fences, and offline publication boundaries.
- `tests/organizations.py --binary /tmp/rootyard-review-ci-6c30bc3 --report /workspace/shared/reviews/organizations-recheck.json` — PASS, direct role and team-role row-lock barriers plus inherited capabilities.
- `tests/transfer_revocation.py --binary /tmp/rootyard-review-ci-6c30bc3 --report /workspace/shared/reviews/transfer-revocation-recheck.json` — PASS. Revoking a human token and cancelling a CI checkout stopped native primary/mirror transfers in about 1.05s after 266,240 and 200,704 bytes, respectively.
- `tests/ci_runs_regressions.py` — partial on the stale binary: service principal creation, forged outbox ref rejection, invalid operation rejection, direct trusted-context impersonation denial, run fencing/idempotent report, and new-run polling passed; the final recovery step failed because this binary's migration 109 predates `ci_pull_sync_progress`. A fresh isolated schema confirmed migration version 109 existed while that relation was absent. Rerun after the provenance-matched rebuild.

## Findings

The direct namespace role-revocation barriers passed on rerun; the prior one-off failure did not reproduce. The active transfer recheck works for both ordinary token revocation and CI grant cancellation. The SQL service-principal test rejected both an arbitrary ref event and a service operation missing its typed intent before reaching the stale-schema failure.

Do not cite the `ci_runs_regressions.py` run as complete until rebuilt. The f1e5 binary lacked a relation now defined in source `migrations/109_ci_integration_jobs.sql`, demonstrating the need to bind acceptance results to the refreshed build receipt.
