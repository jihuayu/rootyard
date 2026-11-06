# Independent focused checks: issues #46 and #47

Both suites used `/workspace/shared/rootyard-acceptance-13b28dd`, SHA-256 `ec62504f2c699874fa78a336c9185aba75ade1969a029cabcd786a161a0a31b7`, with the shared live PostgreSQL 17 environment.

- `source /workspace/shared/rootyard-env.sh && python3 tests/organizations.py --binary /workspace/shared/rootyard-acceptance-13b28dd --report /workspace/shared/reviews/organizations-41-review.json` — PASS 2/2. Exercised organization/team inherited access across Git, LFS, Forge and workspace; namespace collision denial; immediate revocation; last-admin protection; and concurrent direct/team role revocation barriers.
- `source /workspace/shared/rootyard-env.sh && python3 tests/web_sessions.py --binary /workspace/shared/rootyard-acceptance-13b28dd --report /workspace/shared/reviews/web-sessions-41-review.json` — PASS 1/1. Exercised browser sign-in, authorized repository discovery, Issue and PR/merge workflow, API/Git credential separation, missing/foreign origin and missing CSRF denial, expiry/revocation, and sign-out.

These are focused native acceptance checks, not a review of every organization or browser route. No defect found in these runs.
