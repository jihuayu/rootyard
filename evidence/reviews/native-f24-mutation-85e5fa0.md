# Native F24 mutation check — baseline 85e5fa0

The mutations were built in detached worktree `/workspace/rootyard-review-mutation` with `CARGO_TARGET_DIR=/workspace/rootyard-review-mutation-target`. No mutation was committed.

## Results

1. A first mutation changed only `auth::writable` to return `Ok(())`. Binary SHA-256: `df97599500fe80be311a77375cfe1c0e3ce7b07f967bad63630748d5f396dca8`. The native F24 `members` dispatcher and native `tests/pulls.py` both passed. This did not change effective authorization because `authorize_repo_with_role` also calls `verify_token(..., true)`, which independently rejects read-only tokens.
2. An observable regression mutation changed `members::rbac::resolve_effective_role` to return `Role::Admin` for every user. Binary SHA-256: `6052fbeb11313d56baeb96d3f3fb58e63209004124a4eaf21033315b67aea2c6`.
   - `python3 tests/members.py --binary <mutant> --case access_and_boundaries --report ...` (real PostgreSQL 17 + Rust service) failed in the named case: `/api/repos/alice/forge/collaborators` expected 404 for non-member Dave, got 200.
   - `python3 tests/e2e_tiers.py --feature F24 --binary <mutant> --report ...` from isolated commit `5184559` exited 1 and reported `native members: FAILED`; the live suite failed at `collaborators_and_5_role_hierarchy` because Bob's PR creation expected 403 and got 201. This is a service-backed regression failure, not a reference-model result.

The parent integration worktree could not run the dispatcher while its schema-baseline conflict was in progress (missing `schema/110_catalog.json`); using a detached `5184559` snapshot avoided that unrelated issue.
