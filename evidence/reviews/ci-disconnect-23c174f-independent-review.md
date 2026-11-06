# CI disconnect and cancellation gate review

Reviewed commit `23c174fc12e9a8ee6df837880a956ef09b82841b` in `/workspace/rootyard-workspace-ci`.

The commit moves CI checkout preparation into a detached task after persisting the `queued` row, claims preparation with a conditional `queued -> preparing` update, and allows a retry to spawn preparation only while that row remains queued. Duplicate tasks race on the state CAS. It also serializes the final start gate against cancellation: `open_start_gate` locks the job row `FOR UPDATE`, verifies it remains running, locks/rechecks the full CI authority tuple (or workspace lease), writes the gate file, then commits. The cancel route's update must wait on that row lock, so it cannot commit cancellation before a previously-started gate transition. On preparation errors, the owned task retries the terminal DB update until acknowledged; if the row has already been cancelled, the conditional update succeeds with zero rows and stops.

Independent native test run:

```
source /workspace/shared/rootyard-env.sh
ROOTYARD_BINARY=/workspace/rootyard-workspace-ci/target/debug/rootyard python3 -m unittest tests.test_ci_sandbox -v
```

PASS: `Ran 1 test in 9.966s; OK`. This exercised the real Rust service with PostgreSQL, the signed CI claim and exact origin checkout, disconnect after persisted queued/preparing row followed by signed retry and successful GCC build, then the deterministic 750ms post-registration pause, cancel, and assertion that the payload marker did not execute. The tested binary SHA-256 was `1f794645a84d59d6b3e2b8744d8b2f0e5cd00cd64b5f815360eee348eac5b3ee`; it was built at 08:24:08Z after commit `23c174f` at 08:23:13Z. It predates unrelated uncommitted source-read edits now visible in the worktree.

Review conclusion: the disconnect recovery and cancellation/start gate fix pass independently. The one-shot error update is replaced by retry-until-acknowledged. This test does not cover hard process crash during `preparing`; startup reconciliation remains responsible for abandoned rows.
