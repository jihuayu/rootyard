# Native sharding CI contract correction (#134)

The previous native metadata drill used ordinary tokens for operator-only
controls and expected simulated transfer/failover/benchmark inputs to confer
real data authority. The service correctly refused those requests. DeepSeek
subagents corrected the native fixtures; production authorization and data
fencing code are unchanged. The separately selected reference model is intact.

- Twelve real HTTP/PostgreSQL sharding cases passed at `926264e`, including
  valid-payload ordinary/readonly/repo-admin/outsider denials, explicit operator
  grants, operator-without-repository-access denial, unused-bucket placement,
  occupied-placement refusal, server-clock lease TTLs, epoch fencing,
  degradation/recovery and exact refusal of unmeasured takeover/DR/transfer.
- Five real HTTP/PostgreSQL benchmark metadata cases passed at `bb67e8f`.
  Receipts must say `simulation_only`, with pinned-root/failover verification
  false and simulation-only Markdown. The historical case method names are
  retained; they are not measurements of real 1/2/4-node capacity or failover.
- Selected source/unit suites ran286 with no failures/errors and six existing
  skips; dedicated native/service/kernel exclusions remain explicit in the report.
- Luna Max found no P1/P2 in the scoped fixture changes. Its lease-tolerance
  finding was fixed: both60s and300s renewals must be within5s of server-clock
  expectations, and the complete twelve-case native suite was rerun.

The executed application is source-bound `0bb2b6c`, SHA-256
`d19daacca4629e60d1109ccb36bcc883c792155b91367d71715e23be98b7fbe2`.
It includes PR135's additional unserved schema139 metadata core. This is not
a claimed rebuild of the entire common branch: the unchanged auth/sharding
paths are exercised by the new native fixtures, and both checkout identities
and the application build receipt are retained. Application, compiled inputs,
fixture/imported-file hashes, driver and checkout heads matched before/after
each accepted run. Root ran verification; no agent claimed unexecuted native work.

`history/` retains the first occupied-bucket409 failure and the later incorrectly
correlated SQL alias failure. The candidate bucket column was then explicitly
qualified. They are failed fixture runs, not qualified passes. Raw reports and
exact commands are beside this file; private fixture credentials are excluded.

CI step labels now describe control-plane guards and simulation metadata.
`production_validation`, `multi_node_ha_validation` and
`data_plane_success_claimed` stay false. Actual transfer/recovery remains the
separate native cluster workload/migration qualification, with physical
#26/#43/#44 boundaries unchanged. Full remoteCI remains pending; #134 stays
open under the maintainer's merge-and-acceptance closure rule.
