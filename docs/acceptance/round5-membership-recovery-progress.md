# Historical receipt projection after membership withdrawal

Issue #98: a real native Git receive can commit before SQL settlement and before
an owner removes the actor's collaborator or organization membership. Recovery
must project that already-finished operation without authorizing a new write.

Migration 137 permits the narrow human Git projection tied to the same terminal
admission, repository, actor and token. A first projection requires the current
repository generation; replay must retain the existing operation identity.
Historical UPDATE preserves creation time, and a terminal row also preserves
outcome, evidence and settlement time. Forge author checks and the CI principal
branch retain their existing rules. Journal authenticity and generation/fence
checks remain in Rust; the admission ledger does not store a generation or
independently authenticate a receipt.

Real acceptance for source `46503e6` used binary SHA-256
`4990a6db38201773b67276a1dd6c04eba2611cd3ba7ba330a64bd08520d6e52a`,
compiled-input digest
`5ba26c9874b0f37867684c0a7f11c4dd59e3dcc2173e48cd1b414a89c27da9b5`:

- Five native stages passed, including real collaborator and organization-member
  withdrawal, recovery from retained native journals, denial of new pushes,
  exact terminal replay and SQLSTATE-23514 negative cases.
- The evidence-immutability negative failed against the preceding candidate
  `46af460d135986414decdc5935d6009135ff2526dbc0a2211a9d26c2aa48a4c4`.
  Its report is retained alongside the passing result.
- Seven genuine format12/schema136 archive stages passed. The independent
  schema136 producer had SHA-256
  `c4d0ef514e45682b6bc554cc137630b720ea3bb39d12499458dbd15169f42d7d`;
  its archive was never edited. Restore required the explicit schema136 opt-in,
  upgraded to schema137 under one new authority, preserved Git/session
  boundaries and left the source authority and objects intact.
- Real PostgreSQL catalog checks passed from both SQL and the built executable,
  including fresh and restored003/006/007 upgrade paths and round trips.
- All-target Clippy passed before the SQL-only immutability correction. The
  corrected executable subsequently built successfully. Luna Max reviewed the
  corrected SQL and Rust boundary and found no remaining P1/P2.

The later token-management parent merge at `985cb21` changed documentation only;
its compiled-input digest was explicitly checked against the accepted binary
and is identical. CI integration is a separate gate. The current-format full
backup/restore drill also passed all seven stages, including unsafe input
rejection, backup barriers, interrupted restore protection, snapshot boundaries
and authenticated clone/fsck after fresh restore.

Receipts are in `round5-membership-recovery-evidence/`. These are functional
loopback tests, not power-loss or production RPO/RTO qualification. No issue is
closed and no release or deployment is claimed by this record.
