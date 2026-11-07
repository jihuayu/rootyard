# Independent Final Acceptance Review - Round 4 Integrated

**Verdict: APPROVED**  
**Coordinator state: passed / complete - 11/11 jobs passed, all exit 0. No P1 blocker. PENDING not applicable.**

## Exact candidate and artifacts

| Item | Value |
|---|---|
| Candidate source | `4c5bcfe56516434ea5b42985e9af90a8c1efe51f` |
| Compiled source | `4c5bcfe56516434ea5b42985e9af90a8c1efe51f` (HEAD, clean) |
| Baseline | `a91c93f` origin/main (`a91c93f3a63914c8416fa96c653f5d28212af785`) |
| Binary SHA-256 | `c0049c3a4a97543cfe95a5deccc80b1404cc3b7f5a3eff2ad54acb9be0de1f45` |
| Production-inputs canonical SHA-256 | `8f399a064af9701de018bad5d527cd652767f03131a96affde8582fb6aac0034` |
| Production-inputs file SHA-256 | `e67ed362bbc8d621d9e92ae34e92fc20c16096674bed0b39cf60d65871aea7db` |
| Production files | 331; 4 changed vs a91 main: `src/web/handlers.rs`, `src/web/session.rs`, `src/lfs/publication.rs`, `src/lfs/storage.rs` |
| DDL/schema | No migration/schema diff. Actual schema max 132; backup manifest format 8; restore compared versions through 132. |

Canonical production map recomputed from HEAD equals `production-inputs.json`; build inputs before/after are identical. The task hypothesis of 3 production paths is not exact: the map shows 4 changed files inside the 3 intended areas (browser handlers/session and LFS publication/storage), with no unexpected path.

## Final job results

| Job | Exit | Result | Evidence |
|---|---:|---|---|
| sessions | 0 | passed | 1/1 case |
| chromium | 0 | passed | 1/1 real Chromium workflow |
| lfs | 0 | passed | 10/10 cases |
| lfs-publication | 0 | passed | 2/2 cases; 4 publication paths |
| lfs-retention | 0 | passed | 3/3 cases; native ShareLock + 4000 files |
| lfs-remote | 0 | passed | 1/1 stock LFS second-node recovery |
| lfs-hydration | 0 | passed | 1/1 concurrent 8 MiB Garage hydration |
| backup-capabilities | 0 | passed | 1/1 format 8, schema 132 restore |
| webhook-regressions | 0 | passed | 4 named stdout checks; manual POST `/webhooks/dispatch` used; no JSON report |
| webhook-worker | 0 | passed | 5/5 native worker cases |
| rust-lib | 0 | passed | 145 passed, 0 failed, 0 ignored |

Totals: 11/11 jobs passed; 9/9 JSON reports passed; 25 report cases passed; 145 Rust lib tests passed; 170 reported test cases passed. 11/11 DB-backed jobs cleaned up `dropped_after_success`. All 10 harness hashes and all 9 report hashes match the coordinator records; all reports carry the certified binary SHA-256. Manual vs automatic proof split preserved: webhook-regressions uses explicit manual `POST /webhooks/dispatch`; webhook-worker proves automatic worker delivery/retry with `manual_dispatch_calls=0`.

## Acceptance criteria

### #39 - Store and recover LFS objects through remote object storage: CLOSABLE

- Real stock `git-lfs` upload, destruction of the entire source data directory, second-process/second-node restart, and clone with exact bytes.
- Remote-only pointer push was validated and hydrated from remote bytes by the native hook.
- Failed, duplicate, interrupted-first and permission-removed uploads preserved the successful object digest; retry became ready without deleting committed bytes.
- Offline paired backup/restore preserved LFS bytes and locks; remote LFS hydrated without the target endpoint; organization RBAC survived.

### #40 - Validate new Git LFS pointers before publishing refs: CLOSABLE

- 12 missing/wrong-size/corrupt pointer kinds rejected before any ref move across smart HTTP receive, atomic smart HTTP receive, direct ref transaction and PR merge.
- 12 bad/missing/wrong-size/corrupt pointer cases were server-rejected; 18 official git-lfs 3.6.1 client probes matched 18 expected accepted/rejected shapes. Invalid header/scheme client-negative forms remain ordinary server content and are not claimed as server-rejected.
- Atomic multi-ref push, non-LFS push and retained history/tag stayed compatible.
- Real `gitfs_stage_cleanup` job ran during native pointer publication; native backend held `rootyard-data-v1` ShareLock with `application_name=rootyard`; 4000 stale staging files were untouched until release and then cleaned.

### #47 - Browser sign-in/sign-out and revocable Web UI sessions: CLOSABLE

- Real `/usr/bin/chromium` 155.0.8059.79 workflow: login, repository discovery, Issue creation, PR creation/merge, logout, old cookie rejected with 401.
- Expired/revoked sessions, parent-token expiry/revocation, cross-origin mutation and CSRF failures were rejected; secrets did not appear in URL or page source.
- Git and API token authentication remained independent; explicit API Authorization took precedence over stale cookies without creating a browser bypass.
- After offline restore, old browser sessions returned 401 while API/repository RBAC still worked.

## Blockers vs residual P2

**P0/P1/acceptance blockers: none.**

Residual P2/limits preserved:

- **pointer-nonutf8-bounded** (#40): Invalid UTF-8 tail/field/oid is ordinary bounded behaviour: actual installed git-lfs --check exits 1 for all such inputs (not a valid client pointer); preserved residual, not a new valid-pointer bypass.
- **pointer-normalizer-dedup-3p2** (#40): Three P2 pointer-normalizer dedup findings accepted in prior independent pointer-delta review; not new blockers.
- **browser-parent-revocation-inflight** (#47): Parent-token revocation is checked on new requests only; an already-admitted in-flight write may finish. Documented as separate accepted #37 P2.
- **adapter-atomic-baseline-not-truncate-fix** (#39/#40): Adapter was already atomic on the old 8 MiB baseline (PASSED). This round adds caller staging 0600-before-rename hardening, not a truncate fix; do not claim a truncate repair.
- **no-object-delete-api** (#39/#40): No LFS object-delete/GC API; retention is asserted against failed uploads and role removal, and the race is against staging cleanup.
- **no-physical-ha-vendor-claim** (scope): Loopback single-node backup has no hardware-failure guarantee; no vendor or physical-HA claim.
- **no-pando-native-gate-runtime** (scope): No Pando-native gate/runtime in this round; the same gate call is source-verified only.
- **ordinary-ci-not-wired** (CI): User ignores ordinary CI; the new harness is not wired into CI and is non-blocking for this acceptance.

## Evidence integrity and scope

- Primary-consistency record: `/workspace/scratch/rootyard-round4/integrated/primary-consistency.json` (SHA-256 `1aaa091ae32bfaea989569267eef0471a86bc1c7a153c2077f9366b50b1f2189`). Primary independently rehashed the binary, all 331 production inputs, all harness hashes, all 9 report hashes and DB cleanup, and scanned for private-key/token markers.
- This review independently rehashed the binary, canonical production map, all 10 harness files and all 9 report files; results match.
- Prior independent source reviews reused: web47 delta (accepted, no P1), lfs39 native lease (B2 closed, real native holder, raw gc17), lfs-hydration storage hardening (869 accepted), pointer normalizer dedup (78 accepted, 3 P2).
- Review was read-only: no repository edits, builds, tests or network. Source acceptance only; publisher performs later docs/facts review. No mass close of other issues.
- No physical-HA/vendor claim; no Pando-native gate/runtime in this round; no object-delete API claim; ordinary CI ignored and new harness not wired into CI.
