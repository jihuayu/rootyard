# Round-4 issues #39 / #40 / #47 acceptance — remote LFS durability, pointer validation, revocable browser sessions

**Verdict:** native **PASSED** (11/11 coordinator jobs exit 0), independent final
acceptance review **APPROVED** with 0 P1 and 0 acceptance blockers. Criteria
**#39, #40 and #47 are close-eligible after the primary's final publication
review and the upcoming PR merge**. The primary owns push, PR, merge and
closure; this document closes nothing.

**Identity:** candidate HEAD = compiled source
`4c5bcfe56516434ea5b42985e9af90a8c1efe51f`, base main `a91c93f`
(`a91c93f3a63914c8416fa96c653f5d28212af785`), immutable local binary
`c0049c3a4a97543cfe95a5deccc80b1404cc3b7f5a3eff2ad54acb9be0de1f45`, production
input `8f399a064af9701de018bad5d527cd652767f03131a96affde8582fb6aac0034`
(331 files, recomputed equal during publication). Four production files changed
vs `a91` main in three intended areas — `src/web/handlers.rs` and
`src/web/session.rs` (browser), `src/lfs/publication.rs` and `src/lfs/storage.rs`
(LFS) — with **no** migration, DDL or schema change: actual schema max **132**,
backup manifest format **8**.

**Actual runs** (`evidence/round4/browser-lfs-4c5bcfe` bundle,
`state=passed`, `stage=complete`, all 11 disposable databases dropped): 11 job
groups, 10 with JSON reports plus one stdout-only regression job. Counts are
kept apart — **145** Rust unit tests (`cargo test --locked --lib`) and **25**
cases across the **9** JSON reports; the "170" total is their sum, not 170
end-to-end scenarios.

| Job | Result |
| --- | --- |
| `sessions` / `chromium` | 1/1 browser-session case; 1/1 real `/usr/bin/chromium` 155.0.8059.79 sign-in → discovery → Issue → PR → merge → logout → old cookie 401 |
| `lfs` | 10/10: streaming upload/download, hash+size rejection, tenant isolation, revocation, stalled-body deadline, stock locks, corrupted blob fail-closed, offline paired backup/restore |
| `lfs-publication` | 2/2: 18 official `git-lfs/3.6.1` client probes matched; 12 bad pointer kinds rejected across 4 publication paths (48 combinations) before any ref move; 4 valid variants published |
| `lfs-retention` | 3/3: failed/duplicate/interrupted first upload, role removal + re-grant, 4000 real `gitfs_stage_cleanup` deletions blocked by the native data `ShareLock` |
| `lfs-remote` | 1/1: stock `git-lfs` + real Garage, source `DATA_DIR` fully removed, second process/new `DATA_DIR` downloaded exact 1 MiB bytes over shared PostgreSQL |
| `lfs-hydration` | 1/1: concurrent 8 MiB cold hydration, `0600` before final rename, no staging leftovers |
| `backup-capabilities` | 1/1: fresh database+volume restore, format 8 / schema 132 versions compared to the manifest, LFS bytes and locks preserved, remote LFS hydrated with the target endpoint absent, old browser session revoked |
| `webhook-regressions` / `webhook-worker` | 4 manual-dispatch stdout checks / 5 automatic-worker cases with `manual_dispatch_calls=0`; both rerun on `c0049c3a…` |

**#39 — remote LFS.** Uploads stream to the configured S3-compatible store
before metadata becomes `ready`; serving verifies the local copy and hydrates
from the remote object when it is missing. The accepted recovery mode is one
physical host with a real Garage backend and shared PostgreSQL: after the source
data directory is removed entirely, a second process with a new directory
downloads the exact bytes, and a remote-only pointer push is hydrated by the
native hook. A current paired backup (format 8, schema through 132) inventories
every ready object and hydrates missing local copies before publication; the
restored target serves those bytes with **no** object-store endpoint
configured. There is **no** LFS object-delete or GC API, so committed objects are
retained indefinitely and no vendor, cloud, multi-host or production-HA claim is
made.

**#40 — pointer validation.** Newly reachable pointer blobs are validated before
the ref moves on all four publication paths (smart HTTP receive, atomic smart
HTTP receive, ref transaction, PR merge). Normalization covers the official
client's LF **and** CRLF forms, leading Unicode whitespace/NBSP, the legacy
`https://hawser.github.com/spec/v1` header and the legacy
`http://git-media.io/v/2` header, and every distinct `(OID, promised size)` pair
is validated, so a good blob sharing an OID with a wrong promised size fails in
either order. Bounds are unchanged: ≤1024 raw bytes per candidate blob, 4096
small blobs, 20000 newly reachable objects, 512 MiB default verification budget
(8 GiB maximum), failing closed when the budget or Git deadline is exhausted.
The native backend holds the data `ShareLock` for the whole publication, so
concurrent staging cleanup cannot delete referenced bytes until it releases.

Supported boundary: binary or non-UTF-8 blobs are **not** valid stock-client
pointers (`git lfs pointer --check` exits 1 for every probe fixture), and a
known P2 allows them as ordinary content; header/scheme shapes the client itself
rejects are likewise ordinary content server-side. This acceptance does **not**
claim that every malformed blob is rejected. The Pando gate call is
source-reviewed only in this round. The caller-side hydration staging is
hardening that sets `0600` before the final rename — the adapter was already
atomic on the old `157748a` baseline (which passed the 8 MiB concurrency case);
this is **not** a truncate-bug fix. The old binary's genuine failure was the
CRLF pointer bypass, preserved as clearly labeled old RED evidence.

**#47 — browser sessions.** A real Chromium workflow covers sign-in, repository
discovery, Issue and PR creation/merge and logout, with the stale cookie
rejected afterwards. Expired and revoked sessions are rejected, parent
API-token expiry/revocation is checked at admission, cross-origin
state-changing requests are rejected, CSRF is enforced, and session/CSRF
secrets never appear in URL or page source. Git push and API token auth remain
independent, and an explicit `Authorization` header wins over a stale browser
cookie. As documented in [browser sessions](../browser-sessions.md), parent
revocation is checked when a request is admitted; an already-admitted in-flight
write may still finish (the separate accepted #37 P2). Upgraded deployments
require one re-sign-in because pre-upgrade unparented sessions fail closed.

**Not claimed.** Loopback services, one disposable PostgreSQL 17, real Garage
and real Chromium on a single physical host. No external CI contact, no
public-CA endpoint, no cross-host failover/fencing, no power loss, no cloud/KMS
or production data. Ordinary CI is intentionally not a merge gate for this
round, and #26/#43/#44 plus umbrella #48 stay **open**.

**Evidence:** [evidence/round4/browser-lfs-4c5bcfe](../../evidence/round4/browser-lfs-4c5bcfe/README.md)
(README, `status.json`, `certificate.json`, `production-inputs.json`,
`primary-consistency.json`, corrected `acceptance-review.json`/`.md`, 11 logs,
9 reports, 4 review pairs, 3 historical fixtures, `manifest.json`).
