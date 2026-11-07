# Round-4 browser + LFS acceptance — 11 native jobs, LFS publication/recovery, revocable browser sessions

Concise evidence bundle for the round-4 integrated candidate at `4c5bcfe`. It
records the primary coordinator's actual native run and the independent final
acceptance review. Nothing here is a build: the binary was compiled earlier from
this exact source, and this publication does not compile, retest or contact any
external system.

## Identity

| Item | Value |
| --- | --- |
| Candidate HEAD / compiled source | `4c5bcfe56516434ea5b42985e9af90a8c1efe51f` |
| Base main | `a91c93f3a63914c8416fa96c653f5d28212af785` (`a91c93f`, origin/main) |
| Immutable local binary | `c0049c3a4a97543cfe95a5deccc80b1404cc3b7f5a3eff2ad54acb9be0de1f45` |
| Production inputs | `8f399a064af9701de018bad5d527cd652767f03131a96affde8582fb6aac0034`, 331 files (map file `e67ed36…`) |
| Coordinator | `state=passed`, `stage=complete`, 11/11 jobs `exit_code=0` |
| Independent review | `APPROVED`, `pending=false`, 0 P1 / 0 acceptance blockers, criteria 39/40/47 `closable=true` |
| Production diff vs `a91` main | 4 files in 3 intended areas: `src/web/handlers.rs`, `src/web/session.rs`, `src/lfs/publication.rs`, `src/lfs/storage.rs` |
| DDL / schema | no migration or schema change; actual schema max **132**, backup manifest format **8** |

The production-input digest recomputed from this worktree equals the stored map
in `production-inputs.json` (331 files, same per-file hashes), and the binary
re-hashed at the recorded path equals `c0049c3a…`. `primary-consistency.json`
records the primary's independent rehash of the binary, all 331 inputs, all
harness hashes, all 9 report hashes, database cleanup and the private-material
marker scan.

## 11 job groups, 11 exit-0 runs

Counts are **not** additive across kinds and are deliberately kept apart:
**145** Rust unit tests (`rust-lib`), **25** cases across the **9** JSON reports,
plus 4 named stdout checks in `webhook-regressions` and the `rust-lib` log,
the two jobs that emit no JSON report. The mixed "170" figure in the review is
`145 + 25` and is not a claim of 170 end-to-end scenarios.

| Job | Exit | Result | Artifact |
| --- | ---: | --- | --- |
| `sessions` | 0 | 1/1 browser-session case | `native/sessions.json`, `native/sessions.log` |
| `chromium` | 0 | 1/1 real Chromium workflow | `native/chromium.json`, `native/chromium.log` |
| `lfs` | 0 | 10/10 native LFS cases | `native/lfs.json`, `native/lfs.log` |
| `lfs-publication` | 0 | 2/2 cases; 4 publication paths | `native/lfs-publication.json`, `.log` |
| `lfs-retention` | 0 | 3/3 cases | `native/lfs-retention.json`, `.log` |
| `lfs-remote` | 0 | 1/1 stock-LFS second-node recovery | `native/lfs-remote.json`, `.log` |
| `lfs-hydration` | 0 | 1/1 concurrent 8 MiB Garage hydration | `native/lfs-hydration.json`, `.log` |
| `backup-capabilities` | 0 | 1/1 format-8/schema-132 restore | `native/backup-capabilities.json`, `.log` |
| `webhook-regressions` | 0 | 4 named stdout checks, no JSON report | `native/webhook-regressions.log` |
| `webhook-worker` | 0 | 5/5 worker cases, `manual_dispatch_calls=0` | `native/webhook-worker.json`, `.log` |
| `rust-lib` | 0 | 145 passed, 0 failed, 0 ignored | `native/rust-lib.log` |

All 11 database-backed jobs ended `dropped_after_success`. The 11 logs and 9
reports in `native/` are byte-exact copies of
`/workspace/scratch/rootyard-round4/integrated/logs/`; each report carries the
certified binary `c0049c3a…`, and each report digest equals the coordinator's
`report_sha256`.

`ci_webhook_regressions` is a **manual** dispatch harness (`POST
/webhooks/dispatch`); `webhook_worker_recovery` has **zero** manual dispatch.
Both were rerun on `c0049c3a…`. The manual-dispatch log must not be cited as
automatic-worker proof, and the worker report must not be cited as the
concurrency-fence proof. Ordinary CI is intentionally not a merge gate for this
round.

## Criterion 39 — LFS through the remote object backend

- `lfs-remote`: real stock `git-lfs`, actual Garage. The source `DATA_DIR` is
  removed entirely, then a **second process with a new `DATA_DIR`** downloads
  the exact 1 MiB bytes over shared PostgreSQL. A remote-only pointer push is
  hydrated by the native hook. This is one physical host; **no vendor, cloud,
  multi-host or production-HA claim** is made.
- `lfs-retention`: failed, duplicate and interrupted **first** uploads keep the
  committed digest; an interrupted first upload stays `pending` and becomes
  `ready` on retry. Role removal denies new reads, and the bytes are retained
  after re-grant.
- `lfs`: 10 native cases — streaming upload/download, hash/size mismatch
  rejection, tenant isolation, revocation, stalled-body deadline, stock locks,
  corrupted-blob fail-closed and offline paired backup/restore.
- `backup-capabilities`: fresh database **and** fresh volume offline restore;
  LFS bytes and lock identity preserved, remote LFS hydrated **with the target
  endpoint absent**, organization inherited access preserved, old browser
  session revoked, cluster authority rotated, stock clone `fsck` passed, and the
  restored schema-version set (through 132) compared against the format-8
  manifest.

Boundaries that stay: no LFS object-delete/GC API exists, so committed objects
are retained indefinitely and cleanup cannot be asserted against object
deletion. The `gitfs_stage_cleanup` race is against real staging deletion.

## Criterion 40 — pointer validation before ref publication

- `lfs-publication` rejects **12** bad pointer kinds — `missing`,
  `wrong_size`, `invalid`, `ready_corrupt_bytes`, `ready_missing_bytes`,
  `same_oid_good_and_wrong_size`, and the CRLF/NBSP/legacy-header variants —
  across **4** real publication paths (smart HTTP receive, atomic smart HTTP
  receive, ref transaction, PR merge). **12 × 4 = 48** rejected combinations,
  all rejected *before* the ref moves.
- **4** valid variants publish: `crlf_valid`, `nbsp_valid`,
  `legacy_hawser_valid`, `legacy_media_valid`.
- **18** official `git-lfs/3.6.1` client probes match all 18 expected
  accepted/rejected shapes.
- Pointer normalization covers the official client's LF **and** CRLF forms,
  leading Unicode whitespace/NBSP, the legacy `https://hawser.github.com/spec/v1`
  header and the legacy `http://git-media.io/v/2` header. Every distinct
  `(OID, promised size)` pair is validated, so `same_oid_good_and_wrong_size`
  fails in either order.
- Bounds are unchanged: **≤1024** raw bytes per candidate blob, **4096** small
  (≤1 KiB) blobs, **20000** newly reachable objects, **512 MiB** default
  verification budget (**8 GiB** maximum). Publication fails closed when the
  budget or Git deadline is exhausted.
- `lfs-retention` also proves atomic multi-ref push, an ordinary non-LFS push
  (300 files), retained tag/history, and 4000 real `gitfs_stage_cleanup`
  deletions that cannot proceed until native publication releases its lock: the
  native Rootyard backend holds the data `ShareLock` (five consecutive samples,
  `application_name=rootyard`) and an exclusive probe is denied while the lease
  is held.

Not claimed: binary/non-UTF-8 malformed blobs are **not** valid stock-client
pointers (`historical/non-utf8-client-probe.json`: all three fixtures exit 1 in
`git lfs pointer --check`); a known P2 allows them as ordinary content. Invalid
header/scheme shapes that the client itself rejects also remain ordinary content
server-side. This round does **not** claim that every malformed blob is
rejected. The Pando gate call is source-reviewed only in this round — no
Pando-native runtime was exercised.

## Criterion 47 — reversible browser sessions

- `chromium`: real `/usr/bin/chromium` 155.0.8059.79 through the Playwright
  workflow — sign-in, repository discovery, Issue creation, PR creation and
  merge, logout, and the old cookie rejected with 401 afterwards.
- `sessions`: expired and revoked sessions rejected, parent browser-token
  expiry/revocation rejected, cross-origin state-changing requests rejected,
  CSRF enforced, and session/CSRF secrets absent from URL and page source. Git
  push and API token auth work independently; mixed cookie + `Authorization`
  handling prefers the explicit API credential.
- `backup-capabilities`: after offline restore, old browser session cookies
  return 401 while repository/API access and restored RBAC still work.

Preserved bound (see `docs/browser-sessions.md`): parent revocation is checked
when a request is admitted, and an already-admitted in-flight write may finish
before revocation is observed. Immediate interruption of admitted operations is
the separate accepted #37 P2; revoke the child session directly for that
stronger bound.

## Hydration: hardening, not a truncate fix

The LFS adapter was **already atomic** on the previous `157748a` baseline: the
old binary **PASSED** the 8 MiB concurrent hydration case
(`historical/hyd-old.json`). This round adds caller-side staging that sets
`0600` **before** the final rename (`local_final_mode=0o600`, `nlink=1`, empty
`staging_leftovers`, `backend_get_count=2`, second hydration overlapping the
first body). Do **not** describe this as a truncate-bug repair. What genuinely
failed on the old binary was the **CRLF pointer bypass**
(`historical/pub-old-red.json`, `passed=false`,
`direct Git push accepted crlf_missing pointer`) — that RED result is kept,
clearly labeled as old evidence, and is the defect this round fixes.

## Files

- `status.json`, `certificate.json` — raw coordinator status and build certificate (byte-exact).
- `production-inputs.json` — the 331-file production digest map used by the run (byte-exact).
- `primary-consistency.json` — the primary's independent rehash/cleanup/marker record (byte-exact).
- `acceptance-review.json`, `acceptance-review.md` — corrected independent final acceptance review (`APPROVED`, criteria 39/40/47 closable).
- `native/` — the 11 job logs and 9 JSON reports (byte-exact).
- `reviews/` — the four independent review pairs carried into this round: browser delta, native lease, hydration source, pointer delta (including the 3 accepted P2 normalizer-dedup findings).
- `historical/` — **old evidence, not current results**: `pub-old-red.json` (old `157748a` CRLF bypass failure), `hyd-old.json` (old `157748a` 8 MiB hydration pass), `non-utf8-client-probe.json` (client-side bound: invalid-UTF-8 blobs are not valid stock-client pointers).
- `manifest.json` — sizes and SHA-256 of every payload above; `manifest.json` itself is excluded to avoid a self-reference.

Raw JSONL run fixtures, PID files, private keys/CA material, certificates,
binaries, configuration files and working progress state are deliberately not
published.

## Not claimed

Loopback services, one disposable PostgreSQL 17, real Garage and real Chromium
on a single physical host. No external CI contact, no public-CA endpoint, no
cross-host failover, no power loss, no production data, no cloud/KMS use, no
physical #26/#43/#44 qualification, and no mass closure of other issues.

## Checks run for this publication

- Production digest recomputed from the worktree before and after the docs
  edits: `8f399a06…`, 331 files, equal to `production-inputs.json` both times.
- Binary re-hashed at the recorded path: `c0049c3a…`.
- All 11 logs and 9 reports compared byte-for-byte with the integrated run
  directory; all 9 report digests equal the coordinator `report_sha256` values.
- Every payload digest equals its `manifest.json` entry.
- Marker scan for private keys, tokens and password material across the
  payloads: no matches.
- `git diff --check 4c5bcfe..HEAD` reports only whitespace diagnostics in
  evidence payloads, listed here for completeness: intentional Markdown
  two-space hard breaks in `acceptance-review.md:3` (byte-exact copy of the
  independent acceptance review) and `reviews/native-lease-review.md:3-5`,
  plus emitted extra final blank lines in `native/rust-lib.log:203` and
  `reviews/native-lease-review.md:84`. Raw reports are preserved byte-for-byte
  and are deliberately **not** normalized; this is not a code or acceptance
  defect. Human-authored documentation in this publication adds no whitespace
  errors.
- Header and in-document relative links checked (all resolve).
