# Source review: 79987b4..869be7d (LFS hydration atomicity + CRLF publication gate)

Scope: exactly 4 files (`src/lfs/storage.rs`, `src/lfs/publication.rs`, `tests/lfs_publication.py`, `tests/lfs_hydration_concurrency.py`; 547+/9-).
Method: source reading of the delta plus the cited call sites; **no build, no native run, no network, no edits**. Behaviour of the new code below is therefore *unverified* unless a recorded run is cited.

## Verdict

- **Blockers: none. P1: none. P2: 4.**
- Publication delta fixes a **real server-side fail-open** (CRLF pointer skipped the LFS gate).
- Storage delta is **defensible hardening, not a truncation bugfix**.
- Both new suites are **outside CI**; do not treat 39/40 as closable before the primary fresh build + native runs.

## 1. Correction of the earlier truncation hypothesis (primary is right)

`src/storage/remote_objects.rs::get_to_file` already: writes `.rootyard-object-<uuid>` in the destination parent, caps at `expected_size`, verifies sha256 + size, `sync_all`, renames to destination, fsyncs the parent, and removes its temp on error. `source-ready.json` records the **old 157748a binary PASSING** the real-Garage 8 MiB cold-read concurrency run (2 backend GETs, both bodies 8388608 bytes / `9ad7ed07...`, final `0600`, nlink 1, no staging leftovers).

=> The reviewed short-body/truncate race is **not reproducible** on the certified baseline. Do not call this a truncate fix.

## 2. Caller staging (`hydrate_verified_remote`): necessity, safety, cost, GC

**Real defect removed (narrow).** Old code passed the final oid path to `get_to_file` and chmod'ed `0600` *after* the callee rename. In that window a concurrent `verify_path_integrity_bounded` sees `mode != 0600` and returns false: a concurrent reader can get a spurious failure and/or trigger a **second full remote hydration**, and the tenant-addressable path transiently carries the umask default (`0644`). The new path chmods/fsyncs/verifies digest+size+mode+nlink1 on its own `.tmp-<uuid>` *before* the final path is replaced. Correct classification: **hardening / window removal**, not data-integrity repair.

**Safety.**
- `guard.disarm()` is reached with no intervening `await`, so no cancellation point exists between a verified rename and disarm; an armed guard only ever unlinks this request's random `.tmp-<uuid>`.
- Cancellation before the rename leaves at most a removed staging file; if the `spawn_blocking` rename then still runs it fails `ENOENT` and nobody observes it. Unverified bytes can never reach the final path.
- Deadline is enforced inside both bounded hash loops and forwarded to `get_to_file`.
- Verification opens with `O_NOFOLLOW` and enforces size/sha256/mode/nlink; `set_permissions` is by path on a self-generated uuid (stylistic only, not attacker-controllable).

**Cost.** One extra full local SHA-256 pass per cold hydration (callee stream hash + staging hash + final `verify_local_until` hash = 3 passes vs 2), two extra `spawn_blocking` tasks. No second download and no byte copy (callee rename target and final path share a directory).

**GC/temp interaction.** `.tmp-<uuid>` matches the pre-existing upload convention (`stream_to_staging_and_publish` uses the same name + `StagingFileGuard`) and is covered by `storage_lifecycle::gitfs` `gitfs_stage_cleanup -> clean_staging`, which deletes regular nlink-1 `.tmp-<uuid>` files older than `stage_age_seconds` (default 3600). In-flight writes advance mtime, so only the post-completion window is exposed, and a sweep hit fails the hydration closed (rename `ENOENT`), never publishing unverified bytes.

**Residual (pre-existing, not introduced here):**
- `clean_staging` does **not** sweep `.rootyard-object-<uuid>`, so a kill/crash mid-download can strand an orphan temp no sweeper reclaims.
- Quota accounting (`check_repo_quota` over `repo_lfs_dir`) transiently counts staging bytes.
- The same post-rename-chmod window persists at `src/backup/lfs_inventory.rs::hydrate` (and `ci_checkouts/mirror_prepare` uses an unswept `.ci-<uuid>` stage), so "final path is always 0600 + verified" is **scoped to the LFS read path**, not the product.

## 3. CRLF: real bug confirmed

- Old gate required the exact byte prefix `version https://git-lfs.github.com/spec/v1` + `\n`; a CRLF pointer fell to `continue`, was treated as ordinary content and skipped existence/size verification.
- Recorded client probe (git-lfs 3.6.1): `--check` exit **0**, `--check --strict` exit **2** — Decode tolerates CRLF while strict canonical re-encode fails, so `git lfs clean` passes the CRLF pointer bytes through verbatim and the raw pointer reaches the server. The premise of the RED is therefore sound.
- Recorded old-binary RED: direct push accepted `crlf_missing` while `missing`/`wrong_size`/`invalid` were rejected in the same run.
- `starts_lfs_pointer` (LF or CRLF after the v1 line) closes it, and it is applied at the shared `validate_new_refs_with_client` gate used by smart-HTTP receive, ref transactions, pull merge and pando publication.

## 4. Bounded correction on the normalizer

`models::parse_pointer` already tokenizes with `str::lines()`, which strips one trailing CR per line, so after recognition is fixed `parse_pointer` alone accepts the tested CRLF shapes: `normalize_pointer_line_endings` is **redundant for the tested forms**. It is not a pure no-op — folding every CRLF also makes `size 13\r\r\n` style variants parseable, so it accepts a slightly **wider** pointer-shape set than the parser alone; the only consequence is fail-closed over-rejection (the shape is then forced through availability/digest verification), never a bypass. Allocation is bounded (1024 per blob, 4096 blobs), and normalization only runs on pointer-recognised blobs, so ordinary text is untouched and canonical LF pointers (no CRLF sequence) are never falsely rejected.

**Out of this delta:** the impl worker is currently expanding the normalizer (leading whitespace, legacy URI). Those shapes are **not** accepted by 869be7d and need a separate narrow follow-up review.

## 5. Test material

**Publication (good):** 7 kinds x 4 asserted paths (direct smart-HTTP push, `--atomic` push with a good ref that must also not move, ref transaction 409, pull/merge 409), each with ref-not-visible `ls-remote` checks and object hold/corrupt/restore; plus a valid CRLF pointer that must publish and match the pushed head.

**Publication (gaps):** no `cat-file -p` assertion that the committed blob bytes equal the CRLF pointer (the client pass-through premise is only recorded in the report, not pinned by the suite); `crlf_*` rejections do not distinguish which guard fired; pando publication (5th call site) untested; **not wired into `.github/workflows/ci.yml`** (only `tests/lfs.py` runs among LFS suites).

**Hydration (good):** deterministic proxy gate proving exactly 2 backend GETs, cold start, second GET before first body completes, first client not done at second first-chunk, exact size+sha256 on both bodies, final `0600`/nlink 1/size, zero `.tmp-`/`.rootyard-object-` leftovers, rehydration after disarm.

**Hydration (gaps):** the same scenario **passes the pre-delta binary**, so it is a concurrency/compatibility regression test and cannot demonstrate the staging hardening; no case drives the pre-fix mode window; no cancellation/kill case asserting staging cleanup or sweeper interaction; single 8 MiB object with proxy-gated timing.

## 6. P2 list

1. Neither new suite is in CI (manual-only regression gate).
2. Third full digest pass on every cold hydration with no code comment recording the cost/justification.
3. `.rootyard-object-<uuid>` orphans are never swept (pre-existing; more visible now that hydration uses two temp names).
4. Backup hydration still has the post-rename chmod window, so the "always 0600 verified at final path" invariant is read-path-scoped.

## 7. Unverified here / required before closure

Not run by this reviewer: fresh build of 869be7d, native `tests/lfs_publication.py` (7x4 rejection + valid CRLF publish), native `tests/lfs_hydration_concurrency.py` against real Garage, full LFS/retention/backup suites.

Required: primary fresh integrated build + both native runs with the recorded commands, and **no 39/40 closure on this review alone**.
