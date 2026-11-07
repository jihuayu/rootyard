# Pointer delta review: 869be7d..78eeffe2f665b4ccaac0ef4fb92e573673869d5a

Head: `78eeffe2f665b4ccaac0ef4fb92e573673869d5a` ("Normalize client-accepted LFS pointers and key inspection by promised size")
Parent: `869be7d42398ec301387883cb678cf4752007821`
Scope: only `src/lfs/publication.rs` and `tests/lfs_publication.py` (2 files, 228+/55-). No build, no native run, no edits by this reviewer.

## Verdict

- **Blockers: 0. P1: 0. P2: 3.**
- The new `canonical_pointer_bytes` is a **strict superset** of the `869be7d` recognition: every blob recognized before is still recognized, so the CRLF fix cannot regress.
- The `(oid, size)` dedup key fixes a **real, previously present fail-open** and the ordering case in the suite is constructed deterministically.
- One concrete P2 remains: a recognized version line followed by **non-UTF-8 bytes** now falls through as ordinary content, where `869be7d` and `79987b4` both failed closed.
- Baseline note unchanged: `get_to_file` already stages/verifies/fsyncs/renames and the baseline concurrency run passed. This delta does not revive any truncation hypothesis, and the previously approved storage hardening is untouched.

## 1. `canonical_pointer_bytes`

Recognized set: optional **leading Unicode whitespace** (`str::trim_start`, i.e. Unicode `White_Space`, which includes NBSP; BOM is not trimmed because U+FEFF is not White_Space), then a first line exactly equal to one of

- `version https://git-lfs.github.com/spec/v1` (canonical),
- `version https://hawser.github.com/spec/v1` (legacy, https only),
- `version http://git-media.io/v/2` (legacy, http only),

with an optional trailing CR before LF; the remainder is CRLF-folded and a legacy header is rewritten to canonical before `models::parse_pointer` runs.

Assessed:

- **Bounds** — `len > MAX_POINTER_BYTES` returns `None` before any UTF-8/trim work, and the batch loop already refuses blobs above `MAX_POINTER_BYTES`, so that early return is defensive only; output is at most 1024 bytes plus the version line.
- **Fail-closed on recognized-invalid** — a recognized header with a non-hex `oid`, non-numeric/absent `size`, or missing fields reaches `parse_pointer`, which returns `None`, and the gate answers `CONFLICT invalid LFS pointer`. Confirmed for the `invalid` kind and for `size`/`oid`-only shapes.
- **Ordinary content unchanged** — trailing space/tab on the version line, reordered fields, `http git-lfs`, `https git-media`, `http hawser` all return `None` and stay content, matching the recorded client probes (`False` in every one of those rows).
- **Monotone relative to `869be7d`** — a blob whose first bytes are the canonical line is still recognized (`trim_start` is a no-op there, the trailing CR is stripped), so nothing that was gated before becomes content.
- **Legacy mapping** — header substitution plus remainder folding keeps `parse_pointer`'s exact first-line equality; checked for LF and CRLF variants of both legacy headers.

## 2. `(oid, size)` inspection key

- Old key `inspected_lfs_oids: BTreeSet<String>` collapsed a *second* pointer to the same oid **before** the size comparison, so a batch holding a correct-size pointer and a wrong-size pointer to the same object validated the first promise and silently skipped the second → push accepted with a wrong-size promise. That is a genuine fail-open, independent of CRLF.
- New key `inspected_lfs_promises: BTreeSet<(String, i64)>` routes every distinct promise through the row-size comparison and `ensure_readable`; identical `(oid, size)` pairs still collapse, which is sound because validation is a pure function of that pair.
- **Ordering determinism (verified in source):** `objects` is a `BTreeSet` of git oids fed to `cat-file --batch-check`, whose output preserves input order and feeds `small` in the same order, so blobs are inspected in git-oid order. The suite raises the wrong-size pointer's size until its blob oid sorts **after** the good canonical blob, so the pre-fix skip is deterministic rather than incidental.
- **Side effect:** `inspected_lfs_bytes` is now charged per distinct `(oid, size)`, so one large oid promised at many sizes consumes the `ROOTYARD_LFS_POINTER_VERIFY_BYTES` budget faster. Over-rejection only, same cap.

## 3. Findings

**P2-1 (concrete, narrow): non-UTF-8 tail after a recognized version line is treated as ordinary content.**
`canonical_pointer_bytes` starts with `std::str::from_utf8(bytes).ok()?`, so a ≤1024-byte blob that begins with a recognized version line and then carries invalid UTF-8 bytes after valid `oid`/`size` lines returns `None` and is published as content. `79987b4` and `869be7d` both reached `parse_pointer` on that shape and answered `CONFLICT`; a line-oriented client decode can still read the valid prefix, so this is a relaxation of fail-closedness in the same failure class the gate exists to stop. Impact is narrow (deliberately crafted tail, no data corruption, no bypass for well-formed pointers) and the new variant matrix does not cover it.
*Fix:* on `from_utf8` failure, still byte-prefix test for a recognized version line (after ASCII whitespace trim) and answer `Err(CONFLICT)`; or expose `recognized()`/`canonical()` so an unparsable recognized blob fails closed.

**P2-2: the suite recomputes blob ids with SHA-1 instead of asking Git.**
The helper hashes the blob header plus body with SHA-1. The harness creates bare repos with `git init --bare` (sha1 by default), so the ordering construction is correct today; but the gate derives `oid_len` from `rev-parse --show-object-format`, so in a sha256 repository the constructed pair would not be oid-ordered and the regression case would silently become nondeterministic while still passing. *Fix:* use `git hash-object --stdin -t blob`, or assert the repository object format.

**P2-3: per-`(oid, size)` byte-budget accounting is undocumented and untested.** Intentional, but a one-line comment at the accounting site would pin the earlier-CONFLICT behaviour at the cap.

## 4. Test material

- **12 rejection kinds × all 4 publication paths** (direct smart-HTTP receive, `--atomic` receive with a good ref that must also not move, ref transaction `409`, pull/merge `409`), each with ref-not-visible `ls-remote` checks and object hold/corrupt/restore. New kinds: `nbsp_missing`, `nbsp_wrong_size`, `legacy_hawser_missing`, `legacy_media_wrong_size`, `same_oid_good_and_wrong_size`.
- **4 valid ready variants publish successfully** (`crlf_valid`, `nbsp_valid`, `legacy_hawser_valid`, `legacy_media_valid`), each with `returncode == 0` and `ls-remote` head equality against a ready, digest-verified object — so normalization is proven not to over-reject, not just asserted.
- **Client-compatibility probe** records `git lfs pointer --check` exits for 18 shapes and asserts them against the recorded expectations, so the premise is re-verified on the machine that runs the suite rather than in prose (gracefully skipped if git-lfs is absent).
- Remaining gaps: no invalid-UTF-8-tail case (P2-1); no `cat-file` assertion that the committed blob equals the pointer bytes, so client pass-through is still inferred; pando publication (fifth `validate_new_refs_with_client` call site) is not exercised. CI wiring is out of scope per instruction.

## 5. Unverified here / needed for final approval

- Fresh native build of `78eeffe` — primary is running the integrated build, not this reviewer.
- Native `tests/lfs_publication.py` on `78eeffe`: 12 kinds × 4 paths rejection, 4 valid ready variants publish, client probe matrix.

Neither P2 finding blocks the combined 39/40 native approval decision; P2-1 should be a tracked follow-up (one-line fail-closed tweak plus one variant) rather than a gate.
