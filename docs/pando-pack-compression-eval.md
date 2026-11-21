# Pando Native Git Pack Compression & Delta Evaluation (`#178`)

This document specifies the reproducible benchmark harness, safety gates, metric contracts, and engineering recommendations for evaluating Git native `pack-objects` compression and delta parameters (`pack.compression`, `pack.window`, `pack.depth`, `pack.windowMemory`, `pack.threads`) across Rootyard's **PostgreSQL RefStore + OpenDAL/S3 (`serve-blob`)** path and native Git repositories (`Refs #178`).

## Scope & Guardrails

- **Standard Git formats only**: Evaluates stock Git `.pack` / `.idx` objects and Smart HTTP (`git-receive-pack` / `git-upload-pack`) + Browse API (`/refs`, `/commits`, `/tree`, `/blob`, `/compare`). No external zstd/gzip wrappers, no custom object formats, and no push-time aggressive repack (`gc.auto=0`, `receive.autogc=false`, `receive.unpackLimit=0`).
- **New mode first**: Live service runs target `rootyard serve-blob` over PostgreSQL 17 `ref_store_core_*` tables and an owned Garage 2.1 S3 endpoint metered via loopback `S3MeterProxy` (`scripts/pack_compression_eval/s3_meter.py`). Legacy GitFS / pre-144 Pando helpers are not substituted for `serve-blob` measurements.
- The live fixture sets `ROOTYARD_MAX_INFLIGHT_BYTES` to `436207616` (416 MiB) in the child environment. This covers three 128 MiB push ceilings and one 32 MiB peak shared lease for Phase 3's sequential Browse requests.
- **Cold and warm fetch** use stock Git Smart HTTP from a fresh empty bare client in each phase. The cold phase starts after a server restart clears Rootyard scratch. The warm phase uses the same server process and a new client. Each fetch resolves the expected branch tip and passes strict fsck outside the timer. The report includes the per-repository samples, P50/P95/P99, and separate S3 GET counters for each phase. The measurements cover Rootyard's process and scratch caches. OS and physical object-store caches may already be warm.
- **No unverified physical savings claims**: Because `serve-blob` leaves physical Blob GC unimplemented (`ref_store_core_pack_artifacts` retains historical pack pairs across pushes), every live run reports both `serving_pack_bytes` and `coexisting_non_gc_bytes` with `physical_savings_claimed: false`. Local post-unlink sizes (`local_isolated_post_unlink_pack_idx_bytes`) are explicitly labeled as isolated scratch copies only.
- **Three-repository first incremental pushes**: Each candidate configuration gets the same new cohort selected from its enrolled candidate repositories: the first two plus the final repository (`sha1`, `sha1`, `sha256`). One local fixture client per repository is cloned from that repository's already-seeded work tree, checked against the advertised `main` head, given one deterministic extra commit on a distinct small file, and pushed once to the fixed `refs/heads/multi-repo-eval` ref under the configuration's own tenant writer. The three clients synchronize on a `Barrier(3)` in a bounded three-worker executor; there are no retries. Reported overlap is limited to surrounding **client invocation** intervals; no server-internal overlap is claimed. S3 counters are reset and snapshotted with settled boundaries around the push phase only. After the snapshot, a fresh read-only stock clone per repository runs strict fsck and checks `refs/remotes/origin/multi-repo-eval`, its exact OID, the known fixture file, and unchanged `refs/remotes/origin/main`. No repository outside that configuration's own cohort is touched, and the existing same-repository ACK/ref and concurrent phase remain unchanged.
- **No fabricated metrics**: Missing `rootyard`, `git`, PostgreSQL DSN, or S3 settings fail immediately in `--mode full` rather than emitting stub results.

## Harness Layout

- [`scripts/pando_pack_compression_eval.py`](../scripts/pando_pack_compression_eval.py): CLI entrypoint (`--mode {full,git-only}`, `--scale {quick,full}`).
- [`scripts/pack_compression_eval/corpus.py`](../scripts/pack_compression_eval/corpus.py): Deterministic fixed-seed repository generators for all 6 archetypes (`compressed_media`, `large_binary`, `text_history`, `small_deltas`, `similar_files`, `multi_repo`) supporting `sha1` and `sha256`.
- [`scripts/pack_compression_eval/pack_matrix.py`](../scripts/pack_compression_eval/pack_matrix.py): Controlled compaction sweep (`rootyard_default`, `recompute_c6_w10`, `zlib_store_c0`, `zlib_fast_c1`, `balanced_c6_w25`, `wide_window_c6_w50_t2`, `deep_archive_c9_w50_d100`, `threaded_c6_w25_t4`) capturing wall time, `os.wait4`/proc CPU & peak RSS, scratch disk, `verify-pack -v` delta counts/depth, and `coexisting_non_gc_bytes`.
- [`scripts/pack_compression_eval/correctness.py`](../scripts/pack_compression_eval/correctness.py): `sha1` + `sha256` exact OID/type/ref parity, standalone single-pack `git fsck --full --strict`, delta depth checks, `SIGKILL` mid-repack cancellation preservation, and truncated/missing-`.idx`/invalid-config fail-closed tests.
- [`scripts/pack_compression_eval/e2e_serve_blob.py`](../scripts/pack_compression_eval/e2e_serve_blob.py): Real PG17 schema-isolated `rootyard serve-blob` + `S3MeterProxy` -> Garage 2.1 S3 execution across multi-wave uncompacted pushes, restart cold clone/Browse, warm clone/Browse, single-pack candidate comparison, and barrier-synchronized concurrent branch pushes.
- [`scripts/pack_compression_eval/multi_repo.py`](../scripts/pack_compression_eval/multi_repo.py): The independent three-distinct-repository first-incremental-push checkpoint above, including prepared local fixture clients, fixed-ref first-attempt pushes, client-invocation overlap, isolated S3 push accounting, fresh-clone/fsck verification, and finite per-repo samples.
- [`tests/test_pando_pack_compression_eval.py`](../tests/test_pando_pack_compression_eval.py) & [`.github/workflows/pando-pack-compression-eval.yml`](../.github/workflows/pando-pack-compression-eval.yml): Automated unit, safety, and Linux CI qualification gate.

## Reproducible Commands

```bash
# Offline unit, stock-Git SHA-1/SHA-256 parity/safety, and workflow contract suite
python3 -m unittest -v tests.test_pando_pack_compression_eval tests.test_ci_workflow_triggers tests.test_ci_cargo_fork_workflows

# Local stock-Git controlled matrix + safety gates (no PG17/S3 claims emitted)
python3 scripts/pando_pack_compression_eval.py \
  --mode git-only --scale full \
  --report test-results/pando-pack-compression/git-only-report.json \
  --summary-md test-results/pando-pack-compression/git-only-summary.md

# Full live serve-blob + PostgreSQL 17 + Garage S3 qualification (run in Linux CI)
python3 scripts/pando_pack_compression_eval.py \
  --mode full --scale full \
  --binary "$ROOTYARD_BIN" --git "$(command -v git)" \
  --report test-results/pando-pack-compression/report.json \
  --summary-md test-results/pando-pack-compression/summary.md
```

## Observed Full-Scale Matrix (`git-only`, `seed=17820261116`, `git 2.45.1`)

On a multi-push bare baseline (`5..9` packs per archetype, total uncompacted `pack+idx = 900,168 B` across `3,572,147 B` independent logical object bytes):

- **`rootyard_default`** (`pack.compression=-1, window=10, depth=50, windowMemory=32m, threads=1`, source delta reuse): consolidates multi-pack overhead down to `802,528 B` (`-10.85%` total; `-46.2%` on `small_deltas` `21,868 B -> 11,763 B`, `-55.8%` on `similar_files` `15,321 B -> 6,773 B`, `-65.6%` on `large_binary` `45,356 B -> 15,615 B`), yielding `1,702,696 B` coexisting (`pre + compacted`) if prior packs remain retained.
- **`zlib_store_c0`** (`pack.compression=0`, recomputed): saves minor inflate/deflate work on `compressed_media` (`692,328 B` vs `691,923 B`), but bloats aggregate size by **`+64.28%`** (`1,318,394 B`), expanding `large_binary` base blobs (`401,542 B` vs `15,615 B`) and `text_history` (`97,425 B` vs `18,845 B`).
- **Moderate/wide/deep recomputation (`balanced_c6_w25` `798,296 B`, `deep_archive_c9_w50_d100` `797,853 B`)**: reduces `rootyard_default` by only `0.53%–0.58%` (`~4.2–4.7 KiB`) across this mixed corpus (`text_history` `-9.6%` `18,845 B -> 17,040 B`, `compressed_media` `-0.005%`), while requiring full `--no-reuse-delta --no-reuse-object` CPU work. Live Linux `serve-blob` + PG17 + Garage S3 P50/P95/P99 latency, RSS, CPU, and S3 byte measurements are recorded per PR run in the `pando-pack-compression-eval-receipts` CI artifact.

## Recommendations & Rollback Criteria

1. **Interactive push path (`git-receive-pack`) — Keep Status Quo**:
   - Keep `pack.compression=-1, window=10, depth=50, windowMemory=32m, threads=1` with `gc.auto=0` / `receive.autogc=false`. Multi-push consolidation belongs in bounded background maintenance, never synchronously during push ACK.
2. **Background compaction (`#162` input) — Consolidate First, Keep `32m/t=1` Default**:
   - Pack consolidation (`N packs -> 1 pack`) delivers the vast majority of byte reduction on multi-push incremental histories without changing `c=9` or `window=50`.
   - Do **not** enable `pack.compression=0` globally (severe bloat on code, diffs, and patchable binaries) and do **not** run periodic compaction expecting S3 billing savings until remote Blob GC is wired and verified (`coexisting_non_gc_bytes > uncompacted_bytes` before GC!).
   - Optional opt-in (`window=25, depth=50, windowMemory=64m, compression=6, threads=1..2`) is justified only for large code/template monorepos after GC activation, never for media/binary repositories (`compressed_media`).
3. **Rollback / Fallback Triggers**:
   - Fall back immediately to `pack.window=10, pack.windowMemory=32m, pack.threads=1` (with delta/object reuse) if background `pack-objects` peak RSS approaches worker `RLIMIT_AS` or concurrent CPU load elevates `serve-blob` P95/P99 latencies.
   - Refuse compacted pack promotion on any `git fsck --full --strict`, OID/type/ref mismatch, or delta chain depth above `pack.depth`.
4. **Explicit Non-Claims**:
   - Measurements reflect bounded single-host evaluation corpora (`quick`/`full`) and single-node PG17 + Garage S3 loopback topology; they do not claim universal compression ratios across arbitrary customer monorepos or cross-host network throughput.
