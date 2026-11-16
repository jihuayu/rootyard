# Rubicon Mixed Push/Read/Maintenance Workload & Compute Scaling Baseline (Issue #164)

Reproducible, source-and-binary-bound real Smart HTTP mixed-load harness for `rootyard serve-blob` over PostgreSQL 17, Garage/S3 (`OpenDAL`), and stock Git (`scripts/rubicon_mixed_workload.py`, package `scripts/rubicon_workload/`).

## 1. Scope & Truth Boundaries

- **Purpose**: Provide a repeatable, self-hosted mixed Git/HTTP/PG/Blob workload baseline covering concurrent writes, single-ref CAS contention, atomic vs. accepted-subset multi-ref pushes, post-push CI read amplification, cold vs. warm reads/Browse alongside background PG snapshot/pack metadata queries, revocation/fault outcome separation, and `1/2/(4)` compute-process scaling.
- **Explicit non-goals & external references**:
  - GitHub Rubicon's `7200 pushes/s` figure is external context and is **never** a Rootyard SLA target. Rootyard baselines are defined exclusively by reproducible local/CI measurements bound to exact source commits, binaries, datasets, hardware, and topology.
  - Fault qualification across three physical hosts remains governed by `#157`; capacity contracts (`#177`), verifier budget isolation (`#176`), pack compression experiments (`#178`), and cold-read optimization (`#179`) consume metrics produced here without being closed automatically by this harness.
  - **No simulated or mocked fallback**: if `--binary`, `<binary>.build.json` (when required), executable `git`, `psql`, Linux `/proc`, `ROOTYARD_TEST_DATABASE_URL`, or `ROOTYARD_BLOB_*` (`opendal` + `s3`) is absent, `scripts/rubicon_mixed_workload.py` fails immediately (`exit 1`) without emitting fake timings.

## 2. Corpus Classes & Workload Mix

All repositories and commits are synthesized deterministically from `--seed` (default `16420261116`), bounded cleanly within `migration 142` (`16` memberships / `8 MiB` per repository, `64` memberships / `32 MiB` per tenant) and `browse::MAX_CAPTURE_BYTES` (`4 MiB`):

| Dataset Class | Content & Purpose |
| :--- | :--- |
| `text_history` | Multi-commit source/markdown history testing delta + zlib compression and history traversal. |
| `similar_files` | Shared template prefix with localized diffs testing Git pack delta efficiency. |
| `compressed_media` | High-entropy incompressible binary payloads stressing `index-pack` CPU and raw S3 bandwidth. |
| `small_deltas` | Frequent small incremental file edits stressing metadata/admission/PG round-trip overhead. |
| `multi_repo` | Distinct tenant-owned repositories exercised concurrently to distribute PG/membership budgets. |

Each compute tier (`1`, `2`, and `4` when `logical_cpus >= 4`) executes:
1. **Warmup & Seed**: Provision repositories via `POST /api/repos`, poll `state == ready`, seed via Smart HTTP `git push`.
2. **Cross-Repo Concurrent Overlap (`independent_ref_overlap`)**: Barrier-synchronized concurrent pushes across `6` distinct repositories (`refs/heads/indep_*`) round-robin across `serve-blob` processes, recording monotonic `(start_ns, end_ns)` intervals to verify real overlap (`max_concurrent_overlap >= 2`) alongside concurrent `/api/repos/{owner}/{name}/{refs,commits,tree,blob}` Browse requests and read-only PG pack/snapshot/operations `SELECT` inspection queries (`query_pg_snapshot_json`), followed by timed mixed waves bounded by `--duration-seconds`.
3. **Same-Repo Mixed Concurrency (`same_repo_mixed_concurrency`)**: Barrier-synchronized concurrent pushes targeting `3` independent branches (`refs/heads/same_branch_{0..2}`) on the **same** repository alongside concurrent `git ls-remote`, Browse API reads, and read-only PG `SELECT` inspection queries (`query_pg_snapshot_json`); handles pre-admission gate-revision contention retries while recording initial overlap and ensuring all committed refs enter the 100% audit set. Note: `serve-blob` runs no background pack compaction or physical Blob GC (`gc_executed == false`), so maintenance traffic strictly exercises read-only PG inspection queries.
4. **Hot Single-Ref CAS Contention**: `4` workers race barrier-synchronized `git push --porcelain origin HEAD:refs/heads/main` against the same `old_oid` with distinct `X-Rootyard-Operation` headers; enforces `winner_count == 1`, `loser_refused == 3`, `false_ok == 0`, and exact remote ref match.
5. **Atomic vs. Accepted-Subset Multi-Ref Pushes**: Verifies `--atomic` non-fast-forward all-or-nothing refusal, non-atomic partial `ok` + `ng` subset accuracy, and positive `--atomic` multi-ref commit.
6. **Post-Push CI Read-Amplification Burst**: Concurrent read-only clones across freshly pushed `text_history` and `compressed_media` targets with S3 wire read-amplification accounting.
7. **Cold vs. Warm Clones & Browse**: Gracefully stops all `serve-blob` workers, wipes and recreates empty `0700` `ROOTYARD_SCRATCH_DIR` directories, restarts the `serve-blob` fleet, runs Cold clones + Browse sweeps, then repeats Warm clones + Browse sweeps. *Cold* strictly denotes a restarted process with empty local scratch (`serve-blob` maintains no cross-request pack cache in `read_session.rs`); backing S3/OS page-cache state is not reset or claimed observed.
8. **Revocation / Fault Window**: Revokes a live token via `rootyard revoke-token` and sends unreachable-endpoint / revoked requests; strictly records every outcome as `typed_refusal` or `unknown_outcome` with `committed_success == 0`.
9. **Steady-State 100% ACK Audit**: Verifies `100%` of ACKed `(repository, ref, oid)` pairs (including retried timed waves and same-repo branches) via `git ls-remote`, `git clone --mirror`, `git fsck --full --strict`, and `git rev-parse --verify <oid>^{commit}`.

## 3. Telemetry & Accounting Rules

- **Source & Build Provenance Binding**: When `<binary>.build.json` is present (and required by default without `--allow-missing-build-receipt`), `runner.py` binds `--binary` against `HEAD` via `native_build_receipt.load_receipt(..., source_root=repo_root, binary_path=binary_path, expected_commit=HEAD, verify_source_files=True)` and records `workspace_commit`, `config_digest`, `source_inputs_sha256`, and `receipt_sha256` directly in the report.
- **S3 Wire Metering (`S3MeterProxy`)**: On loopback `http://` S3 endpoints (`--s3-meter=auto`), a byte-transparent HTTP/1.1 forwarder records exact `GET`/`PUT`/`HEAD` request counts and payload bytes while preserving all headers (including `Host` for AWS SigV4). On external `https://` endpoints (or `--s3-meter=off`), `s3_wire.observed` stays `false` and `topology` labels the provider as unmetered external/loopback `HTTPS`/`HTTP` rather than claiming loopback metering.
- **Process, Disk & PostgreSQL Sampling (`ResourceSampler`)**: Periodically reads `/proc/<pid>/{status,stat,io}`, recursive `max_temp_disk_bytes` covering both `max_server_scratch_bytes` (`ROOTYARD_SCRATCH_DIR`) and `max_client_worktree_bytes` (`tier_dir` client clones/worktrees, without double counting), `pg_stat_activity` active/lock-waiter counts, `ref_store_core_pack_memberships`, `ref_store_core_pack_artifacts`, `ref_store_core_pack_publications`, `ref_store_core_serving_reads`, and `ref_store_operations` (`pending_ops` backlog time series).
- **Serving vs. Coexisting Pack Bytes**: Separately reports active `serving_pack_bytes` (`ref_store_core_pack_memberships`) vs. `coexisting_pack_bytes` (`ref_store_core_pack_artifacts`, including uncommitted/cancelled publications) and enforces `physical_savings_claimed == false` whenever physical Blob GC/deletion is disabled (`gc_executed == false`).

## 4. Running & Testing

```bash
# Offline unit contract tests (run automatically by scripts/run_python_ci_tests.py)
python3 -m unittest -v tests.test_rubicon_mixed_workload

# Live CI benchmark profile (requires PG17 with public.cluster_authority migrated once on the base DB,
# Garage/S3 ROOTYARD_BLOB_*, git, psql, built binary + .build.json)
env DATABASE_URL="$ROOTYARD_TEST_DATABASE_URL" "$ROOTYARD_BIN" migrate
python3 scripts/rubicon_mixed_workload.py \
  --binary "$ROOTYARD_BIN" \
  --git "$(command -v git)" \
  --report test-results/rubicon-mixed-workload/report.json \
  --summary-md test-results/rubicon-mixed-workload/summary.md \
  --tiers auto --duration-seconds 12 --warmup-seconds 2

# Extended qualification profile (explicit duration and 1/2/4 tiers on >=4-core host)
python3 scripts/rubicon_mixed_workload.py \
  --binary "$ROOTYARD_BIN" \
  --git "$(command -v git)" \
  --report test-results/rubicon-mixed-workload/qual-report.json \
  --tiers 1,2,4 --duration-seconds 120 --warmup-seconds 5
```

See `.github/workflows/rubicon-mixed-workload.yml` for the hosted Ubuntu 22.04 PG 17 + Garage 2.1.0 execution workflow.
