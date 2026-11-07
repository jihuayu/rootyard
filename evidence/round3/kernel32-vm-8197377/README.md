# Kernel cgroup resource acceptance - hosted VM pass (source `8197377`)

Verified positive native acceptance for the production cgroup sandbox profile on
the supported execution environment (GitHub-hosted Ubuntu 22.04 VM, unprivileged
uid 1001, delegated cgroup v2 subtree, rebuilt bubblewrap that implements
`--size`).

- Workflow run: https://github.com/jihuayu/rootyard/actions/runs/42335322441
- Job: `128290838175` (all steps succeeded, including reclaim/cleanup and the final
  enforce step; run conclusion `success`)
- Artifact: `13559178383` with ZIP SHA-256 `4107dfdfd0cd96cb3f1c5a85c5cf5f1ea0586e93efbfb4e08a34be018232bc73`
- Compiled source: `8197377e6d85c3b80082331d7b86cab8c84070f5` / binary SHA-256 `e4deb3e032ee138376c1b277be7bdaf6476599099a66f130aed2d122b8b17bd7`
- Receipt status `passed`, profile `cgroup`, 17/17 required assertions `true`
- Artifact export pool: real 64 MiB tmpfs (`pool_capacity_bytes_measured` 67108864)

Files:

- `receipt.json`, `evidence/native-cgroup-receipt.json` - exact sanitized
  passing receipt from the artifact.
- `binary.sha256` - the binary hash recorded by the workflow build step.
- `source-inputs.json` - `source_digest.py` map over `src/`, `migrations/`,
  `schema/`, `Cargo.toml`, `Cargo.lock` of the compiled tree.
- `artifact-manifest.json` - run/job/artifact identifiers, source/binary/test/
  workflow hashes, ZIP hash and the SHA-256 of every file stored here.
- `independent-runtime-review.json` - unchanged independent runtime review for
  production source `9bad208` (verdict APPROVE_DELTA (0 P1)). `8197377` differs from
  `9bad208` only in `tests/test_sandbox_cgroup_native.py` (the ENOSPC fixture),
  so the production review applies unchanged; compiled source and reviewed
  source are recorded separately.
- `failed-attempts/` - the two earlier hosted receipts and a ledger. They are
  failed attempts and are never counted as acceptance.

What this proves: for this supported profile the production cgroup backend
really enforced memory OOM, `pids.max`, aggregate `cpu.max` quota, workspace
`ENOSPC`, cancellation/timeout reclamation, live controls and supervisor
membership, artifact export/authorization/reclaim, CI checkout builds with a
fenced retry as a new attempt, and service-crash descendant teardown.

What this does not prove: this host remains unable to execute native cgroup
acceptance (no delegated cgroup v2 subtree; rootless Docker cgroup driver
`none`) - a separate execution-environment fact, not a product regression. No
claim is made for cross-host HA, other features or profiles, or any
configuration outside the one recorded above.
