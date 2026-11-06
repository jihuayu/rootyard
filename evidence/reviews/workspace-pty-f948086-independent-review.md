# Workspace PTY and signed CI sandbox review: `f948086`

Status: **reviewed; no blocking terminal authority or PTY isolation defect found.** The PTY master remains service-side; the sandbox receives only slave stdio, and the regression asserts the sandbox cannot open `/dev/ptmx`. Input is limited to 4096 decoded bytes, output is drained even when the client does not poll and retained up to 256 KiB, and resize bounds rows/columns. User terminal endpoints require workspace authorization and `terminal=true`; writes additionally require write role and a running job. Signed CI terminal operations remain tied to the claimed run/job tuple and CI capability.

Independent native checks passed against PostgreSQL and the compiled Rust service:

- `tests.test_sandbox_service`: 1/1 passed in 6.958s, including terminal input/output, resize, denial for nonterminal jobs, cancel/timeout, and migration 114→115 reapply.
- `tests.test_ci_sandbox`: 1/1 passed in 12.149s, including signed claimed-origin checkout, a real GCC build, terminal I/O, stale tuple rejection, and cancellation.

The test source was exact branch HEAD `f9480860b76d9744f9a96f6b82ed1810f6f03368`. The executable SHA-256 was `bd2bd5061419fd84a5803f70b44dfd8d733bdaa8d8c4d8ba6009c6515ab6359f`; it also included Workspace's uncommitted lazy-FUSE draft, so this is evidence for the reviewed terminal source and a superset binary, not a bit-for-bit f948-only build. The tests ran separately from `/workspace/rootyard-workspace-ci` with `ROOTYARD_BINARY=/workspace/rootyard-workspace-ci/target/debug/rootyard` and the configured PostgreSQL environment.

No physical cgroup-mode acceptance was part of these two cases; the sandbox tests use the development mode. The existing source does require cgroup v2 in production and fails closed when its configured controllers are unavailable. I found no issue that changes the PTY review result.
