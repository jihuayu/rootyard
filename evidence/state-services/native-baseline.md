# Root native baseline receipt（root-provided; not re-run by W0）

Status: **received for integration review; issue #106 remains OPEN.** The W0 worker did not execute Cargo, the native service, or this runner.

| Item | Value |
| --- | --- |
| Source commit | `d689bf8062a73cfadbc0a72abf3f1546d992e09c` |
| Native binary | `/workspace/scratch/state-baseline-main-v1/rootyard` |
| Binary SHA-256 | `f39838f139e27d6f00a55a88c7ef98974c993f2da3139e0eb3b4e04b05ff8e0b` |
| Inputs digest | `6225c08c28ace0bc45c4e6810e0e8642ee4215a9cb0bc930b87d5fa3eab7fb10` |
| Root runner | `/workspace/scratch/state-native-baseline.py` |
| Root runner SHA-256 | `f6f3560ca0ec730407c3b29a8db138c2bb1f0953afec4951a3a7c6f9900b3f04` |
| Report v2 | `/workspace/scratch/state-native-baseline-v2.json` |
| Report v2 result | `PASS true Pando PG Garage Vault` |
| v2 samples | 109 |
| v2 PostgreSQL peak | 15 connections of pool 16 |
| v2 RSS | idle 29,876 KiB; final 39,920 KiB |

## Measurement history / integrity

- **v1 is not accepted.** It used the wrong PostgreSQL selector. It is retained as a failed measurement and must not be used as evidence.
- v2 is the only accepted receipt reported by root. It binds the native binary, source commit and inputs digest above.
- The root runner is currently under independent review. Its external harness path portability is **not yet verified**, and this W0 bundle does not claim that the runner is portable.
- W0 records the exact runner hash so a later reviewer can verify the same harness; W0 does not execute it.

## Still unmeasured / open

- Full-phase waits are not measured.
- Blob bytes/throughput and provider consistency are not measured (OpenDAL BlobStore does not exist at baseline).
- Multi-host, multi-failure-domain, network-partition and long-steady-state results are absent.
- Complete producer coverage and all W1–W9 gates remain open.
- The bounded local Git smoke report produced by `scripts/state_services_baseline.py` is only a smoke/provenance artifact; it is not a #106 runtime baseline and must not be merged into the v2 receipt.

**Conclusion:** v2 gives a real Pando/PG/Garage/Vault native baseline receipt for review, but #106 cannot be marked complete from it. Runtime baseline, complete producer coverage, phase instrumentation and the design gates remain outstanding.
