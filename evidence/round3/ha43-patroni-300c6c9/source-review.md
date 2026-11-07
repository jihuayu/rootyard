# HA43/ops43 final source review: 300c6c9 delta

**Verdict:** SOURCE APPROVED - 0 P1/P2 in the 300c6c9 delta; native 300 result remains pending.

Reviewed HA head: `300c6c93cc054fbd723af2243a8f321307835cbc` (`300c6c9`). Composed head from git: `ac54f7163561ad98fb83e4c5f45cd2e1f7151f74` (ops HEAD includes HA 300c6c9 and Pando schema132/format8).

Prior 579 failed review preserved at `source-review-579.json` / `.md`.

Source equivalence: compiled `1061a8ee`, production inputs `9e33859a`, binary `6f76d709`, 329 files identical; current harness hash `07c5265aa...` equals HA 300c6c9.

## Native status

Current 300 composed 132/8 run: **running**; report exists: **False**. It is pending at source-review time. The archived 85 pass is not a 300 pass and is not counted here.

## Schema and receipt proof

- **Intent Schema:** src/ci_pins/models.rs:31-42: Intent is version:u32, job_id:Uuid, owner_id:Uuid, repository_id:Uuid, storage_generation:i64, object_format:String, target_oid:String, retention_ref:String; #[serde(deny_unknown_fields)]; no state field
- **Version Validation:** src/ci_pins/models.rs:43-52: validate requires version == 1, valid object_format/OID, storage_generation > 0, retention_ref == refs/rootyard-ci/jobs/<job_id>
- **Durable Intent File:** src/ci_pins/store.rs:6-15: load_intent parses <job>.json as Intent and validates repository/job identity
- **Durable Receipt:** src/ci_pins/store.rs:17-22: receipt writes serde_json::to_vec(&intent) to <job>.pinned.json
- **Receipt Integrity:** src/ci_pins/store.rs:35-70: intents reads .pinned.json and requires its bytes equal serde_json::to_vec(intent)
- **Test Source Assertions:** tests/cluster_patroni_native.py:690-711: parse <job>.json Intent; assert version==1, job/repo/owner(if present)/target/storage/object_format/retention_ref; parse <job>.pinned.json receipt; require receipt == Intent and canonical SHA-256 equality; API overlap limited to job_id/target_oid/retention_ref; Git rev-parse retention_ref == target and cat-file commit
- **Test Restore Assertions:** tests/cluster_patroni_native.py:933-949: parse restored <job>.json and <job>.pinned.json; require restored descriptor == source Intent, canonical hash equality, restored receipt == source Intent, restored retention_ref OID == target and cat-file commit
- **Report Booleans:** tests/cluster_patroni_native.py:998-1008: source_pin_receipt_matches_intent and restored_pin_receipt_matches_source_intent are true only after the real receipt/Intent assertions; root-field equality uses version, not state.
- **No Weakening:** 300c6c9 is test-only; no global Git config, no authority SQL rotation, no grant SQL rewrite, no assertion removal; prior full-scope checks remain.
- **Scope:** No physical cross-host, hardware watchdog/power-loss or Kafka HA qualification; #43/#44 remain open. The bounded reference profile should not be blocked on unavailable physical hardware; this review is source-only and native-pending.
- **Review Method:** R; e; a; d; -; o; n; l; y;  ; g; i; t; /; s; o; u; r; c; e; /; s; t; a; t; u; s;  ; i; n; s; p; e; c; t; i; o; n; ;;  ; n; o;  ; p; r; o; j; e; c; t;  ; e; d; i; t; s; ,;  ; C; a; r; g; o; /; n; a; t; i; v; e;  ; t; e; s; t; ,;  ; n; e; t; w; o; r; k;  ; o; r;  ; G; i; t; H; u; b;  ; m; u; t; a; t; i; o; n; .

## Findings

No P1/P2 findings in the 300c6c9 delta.

## Scope

No physical cross-host, hardware watchdog, power-loss, rack/zone or Kafka HA claim; #43/#44 physical scope remains open. Do not block the bounded reference profile on unavailable hardware. The native 300 report is pending and is not claimed.

Read-only git/source/status inspection; no project edits, Cargo/native test, network or GitHub mutation.
