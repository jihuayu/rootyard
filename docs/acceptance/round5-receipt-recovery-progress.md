# Recorded Git receipt recovery — issue #96

A native Git push can commit refs before SQL settlement fails. Restart now projects that already committed receipt while the repository carries only `recovering/push_outcome_unknown`, including when the original token was subsequently revoked. New writes still require current authorization.

A crate-only proof checks a quiescent finished journal, its parent grant, whole request, successful receipt subset and committed hook events. Publication binds the operation, actor/token, audit sequence/name, generation, admission and exact event set. The same transaction checks repository state/recovery reason and route/fence authority. Terminal admission replay permits only the original operation and identical events.

Luna Max found no remaining P1/P2 in the schema-132 backport. All-target Clippy, [12 receipt tests](round5-receipt-recovery-evidence/proof-tests.log) including four real PostgreSQL tests, and [three admission tests](round5-receipt-recovery-evidence/admission-tests.log) passed. The [full native recovery suite](round5-receipt-recovery-evidence/reliability.json) passes 18 cases, and the [revoked-token native drill](round5-receipt-recovery-evidence/revoked-token-native.json) verifies recovery to COMMITTED/ready plus repeat-restart idempotence.

The [fresh build receipt](round5-receipt-recovery-evidence/build.json) binds binary `8826b82b3d4839e041074698cd81c3d44e9a862c291853184924a1757959da60` to compiled inputs `2e2090a4e52be250f9a114f912de772e105c3d4203511b45b6690d184902016f`. The primary checkout digest was checked equal after integration. Subsequent changes include test/CI/docs edits and Rust formatting in `b790b74`; the receipt identifies the pre-format native candidate, while hosted CI must qualify the current formatted head. Schema 132 and backup format 8 are unchanged.

Oversized receive requests now have explicit HTTP-parser assertions: 400, no native refs/events/operation/admission/journal. The missing-hook test carries a real write command rather than an empty flush. These tests do not claim the native hook handled requests rejected before Git. Faults are process restarts and synthetic SQL triggers on one host; no power-loss or multi-host qualification is claimed. Remote CI is pending.

The Pull workflow was requalified after the remote CI restart-snapshot race.
All eleven native stages pass with harness `97a325b`; the receipt records its
Python input digest. Harness-written check rows remain byte-identical across
restart. Only the known automatic context may appear or advance, with exact
repository/head binding, finite fields, monotonic attempt/sequence, immutable
creation time, and matching durable scheduler records. A non-null linked run
must match that evidence. The check follows the actual sequence-ordering API
and does not invent a status-transition ladder. Matching scheduler records are
supporting provenance, not an authenticity proof against an arbitrary writer.
Luna Max reviewed the corrections; a complete remote CI run is still pending.
