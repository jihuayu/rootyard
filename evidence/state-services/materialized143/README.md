# A5b materialized read qualification

Unserved library foundation for #105/#107; also fixes the shared verifier's loose-ref directory amplification (#139). No new schema/backup format or serving route is added. Base PR140 separately qualifies migration143/format19 and genuine18 upgrades. Its metadata-only PackReadSnapshot remains incomplete as a Git read; only the new privately constructed MaterializedPackRead reports complete after actual bytes/native verification and a final locked live-pin check.

Production input SHA256: `f7d308c01899835c09dbee529676cd8f903a865ba3fd9aa3e17178588282ebca`. Each native/build record includes exact source/test/binary/head, actual commands, unchanged-input checks and limitations. Later test-only fixes do not change these production inputs.

| Check | Actual result |
| --- | --- |
| Final PG17 + Garage S3 + Git materialized reads | 12 passed, zero failed/ignored; 54.704s; candidate8d398e64, binarye5a9c3fab64e426672c907ea9669de649b90903deb1c554be363ace83ce2fbd4 |
| Same-production A4 registered-pack regression | 8 passed, zero failed/ignored;14.959s |
| Library |384 passed, zero failed,9 existing/provider tests ignored;15.430s |
| All-target Clippy |pando-lab + blob-azblob, denied warnings, PASS53.44s; final test-budget tightening adds no production changes |
| Reference models |591/591, zero skips; reference-only |
| Selected Python source/unit suites |286 passed,6 existing skips; native modules explicitly excluded |

The twelve real cases exercise SHA1/SHA256 exact copied pack/index bytes, old pinned revisions after a newer verified commit, foreign backend/missing/corrupt objects, release/generation/realm/real DB-clock expiry, both pool deadlines, a max-1 pool observer during native work, two retained views with independent native admission and subsequent view-budget reclamation,128 legal refs including127 nested52-byte names, mixed A4/A5 global-native2 admission with a third Git marker absent, and expiry after T2 waits on the exact publication-ledger relation/backend. The final third-view test refuses an actual admission wait rather than accepting a T1 timeout, and also proves its Git wrapper never started.

T1 releases every PostgreSQL client before Blob/native work. T2 rechecks full scope/digest and a fresh database clock after slow ledgers, constructs the sealed view under the pin lock, and requires bounded successful transaction cleanup before returning. Its locked final check is the read linearization point; later mutation does not invalidate an already copied value.

Blob lifecycle tests use memory storage and actual owned transfer/unlink gates. They verify shared ReadLease+workspace ownership through timeout, actual inner completion and blocked unlink; settled/unsettled guards and a real unlink error cover release/quarantine. These are unit ownership tests, not provider qualification. Runtime abort/unknown cleanup conservatively retains resources until process exit.

The first real run's7/10 failure history is preserved:128 updates exceeded the unchanged64KiB worst-case terminal bound (fixed by actual ref-only A4 batches<=32, with one registered pack); a backwards expiry mutation was correctly refused (replaced with a real short lease/DB clock); a successful fresh A4 commit was mistakenly expected to remain at bootstrap revision1 (correct post-commit revision2). Final tests add explicit mixed-admission and late-expiry probes. An earlier12/12 run and each build/compiler failure remain preserved, before the final admission assertion was strengthened.

Root alone built and ran fixtures, library and native commands. Actual DeepSeek workers wrote primary production/tests and lifecycle fixes; Luna Max performed static reviews. Static review records are not native acceptance. Review's final third-budget finding was addressed and re-run.

This is a process-local, loopback qualification: no serving cutover, full roots/decisions/subset contract, HA, power-loss, packet-loss, encryption, physical Blob-byte backup or real Azure qualification. The PG observer is held during native work; no separate blocked-provider-GET proxy was used. Workspace counts concern admitted work/live views; final temp directory removal remains best effort, without a total physical orphan-disk quota or restart cleanup qualification. No epoch rollback or new-authority re-admission is claimed. All related issues remain open until relevant merges and completed acceptance.
