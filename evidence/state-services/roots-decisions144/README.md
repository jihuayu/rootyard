# Retention roots, decisions and accepted-subset qualification

This is an unserved PostgreSQL library increment for #105/#107, stacked on PR141.
The final production input SHA-256 is
`753bfabe4d6c1f4ba793bad38e4997f0b610222e6bcb205de98f6e904cf00b30`
(production commit `84cae1e50feba336503cfae4e1a1eb4bf9a7ba25`). Later changes
repair backup fixtures/assertions and add evidence, without changing those
production inputs. Each record identifies its actual source, test/support
inputs, binary, commands and candidate HEAD; records are not relabeled to a
later commit.

| Actual check | Result |
| --- | --- |
| Roots: real PG17, Garage S3, native Git | 11 passed, zero failed/ignored |
| Authorized decisions/accepted subset: real PG/S3/Git | 20 passed, zero failed/ignored |
| Same-production A4 pack commit regression | 8 passed, zero failed/ignored |
| Same-production A5b materialized-read regression | 12 passed, zero failed/ignored |
| Library | 410 passed, zero failed; 9 existing/provider cases ignored |
| Rust binary schema144 migration | 132 tables, 50 functions, 119 triggers; canonical/dump roundtrip/003,006,007 upgrades/custom search path/idempotence pass |
| Populated current format20 backup/restore | Seven real cases, zero skips |
| Genuine format19/schema143 to format20/schema144 | Seven real cases, zero skips, using the retained old producer and old typed A5 helper |
| Strict Clippy | All targets with pando-lab and blob-azblob; later changed backup fixture checked separately; denied warnings pass |
| Reference models | 591/591, no skips; reference-only |
| Selected Python source/unit suites | 286 passed, 6 existing skips; unrelated native/kernel modules explicitly excluded |

The roots cases verify independent retention after source-pin expiry/release,
old non-ref and tree OID selection, actual copied bytes with stock Git,
generation/tombstone/replay rules, concurrent identical register/release with
one charge and stable stored timestamps, logical-byte/root-count ceilings,
release during paused native work, and historical metadata after repository
deletion without a new byte view.

The decision cases verify mixed CAS and atomic behavior, missing new targets,
non-commit branch targets, shared missing bytes, protected branches, actual API
token and RBAC revocation, restricted PAT scope removal, phantom rules,
withdrawn trusted checks, real DB-clock expiry, cancel-before-install and
cancel/commit competition, the irreversible legacy-write fence and old replay,
original-order prefix/HEAD rules, and authorized metadata. Metadata admission
reserves terminal/event bytes; an installed operation finishes even when later
usage fills the counter, while a fresh install refuses atomically. All results
include every original ref; final verification cannot silently shrink selection.

The current backup drill uses the real A3/A4/A5/root/authorized-decision APIs to
populate every schema144 table, including active/released/tombstoned roots,
consumed/cancelled decisions and a decision-less cancellation. It restores all
RefStore ledgers exactly, replays typed historical reads and verifies retained
root bytes against surviving external S3 originals. Every schema table is also
compared before/after read-only replay. Cluster authority intentionally rotates
on restore and is not mistaken for immutable RefStore history. Real negative
UPDATE/DELETE/quota/fence checks and a fresh authenticated clone/fsck complete
the drill. The final review tightened exact root row/quota/released-root shape
and Push action assertions; the complete seven cases were rerun successfully.
CI path filters include Rust, Blob/bootstrap scripts and toolchain inputs.
Metadata archives do not copy external Blob bytes.

Failed attempts remain in this directory. The first decision run exposed an
actual metadata INSERT bug: authz parameter25 repeated the facts digest. It was
repaired without relaxing the final live check; all twenty real cases were then
rebuilt and passed. Other retained failures include Git/pin fixture setup,
JSONB/text parameter types, stale prefix/code expectations, INT4 length decoding,
tombstone counts, duplicate marker keys, a stale protocol marker, reconstruction
of a refused request identity, and expected trigger-error wording. See
`validation-notes.json`. The unfiltered Python attempt failed for unrelated
missing native executables/kernel fixtures and is not represented as a pass.

Root alone compiled and ran services/native Git/fixtures. Actual DeepSeek CLI
agents wrote the primary implementation and tests; Luna Max conducted source-only
reviews, including quota reserves and SQL binding checks. Review files do not
claim runtime acceptance. Selected integration artifacts are actual
Fresh=false Cargo outputs; the final helper reused matching dependencies while
recompiling the changed test/support code, with that reuse explicit in its receipt.

This qualifies a loopback, process-local library foundation. It does not activate
serving, a distributed Raft bridge, PR Merge producers/finalizers, GC, encryption,
physical Blob-byte backups, power-loss behavior or Azure provider runtime. LFS
pointer refs fail closed without durable remote attestation. Native/view/workspace
bounds are process-local; physical orphan-disk bounds and restart cleanup are not
claimed. Related issues remain open until the relevant merges and acceptance.
