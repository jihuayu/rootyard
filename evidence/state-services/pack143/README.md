# A5a registered-membership snapshot qualification

This is an unserved PostgreSQL metadata/pin foundation for issues #105/#107. It captures every ref, HEAD and complete registered pack identity with a durable pin, original request digest, immutable receipt/history, permanent identity reservation and quota charges in one transaction. A5a `PackReadSnapshot.complete_git_read_snapshot()` remains false. Actual Blob/native materialization is a later A5b change; serving, roots/decisions/subsets, GC, encryption and physical Blob-byte backup are not qualified here.

Production inputs SHA-256: `83d6e4d428f102bccf9e841196705ca8e3ba8fa3fb6166985e7ed1631582db80`. The manifests and individual receipts identify the exact source/test/binary/head and actual commands. Later commits fix backup fixtures or format the native assertion; they do not change those production inputs. Rebuild the selected test from the checked-out test source before replaying a source-bound runner: the retained passing native test is from `928d8a0`, before the formatting-only `f7898cb` assertion change.

| Check | Actual result |
| --- | --- |
| Real PG17 + Garage S3 + Git2.47.3 | 10 passed, 0 failed, 0 ignored; 29.197s |
| Rust library | 374 passed, 0 failed, 9 existing/provider tests ignored; 14.257s |
| Native binary schema143 | PASS; 115 tables, 39 functions, 95 triggers; fresh/custom schema, exact catalog and upgrades/roundtrip |
| Populated current format19 | Seven of seven real backup/restore cases passed; exact A5/A2/A4/A3/core rows, owner isolation, replay/no quota mutation, active/renewed/released/expired pins |
| Genuine format18/schema142 upgrade | Seven of seven passed, 45.738s; retained original producer and typed old A4 S3/native-Git seed helper, no relabelled archive |
| All-target Clippy | pando-lab + blob-azblob, warnings denied, PASS; Azure compile coverage only |
| Python reference models | 591/591, zero skips; reference models are not production qualification |
| Python source/unit selection | 286 passed with six existing skips; native-only modules explicitly excluded |

Loopback PostgreSQL17 has fsync/synchronous_commit/full_page_writes enabled. These tests do not establish power-loss, network-loss, HA, production RPO/RTO or real Azure guarantees. The S3 originals remain external to the PostgreSQL metadata archive and are re-read without deletion. No private fixture configuration is included.

Failed histories are retained: native9/10 (wrong expected SQLSTATE), duplicate diagnostic name compilation, fixture ref counts for the empty old snapshot, wrong cancellation-table name, wrong tenant/repository scopes, exact old-owner restore refusal, and restored guard-message/name-family mismatches. The retained old-ledger upgrade initially compared three table names with the six-table helper marker; its final check compares all six exact row sets. Current-format failures v1-v7 are preserved beside the passing v8 record. A build session interrupted before any receipt is explicitly unqualified and was rebuilt with retained process status/logs. A proposed extra binding charge was rejected: typed receipt bytes already include that charge, and the actual exact-byte assertion passed.

Root alone built/ran native commands and fixtures. Actual DeepSeek agents wrote the primary implementation, test and restore code; Luna Max reviewed scopes, replay, permanent identities, deadlines, accounting and backup fixtures. Static review records are not native-test results. Every issue remains open until the relevant changes are merged and acceptance is complete.
