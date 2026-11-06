# Independent review: format-6 remote LFS backup closure

- Commit: `82e8fdf2dd01f6f730e1df2d1707a04305ab0c5d`
- Scope: `src/backup/lfs_inventory.rs`, snapshot and restore closure validation.
- Binary: `/workspace/shared/rootyard-acceptance-82e8fdf`, SHA-256 `ce584c94b69b0e1a4439de981ba4a777f5e8d9109cd4a1ea691b063f4025c861`, matching `.build.json` receipt.
- Test actually run: `source /workspace/shared/rootyard-env.sh && source /tmp/rootyard-garage-test/env && python3 tests/backup_capabilities.py --binary /workspace/shared/rootyard-acceptance-82e8fdf --remote-lfs --report /workspace/shared/reviews/backup-remote-lfs-independent.json`.
- Result: PASS, `populated_capability_restore` (21.18s). The live Garage-backed source object was remote-only when backup started; the test verified backup hydration and restored byte-for-byte LFS availability with the object-store endpoint removed. It also checked tenant denial, inherited organization access, LFS lock identity, workspace bytes, revoked browser session, authority rotation, lease epoch fencing/renewal, and stock Git clone plus fsck.
- Static review: no defect found in this closure. Ready rows are enumerated under the exported repeatable-read snapshot; the remote download checks content digest and size before local publication; backup includes hydrated bytes in the volume inventory; restore validates manifest closure, each object’s digest/size, and restored ready-row metadata before publishing the restored volume. The existing `authenticity_verified=false` and loopback-only limitation are accurately reported.
- Status: reviewed for this exact binary/commit; no completion claim beyond the exercised backup/restore path.
