# Web repository discovery pagination — partial issue #74

`GET /web/repos` now traverses all authorized repositories in bounded 100-row keyset pages rather than silently dropping everything beyond the first page. Current membership and restricted-token grants are applied before the cursor predicate. The opaque position is bound to actor/list/audience; it is not a signed capability or a snapshot.

All-target Clippy and all eight [native cases](round5-web-discovery-evidence/native.json) passed: 106 repositories across two pages, malformed/foreign cursors, access removal, read-only browser and bearer traversal, restricted/empty grants and anonymous navigation. Bulk repository rows and restricted scope rows are explicitly SQL-seeded in this harness; the real API creates the disk-backed fixture repository. No scale benchmark is claimed.

The [fresh build receipt](round5-web-discovery-evidence/build.json) binds binary `9e9578fe121caa7d016eecb242412facea04ac7409e74faa5c346a94ba4af570`, source `e011b2d5b5e84d7ddaeedb2df06f4de48067efbd`, compiled inputs `9f33758696c25d0e5d73caffe0e98ea6e6b98edde1bd7d62dd4d63f5d3534829`. Later test-only changes corrected read-only assertions to traverse both pages. Luna Max review is pending.

This does not close every listing requirement in #74: token grant-picker lists and other administration lists still need their own pagination and acceptance. No production deployment, browser rendering or complete issue-82 acceptance is claimed.
