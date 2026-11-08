# Bounded web detail history

Issue comments and pull-request reviews now use ascending number keysets with a 100-row page and a one-row continuation probe. Cursors bind the actor, repository, parent number and list kind; every page rechecks current authorization. Mutation responses and idempotent comment replay render the first page with its continuation link. The UI no longer recounts all historical comments to render one page.

The [native report](round5-web-detail-evidence/native-pagination.json) passed all eight cases against [this attested build](round5-web-detail-evidence/build.json): traversal, page boundaries, malformed/cross-parent/cross-kind cursors, review traversal, anonymous rejection, mutation rendering, collaborator cursor binding and membership/token revocation. The history fixture contains 105 operator-seeded rows per list; parents and additional mutations are real HTTP/Git operations. This is functional evidence on disposable loopback PostgreSQL, not a throughput benchmark or a snapshot-pagination guarantee.

The candidate passed formatting and all-target Clippy. An independent GPT-6 Luna reviewer at max effort found no blocking P1/P2 in this scope. The exact build input digest and executable SHA are retained in the receipt; subsequent evidence-only commits do not change compiled inputs.

This advances #74. API repository and organization pagination are in the parent stack; web repository discovery still has a separate first-page limit and remains open. No completion of the whole issue or all open issues is claimed.
