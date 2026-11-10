# Retention roots and authorized ref publication

This library increment builds on the registered-pack reads in
[materialized reads](ref-store-materialized-reads.md). Migration 144 adds
retained roots, a publication-decision ledger and a separate per-repository
protocol realm. It introduces no HTTP route or serving cutover. Existing
repositories continue using their existing authority until explicitly provisioned.

## Durable roots

`PgRetentionRoots::prepare` captures a real A5 pack snapshot under its live pin,
then validates registered Blob bytes and native Git closure outside PostgreSQL.
The opaque candidate can be registered only while that exact source remains
valid. A root retains its own refs, selected OIDs and complete registered
pack/index identities. An exact OID selector can retain an object that is no
longer a current ref target; snapshot selection retains the captured ref set.

The registered root is independent of the source pin's later expiry/release.
Materialization reads the retained rows, verifies bytes with the shared bounded
native engine, then rechecks the live realm and active root at a final locked
T2 admission point. Releasing the root before T2 refuses a new view. A local
copy admitted earlier is not revocable. Released roots, receipts and usage are
retained; root IDs cannot be reused. Release-before-register writes a tombstone
bound to the expected register digest and blocks delayed registration.

Whole-repository deletion preserves historical root metadata and locators but
removes the live gate needed for a new byte view. This is retention metadata;
it adds neither a physical GC consumer nor an automatic Blob deletion path.

## Publication decisions

The supported actor is a real writable API-token identity, bound to the
operation issuer. `PgAuthorizedCommit` stages pack publication as follows:

1. `prepare` captures the existing pending operation, gate, refs and pack set.
2. `select` gathers actual native facts without a PG client, then locks the
   actual authorization/policy source tables and installs a sealed selection
   and single-use decision in a short transaction.
3. `verify` validates the complete resulting ref map and native closure for
   that exact selection, using the original whole-operation identity.
4. `commit` rechecks current authority, policy, realm, capture and proof, then
   consumes the decision in the same transaction as selected ref effects,
   gate revision, terminal result, event and retained quota charges.

`PgAuthorizedMetadata` performs the corresponding decision install/final commit
for a real `CommitRefsRequest` on a `metadata_only` gate. Its receipts attest
metadata, without claiming object availability or fabricating a pack proof.
Both facades return exact historical terminals before fresh-write checks.

Decision install enables the irreversible `decision_required` fence in the
same transaction. Fresh legacy metadata and A4 writes then refuse; exact old
terminal replay remains available. Authorization and policy sources use
`SHARE NOWAIT` locks covering real writers and phantom inserts, followed by
the repository/usage/gate/protocol/decision row order. Current facts are
recomputed at final admission; token expiry bounds the decision window.
Contention or timeout requires retry under the same operation identity.

Authorized cancellation writes both the migration-138 tombstone and the
decision tombstone in one transaction. Commit and cancellation share the
operation prefix, so only one terminal outcome wins. Cancellation requires
current repository owner/admin authority. An ambiguous COMMIT remains unknown;
it grants no refund or new authority and must be resolved through the durable
operation record.

## Accepted subset

Atomic mode keeps all-or-nothing semantics. Accepted-subset mode records a
verdict for every original ref in original request order and applies only the
sealed accepted updates. A stale CAS, missing new target, non-commit branch
target or per-ref policy refusal need not hide a valid sibling. Shared pack
corruption or missing old captured objects fail the whole operation. Namespace
and HEAD rules use the same original-order selection as the writer; final
verification cannot silently shrink a previously selected set.

An all-rejected selection writes a durable rejected result with no ref,
membership or gate-revision change. A final authorization/policy change also
records a durable rejection. Aggregate terminal bodies remain limited to
64 KiB. Retained quotas grow monotonically, including rejection/cancellation
data and metadata terminal/event copies; exact replay charges zero. Quota
refusal rolls back the complete transaction and never causes pruning.
Admission conservatively reserves metadata terminal/event bytes and one
cancellation record for an installed decision. Finalization uses that retained
reservation, so later admissions filling the counter cannot strand an already
installed metadata decision. Unused reservation is never refunded.

## Verification and boundaries

The dedicated integration targets are `ref_store_retention_roots` and
`ref_store_decision_subset`. Their ignored cases require explicit PostgreSQL,
S3 and trusted Git configuration and must be run with
`--ignored --test-threads=1`; ordinary Cargo tests do not qualify those paths.
The populated format20 backup harness is
`tests/backup_refstore_roots_decisions144.py`, using its separately built typed
fixture. `tests/backup_legacy143_roots_decisions.py` requires a genuine frozen
format19 producer and old A5 fixture, then verifies preservation through the
explicit schema143 upgrade. See [backup and restore](backup-restore.md).

Browser-session authorization, pull-request Merge producers/finalization,
distributed Raft barriers and service activation remain separate work. Merge
fails closed in this increment. LFS pointers require durable remote byte
attestation; a local file or `ready` metadata row cannot grant it, so the
current facade refuses pointer-bearing refs. Backups archive PostgreSQL
metadata and do not copy external Blob bytes. Issues close only after merge
and completed acceptance; source or test existence alone is not acceptance.
