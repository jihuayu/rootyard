# Retention roots and authorized ref publication

This library increment builds on the registered-pack reads in
[materialized reads](ref-store-materialized-reads.md). Migration 144 adds
retained roots, a publication-decision ledger and a separate per-repository
protocol realm. It introduces no serving cutover. Existing
repositories continue using their existing authority until explicitly provisioned.
The roots HTTP surface is limited to the metadata/intent transport and the
authorized tree/blob browsing described below; no root tree writes, current
refs fallback or #174 session/proof is exposed.

## Metadata and intent HTTP transport

The opt-in serve-blob gateway exposes only these retention-root controls:

```text
POST   /api/repos/{owner}/{name}/roots
GET    /api/repos/{owner}/{name}/roots/{root_id}
DELETE /api/repos/{owner}/{name}/roots/{root_id}
POST   /api/repos/{owner}/{name}/roots/release-intent
```

Create accepts an opaque create key, source snapshot UUID, bounded purpose and
tagged `snapshot`/`oids` selector (at most 256 full OIDs). It has no client root
id, digest, pin, scope, epoch, backend or native field. The response is 201 on
first registration and 200 with `replayed=true` for an exact retry. Metadata GET
returns only current root state, generation, purpose, selector kind, object
format, HEAD and row counts. Receipts expose only action, root id, generation,
replay flag, creation time, `receipt_only` and historical `receipt_state`; the
stored receipt body/internal root rows are never serialized. No session/HWM or
#174 proof is issued. Every response is bounded `application/json`, no-store
and session-header-free, with API Bearer challenges on 401.

DELETE releases an existing root by id. `POST .../release-intent` accepts the
bounded original create intent plus a release key/reason and derives the root id
server-side, so release-before-register needs no client root id. Existing and
exact-release/intent replays remain source-pin independent after source release,
expiry or source-snapshot loss where retained rows suffice. A changed source,
selector or purpose under the same create key conflicts after current late write
authorization and does not touch an existing root.

All mutations require current Owner/Admin + ContentsWrite and metadata requires
current Owner/Admin + ContentsRead in the coordinator; HTTP performs no SQL or
authority derivation. An ambiguous retention-root COMMIT is reported as 503 and
must be retried with the exact same key and body; no client retry may switch to a
new idempotency key or claim failure. Post-encoding byte races and full
HTTP/native/CI acceptance remain later work.

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

## Root tree/blob browsing

```text
GET /api/repos/{owner}/{name}/roots/{root_id}/tree
GET /api/repos/{owner}/{name}/roots/{root_id}/blob/{oid}
```

Both routes require current Owner/Admin + ContentsRead through the serving
coordinator. The coordinator materializes the retained root's exact verified
pack/index bytes, and the gateway copies them into a private disposable Git
view for bounded Browse parsing. The retained context remains alive through the
copy, native reads and full JSON encoding; after encoding, one final bounded
transaction rechecks current authorization, root activity, binding, opened
Blob backend, ready realm and the original cluster anchor before any body is
served. PostgreSQL is not held across pack/native/file/JSON work. Successful
and refused responses are bounded no-store JSON and never issue a
`X-Rootyard-Session`; refusals use the fixed API error vocabulary and a single
Bearer challenge.

Selector semantics are strict:

- A **snapshot** root installs its stored captured refs and HEAD exactly.
- An **explicit ObjectIds** root installs only
  `refs/roots/oid/<full-selected-oid>` for the root's stored selected OIDs, and
  sets HEAD to the unborn private
  `refs/heads/rootyard-retained-unborn`. No captured refs, captured HEAD or
  current refs are installed. Therefore default/`HEAD` tree reads return 404;
  clients must supply a selected/reachable full OID or the exact synthetic ref.
- The entire reachable closure of the selected objects is browsable, including
  descendant trees/blobs, commit history and annotated-tag peeling. Objects
  present in the same verified packs but outside that closure are 404.

SHA-1 and SHA-256 roots use the same object-format-sized pack trailer/index
checksum naming and bounded path/pagination/blob ceilings. No current GitFS or
Pando authority is consulted, and no session, HWM or #174 proof is produced.
Native/HTTP/CI and full #107 qualification remain pending.

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
