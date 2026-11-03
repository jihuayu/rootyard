# Private-owner Issue and comment slice

This is an initial phase-six API slice built on the phase-two recovery baseline.
It is **not a complete Forge**. The existing access model remains unchanged:
users can access only repositories they own. `tenant_id` on the new tables is
exactly that personal owner's user ID. Organizations, memberships, collaborator
roles and cross-user Issue participation do not exist yet. No token obtains
permissions merely by knowing an Issue number or repository UUID.

## Authorization and transactions

All eight endpoints authenticate a current token. Read-only tokens can read and
list but cannot create or modify Issues or comments. Bearer and existing Basic
credentials work; a Basic username must match the token principal. The server
assigns the author, repository, tenant and numbers; clients cannot choose them.
Another authenticated owner receives the same 404 as a nonexistent repository.
Repositories must be `ready`; provisioning/recovering repositories return 409.

Each request opens a PostgreSQL transaction and acquires locks in the order
`token/user -> repository -> allocation counter/Issue/comment`. Token and
repository rows are share-locked until commit. The request rechecks token owner,
revocation, read-only status and expiry using the database clock after acquiring
the locks, and again immediately before commit. A token revoked before this
locked authorization cannot mutate data. A revoke that follows the request's
lock waits for that request's transaction; it does not retroactively cancel a
previously authorized mutation. Expiry while waiting for a counter/Issue row
causes rollback. The small interval between the final expiry check and COMMIT
is not a database-wide scheduled cancellation mechanism.

Every data query is scoped by both personal tenant and repository. Composite
foreign keys bind comments to the same tenant/repository/Issue and bind Issues
and counters to the actual repository owner. Database checks additionally
require the author to be that owner. These are application and relational
constraints, not PostgreSQL row-level security for untrusted direct SQL users.
Database administrators remain trusted.

Creation allocates monotonic repository-local Issue numbers and Issue-local
comment numbers transactionally, without `max(number)+1`. A failed insert rolls
back its allocation. Mutation requires `expected_version`, with one successful
update per current version and 409 on stale/concurrent updates. Comments have
their own version and do not change the Issue's content version. There is no
hard-delete endpoint or number reuse within an uninterrupted database history. A point-in-time restore rewinds allocation counters: numbers allocated only after the backup can be reused after that acknowledged data is lost. Versions also rewind and may recur after restoration. CAS is scoped to the current database history, not a disaster-recovery epoch. Review external references before reopening a restored service, and have clients GET the restored content/version rather than reuse cached post-boundary identities or versions as a recovery fence.

## HTTP contract

All paths below are relative to `/api/repos/{owner}/{name}`.

| Method and path | Body/query | Result |
| --- | --- | --- |
| POST `/issues` | `{"title":"Example","body":"optional text"}` | 201 Issue |
| GET `/issues` | `?after=0&limit=50` | 200 paged Issues |
| GET `/issues/{number}` | none | 200 Issue |
| PATCH `/issues/{number}` | `{"expected_version":1,"title":"optional","body":"optional","state":"closed"}` | 200 new Issue version |
| POST `/issues/{number}/comments` | `{"body":"Comment text"}` | 201 comment |
| GET `/issues/{number}/comments` | `?after=0&limit=50` | 200 paged comments |
| GET `/issues/{number}/comments/{comment_number}` | none | 200 comment |
| PATCH `/issues/{number}/comments/{comment_number}` | `{"expected_version":1,"body":"Edited text"}` | 200 new comment version |

`state` is `open` or `closed`; reopening is supported. At least one non-null
mutable field is required for Issue PATCH; omitted/null optional fields are
unchanged. Version and resource numbers are positive signed 64-bit integers.
Unknown request fields and duplicate query fields are rejected. No delete,
state filter, labels, assignees, search or PR linkage is implied.

List responses are `{"items":[...],"next_after":7}`. `next_after` is null when no
further row was observed. Results are ascending immutable local numbers;
`after` defaults to 0 and must be nonnegative. `limit` defaults to 50 and must be
1–100. Keyset pagination is a live view, not a transaction snapshot spanning
multiple HTTP requests. New rows can appear on later pages; edits do not reorder
existing rows. Reusing a number cursor never changes repository authorization.

Titles must be nonblank, at most 256 UTF-8 bytes and have no control characters.
Issue bodies can be empty; comment bodies must be nonblank. Bodies are at most
8,192 UTF-8 bytes and allow newline, carriage return and tab but no other control
characters. The total JSON request limit remains 16 KiB, including JSON escapes.
Nonempty Unicode titles and bodies are preserved without normalization. Content
is returned as JSON text, never rendered HTML; any future UI must safely render
untrusted Markdown separately. Successes and application errors use `no-store`.

Missing resources return 404, stale versions/not-ready repositories 409,
invalid domain input 400, malformed/unknown JSON input 400/422, oversized JSON
413, and unavailable database operations 503. Malformed extractor requests may
use Axum's default error format. A server error intentionally does not expose
SQL or token contents.

POST creation is **not idempotent** across retries. A lost HTTP response can hide
a committed Issue/comment. Inspect current records before retrying uncertain
creation; do not assume an error or connection loss means rollback. The supplied
SQL-failure tests establish rollback only at the deliberately injected boundary.

## Migration and integration

`006_forge_issues.sql` is recorded as version 6. The existing migrator explicitly
checks each supported version, so gaps 4/5 are valid on this branch. It runs
under the existing advisory lock in the same transaction as all pending schema
changes. The migration creates:

- `forge_issue_counters` with a composite primary/foreign key.
- `forge_issues` with scoped numbering, author/state/version/text constraints.
- `forge_issue_comments` with a composite Issue foreign key.

The existing phase-two `repositories_owner_identity` unique index on
`repositories(id,owner_id)` is reused; no repository constraint is replaced.

No SQL function, trigger, custom enum/type, external queue or Git ref is added.
The migration is executed once through `db::migrate`; do not rerun its raw SQL
manually. Repeated migrator calls are safe and tested. An interrupted/conflicting
schema migration rolls back all of that migration's changes and version record.

The integrated branch includes format-3 offline backup and isolated restore for
exactly `[1,2,3,6]`, with all fourteen tables in the snapshot lock list. All three reviewed
canonical catalog forms include the three Forge tables, composite keys, checks,
indexes and internal-trigger enabled state. The full public dump preserves Issue
and comment contents, revisions, timestamps and allocation counters. No arbitrary
schema or migration versions are accepted. Earlier format/schema archives need
their matching original executable and a separate reviewed upgrade.

See [the backup contract](backup-restore.md) and [populated Forge restore evidence](forge-backup-verification.md).
Forge writes after the captured boundary are outside the backup, just like later
Git pushes. Restore does not authorize a recovering repository or change token
permissions; standalone workers must stay stopped until the new target succeeds
and is reviewed.

## Verification and deliberate limits

See [the dated verification record](forge-verification.md) for actual passed
checks, tool versions and remaining integration gates.

Run `python3 tests/forge.py --binary target/debug/rootyard --report
test-results/forge.json` with `ROOTYARD_TEST_DATABASE_URL` pointing to a disposable
PostgreSQL 17 database. The existing harness gives the run a unique schema and
removes only its fixtures. This covers migration replay/atomic failure, HTTP
contracts, privacy, read-only/expired/revoked tokens, forged author input,
relational isolation, UTF-8/request bounds, pagination, concurrent allocation,
CAS updates, injected insert rollback, authorization races and process restart.

Still absent: organization/shared-repository permissions, PRs/revisions/reviews,
checks, merge/CAS integration, task/thread/ChangeSet relations, LFS, external CI,
webhooks, Web UI, Markdown rendering, deletion, quotas and idempotent creation.
No throughput, HA, power-loss or production recovery guarantee is made. Adding PRs
later must bind reviews/checks to immutable revisions and exact base/head OIDs;
Issue text and comment changes must not become code revision identities.
