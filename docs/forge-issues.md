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
`token/user -> repository -> optional creation key -> allocation counter/Issue/comment`. Token and
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
| GET `/issues` | `?after=0&limit=50&state=open` (`state` optional) | 200 paged Issues |
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
labels, assignees, search or PR linkage is implied.

List responses are `{"items":[...],"next_after":7}`. `next_after` is null when no
further row was observed. Results are ascending immutable local numbers;
`after` defaults to 0 and must be nonnegative. `limit` defaults to 50 and must be
1–100. Keyset pagination is a live view, not a transaction snapshot spanning
multiple HTTP requests. New rows can appear on later pages; edits do not reorder
existing rows. Reusing a number cursor never changes repository authorization.

Issue lists optionally accept `state=open` or `state=closed`. Omitting `state`
returns both states, preserving the original API. Values are case-sensitive;
empty, unknown and repeated values return 400. Comment lists do not accept
`state`. Filtering happens before the page limit, so `next_after` identifies the
last returned matching Issue only when another matching Issue was observed.

The filter is a live view too. Closing or reopening an Issue ahead of the cursor
can add or remove it from later pages. A newly matching Issue at or below the
cursor is not revisited; restart at `after=0` to reconsider earlier numbers.
Changing filters while retaining a cursor simply keeps its numeric lower bound,
so restart pagination when switching filters if the full new result is needed.
Reads, filtering and cursors never grant write access or bypass a recovering
repository's freeze. The existing tenant/repository/number primary-key index remains available;
no migration or backup format changes. Sparse state matches can require
scanning many rows, so this slice makes no large-repository throughput promise.

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

### Retrying creation

Both POST routes accept an optional `Idempotency-Key` header. Existing requests
without it retain non-idempotent behavior: each successful POST allocates a new
resource. A lost response without a key requires inspecting current records
before retrying; an error or disconnection alone does not prove rollback.

A key must be exactly one header containing 1–128 ASCII letters, digits, `.`, `_`,
`:` or `-`. Empty, repeated and comma-combined headers are rejected with 400.
Use a fresh unpredictable operation identifier, such as a UUID, for each intended
creation, and persist it before sending the request. A key is not a credential.

The key namespace is the authenticated personal user and repository, shared by
Issue and comment creation. The same key and same validated request return the
original 201 JSON, including the original timestamps and version, without a new
number or row. JSON field order, whitespace and escape spelling do not matter;
an omitted Issue body equals an empty body. Text is otherwise compared exactly,
without Unicode normalization. Changing the title/body, operation type or target
Issue under the same key returns 409. Different users or repositories may use
the same key independently. Invalid requests are not recorded.

Replay returns the **creation response**, not current content: later edits or
closure do not replace it. GET the resource to see its current state. Replays
still require a current write-capable token and a ready repository. Revoked,
expired or read-only tokens cannot replay, and a Basic username must still match.
A replacement write token for the same user can retry an earlier key because
idempotency is scoped to the user, not to one token. Token locks and the final
expiry check apply to both initial creation and replay.

A unique PostgreSQL key serializes simultaneous attempts. The key record,
allocation, resource and original response commit in one transaction. A rolled
back attempt leaves none of them, allowing a waiting retry to create once. A
committed attempt with a lost response can be retried with the same key. An
incomplete stored response fails closed with 503 instead of creating a duplicate.
There is no separate in-memory cache or time-limited reservation to lose on
process restart. SQL-failure tests prove only their deliberately injected
boundaries, not all possible database/network failures.

Keys have no automatic expiry and must not be deleted or reused within the same
database history. Each record is bounded, but this is not a repository storage
quota or rate limit. Backup and restore include the records; keys committed only
after the recovery point are lost along with their resources and may create
again after restore. Idempotency does not bridge disaster-recovery timelines or
provide external exactly-once effects. Review current restored content before
resuming uncertain pre-cutover operations.

## Migration and integration

`006_forge_issues.sql` is recorded as version 6, and
`007_forge_idempotency.sql` as version 7. The existing migrator explicitly
checks each supported version, so gaps 4/5 are valid on this branch. It runs
under the existing advisory lock in the same transaction as all pending schema
changes. The migration creates:

- `forge_issue_counters` with a composite primary/foreign key.
- `forge_issues` with scoped numbering, author/state/version/text constraints.
- `forge_issue_comments` with a composite Issue foreign key.
- `forge_creation_requests` with a personal-owner/repository-scoped unique key,
  bounded key/request/response values and the original creation response.

The existing phase-two `repositories_owner_identity` unique index on
`repositories(id,owner_id)` is reused; no repository constraint is replaced.

No SQL function, trigger, custom enum/type, external queue or Git ref is added.
The migration is executed once through `db::migrate`; do not rerun its raw SQL
manually. Repeated migrator calls are safe and tested. An interrupted/conflicting
schema migration rolls back all of that migration's changes and version record.

The integrated branch includes format-4 offline backup and isolated restore for
exactly `[1,2,3,6,7]`, with all fifteen tables in the snapshot lock list. All three reviewed
canonical catalog forms include all four Forge tables, composite keys, checks,
indexes and internal-trigger enabled state. The full public dump preserves Issue
and comment contents, revisions, timestamps, allocation counters and creation
idempotency records. A committed incomplete response is rejected before backup
and during restore validation. No arbitrary
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
Run `tests/forge_idempotency.py` for the optional key contract, concurrent retries,
transaction rollback, permission races and durable original-response replay.
See [the idempotency verification record](forge-idempotency-verification.md).
Run `tests/forge_state_filter.py` for filtered pagination, live state changes,
strict query validation and unchanged authorization boundaries. See
[the state-filter verification record](forge-state-filter-verification.md).

Still absent: organization/shared-repository permissions, PRs/revisions/reviews,
checks, merge/CAS integration, task/thread/ChangeSet relations, LFS, external CI,
webhooks, Web UI, Markdown rendering, deletion and quotas.
No throughput, HA, power-loss or production recovery guarantee is made. Adding PRs
later must bind reviews/checks to immutable revisions and exact base/head OIDs;
Issue text and comment changes must not become code revision identities.
