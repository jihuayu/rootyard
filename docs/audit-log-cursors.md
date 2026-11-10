# Repository audit log: cursor ordering and restore qualification

Status: acceptance implemented for the issue #7 audit-ID sequence; final CI,
independent review and PR merge are pending. This page describes the API and
backup behavior the current binary implements. It is not a production RPO/RTO
or HA claim, and it is not a historical `MAX(id)+1` replay.

## Reading the audit log

`GET /api/repos/{owner}/{name}/audit?after=&limit=&actor=&action=&since=&until=`
(requires repository maintain access; restricted tokens need the
`members_read` scope) returns
`{"items":[...],"next_after":7}` with items in ascending `id` order. `after`
defaults to 0 and must be nonnegative; `limit` defaults to 50 and must be 1–100.

The `id` is a stable, ascending cursor:

- It is allocated by the PostgreSQL sequence `repository_audit_log_id_seq`
  attached to `repository_audit_log.id` (migration 110) at insert time, not
  from `MAX(id)+1`, not from a transaction commit time and not from Git
  commit order.
- The sequence is global; `id` is not dense per repository. Gaps are legal: a
  rolled-back write consumes its value, and another repository's rows occupy
  the numbers in between. A page for one repository can therefore jump, and
  `next_after` is that page's last returned `id`, never the last one plus one.
- Pagination is keyset (`id > after ORDER BY id ASC`) and each page is its own
  read, so it is a live view rather than one snapshot across requests. While
  audit writes are concurrent it does **not** promise to capture every row
  committed later with a lower `id`: a transaction that reserved an id before
  an earlier page read and committed after that page's cursor passed it is
  not returned. Restart at `after=0` to re-scan.
- Once writes finish, walking from 0 (or from a saved floor) in ascending
  `id` order returns the complete stable set. Persist the last observed `id`
  as the floor for the next incremental read.
- `actor`, `action`, `since` and `until` filters apply after the id lower
  bound; tightening a filter while keeping `after` keeps that numeric floor,
  so restart from 0 when the full filtered result is required.

## Restore qualification (issue #7)

`tests/backup_audit_sequence_legacy.py` is the native recovery drill, run by
the `verify` job of `.github/workflows/ci.yml` beside `tests/backup.py` (which
it does not replace) with the PostgreSQL 17 service, the source-bound built
binary and the job fixture environment:

```sh
python3 tests/backup_audit_sequence_legacy.py --binary target/debug/rootyard \
  --report test-results/audit-sequence-backup.json
```

What it establishes, through the CLI and real HTTP/Git only:

- It takes a format 21, metadata-only archive of a real GitFS source served
  by the current source-bound binary (no Blob serving, no format 22 closure)
  and restores it with `restore --isolated` into a brand-new database and
  data directory.
- Real API audit writes after the restore allocate ids strictly above every
  pre-backup id; the ascending `?after=` cursor walk matches the SQL id set,
  and all pre-backup rows are unchanged in every column, `created_at`
  included.
- A single post-restore write, then 32 concurrent real audited writes in one
  restored repository, each allocate one new id and are found by the cursor.
- Git pushes before the backup are proved to be Git/`audit_events` facts:
  they record no `repository_audit_log` row.
- A labelled missing-default control drops the migration-110 sequence default
  in the restored run-owned database only and shows audit writes then fail
  without server-side allocation. It does not reproduce the historical
  `MAX(id)+1` algorithm or its race, and the database is then re-imported
  from the same archive.

Limits: this is a loopback functional drill of one metadata-only format 21
archive, not production RPO/RTO, power-loss, HA or cross-host qualification,
and it is not a Blob-closure backup. The cross-repository concurrency evidence
(32 concurrent audited writes hitting two repositories) is the separate
`tests/members.py` case, whose report is produced by CI and current-coordinator
runs; no such report is claimed by this page. Gaps after rolled-back writes
remain expected in restored data. Issue #7 is closed only after the final CI
pass, independent review and merge.
