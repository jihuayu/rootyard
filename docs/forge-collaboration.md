# Forge Collaboration: Search, Labels, Assignees, Subscriptions, Notifications, and Inline PR Review

This document specifies the delivered behavior, authorization boundaries, optimistic concurrency guarantees, database layout (Migration `150`), and Web UI parity for Issue #86.

## 1. Search (`/api/search`, `/api/repos/{owner}/{name}/search`)

- **Scopes**: `all`, `repositories`, `issues`, `pulls`, `comments` (`comments` searches visible Issue comments and visible inline PR review comments).
- **Deterministic Total-Order Pagination**:
  - `sort=updated` (default): orders by `(updated_at DESC, owner ASC, repo ASC, kind ASC, number ASC, comment_number ASC)`.
  - `sort=number`: orders by `(number DESC, owner ASC, repo ASC, kind ASC, comment_number ASC)`.
  - `cursor` is an opaque HMAC/scoped keyset token bound to `(scope, sort, query, actor_id, repository_scope)`; mismatched or tampered cursors return `400 Bad Request`.
- **Live Permission Filtering**:
  - Evaluates live repository visibility, ownership, org membership/teams, repo collaborators/teams, and restricted PAT action scopes (`repo_read`, `issues_read`, `pulls_read`) inside the transaction so revoked membership or narrowed PAT scopes hide results immediately.
- **Moderation & Soft-Delete Exclusion**:
  - Comments with `moderation_state <> 'visible'` (`hidden` or `deleted`) are excluded from search hits.

## 2. Labels & Assignees

- **Repository Labels (`forge_labels`)**:
  - `GET/POST /api/repos/{owner}/{name}/labels` (`Idempotency-Key` supported on `POST`).
  - `GET/PATCH/DELETE /api/repos/{owner}/{name}/labels/{label}` (`expected_version` optimistic concurrency; `PATCH` cascades name updates to `forge_issue_labels` and `forge_pull_labels` via `ON UPDATE CASCADE`).
- **Issue & PR Label Attachments (`forge_issue_labels`, `forge_pull_labels`)**:
  - `GET/PUT/POST /api/repos/{owner}/{name}/issues/{number}/labels` and `.../pulls/{number}/labels` (`PUT` replaces set, `POST` adds with optional `Idempotency-Key`), `DELETE .../{label}?expected_version=...`.
  - Protected by per-target `label_version` (`FOR UPDATE` row lock + `409 Conflict` on mismatch) and `forge_labels` `FOR SHARE` existence lock.
- **Issue & PR Assignees (`forge_issue_assignees`, `forge_pull_assignees`)**:
  - `GET/PUT/POST /api/repos/{owner}/{name}/issues/{number}/assignees` and `.../pulls/{number}/assignees`, `DELETE .../{username}?expected_version=...`.
  - Every assignee is validated against live repo effective membership (`rbac::resolve_effective_role_by_id` >= `Role::Read`, covering personal owners, org members/teams, and repo collaborators/teams); non-members are rejected.
  - Protected by `assignee_version` (`409 Conflict` on stale expected version) and emits `issue_assigned` / `pull_assigned` notifications.

## 3. Subscriptions & Idempotent In-App Notifications

- **Subscriptions (`forge_subscriptions`)**:
  - `GET/PUT/DELETE` on `/api/repos/{owner}/{name}/subscription`, `/issues/{number}/subscription`, `/pulls/{number}/subscription`.
  - States: `subscribed` (watch) or `ignored` (explicit mute overriding repo-level watch); `expected_version` enforces `409 Conflict` CAS on updates/deletes.
- **In-App Notifications (`forge_notifications`)**:
  - Channel is `"in_app"` (`NOTIFICATION_CHANNEL = "in_app"`).
  - Delivery idempotency is enforced by `UNIQUE (recipient_id, delivery_key)` with `ON CONFLICT DO NOTHING`.
  - Retention is 90 days (`NOTIFICATION_RETENTION_DAYS = 90`, `expires_at = created_at + INTERVAL '90 days'`); expired rows are excluded from `GET /api/notifications` and purged via `POST /api/notifications/prune`.
  - Read acknowledgment (`POST /api/notifications/{id}/read`) is idempotent (`already_read: bool`); bulk ack via `POST /api/notifications/read-all`.
  - All notification reads and acks re-check live repository visibility and restricted PAT read grants.

## 4. Inline PR Review Comments, Outdated Detection & Moderation

- **Anchored Line Comments (`forge_pull_review_comments`)**:
  - `GET/POST /api/repos/{owner}/{name}/pulls/{number}/review-comments`, `GET/PATCH/DELETE .../review-comments/{comment_number}`, `POST .../moderate`, `GET .../revisions`.
  - Anchored to `(commit_oid, base_oid, pull_version, path, side, line)` with normalized relative paths (`side` in `left|right`, `1 <= line <= 10_000_000`).
  - Creation verifies against live Git repository data under read lease (`git diff --name-only base_oid head_oid -- path` and `git cat-file blob side_oid:path` line count). Replies (`in_reply_to_number`) must match the parent comment's `(path, side, line)`.
- **Outdated Tracking**:
  - Advancing PR `head_oid` or `base_oid` preserves historical `(commit_oid, base_oid, pull_version)` coordinates on both `PullReview` and `PullReviewComment` while dynamically computing `outdated = commit_oid != head_oid` (reviews) and `outdated = commit_oid != head_oid || base_oid != base_oid` (line comments).
- **Edits, Soft Delete & Moderation (`forge_comment_revisions`, `repository_audit_log`)**:
  - Supported uniformly across Issue comments (`/api/repos/{owner}/{name}/issues/{number}/comments/{comment_number}*`) and PR inline review comments.
  - Authors and maintainers (`Role::Maintain`) may edit (`edited_at`) or soft-delete (`deleted_at`, `deleted_by`, `moderation_state='deleted'`).
  - Maintainers may `hide`, `unhide`, or `delete` via `/moderate`. `hide` preserves the underlying comment `body` in PostgreSQL so `unhide` restores it cleanly, while reads mask `hidden` as `"[hidden by moderator]"` and `deleted` as `"[deleted]"`.
  - Every edit, soft-delete, and moderation transition appends an immutable row in `forge_comment_revisions` and records an audit event in `repository_audit_log`.

## 5. Web UI & Backup Parity

- Browser HTML views and CSRF-guarded mutation routes are served under both `/web/*` and `/ui/*` (`src/web/collaboration.rs`, `src/web/collaboration_actions.rs`, `src/web/collaboration_views.rs`):
  - `/web|ui/search`, `/web|ui/notifications`, `/web|ui/notifications/read-all`, `/web|ui/notifications/{id}/read`
  - `/web|ui/repos/{owner}/{name}/search`, `/labels*`, `/subscription`, `/issues/{number}/*`, `/pulls/{number}/*`
- PG Migration `150_forge_collaboration.sql` adds the 9 tables (`forge_labels`, `forge_issue_labels`, `forge_pull_labels`, `forge_issue_assignees`, `forge_pull_assignees`, `forge_pull_review_comments`, `forge_comment_revisions`, `forge_subscriptions`, `forge_notifications`) and column extensions, and backup/restore format `27`/`28` covers all new schema artifacts and sequences end-to-end.
