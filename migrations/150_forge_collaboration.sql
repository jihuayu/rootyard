-- Issue #86: Collaboration features (labels, assignees, subscriptions,
-- idempotent in-app notifications, inline diff PR review comments, and comment
-- edit/soft-delete/moderation audit history).
-- All range predicates use explicit >= and <= (never BETWEEN) for pg_dump
-- catalog normalization invariance across fresh, restored, and upgraded schemas,
-- and interval defaults use make_interval(...) for intervalstyle invariance across
-- psql and rootyard backup/restore sessions.

ALTER TABLE forge_issues
    ADD COLUMN IF NOT EXISTS label_version BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS assignee_version BIGINT NOT NULL DEFAULT 1;

ALTER TABLE forge_issues
    ADD CONSTRAINT forge_issues_label_version_check CHECK (label_version > 0),
    ADD CONSTRAINT forge_issues_assignee_version_check CHECK (assignee_version > 0);

ALTER TABLE forge_issue_comments
    ADD COLUMN IF NOT EXISTS edited_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS deleted_by UUID REFERENCES users(id),
    ADD COLUMN IF NOT EXISTS moderation_state TEXT NOT NULL DEFAULT 'visible',
    ADD COLUMN IF NOT EXISTS moderated_by UUID REFERENCES users(id),
    ADD COLUMN IF NOT EXISTS moderated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS moderation_reason TEXT NOT NULL DEFAULT '';

ALTER TABLE forge_issue_comments
    ADD CONSTRAINT forge_issue_comments_moderation_state_check
        CHECK (moderation_state IN ('visible', 'hidden', 'deleted')),
    ADD CONSTRAINT forge_issue_comments_moderation_reason_check
        CHECK (octet_length(moderation_reason) <= 512 AND moderation_reason !~ '[[:cntrl:]]'),
    ADD CONSTRAINT forge_issue_comments_moderation_consistency_check
        CHECK (
            (moderation_state = 'deleted' AND deleted_at IS NOT NULL AND deleted_by IS NOT NULL)
            OR (moderation_state = 'hidden' AND deleted_at IS NULL AND moderated_at IS NOT NULL AND moderated_by IS NOT NULL)
            OR (moderation_state = 'visible' AND deleted_at IS NULL)
        );

ALTER TABLE forge_pulls
    ADD COLUMN IF NOT EXISTS label_version BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS assignee_version BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS next_review_comment_number BIGINT NOT NULL DEFAULT 1;

ALTER TABLE forge_pulls
    ADD CONSTRAINT forge_pulls_label_version_check CHECK (label_version > 0),
    ADD CONSTRAINT forge_pulls_assignee_version_check CHECK (assignee_version > 0),
    ADD CONSTRAINT forge_pulls_next_review_comment_number_check CHECK (next_review_comment_number > 0);

CREATE TABLE forge_labels (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    name TEXT NOT NULL CHECK (
        octet_length(name) >= 1 AND octet_length(name) <= 64
        AND btrim(name) = name AND btrim(name) <> '' AND name !~ '[[:cntrl:]]'
    ),
    color TEXT NOT NULL CHECK (color COLLATE "C" ~ '^[0-9a-f]{6}$'),
    description TEXT NOT NULL DEFAULT '' CHECK (
        octet_length(description) <= 256 AND description !~ '[[:cntrl:]]'
    ),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, name),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id)
);

CREATE TABLE forge_issue_labels (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    issue_number BIGINT NOT NULL,
    label_name TEXT NOT NULL,
    added_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, issue_number, label_name),
    FOREIGN KEY (tenant_id, repository_id, issue_number)
        REFERENCES forge_issues(tenant_id, repository_id, number),
    FOREIGN KEY (tenant_id, repository_id, label_name)
        REFERENCES forge_labels(tenant_id, repository_id, name)
        ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE forge_pull_labels (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    pull_number BIGINT NOT NULL,
    label_name TEXT NOT NULL,
    added_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, pull_number, label_name),
    FOREIGN KEY (tenant_id, repository_id, pull_number)
        REFERENCES forge_pulls(tenant_id, repository_id, number),
    FOREIGN KEY (tenant_id, repository_id, label_name)
        REFERENCES forge_labels(tenant_id, repository_id, name)
        ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE forge_issue_assignees (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    issue_number BIGINT NOT NULL,
    assignee_id UUID NOT NULL REFERENCES users(id),
    assigned_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, issue_number, assignee_id),
    FOREIGN KEY (tenant_id, repository_id, issue_number)
        REFERENCES forge_issues(tenant_id, repository_id, number)
);

CREATE TABLE forge_pull_assignees (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    pull_number BIGINT NOT NULL,
    assignee_id UUID NOT NULL REFERENCES users(id),
    assigned_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, pull_number, assignee_id),
    FOREIGN KEY (tenant_id, repository_id, pull_number)
        REFERENCES forge_pulls(tenant_id, repository_id, number)
);

CREATE TABLE forge_pull_review_comments (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    pull_number BIGINT NOT NULL,
    number BIGINT NOT NULL CHECK (number > 0),
    review_number BIGINT,
    in_reply_to_number BIGINT,
    author_id UUID NOT NULL REFERENCES users(id),
    commit_oid TEXT NOT NULL CHECK (
        commit_oid COLLATE "C" ~ '^([0-9a-f]{40}|[0-9a-f]{64})$' AND commit_oid !~ '^0+$'
    ),
    base_oid TEXT NOT NULL CHECK (
        base_oid COLLATE "C" ~ '^([0-9a-f]{40}|[0-9a-f]{64})$' AND base_oid !~ '^0+$'
    ),
    pull_version BIGINT NOT NULL CHECK (pull_version > 0),
    path TEXT NOT NULL CHECK (
        octet_length(path) >= 1 AND octet_length(path) <= 1024
        AND path !~ '[[:cntrl:]]'
        AND path NOT LIKE '/%'
        AND path <> '.'
        AND path <> '..'
        AND position('//' in path) = 0
        AND path !~ '(^|/)\.\.(/|$)'
    ),
    side TEXT NOT NULL CHECK (side IN ('left', 'right')),
    line BIGINT NOT NULL CHECK (line >= 1 AND line <= 10000000),
    body TEXT NOT NULL CHECK (
        octet_length(body) >= 1 AND octet_length(body) <= 8192 AND btrim(body) <> ''
    ),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    moderation_state TEXT NOT NULL DEFAULT 'visible' CHECK (moderation_state IN ('visible', 'hidden', 'deleted')),
    edited_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    deleted_by UUID REFERENCES users(id),
    moderated_by UUID REFERENCES users(id),
    moderated_at TIMESTAMPTZ,
    moderation_reason TEXT NOT NULL DEFAULT '' CHECK (
        octet_length(moderation_reason) <= 512 AND moderation_reason !~ '[[:cntrl:]]'
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, pull_number, number),
    FOREIGN KEY (tenant_id, repository_id, pull_number)
        REFERENCES forge_pulls(tenant_id, repository_id, number),
    FOREIGN KEY (tenant_id, repository_id, pull_number, review_number)
        REFERENCES forge_pull_reviews(tenant_id, repository_id, pull_number, number),
    FOREIGN KEY (tenant_id, repository_id, pull_number, in_reply_to_number)
        REFERENCES forge_pull_review_comments(tenant_id, repository_id, pull_number, number),
    CHECK (in_reply_to_number IS NULL OR in_reply_to_number < number),
    CHECK (
        (moderation_state = 'deleted' AND deleted_at IS NOT NULL AND deleted_by IS NOT NULL)
        OR (moderation_state = 'hidden' AND deleted_at IS NULL AND moderated_at IS NOT NULL AND moderated_by IS NOT NULL)
        OR (moderation_state = 'visible' AND deleted_at IS NULL)
    )
);

CREATE INDEX forge_pull_review_comments_lookup_idx
    ON forge_pull_review_comments (tenant_id, repository_id, pull_number, commit_oid, number);

CREATE TABLE forge_comment_revisions (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    target_type TEXT NOT NULL CHECK (target_type IN ('issue_comment', 'pull_review_comment')),
    parent_number BIGINT NOT NULL CHECK (parent_number > 0),
    comment_number BIGINT NOT NULL CHECK (comment_number > 0),
    revision BIGINT NOT NULL CHECK (revision > 0),
    action TEXT NOT NULL CHECK (action IN ('edited', 'hidden', 'unhidden', 'deleted')),
    actor_id UUID NOT NULL REFERENCES users(id),
    previous_body TEXT NOT NULL CHECK (octet_length(previous_body) <= 8192),
    new_body TEXT NOT NULL CHECK (octet_length(new_body) <= 8192),
    reason TEXT NOT NULL DEFAULT '' CHECK (
        octet_length(reason) <= 512 AND reason !~ '[[:cntrl:]]'
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, target_type, parent_number, comment_number, revision),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id)
);

CREATE TABLE forge_subscriptions (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id),
    target_type TEXT NOT NULL CHECK (target_type IN ('repository', 'issue', 'pull')),
    target_number BIGINT NOT NULL DEFAULT 0 CHECK (target_number >= 0),
    state TEXT NOT NULL CHECK (state IN ('subscribed', 'ignored')),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, user_id, target_type, target_number),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id),
    CHECK (
        (target_type = 'repository' AND target_number = 0)
        OR (target_type IN ('issue', 'pull') AND target_number > 0)
    )
);

CREATE TABLE forge_notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    recipient_id UUID NOT NULL REFERENCES users(id),
    actor_id UUID REFERENCES users(id),
    channel TEXT NOT NULL DEFAULT 'in_app' CHECK (channel IN ('in_app')),
    target_type TEXT NOT NULL CHECK (
        target_type IN ('repository', 'issue', 'pull', 'pull_review', 'pull_review_comment')
    ),
    target_number BIGINT NOT NULL DEFAULT 0 CHECK (target_number >= 0),
    event_kind TEXT NOT NULL CHECK (
        event_kind IN (
            'issue_opened',
            'issue_commented',
            'issue_assigned',
            'pull_opened',
            'pull_synchronized',
            'pull_review_submitted',
            'pull_review_commented',
            'pull_assigned',
            'pull_merged'
        )
    ),
    delivery_key TEXT NOT NULL CHECK (
        octet_length(delivery_key) >= 1 AND octet_length(delivery_key) <= 160
        AND delivery_key !~ '[[:cntrl:]]'
    ),
    title TEXT NOT NULL CHECK (
        octet_length(title) >= 1 AND octet_length(title) <= 256
        AND title !~ '[[:cntrl:]]'
    ),
    body_excerpt TEXT NOT NULL DEFAULT '' CHECK (octet_length(body_excerpt) <= 512),
    delivery_count BIGINT NOT NULL DEFAULT 1 CHECK (delivery_count > 0),
    unread BOOLEAN NOT NULL DEFAULT true,
    read_at TIMESTAMPTZ,
    archived BOOLEAN NOT NULL DEFAULT false,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (clock_timestamp() + make_interval(days => 90)),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (recipient_id, delivery_key),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id),
    CHECK (
        (unread = true AND read_at IS NULL)
        OR (unread = false AND read_at IS NOT NULL)
    )
);

CREATE INDEX forge_notifications_recipient_created_idx
    ON forge_notifications (recipient_id, archived, unread, created_at DESC, id DESC);

CREATE INDEX forge_notifications_repo_expiry_idx
    ON forge_notifications (repository_id, expires_at ASC);

CREATE OR REPLACE FUNCTION forge_enforce_review_comment_object_format()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_length INTEGER;
BEGIN
    SELECT CASE object_format WHEN 'sha256' THEN 64 ELSE 40 END
    INTO expected_length
    FROM repositories
    WHERE id = NEW.repository_id;

    IF expected_length IS NULL THEN
        RAISE EXCEPTION 'repository object format missing';
    END IF;

    IF length(NEW.commit_oid) <> expected_length OR length(NEW.base_oid) <> expected_length THEN
        RAISE EXCEPTION 'review comment object format differs from repository';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS forge_pull_review_comments_object_format ON forge_pull_review_comments;
CREATE TRIGGER forge_pull_review_comments_object_format
    BEFORE INSERT OR UPDATE ON forge_pull_review_comments
    FOR EACH ROW EXECUTE FUNCTION forge_enforce_review_comment_object_format();

DROP TRIGGER IF EXISTS enforce_forge_pull_review_comments_actor_membership ON forge_pull_review_comments;
CREATE TRIGGER enforce_forge_pull_review_comments_actor_membership
    BEFORE INSERT OR UPDATE ON forge_pull_review_comments
    FOR EACH ROW EXECUTE FUNCTION enforce_repository_actor_membership();

INSERT INTO schema_migrations (version) VALUES (150) ON CONFLICT DO NOTHING;
