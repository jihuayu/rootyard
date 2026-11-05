-- Collaborator and Team 5-Role RBAC Hierarchy, Multi-Reviewer PR Self-Approval Policy,
-- and Repository Audit Log.
-- All range checks use explicit >= and <= predicates so pg_dump
-- catalog normalization remains invariant across fresh, restored, and upgraded schemas.

ALTER TABLE forge_issues DROP CONSTRAINT IF EXISTS forge_issues_check;
ALTER TABLE forge_issue_comments DROP CONSTRAINT IF EXISTS forge_issue_comments_check;
ALTER TABLE forge_pulls DROP CONSTRAINT IF EXISTS forge_pulls_check;
ALTER TABLE forge_pull_reviews DROP CONSTRAINT IF EXISTS forge_pull_reviews_check;
ALTER TABLE git_operations DROP CONSTRAINT IF EXISTS git_operations_repository_id_actor_id_fkey;
ALTER TABLE git_operations DROP CONSTRAINT IF EXISTS git_operations_repository_id_fkey;
ALTER TABLE git_operations ADD CONSTRAINT git_operations_repository_id_fkey
    FOREIGN KEY (repository_id) REFERENCES repositories(id);
ALTER TABLE forge_branch_rules ADD COLUMN IF NOT EXISTS prevent_self_approval BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE repository_collaborators (
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('read', 'triage', 'write', 'maintain', 'admin')),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, user_id),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id),
    CHECK (user_id <> tenant_id)
);

CREATE INDEX repository_collaborators_user_idx ON repository_collaborators (user_id, repository_id);

CREATE TABLE repository_teams (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    slug TEXT NOT NULL CHECK ((slug COLLATE "C") ~ '^[a-z0-9][a-z0-9_-]{0,62}$'),
    name TEXT NOT NULL CHECK (
        octet_length(btrim(name)) >= 1 AND octet_length(name) <= 128
        AND name !~ '[[:cntrl:]]'
    ),
    description TEXT NOT NULL DEFAULT '' CHECK (octet_length(description) <= 1024),
    role TEXT NOT NULL CHECK (role IN ('read', 'triage', 'write', 'maintain', 'admin')),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (repository_id, slug),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id)
);

CREATE INDEX repository_teams_repo_idx ON repository_teams (repository_id, slug);

CREATE TABLE repository_team_members (
    team_id UUID NOT NULL REFERENCES repository_teams(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (team_id, user_id)
);

CREATE INDEX repository_team_members_repo_user_idx ON repository_team_members (repository_id, user_id);

CREATE TABLE repository_audit_log (
    id BIGINT PRIMARY KEY CHECK (id > 0),
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    actor_id UUID NOT NULL REFERENCES users(id),
    actor_name TEXT NOT NULL CHECK (length(actor_name) >= 1 AND length(actor_name) <= 63),
    action TEXT NOT NULL CHECK (octet_length(action) >= 1 AND octet_length(action) <= 64),
    target_type TEXT NOT NULL CHECK (octet_length(target_type) >= 1 AND octet_length(target_type) <= 64),
    target_name TEXT NOT NULL CHECK (octet_length(target_name) <= 256),
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_unix BIGINT NOT NULL DEFAULT 0 CHECK (created_unix >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id)
);

CREATE INDEX repository_audit_log_repo_id_idx ON repository_audit_log (repository_id, id);
CREATE INDEX repository_audit_log_repo_actor_idx ON repository_audit_log (repository_id, actor_name, id);
CREATE INDEX repository_audit_log_repo_action_idx ON repository_audit_log (repository_id, action, id);
CREATE INDEX repository_audit_log_repo_unix_idx ON repository_audit_log (repository_id, created_unix, id);

CREATE OR REPLACE FUNCTION enforce_repository_actor_membership()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    actor_user_id UUID;
    repo_owner_id UUID;
BEGIN
    IF TG_TABLE_NAME = 'git_operations' THEN
        actor_user_id := NEW.actor_id;
    ELSE
        actor_user_id := NEW.author_id;
    END IF;

    SELECT owner_id INTO repo_owner_id
    FROM repositories
    WHERE id = NEW.repository_id;

    IF repo_owner_id IS NULL THEN
        RAISE EXCEPTION 'repository does not exist' USING ERRCODE = '23503';
    END IF;

    IF actor_user_id = repo_owner_id THEN
        RETURN NEW;
    END IF;

    IF EXISTS (
        SELECT 1 FROM repository_collaborators
        WHERE repository_id = NEW.repository_id AND user_id = actor_user_id
    ) THEN
        RETURN NEW;
    END IF;

    IF EXISTS (
        SELECT 1 FROM repository_team_members tm
        JOIN repository_teams t ON t.id = tm.team_id
        WHERE tm.repository_id = NEW.repository_id AND tm.user_id = actor_user_id
    ) THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'actor is not a member or collaborator of repository'
        USING ERRCODE = '23514';
END;
$$;

DROP TRIGGER IF EXISTS enforce_forge_issues_actor_membership ON forge_issues;
CREATE TRIGGER enforce_forge_issues_actor_membership
    BEFORE INSERT OR UPDATE ON forge_issues
    FOR EACH ROW EXECUTE FUNCTION enforce_repository_actor_membership();

DROP TRIGGER IF EXISTS enforce_forge_issue_comments_actor_membership ON forge_issue_comments;
CREATE TRIGGER enforce_forge_issue_comments_actor_membership
    BEFORE INSERT OR UPDATE ON forge_issue_comments
    FOR EACH ROW EXECUTE FUNCTION enforce_repository_actor_membership();

DROP TRIGGER IF EXISTS enforce_forge_pulls_actor_membership ON forge_pulls;
CREATE TRIGGER enforce_forge_pulls_actor_membership
    BEFORE INSERT OR UPDATE ON forge_pulls
    FOR EACH ROW EXECUTE FUNCTION enforce_repository_actor_membership();

DROP TRIGGER IF EXISTS enforce_forge_pull_reviews_actor_membership ON forge_pull_reviews;
CREATE TRIGGER enforce_forge_pull_reviews_actor_membership
    BEFORE INSERT OR UPDATE ON forge_pull_reviews
    FOR EACH ROW EXECUTE FUNCTION enforce_repository_actor_membership();

DROP TRIGGER IF EXISTS enforce_git_operations_actor_membership ON git_operations;
CREATE TRIGGER enforce_git_operations_actor_membership
    BEFORE INSERT OR UPDATE ON git_operations
    FOR EACH ROW EXECUTE FUNCTION enforce_repository_actor_membership();

INSERT INTO schema_migrations (version) VALUES (50) ON CONFLICT DO NOTHING;
