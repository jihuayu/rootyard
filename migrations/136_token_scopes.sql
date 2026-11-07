-- Personal access token scopes (schema 136).
--
-- Restricted tokens carry an explicit, additive grant set. A restricted token
-- with no rows in either scope table is denied everything: the empty set is
-- never an alias for "all repositories" or "organisation administration".
-- Tokens created before this migration keep is_restricted = false, i.e. their
-- historical read_only / account-wide behaviour is unchanged.
ALTER TABLE tokens ADD COLUMN is_restricted BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE tokens ADD COLUMN scope_version BIGINT NOT NULL DEFAULT 1
    CHECK (scope_version > 0);
ALTER TABLE tokens ADD COLUMN display_name TEXT
    CHECK (display_name IS NULL OR (char_length(display_name) BETWEEN 1 AND 80));

CREATE TABLE token_repository_scopes (
    token_id UUID NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    action TEXT NOT NULL CHECK (action IN (
        'contents_read','contents_write',
        'issues_read','issues_write',
        'pulls_read','pulls_write',
        'checks_read','checks_write',
        'hooks_read','hooks_admin',
        'members_read','members_admin',
        'ci_read','ci_dispatch',
        'workspaces_read','workspaces_write',
        'repo_read','repo_admin'
    )),
    PRIMARY KEY (token_id, repository_id, action)
);
CREATE INDEX token_repository_scopes_repository_idx
    ON token_repository_scopes (repository_id);

CREATE TABLE token_namespace_scopes (
    token_id UUID NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    action TEXT NOT NULL CHECK (action IN ('org:read','org:members_write','org:teams_write')),
    PRIMARY KEY (token_id, organization_id, action)
);
CREATE INDEX token_namespace_scopes_organization_idx
    ON token_namespace_scopes (organization_id);

INSERT INTO schema_migrations(version) VALUES(136) ON CONFLICT DO NOTHING;
