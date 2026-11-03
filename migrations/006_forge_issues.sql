-- Personal-owner Forge slice only. A tenant is an existing repository owner;
-- this does not create organization membership or grant collaborators access.
CREATE TABLE forge_issue_counters (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    next_number BIGINT NOT NULL DEFAULT 1 CHECK (next_number > 0),
    PRIMARY KEY (tenant_id, repository_id),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id)
);
CREATE TABLE forge_issues (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    number BIGINT NOT NULL CHECK (number > 0),
    author_id UUID NOT NULL REFERENCES users(id),
    title TEXT NOT NULL CHECK (octet_length(title) BETWEEN 1 AND 256 AND btrim(title) <> '' AND title !~ '[[:cntrl:]]'),
    body TEXT NOT NULL DEFAULT '' CHECK (octet_length(body) <= 8192),
    state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'closed')),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    next_comment_number BIGINT NOT NULL DEFAULT 1 CHECK (next_comment_number > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, number),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id),
    -- No unimplemented membership model is used to manufacture author authority.
    CHECK (author_id = tenant_id)
);
CREATE TABLE forge_issue_comments (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    issue_number BIGINT NOT NULL,
    number BIGINT NOT NULL CHECK (number > 0),
    author_id UUID NOT NULL REFERENCES users(id),
    body TEXT NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 8192 AND btrim(body) <> ''),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, issue_number, number),
    FOREIGN KEY (tenant_id, repository_id, issue_number) REFERENCES forge_issues(tenant_id, repository_id, number),
    CHECK (author_id = tenant_id)
);
INSERT INTO schema_migrations (version) VALUES (6);
