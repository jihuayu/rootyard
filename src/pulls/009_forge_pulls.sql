-- Personal-owner Forge Pull Requests, Reviews, Check Runs, and Branch Rules.
-- All range checks use explicit >= and <= predicates so pg_dump
-- catalog normalization is invariant across fresh, restored, and upgraded schemas.
CREATE TABLE forge_pull_counters (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    next_number BIGINT NOT NULL DEFAULT 1 CHECK (next_number > 0),
    PRIMARY KEY (tenant_id, repository_id),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id)
);

CREATE TABLE forge_pulls (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    number BIGINT NOT NULL CHECK (number > 0),
    author_id UUID NOT NULL REFERENCES users(id),
    title TEXT NOT NULL CHECK (
        octet_length(title) >= 1 AND octet_length(title) <= 256
        AND btrim(title) <> '' AND title !~ '[[:cntrl:]]'
    ),
    body TEXT NOT NULL DEFAULT '' CHECK (octet_length(body) <= 8192),
    state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'closed', 'merged')),
    head_ref TEXT NOT NULL CHECK (
        octet_length(head_ref) >= 12 AND octet_length(head_ref) <= 1024
        AND head_ref LIKE 'refs/heads/%'
    ),
    base_ref TEXT NOT NULL CHECK (
        octet_length(base_ref) >= 12 AND octet_length(base_ref) <= 1024
        AND base_ref LIKE 'refs/heads/%'
    ),
    head_oid TEXT NOT NULL CHECK (
        head_oid COLLATE "C" ~ '^[0-9a-f]{40}$' AND head_oid <> repeat('0', 40)
    ),
    base_oid TEXT NOT NULL CHECK (
        base_oid COLLATE "C" ~ '^[0-9a-f]{40}$' AND base_oid <> repeat('0', 40)
    ),
    merge_commit_oid TEXT CHECK (
        merge_commit_oid COLLATE "C" ~ '^[0-9a-f]{40}$' AND merge_commit_oid <> repeat('0', 40)
    ),
    merged_storage_generation BIGINT CHECK (merged_storage_generation > 0),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    next_review_number BIGINT NOT NULL DEFAULT 1 CHECK (next_review_number > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, number),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id),
    CHECK (author_id = tenant_id),
    CHECK (
        (state = 'merged' AND merge_commit_oid IS NOT NULL AND merged_storage_generation IS NOT NULL)
        OR (state <> 'merged' AND merge_commit_oid IS NULL AND merged_storage_generation IS NULL)
    )
);

CREATE TABLE forge_pull_reviews (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    pull_number BIGINT NOT NULL,
    number BIGINT NOT NULL CHECK (number > 0),
    author_id UUID NOT NULL REFERENCES users(id),
    state TEXT NOT NULL CHECK (state IN ('approved', 'changes_requested', 'commented')),
    commit_oid TEXT NOT NULL CHECK (
        commit_oid COLLATE "C" ~ '^[0-9a-f]{40}$' AND commit_oid <> repeat('0', 40)
    ),
    pull_version BIGINT NOT NULL CHECK (pull_version > 0),
    body TEXT NOT NULL DEFAULT '' CHECK (octet_length(body) <= 8192),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, pull_number, number),
    FOREIGN KEY (tenant_id, repository_id, pull_number) REFERENCES forge_pulls(tenant_id, repository_id, number),
    CHECK (author_id = tenant_id)
);

CREATE TABLE forge_check_runs (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    commit_oid TEXT NOT NULL CHECK (
        commit_oid COLLATE "C" ~ '^[0-9a-f]{40}$' AND commit_oid <> repeat('0', 40)
    ),
    context TEXT NOT NULL CHECK (
        octet_length(context) >= 1 AND octet_length(context) <= 128
        AND btrim(context) <> '' AND context !~ '[[:cntrl:]]'
    ),
    attempt BIGINT NOT NULL DEFAULT 1 CHECK (attempt > 0),
    sequence BIGINT NOT NULL DEFAULT 1 CHECK (sequence > 0),
    status TEXT NOT NULL CHECK (status IN ('queued', 'in_progress', 'completed')),
    conclusion TEXT CHECK (
        conclusion IN ('success', 'failure', 'neutral', 'cancelled', 'timed_out', 'skipped')
    ),
    output TEXT NOT NULL DEFAULT '' CHECK (octet_length(output) <= 8192),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, commit_oid, context),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id),
    CHECK (
        (status = 'completed' AND conclusion IS NOT NULL)
        OR (status <> 'completed' AND conclusion IS NULL)
    )
);

CREATE TABLE forge_branch_rules (
    tenant_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    branch_ref TEXT NOT NULL CHECK (
        octet_length(branch_ref) >= 12 AND octet_length(branch_ref) <= 1024
        AND branch_ref LIKE 'refs/heads/%'
    ),
    required_approvals BIGINT NOT NULL DEFAULT 0 CHECK (
        required_approvals >= 0 AND required_approvals <= 100
    ),
    required_checks JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (
        jsonb_typeof(required_checks) = 'array' AND octet_length(required_checks::text) <= 8192
    ),
    require_fast_forward BOOLEAN NOT NULL DEFAULT true,
    prevent_deletion BOOLEAN NOT NULL DEFAULT true,
    prevent_force_push BOOLEAN NOT NULL DEFAULT true,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, branch_ref),
    FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id)
);

INSERT INTO schema_migrations (version) VALUES (9);
