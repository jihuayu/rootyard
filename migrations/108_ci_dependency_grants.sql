-- Each gitlink gets a distinct bearer scoped to its immutable source pin.
CREATE TABLE ci_checkout_delegations (
    parent_repository_id UUID NOT NULL,
    parent_job_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    job_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    plan JSONB NOT NULL,
    issuer_token_id UUID NOT NULL REFERENCES tokens(id),
    credential_digest BYTEA NOT NULL UNIQUE CHECK(octet_length(credential_digest)=32),
    expires_unix BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(repository_id,job_id),
    FOREIGN KEY(parent_repository_id,parent_job_id)
        REFERENCES ci_checkout_jobs(repository_id,job_id),
    FOREIGN KEY(repository_id,owner_id) REFERENCES repositories(id,owner_id)
);
CREATE INDEX ci_checkout_delegations_parent_idx
    ON ci_checkout_delegations(parent_repository_id,parent_job_id);
INSERT INTO schema_migrations(version) VALUES(108) ON CONFLICT DO NOTHING;
