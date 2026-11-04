-- Durable per-repository/job authority. Source retention remains a separate
-- durable file/native-ref contract; these rows never manufacture Git roots.
CREATE TABLE ci_checkout_jobs (
    repository_id UUID NOT NULL,
    job_id UUID NOT NULL,
    owner_id UUID NOT NULL REFERENCES users(id),
    cancelled BOOLEAN NOT NULL DEFAULT false,
    revoked BOOLEAN NOT NULL DEFAULT false,
    plan JSONB,
    issuer_token_id UUID REFERENCES tokens(id),
    credential_digest BYTEA UNIQUE CHECK (octet_length(credential_digest) = 32),
    expires_unix BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, job_id),
    FOREIGN KEY (repository_id, owner_id) REFERENCES repositories(id, owner_id),
    CHECK (
        (plan IS NULL AND cancelled AND issuer_token_id IS NULL
         AND credential_digest IS NULL AND expires_unix IS NULL)
        OR
        (plan IS NOT NULL AND issuer_token_id IS NOT NULL
         AND credential_digest IS NOT NULL AND expires_unix IS NOT NULL
         AND expires_unix > 0)
    ),
    CHECK (plan IS NULL OR (
        jsonb_typeof(plan) = 'object'
        AND plan ?& ARRAY['version','job_id','owner_id','repository_id',
            'storage_generation','object_format','target_oid',
            'source_receipt_sha256','mirror_audience','expires_unix']
        AND octet_length(plan::text) <= 8192
        AND plan->'version' = '1'::jsonb
        AND plan->'job_id' = to_jsonb(job_id::text)
        AND plan->'owner_id' = to_jsonb(owner_id::text)
        AND plan->'repository_id' = to_jsonb(repository_id::text)
        AND jsonb_typeof(plan->'storage_generation') = 'number'
        AND (plan->>'storage_generation') ~ '^[1-9][0-9]*$'
        AND plan->'object_format' = '"sha1"'::jsonb
        AND jsonb_typeof(plan->'target_oid') = 'string'
        AND (plan->>'target_oid') COLLATE "C" ~ '^[0-9a-f]{40}$'
        AND plan->>'target_oid' <> repeat('0', 40)
        AND jsonb_typeof(plan->'source_receipt_sha256') = 'string'
        AND (plan->>'source_receipt_sha256') COLLATE "C" ~ '^[0-9a-f]{64}$'
        AND jsonb_typeof(plan->'mirror_audience') = 'string'
        AND (plan->>'mirror_audience') COLLATE "C" ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        AND plan->'expires_unix' = to_jsonb(expires_unix)
    ))
);
CREATE FUNCTION protect_ci_checkout_job() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION 'CI checkout jobs and cancellation tombstones are permanent';
    END IF;
    IF ROW(NEW.repository_id, NEW.job_id, NEW.owner_id, NEW.plan,
           NEW.issuer_token_id, NEW.credential_digest, NEW.expires_unix, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.repository_id, OLD.job_id, OLD.owner_id, OLD.plan,
           OLD.issuer_token_id, OLD.credential_digest, OLD.expires_unix, OLD.created_at)
       OR (OLD.cancelled AND NOT NEW.cancelled)
       OR (OLD.revoked AND NOT NEW.revoked) THEN
        RAISE EXCEPTION 'CI checkout authority is immutable except monotonic cancellation/revocation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER ci_checkout_jobs_immutable
    BEFORE UPDATE OR DELETE ON ci_checkout_jobs
    FOR EACH ROW EXECUTE FUNCTION protect_ci_checkout_job();
CREATE TRIGGER ci_checkout_jobs_no_truncate
    BEFORE TRUNCATE ON ci_checkout_jobs
    FOR EACH STATEMENT EXECUTE FUNCTION protect_ci_checkout_job();
INSERT INTO schema_migrations (version) VALUES (8);
