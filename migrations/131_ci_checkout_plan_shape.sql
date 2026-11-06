-- Migration 008 created an unnamed plan CHECK that PostgreSQL named
-- ci_checkout_jobs_check1. It hard-coded object_format='sha1' and a 40-hex
-- target even after 109 made the checkout plan format-aware for SHA-256.
-- Replace it with the same shape checks, now keyed by the declared format, so
-- a complete SHA-256 checkout plan can be persisted without weakening any
-- other plan invariant. Existing SHA-1 rows still satisfy every predicate.
ALTER TABLE ci_checkout_jobs DROP CONSTRAINT IF EXISTS ci_checkout_jobs_check1;
ALTER TABLE ci_checkout_jobs ADD CONSTRAINT ci_checkout_jobs_plan_shape CHECK (
    plan IS NULL OR (
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
        AND plan->>'object_format' IN ('sha1','sha256')
        AND jsonb_typeof(plan->'target_oid') = 'string'
        AND (plan->>'target_oid') COLLATE "C" ~ '^[0-9a-f]+$'
        AND length(plan->>'target_oid') =
            CASE WHEN plan->>'object_format' = 'sha1' THEN 40 ELSE 64 END
        AND plan->>'target_oid' <> repeat('0', length(plan->>'target_oid'))
        AND jsonb_typeof(plan->'source_receipt_sha256') = 'string'
        AND (plan->>'source_receipt_sha256') COLLATE "C" ~ '^[0-9a-f]{64}$'
        AND jsonb_typeof(plan->'mirror_audience') = 'string'
        AND (plan->>'mirror_audience') COLLATE "C" ~
            '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        AND plan->'expires_unix' = to_jsonb(expires_unix)
    )
);

-- Migration 109 dropped the 008 plan-presence constraint while replacing only
-- the plan JSON shape. Restore it under an explicit name so a cancelled
-- tombstone can still omit a plan, but a plan-bearing row cannot omit its
-- credential/token/expiry fields (and a cancellation cannot carry them).
ALTER TABLE ci_checkout_jobs DROP CONSTRAINT IF EXISTS ci_checkout_jobs_plan_presence;
ALTER TABLE ci_checkout_jobs ADD CONSTRAINT ci_checkout_jobs_plan_presence CHECK (
    (plan IS NULL AND cancelled AND issuer_token_id IS NULL
     AND credential_digest IS NULL AND expires_unix IS NULL)
    OR
    (plan IS NOT NULL AND issuer_token_id IS NOT NULL
     AND credential_digest IS NOT NULL AND expires_unix IS NOT NULL
     AND expires_unix > 0)
);

INSERT INTO schema_migrations (version) VALUES (131) ON CONFLICT DO NOTHING;
