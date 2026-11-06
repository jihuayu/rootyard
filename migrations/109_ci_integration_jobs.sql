-- A trusted webhook may issue only an exact run-attempt checkout capability.
ALTER TABLE ci_runs DROP CONSTRAINT ci_runs_head_oid_check;
ALTER TABLE ci_runs DROP CONSTRAINT ci_runs_base_oid_check;
ALTER TABLE ci_runs ADD CONSTRAINT ci_runs_head_oid_format CHECK (
    head_oid COLLATE "C" ~ '^[0-9a-f]+$' AND length(head_oid) IN (40,64));
ALTER TABLE ci_runs ADD CONSTRAINT ci_runs_base_oid_format CHECK (
    base_oid COLLATE "C" ~ '^[0-9a-f]+$' AND length(base_oid)=length(head_oid));
ALTER TABLE ci_checkout_jobs DROP CONSTRAINT ci_checkout_jobs_check;
ALTER TABLE ci_checkout_jobs ADD CONSTRAINT ci_checkout_jobs_plan_format CHECK (
    plan IS NULL OR (
        jsonb_typeof(plan)='object' AND octet_length(plan::text)<=8192
        AND plan ?& ARRAY['version','job_id','owner_id','repository_id','storage_generation',
            'object_format','target_oid','source_receipt_sha256','mirror_audience','expires_unix',
            'dependencies']
        AND plan->'version'='1'::jsonb
        AND plan->'job_id'=to_jsonb(job_id::text)
        AND plan->'owner_id'=to_jsonb(owner_id::text)
        AND plan->'repository_id'=to_jsonb(repository_id::text)
        AND plan->'expires_unix'=to_jsonb(expires_unix)
        AND plan->>'object_format' IN ('sha1','sha256')
        AND jsonb_typeof(plan->'target_oid')='string'
        AND (plan->>'target_oid') COLLATE "C" ~ '^[0-9a-f]+$'
        AND length(plan->>'target_oid')=CASE WHEN plan->>'object_format'='sha1' THEN 40 ELSE 64 END
        AND plan->>'target_oid' <> repeat('0',length(plan->>'target_oid'))
        AND (plan->>'source_receipt_sha256') COLLATE "C" ~ '^[0-9a-f]{64}$'
        AND jsonb_typeof(plan->'dependencies')='object'
        AND plan->'dependencies'->'version'='1'::jsonb
    )
);
CREATE TABLE ci_integration_checkout_jobs (
    run_id UUID NOT NULL REFERENCES ci_runs(id),
    attempt BIGINT NOT NULL,
    lease_generation BIGINT NOT NULL,
    repository_id UUID NOT NULL,
    job_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    issuer_webhook_id UUID NOT NULL REFERENCES forge_webhooks(id) ON DELETE CASCADE,
    plan JSONB NOT NULL,
    credential_digest BYTEA NOT NULL UNIQUE CHECK(octet_length(credential_digest)=32),
    expires_unix BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(run_id,attempt,lease_generation,repository_id,job_id),
    FOREIGN KEY(repository_id,owner_id) REFERENCES repositories(id,owner_id)
);
CREATE TABLE ci_integration_source_grants (
    issuer_webhook_id UUID NOT NULL REFERENCES forge_webhooks(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(issuer_webhook_id,repository_id)
);
CREATE INDEX ci_integration_checkout_jobs_job_idx
    ON ci_integration_checkout_jobs(repository_id,job_id);
-- Non-login maintenance actor. It can publish only one exact CI retention ref.
CREATE TABLE ci_service_principals (
    id UUID PRIMARY KEY,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind='ci-pin'),
    issuer_webhook_id UUID REFERENCES forge_webhooks(id) ON DELETE CASCADE,
    active BOOLEAN NOT NULL DEFAULT true,
    UNIQUE(id,repository_id),
    UNIQUE(repository_id,kind)
);
ALTER TABLE git_operations ALTER COLUMN actor_id DROP NOT NULL;
ALTER TABLE git_operations ALTER COLUMN token_id DROP NOT NULL;
ALTER TABLE git_operations ADD COLUMN service_principal_id UUID;
ALTER TABLE git_operations ADD CONSTRAINT git_operations_service_principal_fkey
    FOREIGN KEY(service_principal_id,repository_id)
    REFERENCES ci_service_principals(id,repository_id);
ALTER TABLE git_operations ADD CONSTRAINT git_operations_exactly_one_principal CHECK (
    (actor_id IS NOT NULL AND token_id IS NOT NULL AND service_principal_id IS NULL)
    OR (actor_id IS NULL AND token_id IS NULL AND service_principal_id IS NOT NULL));

CREATE OR REPLACE FUNCTION enforce_repository_actor_membership()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE actor_user_id UUID; repo_owner_id UUID;
BEGIN
    IF TG_TABLE_NAME='git_operations' THEN
      IF NEW.service_principal_id IS NOT NULL THEN
        IF NEW.actor_id IS NOT NULL OR NEW.token_id IS NOT NULL OR
           NEW.actor_name IS DISTINCT FROM 'ci-scheduler' OR
           NEW.outcome NOT IN ('unknown','recorded') OR
           (NEW.evidence->>'kind') IS DISTINCT FROM 'observed_immutable_ci_root' OR
           (NEW.evidence->'intent'->>'repository_id') IS DISTINCT FROM NEW.repository_id::text OR
           (NEW.evidence->'intent'->>'storage_generation') IS DISTINCT FROM NEW.storage_generation::text OR
           NOT COALESCE((NEW.evidence->'intent'->>'job_id') COLLATE "C" ~
             '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',false) OR
           NOT COALESCE((NEW.evidence->'intent'->>'target_oid') COLLATE "C" ~
             '^([0-9a-f]{40}|[0-9a-f]{64})$',false) OR
           (NEW.evidence->'intent'->>'retention_ref') IS DISTINCT FROM
             ('refs/rootyard-ci/jobs/' || (NEW.evidence->'intent'->>'job_id')) OR
           NOT EXISTS(SELECT 1 FROM ci_service_principals s
               JOIN repositories r ON r.id=s.repository_id
               WHERE s.id=NEW.service_principal_id AND s.repository_id=NEW.repository_id
               AND s.kind='ci-pin' AND s.active AND r.state='ready'
               AND r.storage_generation=NEW.storage_generation
               AND (NEW.evidence->'intent'->>'owner_id')=r.owner_id::text
               AND (s.issuer_webhook_id IS NULL OR EXISTS(
                   SELECT 1 FROM forge_webhooks w JOIN forge_trusted_check_contexts b
                     ON b.webhook_id=w.id AND b.repository_id=w.repository_id AND b.active
                   WHERE w.id=s.issuer_webhook_id AND w.repository_id=s.repository_id AND w.active)))
        THEN RAISE EXCEPTION 'invalid CI service principal operation' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
      END IF;
      actor_user_id:=NEW.actor_id;
    ELSE
      actor_user_id:=NEW.author_id;
    END IF;
    SELECT owner_id INTO repo_owner_id FROM repositories WHERE id=NEW.repository_id;
    IF repo_owner_id IS NULL THEN
        RAISE EXCEPTION 'repository does not exist' USING ERRCODE='23503';
    END IF;
    IF actor_user_id=repo_owner_id OR EXISTS(
        SELECT 1 FROM repository_collaborators WHERE repository_id=NEW.repository_id AND user_id=actor_user_id)
       OR EXISTS(SELECT 1 FROM repository_team_members tm JOIN repository_teams t ON t.id=tm.team_id
                 WHERE tm.repository_id=NEW.repository_id AND tm.user_id=actor_user_id)
    THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'actor is not a member or collaborator of repository' USING ERRCODE='23514';
END $$;

CREATE OR REPLACE FUNCTION enforce_ci_service_ref()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE intent JSONB;
BEGIN
    SELECT o.evidence->'intent' INTO intent FROM git_operations o
    WHERE o.id=NEW.operation_id AND o.repository_id=NEW.repository_id
      AND o.service_principal_id IS NOT NULL;
    IF FOUND AND (NEW.ref_name IS DISTINCT FROM (intent->>'retention_ref') OR
        NEW.new_oid IS DISTINCT FROM (intent->>'target_oid') OR
        NEW.ref_name IS DISTINCT FROM ('refs/rootyard-ci/jobs/' || (intent->>'job_id')) OR
        NEW.storage_generation::text IS DISTINCT FROM (intent->>'storage_generation')) THEN
        RAISE EXCEPTION 'CI service operation ref differs from exact intent' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER enforce_ci_service_ref BEFORE INSERT OR UPDATE ON outbox_events
FOR EACH ROW EXECUTE FUNCTION enforce_ci_service_ref();
INSERT INTO schema_migrations(version) VALUES(109) ON CONFLICT DO NOTHING;
