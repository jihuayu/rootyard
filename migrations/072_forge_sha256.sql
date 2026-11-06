-- Existing SHA-1 rows stay valid; each repository selects one immutable Git
-- object format in migration 070. The trigger prevents mixed-format rows.
ALTER TABLE forge_pulls DROP CONSTRAINT IF EXISTS forge_pulls_head_oid_check;
ALTER TABLE forge_pulls DROP CONSTRAINT IF EXISTS forge_pulls_base_oid_check;
ALTER TABLE forge_pulls DROP CONSTRAINT IF EXISTS forge_pulls_merge_commit_oid_check;
ALTER TABLE forge_pulls ADD CONSTRAINT forge_pulls_head_oid_check
    CHECK (head_oid COLLATE "C" ~ '^([0-9a-f]{40}|[0-9a-f]{64})$' AND head_oid !~ '^0+$');
ALTER TABLE forge_pulls ADD CONSTRAINT forge_pulls_base_oid_check
    CHECK (base_oid COLLATE "C" ~ '^([0-9a-f]{40}|[0-9a-f]{64})$' AND base_oid !~ '^0+$');
ALTER TABLE forge_pulls ADD CONSTRAINT forge_pulls_merge_commit_oid_check
    CHECK (merge_commit_oid COLLATE "C" ~ '^([0-9a-f]{40}|[0-9a-f]{64})$' AND merge_commit_oid !~ '^0+$');

ALTER TABLE forge_pull_reviews DROP CONSTRAINT IF EXISTS forge_pull_reviews_commit_oid_check;
ALTER TABLE forge_pull_reviews ADD CONSTRAINT forge_pull_reviews_commit_oid_check
    CHECK (commit_oid COLLATE "C" ~ '^([0-9a-f]{40}|[0-9a-f]{64})$' AND commit_oid !~ '^0+$');
ALTER TABLE forge_check_runs DROP CONSTRAINT IF EXISTS forge_check_runs_commit_oid_check;
ALTER TABLE forge_check_runs ADD CONSTRAINT forge_check_runs_commit_oid_check
    CHECK (commit_oid COLLATE "C" ~ '^([0-9a-f]{40}|[0-9a-f]{64})$' AND commit_oid !~ '^0+$');

CREATE OR REPLACE FUNCTION forge_enforce_repository_object_format() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE expected_length INTEGER;
BEGIN
    SELECT CASE object_format WHEN 'sha256' THEN 64 ELSE 40 END INTO expected_length
      FROM repositories WHERE id = NEW.repository_id;
    IF expected_length IS NULL THEN
        RAISE EXCEPTION 'repository object format missing';
    END IF;
    IF TG_TABLE_NAME = 'forge_pulls' THEN
        IF length(NEW.head_oid) <> expected_length OR length(NEW.base_oid) <> expected_length
           OR (NEW.merge_commit_oid IS NOT NULL AND length(NEW.merge_commit_oid) <> expected_length) THEN
            RAISE EXCEPTION 'pull object format differs from repository';
        END IF;
    ELSIF length(NEW.commit_oid) <> expected_length THEN
        RAISE EXCEPTION 'commit object format differs from repository';
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS forge_pulls_object_format ON forge_pulls;
CREATE TRIGGER forge_pulls_object_format BEFORE INSERT OR UPDATE ON forge_pulls
    FOR EACH ROW EXECUTE FUNCTION forge_enforce_repository_object_format();
DROP TRIGGER IF EXISTS forge_pull_reviews_object_format ON forge_pull_reviews;
CREATE TRIGGER forge_pull_reviews_object_format BEFORE INSERT OR UPDATE ON forge_pull_reviews
    FOR EACH ROW EXECUTE FUNCTION forge_enforce_repository_object_format();
DROP TRIGGER IF EXISTS forge_check_runs_object_format ON forge_check_runs;
CREATE TRIGGER forge_check_runs_object_format BEFORE INSERT OR UPDATE ON forge_check_runs
    FOR EACH ROW EXECUTE FUNCTION forge_enforce_repository_object_format();

INSERT INTO schema_migrations (version) VALUES (72) ON CONFLICT DO NOTHING;
