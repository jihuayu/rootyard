ALTER TABLE repositories ADD COLUMN incident_revision BIGINT NOT NULL DEFAULT 0 CHECK(incident_revision>=0);
CREATE FUNCTION rootyard_incident_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.state,NEW.recovery_reason,NEW.storage_generation) IS DISTINCT FROM (OLD.state,OLD.recovery_reason,OLD.storage_generation) THEN
  NEW.incident_revision := OLD.incident_revision+1;
 ELSE NEW.incident_revision := OLD.incident_revision;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER repository_incident_revision BEFORE UPDATE ON repositories FOR EACH ROW EXECUTE FUNCTION rootyard_incident_revision();
CREATE TABLE recovery_resolutions (
 id UUID PRIMARY KEY,
 repository_id UUID NOT NULL REFERENCES repositories(id),
 old_generation BIGINT NOT NULL CHECK(old_generation>0),
 new_generation BIGINT NOT NULL CHECK(new_generation=old_generation+1),
 incident_revision BIGINT NOT NULL,
 inspected_fingerprint TEXT NOT NULL CHECK(inspected_fingerprint ~ '^[0-9a-f]{64}$'),
 volume_id UUID NOT NULL,
 snapshot JSONB NOT NULL,
 reason TEXT NOT NULL CHECK(octet_length(reason) BETWEEN 1 AND 4096),
 database_actor TEXT NOT NULL DEFAULT current_user,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(repository_id,old_generation,inspected_fingerprint),
 UNIQUE(id,repository_id)
);
CREATE UNIQUE INDEX git_operations_repository_identity ON git_operations(id,repository_id);
CREATE TABLE operation_resolutions (
 operation_id UUID PRIMARY KEY,
 repository_id UUID NOT NULL,
 resolution_id UUID NOT NULL,
 operation_digest TEXT NOT NULL CHECK(operation_digest ~ '^[0-9a-f]{64}$'),
 journal_digest TEXT CHECK(journal_digest ~ '^[0-9a-f]{64}$'),
 journal_evidence JSONB,
 FOREIGN KEY(operation_id,repository_id) REFERENCES git_operations(id,repository_id),
 FOREIGN KEY(resolution_id,repository_id) REFERENCES recovery_resolutions(id,repository_id),
 CHECK((journal_digest IS NULL)=(journal_evidence IS NULL))
);
CREATE FUNCTION rootyard_immutable_resolution() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'recovery resolution records are immutable'; END $$;
CREATE TRIGGER immutable_recovery_resolution BEFORE UPDATE OR DELETE ON recovery_resolutions FOR EACH ROW EXECUTE FUNCTION rootyard_immutable_resolution();
CREATE TRIGGER immutable_operation_resolution BEFORE UPDATE OR DELETE ON operation_resolutions FOR EACH ROW EXECUTE FUNCTION rootyard_immutable_resolution();
CREATE FUNCTION rootyard_freeze_resolved_operation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM operation_resolutions WHERE operation_id=OLD.id) AND (TG_OP='DELETE' OR NEW IS DISTINCT FROM OLD) THEN
  RAISE EXCEPTION 'resolved unknown operation history is immutable';
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;
CREATE TRIGGER freeze_resolved_operation BEFORE UPDATE OR DELETE ON git_operations FOR EACH ROW EXECUTE FUNCTION rootyard_freeze_resolved_operation();
ALTER TABLE repository_ref_projection ALTER COLUMN event_id DROP NOT NULL;
ALTER TABLE repository_ref_projection ADD COLUMN source_kind TEXT NOT NULL DEFAULT 'push_receipt';
ALTER TABLE repository_ref_projection ADD COLUMN resolution_id UUID REFERENCES recovery_resolutions(id);
ALTER TABLE repository_ref_projection ADD CONSTRAINT projection_source CHECK(
 (source_kind='push_receipt' AND event_id IS NOT NULL AND resolution_id IS NULL)
 OR (source_kind='recovery_snapshot' AND event_id IS NULL AND resolution_id IS NOT NULL));
ALTER TABLE event_deliveries ADD COLUMN effect TEXT CHECK(effect IN ('applied','superseded_generation','discarded_unknown'));
UPDATE event_deliveries SET effect='applied' WHERE state='delivered';
CREATE FUNCTION rootyard_projection_epoch() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE current_generation BIGINT;
BEGIN
 SELECT storage_generation INTO current_generation FROM repositories WHERE id=NEW.repository_id FOR SHARE;
 IF NEW.storage_generation IS DISTINCT FROM current_generation THEN RAISE EXCEPTION 'stale projection storage generation'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER projection_storage_epoch BEFORE INSERT OR UPDATE ON repository_ref_projection FOR EACH ROW EXECUTE FUNCTION rootyard_projection_epoch();
CREATE FUNCTION rootyard_no_resolved_events() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM operation_resolutions WHERE operation_id=NEW.operation_id) THEN RAISE EXCEPTION 'resolved unknown operation cannot publish events'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER no_resolved_events BEFORE INSERT ON outbox_events FOR EACH ROW EXECUTE FUNCTION rootyard_no_resolved_events();
INSERT INTO schema_migrations(version) VALUES(3);
