#!/usr/bin/env python3
"""Native PostgreSQL/Git regression for cluster authority and marker rollback."""
import argparse
import json
from pathlib import Path

from e2e import Harness


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    harness = Harness(args)
    try:
        harness.setup()
        harness.api()
        harness.roundtrip()
        route_path = "/api/repos/alice/demo/shard-route"
        route = json.loads(harness.expect(route_path, 200, token=harness.alice))
        node_path = "/api/shards/nodes/" + route["primary_node_id"]
        for actor in (harness.alice, harness.bob):
            harness.expect(node_path, 403, token=actor, method="PATCH", body={"status": "offline"})
        node = json.loads(harness.expect(node_path, 200, token=harness.alice))
        assert node["status"] == "healthy"

        harness.sql("INSERT INTO cluster_operator_tokens(token_id, granted_by) VALUES ('" +
                    harness.alice["token_id"] + "', 'native-test')")
        harness.expect(node_path, 200, token=harness.alice, method="PATCH",
                       body={"status": "healthy", "expected_version": node["version"]})

        trigger = """CREATE FUNCTION shard_audit_reject() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'injected audit failure'; END $$;
        CREATE TRIGGER shard_audit_reject BEFORE INSERT ON repository_audit_log
        FOR EACH ROW EXECUTE FUNCTION shard_audit_reject();"""
        harness.sql(trigger)
        try:
            harness.expect("/api/repos/alice/demo/shard-degrade", 503, token=harness.alice,
                           method="POST", body={"mode": "degrade", "reason": "rollback regression"})
        finally:
            harness.sql("DROP TRIGGER shard_audit_reject ON repository_audit_log; DROP FUNCTION shard_audit_reject()")
        assert harness.sql("SELECT read_only_degraded FROM repository_shard_routes WHERE repository_id='" +
                           harness.repo["id"] + "'") == "f"
        assert harness.sql("SELECT COUNT(*) FROM shard_marker_transitions WHERE repository_id='" +
                           harness.repo["id"] + "' AND state='pending'") == "0"
        marker_path = Path(harness.bare) / "rootyard-shard-fence.json"
        if marker_path.exists():
            assert json.loads(marker_path.read_text())["read_only_degraded"] is False

        harness.stop()
        harness.start()
        (harness.work / "hello.txt").write_text("after failed shard transition\n")
        harness.git("commit", "-am", "after rollback", cwd=harness.work)
        harness.git("push", "origin", "HEAD:main", cwd=harness.work, token=harness.alice)
        print(json.dumps({"result": "passed", "checks": ["operator isolation", "authorized operator", "audit rollback", "restart push"]}))
    finally:
        harness.cleanup()


if __name__ == "__main__":
    main()
