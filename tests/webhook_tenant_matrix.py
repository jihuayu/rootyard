def _exercise_hook_api(h, actor, repo, foreign_repo, label):
    import uuid

    hooks_path = repo + "/webhooks"
    hook_body = {
        "url": h.receiver.url,
        "secret": h.webhook_secret,
        "events": ["ping"],
    }

    primary = h.document(
        hooks_path, code=201, token=actor, method="POST", body=dict(hook_body)
    )
    secondary = h.document(
        hooks_path, code=201, token=actor, method="POST", body=dict(hook_body)
    )
    for hook in (primary, secondary):
        assert "id" in hook, hook
        assert "version" in hook, hook
        assert "max_attempts" in hook, hook

    collection = h.document(hooks_path, code=200, token=actor, method="GET")
    collection_ids = [item["id"] for item in collection["items"]]
    assert primary["id"] in collection_ids, collection
    assert secondary["id"] in collection_ids, collection

    primary_path = hooks_path + "/" + str(primary["id"])
    fetched = h.document(primary_path, code=200, token=actor, method="GET")
    assert fetched["id"] == primary["id"], fetched

    new_max_attempts = fetched["max_attempts"] + 1
    patched = h.document(
        primary_path,
        code=200,
        token=actor,
        method="PATCH",
        body={
            "expected_version": fetched["version"],
            "max_attempts": new_max_attempts,
        },
    )
    assert patched["version"] == fetched["version"] + 1, patched
    assert patched["max_attempts"] == new_max_attempts, patched

    secondary_path = hooks_path + "/" + str(secondary["id"])
    deleted = h.document(secondary_path, code=200, token=actor, method="DELETE")
    assert deleted == {"deleted": True, "id": secondary["id"]}, deleted
    h.document(secondary_path, code=404, token=actor, method="GET")

    event_id = "wh67-" + uuid.uuid4().hex
    pinged = h.document(
        primary_path + "/ping",
        code=200,
        token=actor,
        method="POST",
        body={"event_id": event_id, "deliver_now": True},
    )
    assert pinged["event_id"] == event_id, pinged
    assert pinged["state"] == "delivered", pinged

    deliveries = h.document(
        primary_path + "/deliveries", code=200, token=actor, method="GET"
    )
    matching = [
        item for item in deliveries["items"] if item.get("event_id") == event_id
    ]
    assert len(matching) == 1, deliveries
    delivery = h.document(
        primary_path + "/deliveries/" + str(matching[0]["id"]),
        code=200,
        token=actor,
        method="GET",
    )
    assert delivery["id"] == matching[0]["id"], delivery
    assert delivery["event_id"] == event_id, delivery

    retried = h.document(
        primary_path + "/deliveries/" + str(delivery["id"]) + "/retry",
        code=200,
        token=actor,
        method="POST",
        body={"deliver_now": False},
    )
    assert retried["state"] == "pending", retried

    dispatch_delivery_id = _exercise_dispatch_api(h, actor, repo, primary_path)

    h.document(foreign_repo + "/webhooks", code=404, token=actor, method="GET")

    return (primary["id"], dispatch_delivery_id, patched["version"])


def _exercise_restricted_pat(h, actor, repo, repo_owner, repo_name, primary_id, delivery_id):
    owner_sql = str(repo_owner).replace("'", "''")
    name_sql = str(repo_name).replace("'", "''")
    repo_id = h.sql(
        "SELECT r.id FROM repositories r JOIN namespaces n ON n.id=r.owner_id "
        "WHERE n.slug='" + owner_sql + "' AND r.name='" + name_sql + "'"
    )
    assert repo_id, "repository UUID lookup returned empty"

    pat = h.issue_token(actor["username"])
    pat_id = str(pat["token_id"])
    pat_id_sql = pat_id.replace("'", "''")
    repo_id_sql = str(repo_id).replace("'", "''")

    h.sql(
        "UPDATE tokens SET is_restricted=true, scope_version=scope_version+1 "
        "WHERE id='" + pat_id_sql + "'"
    )
    h.sql(
        "INSERT INTO token_repository_scopes (token_id, repository_id, action) VALUES "
        "('" + pat_id_sql + "', '" + repo_id_sql + "', 'hooks_read')"
    )
    scope_count = h.sql(
        "SELECT count(*)::text FROM token_repository_scopes WHERE token_id='" + pat_id_sql + "'"
    )
    assert scope_count == "1", "expected exactly one token_repository_scopes row, got %r" % (scope_count,)

    primary_path = repo + "/webhooks/" + str(primary_id)

    collection = h.document(repo + "/webhooks", code=200, token=pat)
    primary = h.document(primary_path, code=200, token=pat)

    assert any(item.get("id") == primary_id for item in collection["items"]), \
        "primary webhook missing from collection for restricted PAT"
    assert primary["id"] == primary_id, "fetched primary id mismatch"

    snapshot_ids = sorted(item["id"] for item in h.document(repo + "/webhooks", code=200, token=pat)["items"])
    version_before = h.document(primary_path, code=200, token=pat)["version"]
    max_attempts_before = primary["max_attempts"]
    delivery_path = repo + "/webhooks/" + str(primary_id) + "/deliveries/" + str(delivery_id)
    delivery_before = h.document(delivery_path, code=200, token=pat)
    state_before = delivery_before["state"]
    attempts_before = delivery_before["attempts"]

    h.document(
        repo + "/webhooks",
        code=403,
        token=pat,
        method="POST",
        body={"url": h.receiver.url, "secret": h.webhook_secret, "events": ["ping"]},
    )
    h.document(
        primary_path,
        code=403,
        token=pat,
        method="PATCH",
        body={"expected_version": version_before, "max_attempts": max_attempts_before + 1},
    )
    h.document(
        delivery_path + "/retry",
        code=403,
        token=pat,
        method="POST",
        body={"deliver_now": False},
    )
    h.document(
        repo + "/webhooks/dispatch",
        code=403,
        token=pat,
        method="POST",
        body={"limit": 5, "sync_outbox": False, "sync_pulls": False},
    )

    after_ids = sorted(item["id"] for item in h.document(repo + "/webhooks", code=200, token=pat)["items"])
    version_after = h.document(primary_path, code=200, token=pat)["version"]
    delivery_after = h.document(delivery_path, code=200, token=pat)

    assert after_ids == snapshot_ids, "webhook set changed after denied scoped writes"
    assert version_after == version_before, "primary webhook version changed after denied PATCH"
    assert delivery_after["state"] == state_before, "delivery state changed after denied retry"
    assert delivery_after["attempts"] == attempts_before, "delivery attempts changed after denied retry"

    h.cli("revoke-token", pat_id)
    h.document(repo + "/webhooks", code=401, token=pat)

    return {
        "token_id": pat_id,
        "repo_id": repo_id,
        "primary_id": primary_id,
        "delivery_id": delivery_id,
    }


def _exercise_dispatch_api(h, actor, repo, primary_path):
    """Dispatch a tenant-owned, API-created failed ping using a virtual clock."""
    import time
    import uuid

    def is_int(value):
        return isinstance(value, int) and not isinstance(value, bool)

    with h.receiver.lock:
        h.receiver.planned_statuses.clear()
        h.receiver.default_status = 500
    event_id = "dispatch-ping-" + uuid.uuid4().hex
    try:
        ping = h.document(
            primary_path + "/ping",
            code=200,
            token=actor,
            method="POST",
            body={"event_id": event_id, "deliver_now": True},
        )
        delivery_id = str(ping["id"])
        assert ping["event_id"] == event_id, ping
        assert ping["event_type"] == "ping", ping
        assert ping["state"] == "failed", ping
        assert ping["response_status"] == 500, ping
        assert is_int(ping["attempts"]) and ping["attempts"] >= 1, ping
        assert is_int(ping["next_attempt_unix"]) and ping["next_attempt_unix"] > 0, ping

        webhook_id = primary_path.rsplit("/", 1)[-1]
        delivery_sql = delivery_id.replace("'", "''")
        webhook_sql = webhook_id.replace("'", "''")
        scheduled = int(time.time()) + 120
        changed = h.sql(
            "WITH updated AS ("
            " UPDATE forge_webhook_deliveries SET next_attempt_unix = "
            + str(scheduled)
            + " WHERE id='"
            + delivery_sql
            + "'::uuid AND webhook_id='"
            + webhook_sql
            + "'::uuid RETURNING next_attempt_unix"
            + ") SELECT next_attempt_unix::text FROM updated"
        )
        assert changed == str(scheduled), changed
    finally:
        with h.receiver.lock:
            h.receiver.planned_statuses.clear()
            h.receiver.default_status = 200

    summary = h.document(
        repo + "/webhooks/dispatch",
        code=200,
        token=actor,
        method="POST",
        body={
            "limit": 5,
            "now_unix": scheduled + 1,
            "sync_outbox": False,
            "sync_pulls": False,
        },
    )
    for field in (
        "synced_outbox_deliveries",
        "orchestrated_pulls",
        "attempted_deliveries",
        "delivered_count",
        "failed_count",
        "dead_letter_count",
    ):
        assert is_int(summary[field]), (field, summary)
    assert summary["attempted_deliveries"] >= 1, summary
    assert summary["delivered_count"] >= 1, summary

    matches = [
        item
        for item in summary["deliveries"]
        if str(item.get("id")) == delivery_id
        and item.get("event_id") == event_id
    ]
    assert len(matches) == 1, (delivery_id, event_id, summary)
    dispatched = matches[0]
    assert dispatched["state"] == "delivered", dispatched
    assert is_int(dispatched["attempts"]), dispatched
    assert dispatched["attempts"] > ping["attempts"], (ping, dispatched)

    readback = h.document(
        primary_path + "/deliveries/" + delivery_id,
        code=200,
        token=actor,
        method="GET",
    )
    assert str(readback["id"]) == delivery_id, readback
    assert str(readback["webhook_id"]) == webhook_id, readback
    assert readback["event_id"] == event_id, readback
    assert readback["state"] == dispatched["state"] == "delivered", readback
    assert readback["response_status"] == 200, readback
    assert readback["attempts"] == dispatched["attempts"], (readback, dispatched)
    return delivery_id


def run_matrix(h):
    owner = h.alice
    repo = "/api/repos/alice/wh67matrix"
    foreign = "/api/repos/alice/other"

    h.document("/api/repos", code=201, token=owner, method="POST",
               body={"name": "wh67matrix"})
    h.document("/api/orgs", code=201, token=owner, method="POST",
               body={"slug": "wh67org"})
    h.document("/api/repos", code=201, token=owner, method="POST",
               body={"name": "project", "owner": "wh67org"})

    team = h.issue_token("wh67team", create_user=True)
    admin = h.issue_token("wh67admin", create_user=True)
    orgteam = h.issue_token("wh67orgteam", create_user=True)

    h.document(repo + "/teams", code=201, token=owner, method="POST",
               body={"slug": "hooks", "name": "Hooks", "role": "write"})
    h.document(repo + "/teams/hooks/members/wh67team", code=201, token=owner,
               method="PUT")
    h.document("/api/orgs/wh67org/members/wh67admin", code=201, token=owner,
               method="PUT", body={"role": "admin"})
    h.document("/api/orgs/wh67org/members/wh67orgteam", code=201, token=owner,
               method="PUT", body={"role": "read"})
    h.document("/api/orgs/wh67org/teams", code=201, token=owner, method="POST",
               body={"slug": "hooks", "name": "Hooks", "role": "write"})
    h.document("/api/orgs/wh67org/teams/hooks/members/wh67orgteam", code=200,
               token=owner, method="PUT")

    primary_id, delivery_id, patched_version = _exercise_hook_api(
        h, team, repo, foreign, "team")
    _exercise_restricted_pat(
        h, team, repo, "alice", "wh67matrix", primary_id, delivery_id)
    h.document(repo + "/teams/hooks/members/wh67team", code=200, token=owner,
               method="DELETE")
    h.document(repo + "/webhooks/" + primary_id, code=404, token=team,
               method="GET")
    body = h.document(repo + "/webhooks/" + primary_id, code=200, token=owner,
                      method="GET")
    assert body["id"] == primary_id

    org_repo = "/api/repos/wh67org/project"
    org_foreign = "/api/repos/alice/forge"
    primary_id, delivery_id, patched_version = _exercise_hook_api(
        h, admin, org_repo, org_foreign, "org-admin")
    _exercise_restricted_pat(
        h, admin, org_repo, "wh67org", "project", primary_id, delivery_id)
    h.document("/api/orgs/wh67org/members/wh67admin", code=200, token=owner,
               method="DELETE")
    h.document(org_repo + "/webhooks/" + primary_id, code=404, token=admin,
               method="GET")
    body = h.document(org_repo + "/webhooks/" + primary_id, code=200,
                      token=owner, method="GET")
    assert body["id"] == primary_id

    primary_id, delivery_id, patched_version = _exercise_hook_api(
        h, orgteam, org_repo, org_foreign, "org-team")
    _exercise_restricted_pat(
        h, orgteam, org_repo, "wh67org", "project", primary_id, delivery_id)
    h.document("/api/orgs/wh67org/teams/hooks/members/wh67orgteam", code=200,
               token=owner, method="DELETE")
    body = h.document(org_repo + "/webhooks/" + primary_id, code=200,
                      token=orgteam, method="GET")
    assert body["id"] == primary_id
    h.document(org_repo + "/webhooks/" + primary_id, code=403, token=orgteam,
               method="PATCH",
               body={"expected_version": patched_version, "max_attempts": 5})
    h.document("/api/orgs/wh67org/members/wh67orgteam", code=200, token=owner,
               method="DELETE")
    h.document(org_repo + "/webhooks/" + primary_id, code=404, token=orgteam,
               method="GET")
    body = h.document(org_repo + "/webhooks/" + primary_id, code=200,
                      token=owner, method="GET")
    assert body["id"] == primary_id

    return {"repo": repo, "org_repo": org_repo, "status": "ok"}
