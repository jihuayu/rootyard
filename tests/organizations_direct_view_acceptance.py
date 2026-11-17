"""Direct organization read-only membership and existing View bundle acceptance.

This helper is imported by ``tests/organizations_lifecycle.py`` so the #46
lifecycle module only gains wiring while the focused case stays reviewable. It
is a real-service case: every grant observation below comes from the public
REST contract, and the returned bundle is checked with stock Git rather than a
body length/boolean proxy.
"""
import hashlib

PRINCIPAL = "directviewer"
BUNDLE_NAME = "direct-read-view.bundle"


def run_direct_read_view_bundle_revocation(h):
    """Grant one direct org read membership, use the existing org View, revoke.

    The principal is created from the owned harness fixture and receives only
    ``PUT /api/orgs/acme/members/directviewer {"role":"read"}``. Its actual
    permission projection is read back from the service, including the empty
    team role, and the repository collaborator list plus every organization
    team member list are checked to prove the direct-only grant. The existing
    View was created by dave (another actor) on an org-owned namespace; this
    case neither recreates it nor grants the principal write/admin.
    """
    principal = h.account("create-user", PRINCIPAL)
    view = h.dave_view
    view_id = view["id"]
    bundle_path = f"/api/views/{view_id}/bundle"
    permissions_path = f"/api/repos/acme/app/permissions/{PRINCIPAL}"
    membership_path = f"/api/orgs/acme/members/{PRINCIPAL}"

    # Fixture identity: new principal, org-owned acme namespace, existing View
    # created by dave rather than by the principal under test.
    assert principal["username"] == PRINCIPAL
    assert principal["user_id"] not in {
        h.alice["user_id"], h.bob["user_id"], h.carol["user_id"],
        h.dave["user_id"], h.oscar["user_id"], h.erin["user_id"],
    }
    assert h.doc("/api/orgs/acme", 200)["id"] == h.acme["id"]
    assert view["namespace_id"] == h.dave_ns["id"]
    assert view["source_oid"] == h.app_base_oid
    assert h.doc(f"/api/views/{view_id}", 200, token=h.dave)["id"] == view_id

    # Before any grant the new principal has no effective repository role.
    initial = h.doc(permissions_path, 200, token=h.alice)
    assert initial["role"] is None and initial["direct_role"] is None
    assert initial["team_role"] is None and initial["is_owner"] is False
    assert h.http("/api/repos/acme/app", token=principal)[0] == 404

    # The only grant: one direct organization read membership, added by the
    # organization admin (alice owns acme).
    membership = h.doc(
        membership_path, 201, token=h.alice, method="PUT", body={"role": "read"}
    )
    assert membership == {"username": PRINCIPAL, "role": "read", "version": 1}

    # Actual REST proof of direct-only read: read role, no team-derived role,
    # not the owner, no repository collaborator row, and no organization team
    # membership. The member list also shows the single direct row.
    granted = h.doc(permissions_path, 200, token=h.alice)
    assert granted["role"] == "read" and granted["direct_role"] == "read"
    assert granted["team_role"] is None and granted["is_owner"] is False
    members = h.doc("/api/orgs/acme/members?limit=1000", 200, token=h.alice)["items"]
    assert [m for m in members if m["username"] == PRINCIPAL] == [
        {"username": PRINCIPAL, "role": "read", "version": 1}
    ]
    collaborators = h.doc("/api/repos/acme/app/collaborators", 200, token=h.alice)["items"]
    assert all(c["username"] != PRINCIPAL for c in collaborators)
    teams = h.doc("/api/orgs/acme/teams?limit=1000", 200, token=h.alice)["items"]
    assert teams, "acme teams fixture is required to prove non-membership"
    for team in teams:
        team_members = h.doc(
            f"/api/orgs/acme/teams/{team['slug']}/members?limit=1000",
            200,
            token=h.alice,
        )["items"]
        assert all(m["username"] != PRINCIPAL for m in team_members), team["slug"]

    # The direct read membership alone satisfies the existing View's Read
    # contract. Verify the returned bytes as a real Git bundle with stock Git.
    assert h.http("/api/repos/acme/app", token=principal)[0] == 200
    bundle = h.expect(bundle_path, 200, token=principal)
    assert len(bundle) > 0
    archive = h.root / BUNDLE_NAME
    archive.write_bytes(bundle)
    verify_repo = h.root / "direct-view-verify.git"
    h.git("init", "--bare", str(verify_repo))
    h.git("bundle", "verify", str(archive), cwd=verify_repo)
    heads = [
        line.split()
        for line in h.git(
            "bundle", "list-heads", str(archive), cwd=verify_repo
        ).stdout.decode().splitlines()
        if line.strip()
    ]
    assert [view["projected_oid"], "refs/heads/projected"] in heads, heads

    # Remove only that direct membership, as the organization admin.
    removed = h.doc(membership_path, 200, token=h.alice, method="DELETE")
    assert removed == {"removed": True, "username": PRINCIPAL}

    # The same token is still valid, no broad fallback repository role exists,
    # and the View itself is still present for its creator.
    assert h.doc("/api/orgs", 200, token=principal)["items"] == []
    assert h.http("/api/repos/acme/app", token=principal)[0] == 404
    revoked = h.doc(permissions_path, 200, token=h.alice)
    assert revoked["role"] is None and revoked["direct_role"] is None
    assert revoked["team_role"] is None and revoked["is_owner"] is False
    assert h.doc(f"/api/views/{view_id}", 200, token=h.dave)["id"] == view_id

    # Actual bundle handler contract for the same View and same token: the
    # missing effective role is a not-found denial, never a broad fallback.
    denial_status, _, _ = h.http(bundle_path, token=principal)
    assert denial_status == 404

    return {
        "direct_org_read_only_principal": True,
        "existing_org_view_bundle_ok": True,
        "bundle_bytes": len(bundle),
        "bundle_sha256": hashlib.sha256(bundle).hexdigest(),
        "bundle_projected_oid_matched": True,
        "direct_membership_removed": True,
        "same_view_same_token_denial_status": denial_status,
        "principal_team_role_absent": True,
        "principal_repo_collaborator_absent": True,
        "post_revocation_role_absent": True,
        "token_still_valid_after_revocation": True,
    }
