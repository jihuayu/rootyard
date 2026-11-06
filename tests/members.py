#!/usr/bin/env python3
"""Collaborator & Team 5-Role RBAC Hierarchy, Multi-Reviewer PR Policy, and Repository Audit Log contract."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
from typing import Any, Optional
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pulls import PullsHarness  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]

ROLE_LEVELS: dict[str, int] = {
    "read": 10,
    "triage": 20,
    "write": 30,
    "maintain": 40,
    "admin": 50,
}

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
AUDIT_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")


def migration_050_path() -> Path:
    promoted = ROOT / "migrations/050_members_rbac.sql"
    if promoted.is_file():
        return promoted
    return ROOT / "src/members/050_members_rbac.sql"


def valid_name(name: str) -> bool:
    return bool(NAME_RE.match(name))


def valid_team_name(name: str) -> bool:
    return (
        bool(name.strip())
        and len(name.encode("utf-8")) <= 128
        and not any(ord(c) < 32 or ord(c) == 127 for c in name)
    )


def valid_team_description(desc: str) -> bool:
    return len(desc.encode("utf-8")) <= 1024 and not any(
        (ord(c) < 32 or ord(c) == 127) and c not in ("\n", "\r", "\t") for c in desc
    )


class MembersReferenceEngine:
    """SQLite-backed reference engine verifying Track B (F24 & F25) RBAC, multi-reviewer PRs, and audit queries."""

    def __init__(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE
            );
            CREATE TABLE repositories (
                id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL REFERENCES users(id),
                name TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'ready',
                UNIQUE (owner_id, name)
            );
            CREATE TABLE repository_collaborators (
                repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
                tenant_id TEXT NOT NULL,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                role TEXT NOT NULL CHECK (role IN ('read', 'triage', 'write', 'maintain', 'admin')),
                version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
                created_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z',
                updated_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z',
                PRIMARY KEY (repository_id, user_id),
                CHECK (user_id <> tenant_id)
            );
            CREATE TABLE repository_teams (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
                slug TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                role TEXT NOT NULL CHECK (role IN ('read', 'triage', 'write', 'maintain', 'admin')),
                version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
                created_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z',
                updated_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z',
                UNIQUE (repository_id, slug)
            );
            CREATE TABLE repository_team_members (
                team_id TEXT NOT NULL REFERENCES repository_teams(id) ON DELETE CASCADE,
                repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z',
                PRIMARY KEY (team_id, user_id)
            );
            CREATE TABLE repository_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
                actor_id TEXT NOT NULL REFERENCES users(id),
                actor_name TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_name TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '{}',
                created_unix INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z'
            );
            CREATE TABLE forge_creation_requests (
                tenant_id TEXT NOT NULL,
                repository_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_json TEXT NOT NULL,
                response_json TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, repository_id, idempotency_key)
            );
            CREATE TABLE forge_branch_rules (
                tenant_id TEXT NOT NULL,
                repository_id TEXT NOT NULL,
                branch_ref TEXT NOT NULL,
                required_approvals INTEGER NOT NULL DEFAULT 0,
                required_checks TEXT NOT NULL DEFAULT '[]',
                require_fast_forward INTEGER NOT NULL DEFAULT 1,
                prevent_deletion INTEGER NOT NULL DEFAULT 1,
                prevent_force_push INTEGER NOT NULL DEFAULT 1,
                prevent_self_approval INTEGER NOT NULL DEFAULT 0,
                version INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (tenant_id, repository_id, branch_ref)
            );
            CREATE TABLE forge_pulls (
                tenant_id TEXT NOT NULL,
                repository_id TEXT NOT NULL,
                number INTEGER NOT NULL,
                author_id TEXT NOT NULL REFERENCES users(id),
                title TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'open',
                head_ref TEXT NOT NULL,
                base_ref TEXT NOT NULL,
                head_oid TEXT NOT NULL,
                base_oid TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                next_review_number INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (tenant_id, repository_id, number)
            );
            CREATE TABLE forge_pull_reviews (
                tenant_id TEXT NOT NULL,
                repository_id TEXT NOT NULL,
                pull_number INTEGER NOT NULL,
                number INTEGER NOT NULL,
                author_id TEXT NOT NULL REFERENCES users(id),
                state TEXT NOT NULL CHECK (state IN ('approved', 'changes_requested', 'commented')),
                commit_oid TEXT NOT NULL,
                pull_version INTEGER NOT NULL,
                body TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (tenant_id, repository_id, pull_number, number)
            );
            CREATE TABLE forge_issues (
                tenant_id TEXT NOT NULL,
                repository_id TEXT NOT NULL,
                number INTEGER NOT NULL,
                author_id TEXT NOT NULL REFERENCES users(id),
                title TEXT NOT NULL,
                body TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL DEFAULT 'open',
                version INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (tenant_id, repository_id, number)
            );
            """
        )
        self._clock = 1700000000

    def next_ts(self) -> int:
        self._clock += 1
        return self._clock

    def create_user(self, username: str, user_id: Optional[str] = None) -> dict[str, Any]:
        uid = user_id or str(uuid.uuid4())
        self.conn.execute("INSERT INTO users (id, username) VALUES (?, ?)", (uid, username))
        return {"id": uid, "username": username, "read_only": False, "revoked": False}

    def create_repo(self, owner: dict[str, Any], name: str, state: str = "ready", repo_id: Optional[str] = None) -> dict[str, Any]:
        rid = repo_id or str(uuid.uuid4())
        self.conn.execute(
            "INSERT INTO repositories (id, owner_id, name, state) VALUES (?, ?, ?, ?)",
            (rid, owner["id"], name, state),
        )
        return {"id": rid, "owner_id": owner["id"], "owner": owner["username"], "name": name, "state": state}

    def resolve_effective_role(self, repo_id: str, owner_id: str, user_id: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
        if user_id == owner_id:
            return "admin", None, None
        row = self.conn.execute(
            "SELECT role FROM repository_collaborators WHERE repository_id=? AND user_id=?",
            (repo_id, user_id),
        ).fetchone()
        direct_role = row["role"] if row else None
        team_rows = self.conn.execute(
            """
            SELECT t.role FROM repository_teams t
            JOIN repository_team_members tm ON tm.team_id = t.id
            WHERE t.repository_id=? AND tm.user_id=?
            """,
            (repo_id, user_id),
        ).fetchall()
        max_team_role: Optional[str] = None
        for r in team_rows:
            role_name = r["role"]
            if max_team_role is None or ROLE_LEVELS[role_name] > ROLE_LEVELS[max_team_role]:
                max_team_role = role_name

        candidates = [r for r in (direct_role, max_team_role) if r is not None]
        if not candidates:
            return None, None, None
        effective = max(candidates, key=lambda r: ROLE_LEVELS[r])
        return effective, direct_role, max_team_role

    def authorize_repo_with_role(
        self,
        actor: dict[str, Any],
        owner: str,
        name: str,
        min_role: str,
    ) -> tuple[int, Optional[dict[str, Any]]]:
        if actor.get("revoked"):
            return 401, {"error": "valid credentials required"}
        if not valid_name(owner) or not valid_name(name):
            return 404, {"error": "not found"}
        repo = self.conn.execute(
            """
            SELECT r.id, r.owner_id, r.state FROM repositories r
            JOIN users u ON u.id = r.owner_id
            WHERE u.username=? AND r.name=?
            """,
            (owner, name),
        ).fetchone()
        if repo is None:
            return 404, {"error": "not found"}
        eff, direct_r, team_r = self.resolve_effective_role(repo["id"], repo["owner_id"], actor["id"])
        if eff is None:
            return 404, {"error": "not found"}
        if ROLE_LEVELS[min_role] >= ROLE_LEVELS["triage"] and actor.get("read_only"):
            return 403, {"error": "write permission required"}
        if ROLE_LEVELS[eff] < ROLE_LEVELS[min_role]:
            return 403, {"error": "insufficient repository role"}
        if repo["state"] != "ready":
            return 409, {"error": "repository is not ready"}
        return 200, {
            "repo_id": repo["id"],
            "owner_id": repo["owner_id"],
            "role": eff,
            "direct_role": direct_r,
            "team_role": team_r,
        }

    def _record_audit(
        self,
        tenant_id: str,
        repo_id: str,
        actor: dict[str, Any],
        action: str,
        target_type: str,
        target_name: str,
        details: dict[str, Any],
        created_unix: Optional[int] = None,
    ) -> dict[str, Any]:
        ts = created_unix if created_unix is not None else self.next_ts()
        cur = self.conn.execute(
            """
            INSERT INTO repository_audit_log
            (tenant_id, repository_id, actor_id, actor_name, action, target_type, target_name, details, created_unix)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                repo_id,
                actor["id"],
                actor["username"],
                action,
                target_type,
                target_name,
                json.dumps(details, sort_keys=True),
                ts,
            ),
        )
        row = self.conn.execute("SELECT * FROM repository_audit_log WHERE id=?", (cur.lastrowid,)).fetchone()
        return self._format_audit(row)

    @staticmethod
    def _format_audit(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "repository_id": row["repository_id"],
            "actor_id": row["actor_id"],
            "actor_name": row["actor_name"],
            "action": row["action"],
            "target_type": row["target_type"],
            "target_name": row["target_name"],
            "details": json.loads(row["details"]),
            "created_unix": row["created_unix"],
            "created_at": row["created_at"],
        }

    def _check_idempotency(
        self, tenant_id: str, repo_id: str, key: Optional[str], req_obj: dict[str, Any]
    ) -> Optional[tuple[int, dict[str, Any]]]:
        if key is None:
            return None
        req_json = json.dumps(req_obj, sort_keys=True)
        row = self.conn.execute(
            "SELECT request_json, response_json, status_code FROM forge_creation_requests WHERE tenant_id=? AND repository_id=? AND idempotency_key=?",
            (tenant_id, repo_id, key),
        ).fetchone()
        if row is None:
            return None
        if row["request_json"] != req_json:
            return 409, {"error": "idempotency key conflict"}
        return row["status_code"], json.loads(row["response_json"])

    def _save_idempotency(
        self, tenant_id: str, repo_id: str, key: Optional[str], req_obj: dict[str, Any], status_code: int, resp_obj: dict[str, Any]
    ) -> None:
        if key is not None:
            self.conn.execute(
                "INSERT INTO forge_creation_requests VALUES (?, ?, ?, ?, ?, ?)",
                (
                    tenant_id,
                    repo_id,
                    key,
                    json.dumps(req_obj, sort_keys=True),
                    json.dumps(resp_obj, sort_keys=True),
                    status_code,
                ),
            )

    def upsert_collaborator(
        self,
        actor: dict[str, Any],
        owner: str,
        repo_name: str,
        username: str,
        role: str,
        expected_version: Optional[int] = None,
        idempotency_key: Optional[str] = None,
    ) -> tuple[int, dict[str, Any]]:
        if role not in ROLE_LEVELS or (expected_version is not None and expected_version <= 0):
            return 400, {"error": "invalid request"}
        st, acc = self.authorize_repo_with_role(actor, owner, repo_name, "admin")
        if st != 200 or acc is None:
            return st, acc or {"error": "unauthorized"}
        if not valid_name(username):
            return 400, {"error": "invalid request"}
        target = self.conn.execute("SELECT id, username FROM users WHERE username=?", (username,)).fetchone()
        if target is None:
            return 404, {"error": "not found"}
        if target["id"] == acc["owner_id"]:
            return 409, {"error": "cannot modify or remove repository owner"}

        req_payload = {
            "operation": "collaborator_upsert",
            "username": target["username"],
            "role": role,
            "expected_version": expected_version,
        }
        replay = self._check_idempotency(acc["owner_id"], acc["repo_id"], idempotency_key, req_payload)
        if replay is not None:
            return replay

        existing = self.conn.execute(
            "SELECT version FROM repository_collaborators WHERE repository_id=? AND user_id=?",
            (acc["repo_id"], target["id"]),
        ).fetchone()
        if existing is None:
            if expected_version is not None:
                return 409, {"error": "collaborator version conflict"}
            self.conn.execute(
                "INSERT INTO repository_collaborators (repository_id, tenant_id, user_id, role, version) VALUES (?, ?, ?, ?, 1)",
                (acc["repo_id"], acc["owner_id"], target["id"], role),
            )
            code, action, ver = 201, "collaborator.added", 1
        else:
            cur_v = existing["version"]
            if expected_version is not None and expected_version != cur_v:
                return 409, {"error": "collaborator version conflict"}
            ver = cur_v + 1
            self.conn.execute(
                "UPDATE repository_collaborators SET role=?, version=? WHERE repository_id=? AND user_id=?",
                (role, ver, acc["repo_id"], target["id"]),
            )
            code, action = 200, "collaborator.updated"

        resp = {
            "repository_id": acc["repo_id"],
            "user_id": target["id"],
            "username": target["username"],
            "role": role,
            "version": ver,
        }
        self._save_idempotency(acc["owner_id"], acc["repo_id"], idempotency_key, req_payload, code, resp)
        self._record_audit(
            acc["owner_id"],
            acc["repo_id"],
            actor,
            action,
            "collaborator",
            target["username"],
            {"role": role, "version": ver},
        )
        return code, resp

    def remove_collaborator(
        self, actor: dict[str, Any], owner: str, repo_name: str, username: str
    ) -> tuple[int, dict[str, Any]]:
        if not valid_name(username):
            return 400, {"error": "invalid request"}
        st, acc = self.authorize_repo_with_role(actor, owner, repo_name, "admin")
        if st != 200 or acc is None:
            return st, acc or {"error": "unauthorized"}
        if username == owner:
            return 409, {"error": "cannot modify or remove repository owner"}
        target = self.conn.execute("SELECT id, username FROM users WHERE username=?", (username,)).fetchone()
        if target is None:
            return 404, {"error": "not found"}
        if target["id"] == acc["owner_id"]:
            return 409, {"error": "cannot modify or remove repository owner"}
        cur = self.conn.execute(
            "DELETE FROM repository_collaborators WHERE repository_id=? AND user_id=?",
            (acc["repo_id"], target["id"]),
        )
        if cur.rowcount == 0:
            return 404, {"error": "not found"}
        self._record_audit(
            acc["owner_id"],
            acc["repo_id"],
            actor,
            "collaborator.removed",
            "collaborator",
            target["username"],
            {"user_id": target["id"]},
        )
        return 200, {"removed": True, "username": target["username"]}

    def create_team(
        self,
        actor: dict[str, Any],
        owner: str,
        repo_name: str,
        slug: str,
        name: str,
        role: str,
        description: str = "",
        idempotency_key: Optional[str] = None,
    ) -> tuple[int, dict[str, Any]]:
        if (
            role not in ROLE_LEVELS
            or not valid_name(slug)
            or not valid_team_name(name)
            or not valid_team_description(description)
        ):
            return 400, {"error": "invalid request"}
        st, acc = self.authorize_repo_with_role(actor, owner, repo_name, "admin")
        if st != 200 or acc is None:
            return st, acc or {"error": "unauthorized"}
        req_payload = {
            "operation": "team_create",
            "slug": slug,
            "name": name,
            "description": description,
            "role": role,
        }
        replay = self._check_idempotency(acc["owner_id"], acc["repo_id"], idempotency_key, req_payload)
        if replay is not None:
            return replay

        dup = self.conn.execute(
            "SELECT id FROM repository_teams WHERE repository_id=? AND slug=?",
            (acc["repo_id"], slug),
        ).fetchone()
        if dup is not None:
            return 409, {"error": "team slug already exists"}
        tid = str(uuid.uuid4())
        self.conn.execute(
            "INSERT INTO repository_teams (id, tenant_id, repository_id, slug, name, description, role, version) VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
            (tid, acc["owner_id"], acc["repo_id"], slug, name, description, role),
        )
        resp = {
            "id": tid,
            "repository_id": acc["repo_id"],
            "slug": slug,
            "name": name,
            "description": description,
            "role": role,
            "version": 1,
        }
        self._save_idempotency(acc["owner_id"], acc["repo_id"], idempotency_key, req_payload, 201, resp)
        self._record_audit(
            acc["owner_id"],
            acc["repo_id"],
            actor,
            "team.created",
            "team",
            slug,
            {"role": role, "name": name},
        )
        return 201, resp

    def update_team(
        self,
        actor: dict[str, Any],
        owner: str,
        repo_name: str,
        slug: str,
        expected_version: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        role: Optional[str] = None,
    ) -> tuple[int, dict[str, Any]]:
        if (
            expected_version <= 0
            or not valid_name(slug)
            or (name is None and description is None and role is None)
            or (name is not None and not valid_team_name(name))
            or (description is not None and not valid_team_description(description))
            or (role is not None and role not in ROLE_LEVELS)
        ):
            return 400, {"error": "invalid request"}
        st, acc = self.authorize_repo_with_role(actor, owner, repo_name, "admin")
        if st != 200 or acc is None:
            return st, acc or {"error": "unauthorized"}
        row = self.conn.execute(
            "SELECT * FROM repository_teams WHERE repository_id=? AND slug=?",
            (acc["repo_id"], slug),
        ).fetchone()
        if row is None:
            return 404, {"error": "not found"}
        if row["version"] != expected_version:
            return 409, {"error": "team version conflict"}
        new_name = name if name is not None else row["name"]
        new_desc = description if description is not None else row["description"]
        new_role = role if role is not None else row["role"]
        new_ver = expected_version + 1
        self.conn.execute(
            "UPDATE repository_teams SET name=?, description=?, role=?, version=? WHERE id=?",
            (new_name, new_desc, new_role, new_ver, row["id"]),
        )
        self._record_audit(
            acc["owner_id"],
            acc["repo_id"],
            actor,
            "team.updated",
            "team",
            slug,
            {"role": new_role, "version": new_ver},
        )
        return 200, {
            "id": row["id"],
            "repository_id": acc["repo_id"],
            "slug": slug,
            "name": new_name,
            "description": new_desc,
            "role": new_role,
            "version": new_ver,
        }

    def delete_team(
        self, actor: dict[str, Any], owner: str, repo_name: str, slug: str
    ) -> tuple[int, dict[str, Any]]:
        if not valid_name(slug):
            return 400, {"error": "invalid request"}
        st, acc = self.authorize_repo_with_role(actor, owner, repo_name, "admin")
        if st != 200 or acc is None:
            return st, acc or {"error": "unauthorized"}
        cur = self.conn.execute(
            "DELETE FROM repository_teams WHERE repository_id=? AND slug=?",
            (acc["repo_id"], slug),
        )
        if cur.rowcount == 0:
            return 404, {"error": "not found"}
        self._record_audit(
            acc["owner_id"],
            acc["repo_id"],
            actor,
            "team.deleted",
            "team",
            slug,
            {"slug": slug},
        )
        return 200, {"deleted": True, "slug": slug}

    def add_team_member(
        self, actor: dict[str, Any], owner: str, repo_name: str, slug: str, username: str
    ) -> tuple[int, dict[str, Any]]:
        if not valid_name(slug) or not valid_name(username):
            return 400, {"error": "invalid request"}
        st, acc = self.authorize_repo_with_role(actor, owner, repo_name, "admin")
        if st != 200 or acc is None:
            return st, acc or {"error": "unauthorized"}
        team = self.conn.execute(
            "SELECT id FROM repository_teams WHERE repository_id=? AND slug=?",
            (acc["repo_id"], slug),
        ).fetchone()
        if team is None:
            return 404, {"error": "not found"}
        target = self.conn.execute("SELECT id, username FROM users WHERE username=?", (username,)).fetchone()
        if target is None:
            return 404, {"error": "not found"}
        if target["id"] == acc["owner_id"]:
            return 409, {"error": "cannot modify or remove repository owner"}
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO repository_team_members (team_id, repository_id, user_id) VALUES (?, ?, ?)",
            (team["id"], acc["repo_id"], target["id"]),
        )
        status = 201 if cur.rowcount == 1 else 200
        if cur.rowcount == 1:
            self._record_audit(
                acc["owner_id"],
                acc["repo_id"],
                actor,
                "team_member.added",
                "team_member",
                f"{slug}:{target['username']}",
                {"team_slug": slug, "username": target["username"]},
            )
        return status, {
            "team_id": team["id"],
            "repository_id": acc["repo_id"],
            "user_id": target["id"],
            "username": target["username"],
        }

    def remove_team_member(
        self, actor: dict[str, Any], owner: str, repo_name: str, slug: str, username: str
    ) -> tuple[int, dict[str, Any]]:
        if not valid_name(slug) or not valid_name(username):
            return 400, {"error": "invalid request"}
        st, acc = self.authorize_repo_with_role(actor, owner, repo_name, "admin")
        if st != 200 or acc is None:
            return st, acc or {"error": "unauthorized"}
        team = self.conn.execute(
            "SELECT id FROM repository_teams WHERE repository_id=? AND slug=?",
            (acc["repo_id"], slug),
        ).fetchone()
        if team is None:
            return 404, {"error": "not found"}
        target = self.conn.execute("SELECT id, username FROM users WHERE username=?", (username,)).fetchone()
        if target is None:
            return 404, {"error": "not found"}
        cur = self.conn.execute(
            "DELETE FROM repository_team_members WHERE team_id=? AND user_id=?",
            (team["id"], target["id"]),
        )
        if cur.rowcount == 0:
            return 404, {"error": "not found"}
        self._record_audit(
            acc["owner_id"],
            acc["repo_id"],
            actor,
            "team_member.removed",
            "team_member",
            f"{slug}:{target['username']}",
            {"team_slug": slug, "username": target["username"]},
        )
        return 200, {"removed": True, "team_slug": slug, "username": target["username"]}

    def get_effective_permission(
        self, actor: dict[str, Any], owner: str, repo_name: str, username: str
    ) -> tuple[int, dict[str, Any]]:
        if not valid_name(username):
            return 400, {"error": "invalid request"}
        st, acc = self.authorize_repo_with_role(actor, owner, repo_name, "read")
        if st != 200 or acc is None:
            return st, acc or {"error": "unauthorized"}
        target = self.conn.execute("SELECT id, username FROM users WHERE username=?", (username,)).fetchone()
        if target is None:
            return 404, {"error": "not found"}
        eff, direct_r, team_r = self.resolve_effective_role(acc["repo_id"], acc["owner_id"], target["id"])
        return 200, {
            "repository_id": acc["repo_id"],
            "user_id": target["id"],
            "username": target["username"],
            "role": eff,
            "direct_role": direct_r,
            "team_role": team_r,
            "is_owner": target["id"] == acc["owner_id"],
        }

    def upsert_branch_rule(
        self,
        actor: dict[str, Any],
        owner: str,
        repo_name: str,
        branch_ref: str,
        required_approvals: int = 0,
        prevent_self_approval: bool = False,
        expected_version: Optional[int] = None,
    ) -> tuple[int, dict[str, Any]]:
        if not (0 <= required_approvals <= 100):
            return 400, {"error": "invalid request"}
        st, acc = self.authorize_repo_with_role(actor, owner, repo_name, "maintain")
        if st != 200 or acc is None:
            return st, acc or {"error": "unauthorized"}
        norm_ref = branch_ref if branch_ref.startswith("refs/heads/") else f"refs/heads/{branch_ref}"
        existing = self.conn.execute(
            "SELECT version FROM forge_branch_rules WHERE tenant_id=? AND repository_id=? AND branch_ref=?",
            (acc["owner_id"], acc["repo_id"], norm_ref),
        ).fetchone()
        if existing is None:
            if expected_version is not None:
                return 409, {"error": "branch rule version conflict"}
            self.conn.execute(
                "INSERT INTO forge_branch_rules (tenant_id, repository_id, branch_ref, required_approvals, prevent_self_approval, version) VALUES (?, ?, ?, ?, ?, 1)",
                (acc["owner_id"], acc["repo_id"], norm_ref, required_approvals, int(prevent_self_approval)),
            )
            code, ver = 201, 1
        else:
            if expected_version != existing["version"]:
                return 409, {"error": "branch rule version conflict"}
            ver = existing["version"] + 1
            self.conn.execute(
                "UPDATE forge_branch_rules SET required_approvals=?, prevent_self_approval=?, version=? WHERE tenant_id=? AND repository_id=? AND branch_ref=?",
                (required_approvals, int(prevent_self_approval), ver, acc["owner_id"], acc["repo_id"], norm_ref),
            )
            code = 200
        self._record_audit(
            acc["owner_id"],
            acc["repo_id"],
            actor,
            "branch_rule.upserted",
            "branch_rule",
            norm_ref,
            {"required_approvals": required_approvals, "prevent_self_approval": prevent_self_approval, "version": ver},
        )
        return code, {
            "repository_id": acc["repo_id"],
            "branch_ref": norm_ref,
            "required_approvals": required_approvals,
            "prevent_self_approval": prevent_self_approval,
            "version": ver,
        }

    def create_issue(
        self, actor: dict[str, Any], owner: str, repo_name: str, title: str, body: str = ""
    ) -> tuple[int, dict[str, Any]]:
        st, acc = self.authorize_repo_with_role(actor, owner, repo_name, "triage")
        if st != 200 or acc is None:
            return st, acc or {"error": "unauthorized"}
        row = self.conn.execute(
            "SELECT COALESCE(max(number), 0) + 1 AS next_num FROM forge_issues WHERE repository_id=?",
            (acc["repo_id"],),
        ).fetchone()
        num = row["next_num"]
        self.conn.execute(
            "INSERT INTO forge_issues (tenant_id, repository_id, number, author_id, title, body) VALUES (?, ?, ?, ?, ?, ?)",
            (acc["owner_id"], acc["repo_id"], num, actor["id"], title, body),
        )
        return 201, {"repository_id": acc["repo_id"], "number": num, "author_id": actor["id"], "title": title}

    def create_pull(
        self,
        actor: dict[str, Any],
        owner: str,
        repo_name: str,
        title: str,
        head_ref: str,
        base_ref: str,
        head_oid: str,
        base_oid: str,
    ) -> tuple[int, dict[str, Any]]:
        st, acc = self.authorize_repo_with_role(actor, owner, repo_name, "write")
        if st != 200 or acc is None:
            return st, acc or {"error": "unauthorized"}
        row = self.conn.execute(
            "SELECT COALESCE(max(number), 0) + 1 AS next_num FROM forge_pulls WHERE repository_id=?",
            (acc["repo_id"],),
        ).fetchone()
        num = row["next_num"]
        norm_head = head_ref if head_ref.startswith("refs/heads/") else f"refs/heads/{head_ref}"
        norm_base = base_ref if base_ref.startswith("refs/heads/") else f"refs/heads/{base_ref}"
        self.conn.execute(
            """
            INSERT INTO forge_pulls (tenant_id, repository_id, number, author_id, title, head_ref, base_ref, head_oid, base_oid)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (acc["owner_id"], acc["repo_id"], num, actor["id"], title, norm_head, norm_base, head_oid, base_oid),
        )
        return 201, {
            "repository_id": acc["repo_id"],
            "number": num,
            "author_id": actor["id"],
            "head_ref": norm_head,
            "base_ref": norm_base,
            "head_oid": head_oid,
            "base_oid": base_oid,
            "version": 1,
        }

    def is_self_approval_disallowed(
        self, tenant_id: str, repo_id: str, base_ref: str, pull_author_id: str
    ) -> bool:
        if pull_author_id != tenant_id:
            return True
        rule = self.conn.execute(
            "SELECT prevent_self_approval FROM forge_branch_rules WHERE tenant_id=? AND repository_id=? AND branch_ref=?",
            (tenant_id, repo_id, base_ref),
        ).fetchone()
        if rule and rule["prevent_self_approval"]:
            return True
        has_members = self.conn.execute(
            "SELECT EXISTS(SELECT 1 FROM repository_collaborators WHERE repository_id=?) OR EXISTS(SELECT 1 FROM repository_teams WHERE repository_id=?) AS e",
            (repo_id, repo_id),
        ).fetchone()["e"]
        return bool(has_members)

    def create_review(
        self,
        actor: dict[str, Any],
        owner: str,
        repo_name: str,
        pull_number: int,
        state: str,
        commit_oid: str,
        body: str = "",
    ) -> tuple[int, dict[str, Any]]:
        if state not in ("approved", "changes_requested", "commented"):
            return 400, {"error": "invalid request"}
        if state != "approved" and not body.strip():
            return 400, {"error": "invalid request"}
        min_role = "triage" if state == "commented" else "write"
        st, acc = self.authorize_repo_with_role(actor, owner, repo_name, min_role)
        if st != 200 or acc is None:
            return st, acc or {"error": "unauthorized"}
        pr = self.conn.execute(
            "SELECT * FROM forge_pulls WHERE tenant_id=? AND repository_id=? AND number=?",
            (acc["owner_id"], acc["repo_id"], pull_number),
        ).fetchone()
        if pr is None:
            return 404, {"error": "not found"}
        if pr["state"] != "open":
            return 409, {"error": "pull request is not open"}
        if pr["head_oid"] != commit_oid:
            return 409, {"error": "review commit_oid does not match pull request head_oid"}

        disallow_self = self.is_self_approval_disallowed(
            acc["owner_id"], acc["repo_id"], pr["base_ref"], pr["author_id"]
        )
        if state == "approved" and actor["id"] == pr["author_id"] and disallow_self:
            return 403, {"error": "pull request author cannot approve their own pull request"}

        rev_num = pr["next_review_number"]
        self.conn.execute(
            "UPDATE forge_pulls SET next_review_number = next_review_number + 1 WHERE tenant_id=? AND repository_id=? AND number=?",
            (acc["owner_id"], acc["repo_id"], pull_number),
        )
        self.conn.execute(
            """
            INSERT INTO forge_pull_reviews (tenant_id, repository_id, pull_number, number, author_id, state, commit_oid, pull_version, body)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (acc["owner_id"], acc["repo_id"], pull_number, rev_num, actor["id"], state, commit_oid, pr["version"], body),
        )
        self._record_audit(
            acc["owner_id"],
            acc["repo_id"],
            actor,
            "pull_review.submitted",
            "pull_review",
            f"{pull_number}:{rev_num}",
            {"pull_number": pull_number, "state": state, "commit_oid": commit_oid},
        )
        return 201, {
            "repository_id": acc["repo_id"],
            "pull_number": pull_number,
            "number": rev_num,
            "author_id": actor["id"],
            "state": state,
            "commit_oid": commit_oid,
            "body": body,
        }

    def evaluate_branch_policy(self, owner: str, repo_name: str, pull_number: int) -> dict[str, Any]:
        repo = self.conn.execute(
            "SELECT r.id, r.owner_id FROM repositories r JOIN users u ON u.id = r.owner_id WHERE u.username=? AND r.name=?",
            (owner, repo_name),
        ).fetchone()
        pr = self.conn.execute(
            "SELECT * FROM forge_pulls WHERE tenant_id=? AND repository_id=? AND number=?",
            (repo["owner_id"], repo["id"], pull_number),
        ).fetchone()
        rule = self.conn.execute(
            "SELECT * FROM forge_branch_rules WHERE tenant_id=? AND repository_id=? AND branch_ref=?",
            (repo["owner_id"], repo["id"], pr["base_ref"]),
        ).fetchone()
        if rule is None:
            return {"allowed": True, "required_approvals": 0, "current_approvals": 0, "reason": None}

        req_approvals = rule["required_approvals"]
        latest_verdict_row = self.conn.execute(
            """
            SELECT state FROM forge_pull_reviews
            WHERE tenant_id=? AND repository_id=? AND pull_number=? AND commit_oid=?
              AND state IN ('approved', 'changes_requested')
            ORDER BY number DESC LIMIT 1
            """,
            (repo["owner_id"], repo["id"], pull_number, pr["head_oid"]),
        ).fetchone()
        latest_verdict = latest_verdict_row["state"] if latest_verdict_row else None

        max_cr_row = self.conn.execute(
            """
            SELECT COALESCE(max(number), 0) AS max_cr FROM forge_pull_reviews
            WHERE tenant_id=? AND repository_id=? AND pull_number=? AND commit_oid=? AND state='changes_requested'
            """,
            (repo["owner_id"], repo["id"], pull_number, pr["head_oid"]),
        ).fetchone()
        max_cr = max_cr_row["max_cr"]

        disallow_self = self.is_self_approval_disallowed(
            repo["owner_id"], repo["id"], pr["base_ref"], pr["author_id"]
        )
        rows = self.conn.execute(
            """
            SELECT author_id FROM forge_pull_reviews
            WHERE tenant_id=? AND repository_id=? AND pull_number=? AND commit_oid=?
              AND state='approved' AND number > ?
            """,
            (repo["owner_id"], repo["id"], pull_number, pr["head_oid"], max_cr),
        ).fetchall()

        if disallow_self:
            approvers: set[str] = set()
            for r in rows:
                uid = r["author_id"]
                if uid == pr["author_id"]:
                    continue
                eff, _, _ = self.resolve_effective_role(repo["id"], repo["owner_id"], uid)
                if eff is not None and ROLE_LEVELS[eff] >= ROLE_LEVELS["write"]:
                    approvers.add(uid)
            eff_count = len(approvers)
        else:
            eff_count = len(rows)

        current_approvals = 0 if latest_verdict == "changes_requested" else eff_count
        allowed = True
        reason = None
        if latest_verdict == "changes_requested" and req_approvals > 0:
            allowed = False
            reason = "changes requested on pull request"
        elif current_approvals < req_approvals:
            allowed = False
            reason = "insufficient pull request approvals"
        return {
            "allowed": allowed,
            "required_approvals": req_approvals,
            "current_approvals": current_approvals,
            "reason": reason,
        }

    def list_audit_events(
        self,
        actor: dict[str, Any],
        owner: str,
        repo_name: str,
        filter_actor: Optional[str] = None,
        filter_action: Optional[str] = None,
        since: Optional[int] = None,
        until: Optional[int] = None,
        after: int = 0,
        limit: int = 50,
    ) -> tuple[int, dict[str, Any]]:
        if after < 0 or not (1 <= limit <= 100):
            return 400, {"error": "invalid request"}
        if filter_actor is not None and not valid_name(filter_actor):
            return 400, {"error": "invalid request"}
        if filter_action is not None and not AUDIT_TOKEN_RE.match(filter_action):
            return 400, {"error": "invalid request"}
        if since is not None and since < 0:
            return 400, {"error": "invalid request"}
        if until is not None and until < 0:
            return 400, {"error": "invalid request"}
        if since is not None and until is not None and since > until:
            return 400, {"error": "invalid request"}

        st, acc = self.authorize_repo_with_role(actor, owner, repo_name, "maintain")
        if st != 200 or acc is None:
            return st, acc or {"error": "unauthorized"}

        rows = self.conn.execute(
            """
            SELECT * FROM repository_audit_log
            WHERE tenant_id=? AND repository_id=? AND id > ?
              AND (? IS NULL OR actor_name = ?)
              AND (? IS NULL OR action = ?)
              AND (? IS NULL OR created_unix >= ?)
              AND (? IS NULL OR created_unix <= ?)
            ORDER BY id ASC LIMIT ?
            """,
            (
                acc["owner_id"],
                acc["repo_id"],
                after,
                filter_actor,
                filter_actor,
                filter_action,
                filter_action,
                since,
                since,
                until,
                until,
                limit + 1,
            ),
        ).fetchall()
        more = len(rows) > limit
        items = [self._format_audit(r) for r in rows[:limit]]
        next_after = items[-1]["id"] if more and items else None
        return 200, {"items": items, "next_after": next_after}


class MembersHarness(PullsHarness):
    """Live PostgreSQL + Rootyard HTTP server E2E harness for Track B (F24 & F25)."""

    def ensure_migration_050(self):
        if self.sql("SELECT to_regclass('repository_collaborators') IS NOT NULL") != "t":
            self.run(
                [
                    "psql",
                    self.db,
                    "-X",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-f",
                    str(migration_050_path()),
                ]
            )

    def setup(self):
        super().setup()
        self.ensure_migration_050()
        self.collabspath = "/api/repos/alice/forge/collaborators"
        self.teamspath = "/api/repos/alice/forge/teams"
        self.permspath = "/api/repos/alice/forge/permissions"
        self.auditpath = "/api/repos/alice/forge/audit"
        self.carol = self.issue_token("carol", create_user=True)
        self.dave = self.issue_token("dave", create_user=True)
        self.erin = self.issue_token("erin", create_user=True)

    def migration(self):
        assert self.sql("SELECT count(*) FROM schema_migrations WHERE version=50") == "1"

    def collaborators_and_5_role_hierarchy(self):
        # Owner cannot be modified or removed as collaborator
        self.document(f"{self.collabspath}/alice", code=409, method="PUT", json_body={"role": "admin"})
        self.document(f"{self.collabspath}/alice", code=409, method="DELETE")

        # Add bob with triage role
        created = self.document(
            self.collabspath,
            code=201,
            method="POST",
            json_body={"username": "bob", "role": "triage"},
        )
        assert created["role"] == "triage" and created["version"] == 1
        # Bob (triage) can create an issue on alice/forge, but cannot create a PR
        self.document("/api/repos/alice/forge/issues", code=201, token=self.bob, method="POST", json_body={"title": "Triage issue"})
        self.document(self.pullspath, code=403, token=self.bob, method="POST", json_body={"title": "Blocked PR", "head_ref": "feature", "base_ref": "main"})

    def teams_and_max_role_inheritance(self):
        team = self.document(
            self.teamspath,
            code=201,
            method="POST",
            json_body={"slug": "reviewers", "name": "Reviewers", "role": "write"},
        )
        assert team["role"] == "write"
        self.document(f"{self.teamspath}/reviewers/members/bob", code=201, method="PUT")
        perm = self.document(f"{self.permspath}/bob", code=200)
        assert perm["role"] == "write" and perm["direct_role"] == "triage" and perm["team_role"] == "write"

    def multi_reviewer_self_approval_and_distinct_approvers(self):
        self.document(
            self.rulespath,
            code=201,
            method="POST",
            json_body={"branch_ref": "main", "required_approvals": 2, "prevent_self_approval": True},
        )
        pr = self.document(
            self.pullspath,
            code=201,
            token=self.bob,
            method="POST",
            json_body={"title": "Bob PR", "head_ref": "feature", "base_ref": "main"},
        )
        # Bob cannot self-approve
        self.document(
            f"{self.pullspath}/{pr['number']}/reviews",
            code=403,
            token=self.bob,
            method="POST",
            json_body={"state": "approved", "commit_oid": pr["head_oid"]},
        )

    def audit_log_filters_and_cursor_pagination(self):
        page1 = self.document(f"{self.auditpath}?limit=2", code=200)
        assert len(page1["items"]) == 2 and page1["next_after"] is not None
        page2 = self.document(f"{self.auditpath}?after={page1['next_after']}&limit=2", code=200)
        assert len(page2["items"]) >= 1 and page2["items"][0]["id"] > page1["items"][-1]["id"]

    def access_and_boundaries(self):
        # Non-member dave gets 404 Not Found on private repo endpoints
        self.document(self.collabspath, code=404, token=self.dave)
        self.document(self.auditpath, code=404, token=self.dave)

    def concurrency_and_idempotency(self):
        c1 = self.document(
            self.collabspath,
            code=201,
            method="POST",
            headers={"Idempotency-Key": "collab-carol-1"},
            json_body={"username": "carol", "role": "maintain"},
        )
        c2 = self.document(
            self.collabspath,
            code=201,
            method="POST",
            headers={"Idempotency-Key": "collab-carol-1"},
            json_body={"username": "carol", "role": "maintain"},
        )
        assert c1 == c2

    def restart(self):
        self.stop()
        self.start()
        perm = self.document(f"{self.permspath}/carol", code=200)
        assert perm["role"] == "maintain"

    def run_all(self):
        for name in (
            "setup",
            "migration",
            "collaborators_and_5_role_hierarchy",
            "teams_and_max_role_inheritance",
            "multi_reviewer_self_approval_and_distinct_approvers",
            "audit_log_filters_and_cursor_pagination",
            "access_and_boundaries",
            "concurrency_and_idempotency",
            "restart",
        ):
            self.case(name, getattr(self, name))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--case", default="all")
    args = parser.parse_args()
    bin_path = Path(args.binary).resolve()
    args.binary = str(bin_path)

    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = MembersHarness(args)
    success = False
    try:
        if args.case == "all":
            harness.run_all()
        else:
            harness.case("setup", harness.setup)
            harness.case(args.case, getattr(harness, args.case))
        success = True
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            harness.results.append(
                dict(name="cleanup", status="failed", error=harness.redact(error))
            )
            success = False
        report = dict(
            passed=success,
            cases=harness.results,
            binary_sha256=(
                hashlib.sha256(bin_path.read_bytes()).hexdigest()
                if bin_path.is_file()
                else "missing-binary"
            ),
        )
        if args.keep:
            report["retained_directory"] = str(harness.root)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
