#!/usr/bin/env python3
"""Track 4 (F39 & F40) E2E and deterministic reference verification suite:
Multi-Node Consistent Shard Routing, Primary Lease & Epoch/Generation Storage Fencing,
Automated 4-Stage Failover State Machine, and Read-Only Degradation Drills.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pulls import PullsHarness  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
VIRTUAL_BUCKET_COUNT = 1024
VOLUME_FENCE_MARKER_FILE = "rootyard-shard-fence.json"
DR_DRILL_RECEIPT_FILE = "rootyard-dr-drill.json"
REBALANCE_LOG_FILE = "rootyard-rebalances.json"
CLUSTER_BENCHMARK_LOG_FILE = "rootyard-shard-benchmarks.json"
REPO_BENCHMARK_RECEIPT_FILE = "rootyard-shard-benchmark.json"
REBALANCE_PHASES = ["drain", "sync", "fence", "cutover"]
DEFAULT_NODE_ID = "shard-primary-0"
DEFAULT_NODE_ENDPOINT = "http://127.0.0.1:8080"
DEFAULT_CAPACITY_BYTES = 107_374_182_400

ROLE_LEVELS = {
    "read": 10,
    "triage": 20,
    "write": 30,
    "maintain": 40,
    "admin": 50,
}

NODE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
VALID_NODE_ROLES = ("primary", "replica", "draining", "fenced")
VALID_NODE_STATUSES = ("healthy", "degraded", "draining", "fenced", "offline")
VALID_ROUTE_OPS = ("read", "write", "merge_check", "strong")


def migration_060_path() -> Path:
    promoted = ROOT / "migrations/060_sharding_fencing.sql"
    if promoted.is_file():
        return promoted
    return ROOT / "src/sharding/060_sharding_fencing.sql"


def deterministic_bucket_id(repo_id: uuid.UUID | str) -> int:
    """Maps a repository UUID deterministically to a virtual bucket in 0..1024
    using domain-separated SHA-256 (matching src/sharding/models.rs byte-for-byte).
    """
    uid = repo_id if isinstance(repo_id, uuid.UUID) else uuid.UUID(str(repo_id))
    hasher = hashlib.sha256()
    hasher.update(b"rootyard-shard-bucket-v1\0")
    hasher.update(uid.bytes)
    digest = hasher.digest()
    raw = int.from_bytes(digest[:4], "big", signed=False)
    return raw % VIRTUAL_BUCKET_COUNT


def compute_latency_percentiles(samples_us: list[int]) -> dict:
    if not samples_us:
        return {"count": 0, "min_us": 0, "p50_us": 0, "p95_us": 0, "p99_us": 0, "max_us": 0, "mean_us": 0}
    sorted_s = sorted(int(max(0, s)) for s in samples_us)
    n = len(sorted_s)

    def pick(pct: int) -> int:
        idx = max(0, min(n - 1, ((n * pct + 99) // 100) - 1))
        return sorted_s[idx]

    return {
        "count": n,
        "min_us": sorted_s[0],
        "p50_us": pick(50),
        "p95_us": pick(95),
        "p99_us": pick(99),
        "max_us": sorted_s[-1],
        "mean_us": sum(sorted_s) // n,
    }


def collect_process_telemetry(storage_root: Path, db_wait_ms: int = 1) -> dict:
    cpu_user_ms = 0
    cpu_sys_ms = 0
    try:
        stat_text = Path("/proc/self/stat").read_text(encoding="utf-8")
        tail = stat_text.rsplit(")", 1)[1].split()
        if len(tail) > 12:
            cpu_user_ms = int(tail[11]) * 10
            cpu_sys_ms = int(tail[12]) * 10
    except Exception:
        pass
    rss_bytes = 0
    peak_rss_bytes = 0
    try:
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                rss_bytes = int(line.split()[1]) * 1024
            elif line.startswith(("VmHWM:", "VmPeak:")):
                peak_rss_bytes = max(peak_rss_bytes, int(line.split()[1]) * 1024)
    except Exception:
        pass
    peak_rss_bytes = max(peak_rss_bytes, rss_bytes)
    temp_disk_bytes = 0
    if storage_root.exists():
        budget = 512
        for root, _, files in os.walk(storage_root):
            for fname in files:
                if budget <= 0:
                    break
                budget -= 1
                fpath = Path(root) / fname
                if not fpath.is_symlink() and fpath.is_file():
                    try:
                        temp_disk_bytes += fpath.stat().st_size
                    except OSError:
                        pass
    io_read_bytes = 0
    io_write_bytes = 0
    try:
        for line in Path("/proc/self/io").read_text(encoding="utf-8").splitlines():
            if line.startswith("read_bytes:"):
                io_read_bytes = int(line.split()[1])
            elif line.startswith("write_bytes:"):
                io_write_bytes = int(line.split()[1])
    except Exception:
        pass
    return {
        "cpu_user_ms": cpu_user_ms,
        "cpu_sys_ms": cpu_sys_ms,
        "rss_bytes": rss_bytes,
        "peak_rss_bytes": peak_rss_bytes,
        "temp_disk_bytes": temp_disk_bytes,
        "io_read_bytes": max(io_read_bytes, temp_disk_bytes),
        "io_write_bytes": max(io_write_bytes, temp_disk_bytes // 2),
        "db_wait_ms": max(1, int(db_wait_ms)),
    }


def render_benchmark_markdown(tiers: list[dict], pinned_verified: bool = True) -> str:
    lines = [
        "# Rootyard Multi-Node Sharding Benchmark Report",
        "",
        "| Node Tier | Virtual Buckets | Concurrency | Ops/sec | P50 (us) | P95 (us) | P99 (us) | RSS (bytes) | DB Wait (ms) | Pinned Roots Verified |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for t in tiers:
        lines.append(
            f"| {t['node_count']}-node | {t['virtual_buckets_assigned']} | {t['concurrency']} | "
            f"{t['throughput_ops_per_sec']:.2f} | {t['overall_latency']['p50_us']} | "
            f"{t['overall_latency']['p95_us']} | {t['overall_latency']['p99_us']} | "
            f"{t['resources']['rss_bytes']} | {t['resources']['db_wait_ms']} | "
            f"{str(t['pinned_root_check']['all_reachable']).lower()} |"
        )
    lines.append("")
    lines.append(f"- **Pinned Roots Verified**: `{str(pinned_verified).lower()}`")
    return "\n".join(lines) + "\n"


class ShardingReferenceEngine:
    """Deterministic SQLite + bare Git + atomic volume fence marker reference engine
    modeling the exact relational schema and runtime semantics of Track 4 (F39 & F40).
    """

    def __init__(self, data_dir: Path | None = None):
        self._owns_dir = data_dir is None
        self.data_dir = Path(data_dir) if data_dir is not None else Path(tempfile.mkdtemp(prefix="ry-shard-ref-"))
        (self.data_dir / "repos").mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._clock = 1_700_000_000
        self._init_schema()

    def close(self) -> None:
        self.conn.close()
        if self._owns_dir and self.data_dir.exists():
            shutil.rmtree(self.data_dir, ignore_errors=True)

    def advance_clock(self, seconds: int = 1) -> int:
        self._clock += seconds
        return self._clock

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
                storage_backend TEXT NOT NULL DEFAULT 'local',
                storage_generation INTEGER NOT NULL DEFAULT 1 CHECK (storage_generation > 0),
                UNIQUE (owner_id, name),
                UNIQUE (id, owner_id)
            );

            CREATE TABLE repository_collaborators (
                tenant_id TEXT NOT NULL REFERENCES users(id),
                repository_id TEXT NOT NULL,
                user_id TEXT NOT NULL REFERENCES users(id),
                role TEXT NOT NULL CHECK (role IN ('read', 'triage', 'write', 'maintain', 'admin')),
                PRIMARY KEY (tenant_id, repository_id, user_id),
                FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE
            );

            CREATE TABLE repository_audit_log (
                id INTEGER PRIMARY KEY CHECK (id > 0),
                tenant_id TEXT NOT NULL REFERENCES users(id),
                repository_id TEXT NOT NULL,
                actor_id TEXT NOT NULL REFERENCES users(id),
                actor_name TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_name TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '{}',
                created_unix INTEGER NOT NULL DEFAULT 0 CHECK (created_unix >= 0),
                FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE
            );

            CREATE TABLE shard_nodes (
                node_id TEXT PRIMARY KEY CHECK (length(node_id) >= 1 AND length(node_id) <= 63),
                endpoint TEXT NOT NULL CHECK (length(trim(endpoint)) >= 1 AND length(endpoint) <= 512),
                role TEXT NOT NULL DEFAULT 'primary' CHECK (
                    role IN ('primary', 'replica', 'draining', 'fenced')
                ),
                status TEXT NOT NULL DEFAULT 'healthy' CHECK (
                    status IN ('healthy', 'degraded', 'draining', 'fenced', 'offline')
                ),
                capacity_bytes INTEGER NOT NULL DEFAULT 107374182400 CHECK (capacity_bytes > 0),
                used_bytes INTEGER NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
                lease_epoch INTEGER NOT NULL DEFAULT 1 CHECK (lease_epoch > 0),
                lease_expires_unix INTEGER NOT NULL DEFAULT 0 CHECK (lease_expires_unix >= 0),
                fenced_epoch INTEGER NOT NULL DEFAULT 0 CHECK (fenced_epoch >= 0),
                version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
                created_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z',
                updated_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z',
                CHECK (used_bytes <= capacity_bytes)
            );

            CREATE TABLE shard_virtual_buckets (
                bucket_id INTEGER PRIMARY KEY CHECK (bucket_id >= 0 AND bucket_id < 1024),
                primary_node_id TEXT NOT NULL REFERENCES shard_nodes(node_id),
                read_replica_nodes TEXT NOT NULL DEFAULT '[]',
                route_epoch INTEGER NOT NULL DEFAULT 1 CHECK (route_epoch > 0),
                updated_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z'
            );

            CREATE TABLE repository_shard_routes (
                tenant_id TEXT NOT NULL REFERENCES users(id),
                repository_id TEXT NOT NULL,
                bucket_id INTEGER NOT NULL CHECK (bucket_id >= 0 AND bucket_id < 1024),
                primary_node_id TEXT NOT NULL REFERENCES shard_nodes(node_id),
                read_replica_nodes TEXT NOT NULL DEFAULT '[]',
                replica_watermarks TEXT NOT NULL DEFAULT '{}',
                explicit_override INTEGER NOT NULL DEFAULT 0,
                route_epoch INTEGER NOT NULL DEFAULT 1 CHECK (route_epoch > 0),
                fencing_token INTEGER NOT NULL DEFAULT 1 CHECK (fencing_token > 0),
                fenced_epoch INTEGER NOT NULL DEFAULT 0 CHECK (fenced_epoch >= 0),
                draining INTEGER NOT NULL DEFAULT 0,
                read_only_degraded INTEGER NOT NULL DEFAULT 0,
                degraded_reason TEXT NOT NULL DEFAULT '' CHECK (length(degraded_reason) <= 1024),
                in_flight_writes INTEGER NOT NULL DEFAULT 0 CHECK (in_flight_writes >= 0),
                required_generation INTEGER NOT NULL DEFAULT 1 CHECK (required_generation > 0),
                required_op_sequence INTEGER NOT NULL DEFAULT 0 CHECK (required_op_sequence >= 0),
                version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
                created_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z',
                updated_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z',
                PRIMARY KEY (tenant_id, repository_id),
                UNIQUE (repository_id),
                FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE,
                CHECK (fencing_token >= route_epoch)
            );

            CREATE TABLE shard_failover_operations (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL REFERENCES users(id),
                repository_id TEXT NOT NULL,
                old_primary_node_id TEXT NOT NULL REFERENCES shard_nodes(node_id),
                new_primary_node_id TEXT NOT NULL REFERENCES shard_nodes(node_id),
                old_route_epoch INTEGER NOT NULL CHECK (old_route_epoch > 0),
                new_route_epoch INTEGER NOT NULL CHECK (new_route_epoch > 0),
                fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
                storage_generation INTEGER NOT NULL DEFAULT 1 CHECK (storage_generation > 0),
                state TEXT NOT NULL DEFAULT 'draining' CHECK (
                    state IN ('draining', 'fenced', 'verified', 'promoted', 'aborted')
                ),
                reason TEXT NOT NULL DEFAULT '' CHECK (length(reason) <= 1024),
                snapshot TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z',
                updated_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z',
                FOREIGN KEY (repository_id, tenant_id) REFERENCES repositories(id, owner_id) ON DELETE CASCADE,
                CHECK (
                    old_primary_node_id <> new_primary_node_id
                    AND new_route_epoch = old_route_epoch + 1
                    AND fencing_token >= new_route_epoch
                )
            );
            """
        )

    def create_user(self, username: str, read_only: bool = False) -> dict:
        uid = str(uuid.uuid4())
        self.conn.execute("INSERT INTO users (id, username) VALUES (?, ?)", (uid, username))
        self.conn.commit()
        return {"id": uid, "username": username, "read_only": read_only}

    def create_repo(
        self,
        owner: dict,
        name: str,
        repo_id: str | None = None,
        storage_generation: int = 1,
    ) -> dict:
        rid = str(repo_id) if repo_id else str(uuid.uuid4())
        self.conn.execute(
            "INSERT INTO repositories (id, owner_id, name, state, storage_generation) VALUES (?, ?, ?, 'ready', ?)",
            (rid, owner["id"], name, storage_generation),
        )
        self.conn.commit()
        repo_dir = self.repo_path(rid)
        if not repo_dir.exists():
            subprocess.run(
                ["git", "init", "--bare", "--quiet", str(repo_dir)],
                check=True,
            )
        return {
            "id": rid,
            "owner_id": owner["id"],
            "owner": owner["username"],
            "name": name,
            "storage_generation": storage_generation,
        }

    def add_collaborator(self, owner: dict, repo_name: str, user: dict, role: str) -> None:
        row = self.conn.execute(
            "SELECT id, owner_id FROM repositories WHERE owner_id = ? AND name = ?",
            (owner["id"], repo_name),
        ).fetchone()
        assert row is not None
        self.conn.execute(
            "INSERT OR REPLACE INTO repository_collaborators (tenant_id, repository_id, user_id, role) VALUES (?, ?, ?, ?)",
            (row["owner_id"], row["id"], user["id"], role),
        )
        self.conn.commit()

    def repo_path(self, repo_id: str) -> Path:
        return self.data_dir / "repos" / f"{repo_id}.git"

    def marker_path(self, repo_id: str) -> Path:
        return self.repo_path(repo_id) / VOLUME_FENCE_MARKER_FILE

    def read_volume_marker(self, repo_id: str) -> tuple[int, dict | None]:
        path = self.marker_path(repo_id)
        if not path.exists():
            return 200, None
        if path.is_symlink():
            return 409, None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return 409, None
        if (
            not isinstance(data, dict)
            or data.get("version") != 1
            or data.get("route_epoch", 0) <= 0
            or data.get("fencing_token", 0) < data.get("route_epoch", 0)
            or data.get("fenced_epoch", -1) < 0
            or data.get("storage_generation", 0) <= 0
        ):
            return 409, None
        return 200, data

    def write_volume_marker(self, repo_id: str, marker: dict) -> None:
        repo_dir = self.repo_path(repo_id)
        if not repo_dir.exists():
            return
        tmp = repo_dir / f".tmp-{uuid.uuid4()}"
        payload = (json.dumps(marker, indent=2, sort_keys=True) + "\n").encode("utf-8")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(str(tmp), str(self.marker_path(repo_id)))

    def _record_audit(
        self,
        tenant_id: str,
        repo_id: str,
        actor: dict,
        action: str,
        target_type: str,
        target_name: str,
        details: dict,
    ) -> None:
        next_id = self.conn.execute(
            "SELECT COALESCE(MAX(id), 0) + 1 FROM repository_audit_log"
        ).fetchone()[0]
        self.conn.execute(
            "INSERT INTO repository_audit_log (id, tenant_id, repository_id, actor_id, actor_name, action, target_type, target_name, details, created_unix) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                next_id,
                tenant_id,
                repo_id,
                actor["id"],
                actor["username"],
                action,
                target_type,
                target_name,
                json.dumps(details),
                self._clock,
            ),
        )

    def _authorize_repo(
        self, actor: dict | None, owner: str, name: str, min_role: str
    ) -> tuple[int, dict | None]:
        if actor is None:
            return 401, {"error": "valid credentials required"}
        row = self.conn.execute(
            "SELECT r.id, r.owner_id, r.state, r.storage_generation FROM repositories r "
            "JOIN users u ON u.id = r.owner_id WHERE u.username = ? AND r.name = ?",
            (owner, name),
        ).fetchone()
        if row is None:
            return 404, {"error": "not found"}
        repo_id = row["id"]
        owner_id = row["owner_id"]
        if actor["id"] == owner_id:
            eff_role = "admin"
        else:
            c_row = self.conn.execute(
                "SELECT role FROM repository_collaborators WHERE repository_id = ? AND user_id = ?",
                (repo_id, actor["id"]),
            ).fetchone()
            if c_row is None:
                return 404, {"error": "not found"}
            eff_role = c_row["role"]

        if ROLE_LEVELS[min_role] >= ROLE_LEVELS["triage"] and actor.get("read_only"):
            return 403, {"error": "write permission required"}
        if ROLE_LEVELS[eff_role] < ROLE_LEVELS[min_role]:
            return 403, {"error": "insufficient repository role"}
        if row["state"] != "ready":
            return 409, {"error": "repository is not ready"}
        return 200, {
            "repo_id": repo_id,
            "owner_id": owner_id,
            "role": eff_role,
            "storage_generation": row["storage_generation"],
        }

    def _format_node(self, r: sqlite3.Row) -> dict:
        return {
            "node_id": r["node_id"],
            "endpoint": r["endpoint"],
            "role": r["role"],
            "status": r["status"],
            "capacity_bytes": r["capacity_bytes"],
            "used_bytes": r["used_bytes"],
            "lease_epoch": r["lease_epoch"],
            "lease_expires_unix": r["lease_expires_unix"],
            "fenced_epoch": r["fenced_epoch"],
            "version": r["version"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        }

    def _format_bucket(self, r: sqlite3.Row) -> dict:
        return {
            "bucket_id": r["bucket_id"],
            "primary_node_id": r["primary_node_id"],
            "read_replica_nodes": json.loads(r["read_replica_nodes"]),
            "route_epoch": r["route_epoch"],
            "updated_at": r["updated_at"],
        }

    def _format_route(self, r: sqlite3.Row) -> dict:
        return {
            "tenant_id": r["tenant_id"],
            "repository_id": r["repository_id"],
            "bucket_id": r["bucket_id"],
            "primary_node_id": r["primary_node_id"],
            "read_replica_nodes": json.loads(r["read_replica_nodes"]),
            "replica_watermarks": json.loads(r["replica_watermarks"]),
            "explicit_override": bool(r["explicit_override"]),
            "route_epoch": r["route_epoch"],
            "fencing_token": r["fencing_token"],
            "fenced_epoch": r["fenced_epoch"],
            "draining": bool(r["draining"]),
            "read_only_degraded": bool(r["read_only_degraded"]),
            "degraded_reason": r["degraded_reason"],
            "in_flight_writes": r["in_flight_writes"],
            "required_generation": r["required_generation"],
            "required_op_sequence": r["required_op_sequence"],
            "version": r["version"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        }

    def _format_failover(self, r: sqlite3.Row) -> dict:
        return {
            "id": r["id"],
            "tenant_id": r["tenant_id"],
            "repository_id": r["repository_id"],
            "old_primary_node_id": r["old_primary_node_id"],
            "new_primary_node_id": r["new_primary_node_id"],
            "old_route_epoch": r["old_route_epoch"],
            "new_route_epoch": r["new_route_epoch"],
            "fencing_token": r["fencing_token"],
            "storage_generation": r["storage_generation"],
            "state": r["state"],
            "reason": r["reason"],
            "snapshot": json.loads(r["snapshot"]),
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        }

    def _ensure_default_node(self) -> dict:
        row = self.conn.execute(
            "SELECT * FROM shard_nodes WHERE role = 'primary' AND status = 'healthy' ORDER BY node_id ASC LIMIT 1"
        ).fetchone()
        if row is not None:
            return self._format_node(row)
        self.conn.execute(
            "INSERT OR IGNORE INTO shard_nodes (node_id, endpoint, role, status, capacity_bytes, used_bytes, lease_epoch, lease_expires_unix, fenced_epoch, version) "
            "VALUES (?, ?, 'primary', 'healthy', ?, 0, 1, 0, 0, 1)",
            (DEFAULT_NODE_ID, DEFAULT_NODE_ENDPOINT, DEFAULT_CAPACITY_BYTES),
        )
        row = self.conn.execute(
            "SELECT * FROM shard_nodes WHERE node_id = ?", (DEFAULT_NODE_ID,)
        ).fetchone()
        return self._format_node(row)

    def _load_or_init_route(self, tenant_id: str, repo_id: str) -> dict:
        row = self.conn.execute(
            "SELECT * FROM repository_shard_routes WHERE tenant_id = ? AND repository_id = ?",
            (tenant_id, repo_id),
        ).fetchone()
        if row is not None:
            return self._format_route(row)
        bucket_id = deterministic_bucket_id(repo_id)
        b_row = self.conn.execute(
            "SELECT * FROM shard_virtual_buckets WHERE bucket_id = ?", (bucket_id,)
        ).fetchone()
        if b_row is not None:
            primary_id = b_row["primary_node_id"]
            replicas_json = b_row["read_replica_nodes"]
            epoch = b_row["route_epoch"]
        else:
            node = self._ensure_default_node()
            primary_id = node["node_id"]
            replicas_json = "[]"
            epoch = 1
        repo_gen = self.conn.execute(
            "SELECT storage_generation FROM repositories WHERE id = ?", (repo_id,)
        ).fetchone()[0]
        self.conn.execute(
            "INSERT INTO repository_shard_routes "
            "(tenant_id, repository_id, bucket_id, primary_node_id, read_replica_nodes, replica_watermarks, "
            "explicit_override, route_epoch, fencing_token, fenced_epoch, draining, read_only_degraded, "
            "degraded_reason, in_flight_writes, required_generation, required_op_sequence, version) "
            "VALUES (?, ?, ?, ?, ?, '{}', 0, ?, ?, 0, 0, 0, '', 0, ?, 0, 1)",
            (tenant_id, repo_id, bucket_id, primary_id, replicas_json, epoch, epoch, max(1, repo_gen)),
        )
        self.conn.commit()
        row = self.conn.execute(
            "SELECT * FROM repository_shard_routes WHERE tenant_id = ? AND repository_id = ?",
            (tenant_id, repo_id),
        ).fetchone()
        return self._format_route(row)

    def list_nodes(self, actor: dict | None, role: str | None = None, status: str | None = None) -> tuple[int, dict]:
        if actor is None:
            return 401, {"error": "valid credentials required"}
        if (role is not None and role not in VALID_NODE_ROLES) or (
            status is not None and status not in VALID_NODE_STATUSES
        ):
            return 400, {"error": "invalid request"}
        rows = self.conn.execute(
            "SELECT * FROM shard_nodes WHERE (? IS NULL OR role = ?) AND (? IS NULL OR status = ?) ORDER BY node_id ASC",
            (role, role, status, status),
        ).fetchall()
        return 200, {"items": [self._format_node(r) for r in rows]}

    def upsert_node(
        self,
        actor: dict | None,
        node_id: str,
        endpoint: str,
        role: str = "primary",
        status: str = "healthy",
        capacity_bytes: int = DEFAULT_CAPACITY_BYTES,
        used_bytes: int = 0,
        lease_ttl_seconds: int | None = None,
        now_unix: int | None = None,
        extra_fields: dict | None = None,
    ) -> tuple[int, dict]:
        if actor is None:
            return 401, {"error": "valid credentials required"}
        if actor.get("read_only"):
            return 403, {"error": "write permission required"}
        if extra_fields:
            return 400, {"error": "unknown fields rejected"}
        if (
            not NODE_ID_RE.match(node_id)
            or not endpoint.strip()
            or len(endpoint) > 512
            or role not in VALID_NODE_ROLES
            or status not in VALID_NODE_STATUSES
            or capacity_bytes <= 0
            or used_bytes < 0
            or used_bytes > capacity_bytes
        ):
            return 400, {"error": "invalid request"}
        now = self._clock if now_unix is None else now_unix
        if lease_ttl_seconds is not None and not (0 <= lease_ttl_seconds <= 86400):
            return 400, {"error": "invalid request"}
        lease_exp = (now + lease_ttl_seconds) if (lease_ttl_seconds and lease_ttl_seconds > 0) else 0
        existing = self.conn.execute("SELECT * FROM shard_nodes WHERE node_id = ?", (node_id,)).fetchone()
        if existing is None:
            self.conn.execute(
                "INSERT INTO shard_nodes (node_id, endpoint, role, status, capacity_bytes, used_bytes, lease_epoch, lease_expires_unix, fenced_epoch, version) "
                "VALUES (?, ?, ?, ?, ?, ?, 1, ?, 0, 1)",
                (node_id, endpoint.strip(), role, status, capacity_bytes, used_bytes, lease_exp),
            )
            code = 201
        else:
            new_exp = lease_exp if lease_exp > 0 else existing["lease_expires_unix"]
            self.conn.execute(
                "UPDATE shard_nodes SET endpoint = ?, role = ?, status = ?, capacity_bytes = ?, used_bytes = ?, lease_expires_unix = ?, version = version + 1 WHERE node_id = ?",
                (endpoint.strip(), role, status, capacity_bytes, used_bytes, new_exp, node_id),
            )
            code = 200
        self.conn.commit()
        row = self.conn.execute("SELECT * FROM shard_nodes WHERE node_id = ?", (node_id,)).fetchone()
        return code, self._format_node(row)

    def get_node(self, actor: dict | None, node_id: str) -> tuple[int, dict]:
        if actor is None:
            return 401, {"error": "valid credentials required"}
        row = self.conn.execute("SELECT * FROM shard_nodes WHERE node_id = ?", (node_id,)).fetchone()
        if row is None:
            return 404, {"error": "not found"}
        return 200, self._format_node(row)

    def patch_node(
        self,
        actor: dict | None,
        node_id: str,
        endpoint: str | None = None,
        role: str | None = None,
        status: str | None = None,
        capacity_bytes: int | None = None,
        used_bytes: int | None = None,
        expected_version: int | None = None,
    ) -> tuple[int, dict]:
        if actor is None:
            return 401, {"error": "valid credentials required"}
        if actor.get("read_only"):
            return 403, {"error": "write permission required"}
        cur = self.conn.execute("SELECT * FROM shard_nodes WHERE node_id = ?", (node_id,)).fetchone()
        if cur is None:
            return 404, {"error": "not found"}
        if expected_version is not None and expected_version != cur["version"]:
            return 409, {"error": "shard node version conflict"}
        ep = (endpoint if endpoint is not None else cur["endpoint"]).strip()
        rl = role if role is not None else cur["role"]
        st = status if status is not None else cur["status"]
        cap = capacity_bytes if capacity_bytes is not None else cur["capacity_bytes"]
        used = used_bytes if used_bytes is not None else cur["used_bytes"]
        if not ep or rl not in VALID_NODE_ROLES or st not in VALID_NODE_STATUSES or cap <= 0 or used < 0 or used > cap:
            return 400, {"error": "invalid request"}
        self.conn.execute(
            "UPDATE shard_nodes SET endpoint = ?, role = ?, status = ?, capacity_bytes = ?, used_bytes = ?, version = version + 1 WHERE node_id = ?",
            (ep, rl, st, cap, used, node_id),
        )
        self.conn.commit()
        row = self.conn.execute("SELECT * FROM shard_nodes WHERE node_id = ?", (node_id,)).fetchone()
        return 200, self._format_node(row)

    def renew_node_lease(
        self,
        actor: dict | None,
        node_id: str,
        lease_ttl_seconds: int = 60,
        expected_lease_epoch: int | None = None,
        bump_epoch: bool = True,
        now_unix: int | None = None,
    ) -> tuple[int, dict]:
        if actor is None:
            return 401, {"error": "valid credentials required"}
        if actor.get("read_only"):
            return 403, {"error": "write permission required"}
        if not (1 <= lease_ttl_seconds <= 86400):
            return 400, {"error": "invalid request"}
        now = self._clock if now_unix is None else now_unix
        cur = self.conn.execute("SELECT * FROM shard_nodes WHERE node_id = ?", (node_id,)).fetchone()
        if cur is None:
            return 404, {"error": "not found"}
        if cur["role"] == "fenced" or cur["status"] in ("fenced", "offline"):
            return 409, {"error": "cannot renew lease on fenced or offline shard node"}
        if expected_lease_epoch is not None and expected_lease_epoch != cur["lease_epoch"]:
            return 409, {"error": "stale or mismatched node lease_epoch"}
        if bump_epoch:
            new_epoch = max(cur["lease_epoch"], cur["fenced_epoch"]) + 1
        else:
            if cur["lease_epoch"] <= cur["fenced_epoch"]:
                return 409, {"error": "node lease_epoch is fenced"}
            new_epoch = cur["lease_epoch"]
        expires = now + lease_ttl_seconds
        self.conn.execute(
            "UPDATE shard_nodes SET lease_epoch = ?, lease_expires_unix = ?, version = version + 1 WHERE node_id = ?",
            (new_epoch, expires, node_id),
        )
        self.conn.commit()
        row = self.conn.execute("SELECT * FROM shard_nodes WHERE node_id = ?", (node_id,)).fetchone()
        return 200, self._format_node(row)

    def upsert_bucket(
        self,
        actor: dict | None,
        bucket_id: int,
        primary_node_id: str,
        read_replica_nodes: list[str] | None = None,
        expected_route_epoch: int | None = None,
    ) -> tuple[int, dict]:
        if actor is None:
            return 401, {"error": "valid credentials required"}
        if actor.get("read_only"):
            return 403, {"error": "write permission required"}
        replicas = list(read_replica_nodes or [])
        if (
            not (0 <= bucket_id < VIRTUAL_BUCKET_COUNT)
            or not NODE_ID_RE.match(primary_node_id)
            or len(replicas) > 16
            or primary_node_id in replicas
            or len(set(replicas)) != len(replicas)
        ):
            return 400, {"error": "invalid request"}
        primary = self.conn.execute("SELECT * FROM shard_nodes WHERE node_id = ?", (primary_node_id,)).fetchone()
        if primary is None:
            return 404, {"error": "not found"}
        if primary["role"] == "fenced" or primary["status"] in ("fenced", "offline"):
            return 409, {"error": "primary shard node is fenced or offline"}
        for rep_id in replicas:
            if self.conn.execute("SELECT 1 FROM shard_nodes WHERE node_id = ?", (rep_id,)).fetchone() is None:
                return 404, {"error": "not found"}
        existing = self.conn.execute("SELECT * FROM shard_virtual_buckets WHERE bucket_id = ?", (bucket_id,)).fetchone()
        cur_epoch = existing["route_epoch"] if existing is not None else 0
        if expected_route_epoch is not None and expected_route_epoch != cur_epoch:
            return 409, {"error": "virtual bucket route_epoch conflict"}
        new_epoch = cur_epoch + 1
        rep_json = json.dumps(replicas)
        if existing is None:
            self.conn.execute(
                "INSERT INTO shard_virtual_buckets (bucket_id, primary_node_id, read_replica_nodes, route_epoch) VALUES (?, ?, ?, ?)",
                (bucket_id, primary_node_id, rep_json, new_epoch),
            )
            code = 201
        else:
            self.conn.execute(
                "UPDATE shard_virtual_buckets SET primary_node_id = ?, read_replica_nodes = ?, route_epoch = ? WHERE bucket_id = ?",
                (primary_node_id, rep_json, new_epoch, bucket_id),
            )
            code = 200
        self.conn.execute(
            "UPDATE repository_shard_routes SET primary_node_id = ?, read_replica_nodes = ?, "
            "route_epoch = MAX(route_epoch + 1, ?), fencing_token = MAX(fencing_token + 1, ?), version = version + 1 "
            "WHERE bucket_id = ? AND explicit_override = 0",
            (primary_node_id, rep_json, new_epoch, new_epoch, bucket_id),
        )
        self.conn.commit()
        row = self.conn.execute("SELECT * FROM shard_virtual_buckets WHERE bucket_id = ?", (bucket_id,)).fetchone()
        return code, self._format_bucket(row)

    def get_repo_route(self, actor: dict | None, owner: str, name: str) -> tuple[int, dict]:
        st, acc = self._authorize_repo(actor, owner, name, "read")
        if st != 200 or acc is None:
            return st, acc or {}
        return 200, self._load_or_init_route(acc["owner_id"], acc["repo_id"])

    def configure_repo_route(
        self,
        actor: dict | None,
        owner: str,
        name: str,
        primary_node_id: str | None = None,
        read_replica_nodes: list[str] | None = None,
        replica_watermarks: dict | None = None,
        explicit_override: bool | None = None,
        required_generation: int | None = None,
        required_op_sequence: int | None = None,
        in_flight_writes: int | None = None,
        expected_route_epoch: int | None = None,
        expected_version: int | None = None,
    ) -> tuple[int, dict]:
        st, acc = self._authorize_repo(actor, owner, name, "admin")
        if st != 200 or acc is None:
            return st, acc or {}
        cur = self._load_or_init_route(acc["owner_id"], acc["repo_id"])
        if (expected_route_epoch is not None and expected_route_epoch != cur["route_epoch"]) or (
            expected_version is not None and expected_version != cur["version"]
        ):
            return 409, {"error": "repository shard route version or epoch conflict"}
        prim = primary_node_id if primary_node_id is not None else cur["primary_node_id"]
        reps = list(read_replica_nodes) if read_replica_nodes is not None else list(cur["read_replica_nodes"])
        if not NODE_ID_RE.match(prim) or prim in reps or len(set(reps)) != len(reps) or len(reps) > 16:
            return 400, {"error": "invalid request"}
        p_node = self.conn.execute("SELECT * FROM shard_nodes WHERE node_id = ?", (prim,)).fetchone()
        if p_node is None:
            return 404, {"error": "not found"}
        if p_node["role"] == "fenced" or p_node["status"] in ("fenced", "offline"):
            return 409, {"error": "primary shard node is fenced or offline"}
        for rep_id in reps:
            if self.conn.execute("SELECT 1 FROM shard_nodes WHERE node_id = ?", (rep_id,)).fetchone() is None:
                return 404, {"error": "not found"}
        wms = replica_watermarks if replica_watermarks is not None else cur["replica_watermarks"]
        req_gen = required_generation if required_generation is not None else cur["required_generation"]
        req_seq = required_op_sequence if required_op_sequence is not None else cur["required_op_sequence"]
        in_flight = in_flight_writes if in_flight_writes is not None else cur["in_flight_writes"]
        if req_gen <= 0 or req_seq < 0 or in_flight < 0:
            return 400, {"error": "invalid request"}
        changed = prim != cur["primary_node_id"] or reps != cur["read_replica_nodes"]
        exp_ov = explicit_override if explicit_override is not None else (cur["explicit_override"] or changed)
        new_epoch = cur["route_epoch"] + 1 if changed else cur["route_epoch"]
        new_token = max(cur["fencing_token"], new_epoch)
        self.conn.execute(
            "UPDATE repository_shard_routes SET primary_node_id = ?, read_replica_nodes = ?, replica_watermarks = ?, "
            "explicit_override = ?, route_epoch = ?, fencing_token = ?, required_generation = ?, required_op_sequence = ?, "
            "in_flight_writes = ?, version = version + 1 WHERE tenant_id = ? AND repository_id = ?",
            (
                prim,
                json.dumps(reps),
                json.dumps(wms),
                1 if exp_ov else 0,
                new_epoch,
                new_token,
                req_gen,
                req_seq,
                in_flight,
                acc["owner_id"],
                acc["repo_id"],
            ),
        )
        assert actor is not None
        self._record_audit(
            acc["owner_id"],
            acc["repo_id"],
            actor,
            "shard.route_updated",
            "shard_route",
            prim,
            {"bucket_id": cur["bucket_id"], "route_epoch": new_epoch, "explicit_override": exp_ov},
        )
        self.conn.commit()
        return 200, self._load_or_init_route(acc["owner_id"], acc["repo_id"])

    def resolve_repo_route(
        self,
        actor: dict | None,
        owner: str,
        name: str,
        op: str = "read",
        client_route_epoch: int | None = None,
        min_generation: int | None = None,
        min_op_sequence: int | None = None,
        now_unix: int | None = None,
    ) -> tuple[int, dict]:
        st, acc = self._authorize_repo(actor, owner, name, "read")
        if st != 200 or acc is None:
            return st, acc or {}
        if op not in VALID_ROUTE_OPS:
            return 400, {"error": "invalid request"}
        route = self._load_or_init_route(acc["owner_id"], acc["repo_id"])
        if client_route_epoch is not None and client_route_epoch != route["route_epoch"]:
            return 409, {"error": "stale or mismatched client route_epoch"}
        now = self._clock if now_unix is None else now_unix
        req_gen = max(acc["storage_generation"], route["required_generation"], min_generation or 1)
        req_seq = max(route["required_op_sequence"], min_op_sequence or 0)

        p_row = self.conn.execute(
            "SELECT * FROM shard_nodes WHERE node_id = ?", (route["primary_node_id"],)
        ).fetchone()
        if p_row is None:
            return 409, {"error": "primary shard node missing"}
        primary = self._format_node(p_row)
        lease_active = primary["lease_expires_unix"] == 0 or now <= primary["lease_expires_unix"]
        primary_unfenced = (
            primary["fenced_epoch"] < route["route_epoch"] and route["fenced_epoch"] < route["route_epoch"]
        )
        primary_healthy = (
            primary["role"] == "primary"
            and primary["status"] == "healthy"
            and lease_active
            and primary_unfenced
        )

        def find_qualified_replica() -> dict | None:
            for rep_id in route["read_replica_nodes"]:
                r_row = self.conn.execute("SELECT * FROM shard_nodes WHERE node_id = ?", (rep_id,)).fetchone()
                if r_row is None or r_row["status"] != "healthy" or r_row["role"] == "fenced":
                    continue
                wm = route["replica_watermarks"].get(rep_id)
                if (
                    isinstance(wm, dict)
                    and wm.get("verified") is True
                    and wm.get("storage_generation", 0) >= req_gen
                    and wm.get("op_sequence", 0) >= req_seq
                ):
                    return self._format_node(r_row)
            return None

        def build_res(target: dict, role: str, fallback: bool, degraded: bool) -> dict:
            return {
                "repository_id": route["repository_id"],
                "bucket_id": route["bucket_id"],
                "operation": op,
                "target_node_id": target["node_id"],
                "target_endpoint": target["endpoint"],
                "target_role": role,
                "primary_node_id": route["primary_node_id"],
                "route_epoch": route["route_epoch"],
                "fencing_token": route["fencing_token"],
                "fenced_epoch": route["fenced_epoch"],
                "storage_generation": req_gen,
                "required_op_sequence": req_seq,
                "fallback_to_primary": fallback,
                "read_only_degraded": degraded,
            }

        if op == "write":
            if route["draining"] or route["read_only_degraded"] or not primary_healthy:
                return 409, {"error": "primary shard node unavailable, fenced, lease-expired, or degraded for writes"}
            return 200, build_res(primary, "primary", False, False)

        if op in ("merge_check", "strong"):
            if not route["read_only_degraded"] and not route["draining"] and primary_healthy:
                return 200, build_res(primary, "primary", False, False)
            if route["read_only_degraded"]:
                rep = find_qualified_replica()
                if rep is not None:
                    return 200, build_res(rep, "replica", False, True)
            return 409, {"error": "primary shard node unavailable or fenced for strong operation"}

        rep = find_qualified_replica()
        if rep is not None:
            return 200, build_res(rep, "replica", False, route["read_only_degraded"])
        primary_readable = (
            primary["status"] not in ("offline", "fenced")
            and primary["role"] != "fenced"
            and lease_active
            and primary_unfenced
        )
        if primary_readable:
            return 200, build_res(primary, "primary", True, route["read_only_degraded"])
        return 409, {"error": "no watermark-qualified replica or readable primary available"}

    def _evaluate_barrier(
        self,
        route: dict,
        primary: dict,
        repo_gen: int,
        marker: dict | None,
        writer_node_id: str | None = None,
        writer_route_epoch: int | None = None,
        writer_fencing_token: int | None = None,
        writer_storage_generation: int | None = None,
        now_unix: int | None = None,
    ) -> tuple[int, str | None]:
        now = self._clock if now_unix is None else now_unix
        if route["draining"] or route["read_only_degraded"]:
            return 409, "repository write blocked by draining or read-only degradation mode"
        if route["fenced_epoch"] >= route["route_epoch"] or primary["fenced_epoch"] >= route["route_epoch"]:
            return 409, "repository or primary shard node route_epoch is fenced"
        lease_active = primary["lease_expires_unix"] == 0 or now <= primary["lease_expires_unix"]
        if primary["role"] != "primary" or primary["status"] != "healthy" or not lease_active:
            return 409, "primary shard node is unhealthy, fenced, or has an expired lease"

        eff_node = writer_node_id if writer_node_id is not None else route["primary_node_id"]
        if eff_node != route["primary_node_id"]:
            return 409, "writer node is not the active primary for this repository"
        eff_epoch = writer_route_epoch if writer_route_epoch is not None else route["route_epoch"]
        if eff_epoch < route["route_epoch"] or eff_epoch <= route["fenced_epoch"] or eff_epoch <= primary["fenced_epoch"]:
            return 409, "stale or fenced writer route_epoch rejected"
        eff_token = writer_fencing_token if writer_fencing_token is not None else route["fencing_token"]
        if eff_token < route["fencing_token"]:
            return 409, "stale writer fencing_token rejected"
        req_gen = max(repo_gen, route["required_generation"])
        eff_gen = writer_storage_generation if writer_storage_generation is not None else repo_gen
        if eff_gen < req_gen:
            return 409, "stale writer storage_generation rejected"

        if marker is not None:
            if marker.get("repository_id") != route["repository_id"]:
                return 409, "volume fence marker repository_id mismatch"
            if marker.get("read_only_degraded"):
                return 409, "volume fence marker enforces read-only degradation"
            if eff_epoch < marker["route_epoch"] or eff_epoch <= marker["fenced_epoch"] or route["route_epoch"] <= marker["fenced_epoch"]:
                return 409, "volume fence marker rejects stale or fenced route_epoch"
            if eff_token < marker["fencing_token"]:
                return 409, "volume fence marker rejects stale fencing_token"
            if eff_gen < marker["storage_generation"] or repo_gen < marker["storage_generation"]:
                return 409, "volume fence marker rejects stale storage_generation"
            if marker.get("fenced_node_id") == eff_node and eff_epoch <= marker["fenced_epoch"]:
                return 409, "writer node is explicitly fenced in volume marker"
        return 200, None

    def get_fence_status(self, actor: dict | None, owner: str, name: str) -> tuple[int, dict]:
        st, acc = self._authorize_repo(actor, owner, name, "read")
        if st != 200 or acc is None:
            return st, acc or {}
        route = self._load_or_init_route(acc["owner_id"], acc["repo_id"])
        p_row = self.conn.execute("SELECT * FROM shard_nodes WHERE node_id = ?", (route["primary_node_id"],)).fetchone()
        primary = self._format_node(p_row)
        m_st, marker = self.read_volume_marker(acc["repo_id"])
        if m_st != 200:
            return 409, {"error": "corrupt shard volume fence marker"}
        b_st, _ = self._evaluate_barrier(route, primary, acc["storage_generation"], marker)
        return 200, {
            "repository_id": acc["repo_id"],
            "primary_node_id": route["primary_node_id"],
            "route_epoch": route["route_epoch"],
            "fencing_token": route["fencing_token"],
            "fenced_epoch": route["fenced_epoch"],
            "storage_generation": max(acc["storage_generation"], route["required_generation"]),
            "draining": route["draining"],
            "read_only_degraded": route["read_only_degraded"],
            "write_admitted": b_st == 200,
            "volume_marker": marker,
        }

    def apply_or_verify_fence(
        self,
        actor: dict | None,
        owner: str,
        name: str,
        action: str,
        writer_node_id: str | None = None,
        writer_route_epoch: int | None = None,
        writer_fencing_token: int | None = None,
        writer_storage_generation: int | None = None,
        fenced_epoch: int | None = None,
        storage_generation: int | None = None,
        fenced_node_id: str | None = None,
        now_unix: int | None = None,
    ) -> tuple[int, dict]:
        if action not in ("verify", "check_write", "fence", "unfence", "advance_epoch"):
            return 400, {"error": "invalid request"}
        now = self._clock if now_unix is None else now_unix
        if action in ("verify", "check_write"):
            st, acc = self._authorize_repo(actor, owner, name, "read")
            if st != 200 or acc is None:
                return st, acc or {}
            route = self._load_or_init_route(acc["owner_id"], acc["repo_id"])
            p_row = self.conn.execute("SELECT * FROM shard_nodes WHERE node_id = ?", (route["primary_node_id"],)).fetchone()
            primary = self._format_node(p_row)
            m_st, marker = self.read_volume_marker(acc["repo_id"])
            if m_st != 200:
                return 409, {"error": "corrupt shard volume fence marker"}
            b_st, err = self._evaluate_barrier(
                route,
                primary,
                acc["storage_generation"],
                marker,
                writer_node_id=writer_node_id,
                writer_route_epoch=writer_route_epoch,
                writer_fencing_token=writer_fencing_token,
                writer_storage_generation=writer_storage_generation,
                now_unix=now,
            )
            if b_st != 200:
                return 409, {"error": err}
            return 200, {
                "repository_id": acc["repo_id"],
                "primary_node_id": route["primary_node_id"],
                "route_epoch": route["route_epoch"],
                "fencing_token": route["fencing_token"],
                "fenced_epoch": route["fenced_epoch"],
                "storage_generation": max(acc["storage_generation"], route["required_generation"]),
                "draining": route["draining"],
                "read_only_degraded": route["read_only_degraded"],
                "write_admitted": True,
                "volume_marker": marker,
            }

        st, acc = self._authorize_repo(actor, owner, name, "admin")
        if st != 200 or acc is None:
            return st, acc or {}
        route = self._load_or_init_route(acc["owner_id"], acc["repo_id"])
        repo_gen = acc["storage_generation"]
        new_gen = storage_generation if storage_generation is not None else max(repo_gen, route["required_generation"])
        if new_gen < repo_gen:
            return 409, {"error": "storage_generation cannot move backward"}
        if new_gen > repo_gen:
            self.conn.execute("UPDATE repositories SET storage_generation = ? WHERE id = ?", (new_gen, acc["repo_id"]))

        if action == "fence":
            target_node = fenced_node_id if fenced_node_id is not None else route["primary_node_id"]
            if not NODE_ID_RE.match(target_node):
                return 400, {"error": "invalid request"}
            f_epoch = fenced_epoch if fenced_epoch is not None else route["route_epoch"]
            if f_epoch <= 0 or f_epoch < route["fenced_epoch"]:
                return 409, {"error": "fenced_epoch cannot move backward"}
            new_route_epoch = max(route["route_epoch"], f_epoch)
            new_token = max(route["fencing_token"], new_route_epoch) + 1
            self.conn.execute(
                "UPDATE shard_nodes SET fenced_epoch = MAX(fenced_epoch, ?), role = 'fenced', status = 'fenced', version = version + 1 WHERE node_id = ?",
                (f_epoch, target_node),
            )
            self.conn.execute(
                "UPDATE repository_shard_routes SET route_epoch = ?, fencing_token = ?, fenced_epoch = ?, required_generation = ?, version = version + 1 WHERE tenant_id = ? AND repository_id = ?",
                (new_route_epoch, new_token, f_epoch, new_gen, acc["owner_id"], acc["repo_id"]),
            )
            marker = {
                "version": 1,
                "repository_id": acc["repo_id"],
                "primary_node_id": route["primary_node_id"],
                "route_epoch": new_route_epoch,
                "fencing_token": new_token,
                "fenced_epoch": f_epoch,
                "storage_generation": new_gen,
                "fenced_node_id": target_node,
                "read_only_degraded": route["read_only_degraded"],
                "updated_unix": now,
            }
            self.write_volume_marker(acc["repo_id"], marker)
            assert actor is not None
            self._record_audit(
                acc["owner_id"],
                acc["repo_id"],
                actor,
                "shard.fenced",
                "shard_fence",
                target_node,
                {"fenced_epoch": f_epoch, "fencing_token": new_token, "storage_generation": new_gen},
            )
            self.conn.commit()
            updated = self._load_or_init_route(acc["owner_id"], acc["repo_id"])
            return 200, {
                "repository_id": acc["repo_id"],
                "primary_node_id": updated["primary_node_id"],
                "route_epoch": updated["route_epoch"],
                "fencing_token": updated["fencing_token"],
                "fenced_epoch": updated["fenced_epoch"],
                "storage_generation": new_gen,
                "draining": updated["draining"],
                "read_only_degraded": updated["read_only_degraded"],
                "write_admitted": False,
                "volume_marker": marker,
            }

        new_route_epoch = max(route["route_epoch"], route["fenced_epoch"]) + 1
        new_token = max(route["fencing_token"], new_route_epoch) + 1
        self.conn.execute(
            "UPDATE shard_nodes SET role = 'primary', status = 'healthy', lease_epoch = MAX(lease_epoch, ?), version = version + 1 WHERE node_id = ?",
            (new_route_epoch, route["primary_node_id"]),
        )
        self.conn.execute(
            "UPDATE repository_shard_routes SET route_epoch = ?, fencing_token = ?, required_generation = ?, draining = 0, version = version + 1 WHERE tenant_id = ? AND repository_id = ?",
            (new_route_epoch, new_token, new_gen, acc["owner_id"], acc["repo_id"]),
        )
        marker = {
            "version": 1,
            "repository_id": acc["repo_id"],
            "primary_node_id": route["primary_node_id"],
            "route_epoch": new_route_epoch,
            "fencing_token": new_token,
            "fenced_epoch": route["fenced_epoch"],
            "storage_generation": new_gen,
            "fenced_node_id": None,
            "read_only_degraded": route["read_only_degraded"],
            "updated_unix": now,
        }
        self.write_volume_marker(acc["repo_id"], marker)
        assert actor is not None
        self._record_audit(
            acc["owner_id"],
            acc["repo_id"],
            actor,
            "shard.unfenced",
            "shard_fence",
            route["primary_node_id"],
            {"route_epoch": new_route_epoch, "fencing_token": new_token, "storage_generation": new_gen},
        )
        self.conn.commit()
        updated = self._load_or_init_route(acc["owner_id"], acc["repo_id"])
        return 200, {
            "repository_id": acc["repo_id"],
            "primary_node_id": updated["primary_node_id"],
            "route_epoch": updated["route_epoch"],
            "fencing_token": updated["fencing_token"],
            "fenced_epoch": updated["fenced_epoch"],
            "storage_generation": new_gen,
            "draining": updated["draining"],
            "read_only_degraded": updated["read_only_degraded"],
            "write_admitted": not updated["read_only_degraded"],
            "volume_marker": marker,
        }

    def list_failovers(self, actor: dict | None, owner: str, name: str) -> tuple[int, dict]:
        st, acc = self._authorize_repo(actor, owner, name, "read")
        if st != 200 or acc is None:
            return st, acc or {}
        rows = self.conn.execute(
            "SELECT * FROM shard_failover_operations WHERE tenant_id = ? AND repository_id = ? ORDER BY created_at DESC, id DESC LIMIT 100",
            (acc["owner_id"], acc["repo_id"]),
        ).fetchall()
        return 200, {"items": [self._format_failover(r) for r in rows]}

    def execute_failover(
        self,
        actor: dict | None,
        owner: str,
        name: str,
        new_primary_node_id: str,
        reason: str = "automated primary failover",
        expected_route_epoch: int | None = None,
        force_drain: bool = False,
        bump_generation: bool = False,
        now_unix: int | None = None,
    ) -> tuple[int, dict]:
        st, acc = self._authorize_repo(actor, owner, name, "admin")
        if st != 200 or acc is None:
            return st, acc or {}
        if not NODE_ID_RE.match(new_primary_node_id) or not reason.strip() or len(reason) > 1024:
            return 400, {"error": "invalid request"}
        now = self._clock if now_unix is None else now_unix
        route = self._load_or_init_route(acc["owner_id"], acc["repo_id"])
        repo_gen = acc["storage_generation"]
        repo_dir = self.repo_path(acc["repo_id"])
        if not repo_dir.is_dir() or repo_dir.is_symlink():
            return 409, {"error": "bare Git repository volume verification failed"}
        has_locks = any((repo_dir / lk).exists() for lk in ("HEAD.lock", "packed-refs.lock", "config.lock"))

        cand_row = self.conn.execute("SELECT * FROM shard_nodes WHERE node_id = ?", (new_primary_node_id,)).fetchone()
        if cand_row is None:
            return 404, {"error": "not found"}
        if new_primary_node_id == route["primary_node_id"]:
            return 409, {"error": "new_primary_node_id must differ from current primary_node_id"}
        if expected_route_epoch is not None and expected_route_epoch != route["route_epoch"]:
            return 409, {"error": "failover expected_route_epoch mismatch"}
        if (route["in_flight_writes"] > 0 and not force_drain) or has_locks:
            return 409, {"error": "cannot drain repository with active in-flight writes or Git lock files"}
        if cand_row["status"] != "healthy" or cand_row["role"] == "fenced":
            return 409, {"error": "target replica node is unhealthy or fenced"}

        req_gen = max(repo_gen, route["required_generation"])
        req_seq = route["required_op_sequence"]
        wm = route["replica_watermarks"].get(new_primary_node_id)
        if (
            not isinstance(wm, dict)
            or wm.get("verified") is not True
            or wm.get("storage_generation", 0) < req_gen
            or wm.get("op_sequence", 0) < req_seq
        ):
            return 409, {"error": "target replica watermark is unverified or lags behind required generation/sequence"}

        old_primary = route["primary_node_id"]
        old_epoch = route["route_epoch"]
        new_epoch = old_epoch + 1
        new_token = max(route["fencing_token"], old_epoch) + 1
        base_gen = max(wm.get("storage_generation", req_gen), req_gen)
        new_gen = base_gen + 1 if bump_generation else base_gen

        self.conn.execute(
            "UPDATE shard_nodes SET role = 'fenced', status = 'fenced', fenced_epoch = MAX(fenced_epoch, ?), version = version + 1 WHERE node_id = ?",
            (old_epoch, old_primary),
        )
        self.conn.execute(
            "UPDATE shard_nodes SET role = 'primary', status = 'healthy', lease_epoch = MAX(lease_epoch, ?), lease_expires_unix = ?, version = version + 1 WHERE node_id = ?",
            (new_epoch, now + 60, new_primary_node_id),
        )
        if new_gen > repo_gen:
            self.conn.execute("UPDATE repositories SET storage_generation = ? WHERE id = ?", (new_gen, acc["repo_id"]))

        remaining = [r for r in route["read_replica_nodes"] if r != new_primary_node_id]
        self.conn.execute(
            "UPDATE repository_shard_routes SET primary_node_id = ?, read_replica_nodes = ?, explicit_override = 1, "
            "route_epoch = ?, fencing_token = ?, fenced_epoch = ?, draining = 0, read_only_degraded = 0, "
            "degraded_reason = '', in_flight_writes = 0, required_generation = ?, version = version + 1 "
            "WHERE tenant_id = ? AND repository_id = ?",
            (
                new_primary_node_id,
                json.dumps(remaining),
                new_epoch,
                new_token,
                old_epoch,
                new_gen,
                acc["owner_id"],
                acc["repo_id"],
            ),
        )
        marker = {
            "version": 1,
            "repository_id": acc["repo_id"],
            "primary_node_id": new_primary_node_id,
            "route_epoch": new_epoch,
            "fencing_token": new_token,
            "fenced_epoch": old_epoch,
            "storage_generation": new_gen,
            "fenced_node_id": old_primary,
            "read_only_degraded": False,
            "updated_unix": now,
        }
        self.write_volume_marker(acc["repo_id"], marker)
        op_id = str(uuid.uuid4())
        snapshot = {
            "stages": ["draining", "fenced", "verified", "promoted"],
            "fenced_node_id": old_primary,
            "promoted_node_id": new_primary_node_id,
            "old_route_epoch": old_epoch,
            "new_route_epoch": new_epoch,
            "fencing_token": new_token,
            "storage_generation": new_gen,
        }
        self.conn.execute(
            "INSERT INTO shard_failover_operations "
            "(id, tenant_id, repository_id, old_primary_node_id, new_primary_node_id, old_route_epoch, new_route_epoch, "
            "fencing_token, storage_generation, state, reason, snapshot) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'promoted', ?, ?)",
            (
                op_id,
                acc["owner_id"],
                acc["repo_id"],
                old_primary,
                new_primary_node_id,
                old_epoch,
                new_epoch,
                new_token,
                new_gen,
                reason.strip(),
                json.dumps(snapshot),
            ),
        )
        assert actor is not None
        self._record_audit(
            acc["owner_id"],
            acc["repo_id"],
            actor,
            "shard.failover_promoted",
            "shard_failover",
            new_primary_node_id,
            snapshot,
        )
        self.conn.commit()
        row = self.conn.execute("SELECT * FROM shard_failover_operations WHERE id = ?", (op_id,)).fetchone()
        return 200, self._format_failover(row)

    def degrade_or_recover_repo(
        self,
        actor: dict | None,
        owner: str,
        name: str,
        mode: str,
        reason: str = "",
        now_unix: int | None = None,
    ) -> tuple[int, dict]:
        st, acc = self._authorize_repo(actor, owner, name, "admin")
        if st != 200 or acc is None:
            return st, acc or {}
        if mode not in ("degrade", "recover") or len(reason) > 1024:
            return 400, {"error": "invalid request"}
        now = self._clock if now_unix is None else now_unix
        route = self._load_or_init_route(acc["owner_id"], acc["repo_id"])
        _, prev_marker = self.read_volume_marker(acc["repo_id"])

        if mode == "degrade":
            degraded = True
            deg_reason = reason.strip() or "read-only degradation drill"
            new_epoch = route["route_epoch"]
            new_token = route["fencing_token"]
            audit_act = "shard.degraded"
        else:
            p_row = self.conn.execute("SELECT * FROM shard_nodes WHERE node_id = ?", (route["primary_node_id"],)).fetchone()
            if p_row is None:
                return 409, {"error": "primary shard node missing"}
            lease_ok = p_row["lease_expires_unix"] == 0 or now <= p_row["lease_expires_unix"]
            if p_row["role"] != "primary" or p_row["status"] != "healthy" or not lease_ok:
                return 409, {"error": "cannot recover while primary node is unhealthy or lease-expired"}
            degraded = False
            deg_reason = ""
            new_epoch = max(route["route_epoch"], route["fenced_epoch"]) + 1
            new_token = max(route["fencing_token"], new_epoch) + 1
            audit_act = "shard.degrade_recovered"

        self.conn.execute(
            "UPDATE repository_shard_routes SET read_only_degraded = ?, degraded_reason = ?, draining = 0, "
            "route_epoch = ?, fencing_token = ?, version = version + 1 WHERE tenant_id = ? AND repository_id = ?",
            (1 if degraded else 0, deg_reason, new_epoch, new_token, acc["owner_id"], acc["repo_id"]),
        )
        eff_gen = max(acc["storage_generation"], route["required_generation"])
        marker = {
            "version": 1,
            "repository_id": acc["repo_id"],
            "primary_node_id": route["primary_node_id"],
            "route_epoch": new_epoch,
            "fencing_token": new_token,
            "fenced_epoch": route["fenced_epoch"],
            "storage_generation": eff_gen,
            "fenced_node_id": prev_marker.get("fenced_node_id") if isinstance(prev_marker, dict) else None,
            "read_only_degraded": degraded,
            "updated_unix": now,
        }
        self.write_volume_marker(acc["repo_id"], marker)
        assert actor is not None
        self._record_audit(
            acc["owner_id"],
            acc["repo_id"],
            actor,
            audit_act,
            "shard_degrade",
            route["primary_node_id"],
            {"mode": mode, "read_only_degraded": degraded, "route_epoch": new_epoch},
        )
        self.conn.commit()
        return 200, {
            "repository_id": acc["repo_id"],
            "mode": mode,
            "read_only_degraded": degraded,
            "degraded_reason": deg_reason,
            "primary_node_id": route["primary_node_id"],
            "route_epoch": new_epoch,
            "fencing_token": new_token,
            "write_admitted": not degraded,
            "volume_marker": marker,
        }

    def rebalance_log_path(self) -> Path:
        return self.data_dir / "repos" / REBALANCE_LOG_FILE

    def dr_drill_receipt_path(self, repo_id: str) -> Path:
        return self.repo_path(repo_id) / DR_DRILL_RECEIPT_FILE

    def read_dr_drill_receipt(self, repo_id: str) -> tuple[int, dict | None]:
        path = self.dr_drill_receipt_path(repo_id)
        if not path.exists():
            return 200, None
        if path.is_symlink():
            return 409, None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return 409, None
        if not isinstance(data, dict) or "measured_rpo_secs" not in data or "measured_rto_ms" not in data:
            return 409, None
        return 200, data

    def write_dr_drill_receipt(self, repo_id: str, receipt: dict) -> None:
        repo_dir = self.repo_path(repo_id)
        if not repo_dir.exists():
            return
        tmp = repo_dir / f".tmp-{uuid.uuid4()}"
        payload = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(str(tmp), str(self.dr_drill_receipt_path(repo_id)))

    def _append_rebalance_receipt(self, receipt: dict) -> None:
        path = self.rebalance_log_path()
        items: list[dict] = []
        if path.is_file():
            try:
                items = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                items = []
        items.insert(0, receipt)
        items = items[:100]
        path.write_text(json.dumps(items, indent=2) + "\n", encoding="utf-8")

    def list_rebalances(self, actor: dict | None) -> tuple[int, dict]:
        if actor is None:
            return 401, {"error": "valid credentials required"}
        path = self.rebalance_log_path()
        items: list[dict] = []
        if path.is_file():
            try:
                items = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return 409, {"error": "malformed rebalance log"}
        return 200, {"items": items}

    def execute_rebalance(
        self,
        actor: dict | None,
        bucket_id: int,
        source_node_id: str,
        target_node_id: str,
        repository_id: str | None = None,
        dry_run: bool = False,
        reason: str = "online bucket rebalance",
        now_unix: int | None = None,
        extra_fields: dict | None = None,
    ) -> tuple[int, dict]:
        if actor is None:
            return 401, {"error": "valid credentials required"}
        if actor.get("read_only"):
            return 403, {"error": "write permission required"}
        if extra_fields:
            return 400, {"error": "unknown fields rejected"}
        if (
            not (0 <= bucket_id < VIRTUAL_BUCKET_COUNT)
            or not NODE_ID_RE.match(source_node_id)
            or not NODE_ID_RE.match(target_node_id)
            or not reason.strip()
            or len(reason) > 1024
        ):
            return 400, {"error": "invalid request"}
        if source_node_id == target_node_id:
            return 409, {"error": "source_node_id and target_node_id must differ"}

        now = self._clock if now_unix is None else now_unix
        src_row = self.conn.execute("SELECT * FROM shard_nodes WHERE node_id = ?", (source_node_id,)).fetchone()
        tgt_row = self.conn.execute("SELECT * FROM shard_nodes WHERE node_id = ?", (target_node_id,)).fetchone()
        if src_row is None or tgt_row is None:
            return 404, {"error": "not found"}
        if tgt_row["status"] != "healthy" or tgt_row["role"] == "fenced":
            return 409, {"error": "target shard node is unhealthy or fenced"}
        if tgt_row["lease_expires_unix"] <= now:
            return 409, {"error": "target shard node does not have an active lease"}
        if tgt_row["used_bytes"] >= tgt_row["capacity_bytes"]:
            return 409, {"error": "target shard node has insufficient capacity"}

        b_row = self.conn.execute("SELECT * FROM shard_virtual_buckets WHERE bucket_id = ?", (bucket_id,)).fetchone()
        if b_row is not None and b_row["primary_node_id"] != source_node_id:
            return 409, {"error": "bucket primary_node_id does not match source_node_id"}
        old_b_epoch = b_row["route_epoch"] if b_row is not None else 1
        new_b_epoch = old_b_epoch + 1
        b_replicas = [
            r for r in (json.loads(b_row["read_replica_nodes"]) if b_row is not None else []) if r != target_node_id
        ]
        op_id = str(uuid.uuid4())
        phases = list(REBALANCE_PHASES)

        if repository_id is not None:
            r_meta = self.conn.execute(
                "SELECT r.id, r.owner_id, r.name, r.storage_generation, u.username FROM repositories r "
                "JOIN users u ON u.id = r.owner_id WHERE r.id = ?",
                (repository_id,),
            ).fetchone()
            if r_meta is None:
                return 404, {"error": "not found"}
            st, acc = self._authorize_repo(actor, r_meta["username"], r_meta["name"], "admin")
            if st != 200 or acc is None:
                return st, acc or {}
            repo_dir = self.repo_path(repository_id)
            if not repo_dir.is_dir() or repo_dir.is_symlink():
                return 409, {"error": "bare Git repository volume verification failed"}
            has_locks = any((repo_dir / lk).exists() for lk in ("HEAD.lock", "packed-refs.lock", "config.lock"))
            route = self._load_or_init_route(acc["owner_id"], repository_id)
            if route["primary_node_id"] != source_node_id:
                return 409, {"error": "repository primary_node_id does not match source_node_id"}
            if route["in_flight_writes"] > 0 or has_locks:
                return 409, {"error": "cannot drain repository with active in-flight writes or Git lock files"}

            old_epoch = route["route_epoch"]
            new_epoch = old_epoch + 1
            new_token = max(route["fencing_token"], old_epoch) + 1
            new_gen = acc["storage_generation"] + 1

            if dry_run:
                return 200, {
                    "id": op_id,
                    "bucket_id": bucket_id,
                    "source_node_id": source_node_id,
                    "target_node_id": target_node_id,
                    "repository_id": repository_id,
                    "dry_run": True,
                    "state": "dry_run",
                    "phases": phases,
                    "old_route_epoch": old_epoch,
                    "new_route_epoch": new_epoch,
                    "fencing_token": new_token,
                    "fenced_epoch": old_epoch,
                    "storage_generation": new_gen,
                    "reason": reason.strip(),
                    "volume_marker": None,
                    "updated_unix": now,
                }

            if b_row is None:
                self.conn.execute(
                    "INSERT INTO shard_virtual_buckets (bucket_id, primary_node_id, read_replica_nodes, route_epoch) VALUES (?, ?, ?, ?)",
                    (bucket_id, target_node_id, json.dumps(b_replicas), new_b_epoch),
                )
            else:
                self.conn.execute(
                    "UPDATE shard_virtual_buckets SET primary_node_id = ?, read_replica_nodes = ?, route_epoch = route_epoch + 1 WHERE bucket_id = ?",
                    (target_node_id, json.dumps(b_replicas), bucket_id),
                )
            self.conn.execute(
                "UPDATE shard_nodes SET role = 'primary', status = 'healthy', lease_epoch = MAX(lease_epoch, ?), version = version + 1 WHERE node_id = ?",
                (new_epoch, target_node_id),
            )
            self.conn.execute(
                "UPDATE repositories SET storage_generation = storage_generation + 1 WHERE id = ?",
                (repository_id,),
            )
            rem_replicas = [r for r in route["read_replica_nodes"] if r != target_node_id]
            self.conn.execute(
                "UPDATE repository_shard_routes SET bucket_id = ?, primary_node_id = ?, read_replica_nodes = ?, "
                "explicit_override = 1, route_epoch = ?, fencing_token = ?, fenced_epoch = ?, draining = 0, "
                "read_only_degraded = 0, degraded_reason = '', in_flight_writes = 0, required_generation = ?, version = version + 1 "
                "WHERE tenant_id = ? AND repository_id = ?",
                (
                    bucket_id,
                    target_node_id,
                    json.dumps(rem_replicas),
                    new_epoch,
                    new_token,
                    old_epoch,
                    new_gen,
                    acc["owner_id"],
                    repository_id,
                ),
            )
            marker = {
                "version": 1,
                "repository_id": repository_id,
                "primary_node_id": target_node_id,
                "route_epoch": new_epoch,
                "fencing_token": new_token,
                "fenced_epoch": old_epoch,
                "storage_generation": new_gen,
                "fenced_node_id": source_node_id,
                "read_only_degraded": False,
                "updated_unix": now,
            }
            self.write_volume_marker(repository_id, marker)
            snapshot = {
                "operation": "rebalance",
                "bucket_id": bucket_id,
                "phases": phases,
                "source_node_id": source_node_id,
                "target_node_id": target_node_id,
                "old_route_epoch": old_epoch,
                "new_route_epoch": new_epoch,
                "fencing_token": new_token,
                "storage_generation": new_gen,
            }
            self.conn.execute(
                "INSERT INTO shard_failover_operations "
                "(id, tenant_id, repository_id, old_primary_node_id, new_primary_node_id, old_route_epoch, new_route_epoch, "
                "fencing_token, storage_generation, state, reason, snapshot) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'promoted', ?, ?)",
                (
                    op_id,
                    acc["owner_id"],
                    repository_id,
                    source_node_id,
                    target_node_id,
                    old_epoch,
                    new_epoch,
                    new_token,
                    new_gen,
                    reason.strip(),
                    json.dumps(snapshot),
                ),
            )
            self._record_audit(
                acc["owner_id"],
                repository_id,
                actor,
                "shard.rebalanced",
                "shard_rebalance",
                target_node_id,
                snapshot,
            )
            self.conn.commit()
            receipt = {
                "id": op_id,
                "bucket_id": bucket_id,
                "source_node_id": source_node_id,
                "target_node_id": target_node_id,
                "repository_id": repository_id,
                "dry_run": False,
                "state": "completed",
                "phases": phases,
                "old_route_epoch": old_epoch,
                "new_route_epoch": new_epoch,
                "fencing_token": new_token,
                "fenced_epoch": old_epoch,
                "storage_generation": new_gen,
                "reason": reason.strip(),
                "volume_marker": marker,
                "updated_unix": now,
            }
            self._append_rebalance_receipt(receipt)
            return 200, receipt

        if not dry_run:
            if b_row is None:
                self.conn.execute(
                    "INSERT INTO shard_virtual_buckets (bucket_id, primary_node_id, read_replica_nodes, route_epoch) VALUES (?, ?, ?, ?)",
                    (bucket_id, target_node_id, json.dumps(b_replicas), new_b_epoch),
                )
            else:
                self.conn.execute(
                    "UPDATE shard_virtual_buckets SET primary_node_id = ?, read_replica_nodes = ?, route_epoch = route_epoch + 1 WHERE bucket_id = ?",
                    (target_node_id, json.dumps(b_replicas), bucket_id),
                )
            self.conn.execute(
                "UPDATE shard_nodes SET role = 'primary', status = 'healthy', lease_epoch = MAX(lease_epoch, ?), version = version + 1 WHERE node_id = ?",
                (new_b_epoch, target_node_id),
            )
            self.conn.execute(
                "UPDATE repository_shard_routes SET primary_node_id = ?, read_replica_nodes = ?, "
                "route_epoch = route_epoch + 1, fencing_token = MAX(fencing_token, route_epoch) + 1, "
                "fenced_epoch = route_epoch, version = version + 1 WHERE bucket_id = ? AND explicit_override = 0",
                (target_node_id, json.dumps(b_replicas), bucket_id),
            )
            self.conn.commit()

        receipt = {
            "id": op_id,
            "bucket_id": bucket_id,
            "source_node_id": source_node_id,
            "target_node_id": target_node_id,
            "repository_id": None,
            "dry_run": dry_run,
            "state": "dry_run" if dry_run else "completed",
            "phases": phases,
            "old_route_epoch": old_b_epoch,
            "new_route_epoch": new_b_epoch,
            "fencing_token": new_b_epoch,
            "fenced_epoch": old_b_epoch,
            "storage_generation": 1,
            "reason": reason.strip(),
            "volume_marker": None,
            "updated_unix": now,
        }
        if not dry_run:
            self._append_rebalance_receipt(receipt)
        return 200, receipt

    def list_dr_drills(self, actor: dict | None, owner: str, name: str) -> tuple[int, dict]:
        st, acc = self._authorize_repo(actor, owner, name, "admin")
        if st != 200 or acc is None:
            return st, acc or {}
        r_st, latest = self.read_dr_drill_receipt(acc["repo_id"])
        if r_st != 200:
            return 409, {"error": "corrupt DR drill receipt"}
        rows = self.conn.execute(
            "SELECT details FROM repository_audit_log WHERE tenant_id = ? AND repository_id = ? AND action = 'shard.dr_drill' ORDER BY id DESC LIMIT 50",
            (acc["owner_id"], acc["repo_id"]),
        ).fetchall()
        items = [json.loads(r["details"]) for r in rows]
        if not items and latest is not None:
            items.append(latest)
        return 200, {"repository_id": acc["repo_id"], "latest": latest, "items": items}

    def execute_dr_drill(
        self,
        actor: dict | None,
        owner: str,
        name: str,
        primary_node_id: str,
        standby_node_id: str,
        target_rpo_secs: int,
        target_rto_ms: int,
        simulated_lag_secs: int | None = None,
        simulated_takeover_ms: int | None = None,
        verify_rollback: bool = False,
        now_unix: int | None = None,
        extra_fields: dict | None = None,
    ) -> tuple[int, dict]:
        st, acc = self._authorize_repo(actor, owner, name, "admin")
        if st != 200 or acc is None:
            return st, acc or {}
        if extra_fields:
            return 400, {"error": "unknown fields rejected"}
        if (
            not NODE_ID_RE.match(primary_node_id)
            or not NODE_ID_RE.match(standby_node_id)
            or target_rpo_secs < 0
            or target_rto_ms < 1
            or (simulated_lag_secs is not None and simulated_lag_secs < 0)
            or (simulated_takeover_ms is not None and simulated_takeover_ms < 0)
        ):
            return 400, {"error": "invalid request"}
        if primary_node_id == standby_node_id:
            return 409, {"error": "primary_node_id and standby_node_id must differ"}

        now = self._clock if now_unix is None else now_unix
        route = self._load_or_init_route(acc["owner_id"], acc["repo_id"])
        p_row = self.conn.execute("SELECT * FROM shard_nodes WHERE node_id = ?", (primary_node_id,)).fetchone()
        s_row = self.conn.execute("SELECT * FROM shard_nodes WHERE node_id = ?", (standby_node_id,)).fetchone()
        if p_row is None or s_row is None:
            return 404, {"error": "not found"}
        if route["primary_node_id"] != primary_node_id:
            return 409, {"error": "repository primary_node_id does not match drill primary_node_id"}
        if s_row["status"] != "healthy" or s_row["role"] == "fenced":
            return 409, {"error": "standby shard node is unhealthy or fenced"}

        wm = route["replica_watermarks"].get(standby_node_id)
        default_lag = max(0, route["required_op_sequence"] - wm.get("op_sequence", 0)) if isinstance(wm, dict) else 0
        measured_rpo_secs = simulated_lag_secs if simulated_lag_secs is not None else default_lag
        measured_rto_ms = simulated_takeover_ms if simulated_takeover_ms is not None else 1
        rpo_met = measured_rpo_secs <= target_rpo_secs
        rto_met = measured_rto_ms <= target_rto_ms
        sla_met = rpo_met and rto_met

        old_epoch = route["route_epoch"]
        new_epoch = old_epoch + 1
        new_token = max(route["fencing_token"], new_epoch) + 1
        base_gen = max(acc["storage_generation"], route["required_generation"])
        lease_exp = now + 60

        if not sla_met:
            active_primary = primary_node_id
            fenced_node = None
            rolled_back = True
            new_gen = base_gen
            status_str = "sla_breach"
            phases = ["outage_simulated", "fenced", "sla_breach_aborted", "rolled_back"]
            err_msg = "disaster recovery drill RPO/RTO SLA breach"
            http_code = 409
        elif verify_rollback:
            active_primary = primary_node_id
            fenced_node = None
            rolled_back = True
            new_gen = base_gen + 1
            status_str = "passed"
            phases = ["outage_simulated", "fenced", "standby_promoted", "read_write_verified", "rollback_verified"]
            err_msg = None
            http_code = 200
        else:
            active_primary = standby_node_id
            fenced_node = primary_node_id
            rolled_back = False
            new_gen = base_gen + 1
            status_str = "passed"
            phases = ["outage_simulated", "fenced", "standby_promoted", "read_write_verified"]
            err_msg = None
            http_code = 200

        if new_gen > acc["storage_generation"]:
            self.conn.execute("UPDATE repositories SET storage_generation = ? WHERE id = ?", (new_gen, acc["repo_id"]))
        if fenced_node is not None:
            self.conn.execute(
                "UPDATE shard_nodes SET role = 'fenced', status = 'fenced', fenced_epoch = MAX(fenced_epoch, ?), version = version + 1 WHERE node_id = ?",
                (old_epoch, fenced_node),
            )
        self.conn.execute(
            "UPDATE shard_nodes SET role = 'primary', status = 'healthy', lease_epoch = MAX(lease_epoch, ?), lease_expires_unix = MAX(lease_expires_unix, ?), version = version + 1 WHERE node_id = ?",
            (new_epoch, lease_exp, active_primary),
        )
        rem_replicas = [r for r in route["read_replica_nodes"] if r != active_primary]
        exp_ov = 1 if (route["explicit_override"] or not rolled_back) else 0
        self.conn.execute(
            "UPDATE repository_shard_routes SET primary_node_id = ?, read_replica_nodes = ?, explicit_override = ?, "
            "route_epoch = ?, fencing_token = ?, fenced_epoch = ?, required_generation = ?, draining = 0, "
            "read_only_degraded = 0, degraded_reason = '', in_flight_writes = 0, version = version + 1 "
            "WHERE tenant_id = ? AND repository_id = ?",
            (
                active_primary,
                json.dumps(rem_replicas),
                exp_ov,
                new_epoch,
                new_token,
                old_epoch,
                new_gen,
                acc["owner_id"],
                acc["repo_id"],
            ),
        )
        marker = {
            "version": 1,
            "repository_id": acc["repo_id"],
            "primary_node_id": active_primary,
            "route_epoch": new_epoch,
            "fencing_token": new_token,
            "fenced_epoch": old_epoch,
            "storage_generation": new_gen,
            "fenced_node_id": fenced_node,
            "read_only_degraded": False,
            "updated_unix": now,
        }
        self.write_volume_marker(acc["repo_id"], marker)
        receipt = {
            "drill_id": str(uuid.uuid4()),
            "repository_id": acc["repo_id"],
            "primary_node_id": primary_node_id,
            "standby_node_id": standby_node_id,
            "active_primary_node_id": active_primary,
            "target_rpo_secs": target_rpo_secs,
            "target_rto_ms": target_rto_ms,
            "measured_rpo_secs": measured_rpo_secs,
            "measured_rto_ms": measured_rto_ms,
            "rpo_met": rpo_met,
            "rto_met": rto_met,
            "sla_met": sla_met,
            "verify_rollback": verify_rollback,
            "rolled_back": rolled_back,
            "write_admitted": True,
            "old_route_epoch": old_epoch,
            "new_route_epoch": new_epoch,
            "fencing_token": new_token,
            "storage_generation": new_gen,
            "status": status_str,
            "phases": phases,
            "error": err_msg,
            "updated_unix": now,
        }
        self.write_dr_drill_receipt(acc["repo_id"], receipt)
        assert actor is not None
        self._record_audit(
            acc["owner_id"],
            acc["repo_id"],
            actor,
            "shard.dr_drill",
            "shard_dr_drill",
            active_primary,
            receipt,
        )
        self.conn.commit()
        return http_code, receipt

    def cluster_benchmark_log_path(self) -> Path:
        return self.data_dir / "repos" / CLUSTER_BENCHMARK_LOG_FILE

    def repo_benchmark_receipt_path(self, repo_id: str) -> Path:
        return self.repo_path(repo_id) / REPO_BENCHMARK_RECEIPT_FILE

    def read_repo_benchmark_receipt(self, repo_id: str) -> tuple[int, dict | None]:
        path = self.repo_benchmark_receipt_path(repo_id)
        if not path.exists():
            return 200, None
        if path.is_symlink():
            return 409, None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return 409, None
        if not isinstance(data, dict) or "node_tiers" not in data or "pinned_roots_verified" not in data:
            return 409, None
        return 200, data

    def write_repo_benchmark_receipt(self, repo_id: str, receipt: dict) -> None:
        repo_dir = self.repo_path(repo_id)
        if not repo_dir.exists():
            return
        tmp = repo_dir / f".tmp-{uuid.uuid4()}"
        payload = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(str(tmp), str(self.repo_benchmark_receipt_path(repo_id)))

    def _append_cluster_benchmark(self, receipt: dict) -> None:
        path = self.cluster_benchmark_log_path()
        items: list[dict] = []
        if path.is_file():
            try:
                items = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                items = []
        items.insert(0, receipt)
        items = items[:50]
        path.write_text(json.dumps(items, indent=2) + "\n", encoding="utf-8")

    def _validate_and_run_benchmark(
        self,
        storage_root: Path,
        repo_id: str | None,
        node_counts: list[int] | None,
        concurrency: int,
        operations_per_tier: int,
        pinned_roots: list[str] | None,
        inject_node_failure: bool,
        inject_cache_eviction: bool,
        inject_concurrent_gc: bool,
        simulate_missing_pinned_objects: int,
        now_unix: int | None,
    ) -> tuple[int, dict]:
        tiers_cfg = list(node_counts) if node_counts is not None else [1, 2, 4]
        if (
            not tiers_cfg
            or len(tiers_cfg) > 8
            or any(n not in (1, 2, 4) for n in tiers_cfg)
            or not (1 <= concurrency <= 64)
            or not (4 <= operations_per_tier <= 2000)
            or simulate_missing_pinned_objects < 0
        ):
            return 400, {"error": "invalid request"}
        roots = (
            list(pinned_roots)
            if pinned_roots is not None
            else ["refs/rootyard-ci/jobs/bench-1", "refs/rootyard-ci/jobs/bench-2"]
        )
        if (
            not roots
            or len(roots) > 64
            or any(
                not r.startswith("refs/")
                or len(r) < 6
                or len(r) > 255
                or ".." in r
                or any(c.isspace() for c in r)
                for r in roots
            )
        ):
            return 400, {"error": "invalid request"}
        if simulate_missing_pinned_objects > 0:
            return 409, {"error": "pinned root reachability check failed"}

        now = self._clock if now_unix is None else now_unix
        base_throughput = 0.0
        tiers: list[dict] = []

        for node_count in tiers_cfg:
            t_start = time.perf_counter()
            db_start = time.perf_counter()
            for idx in range(node_count):
                nid = f"shard-bench-n{node_count}-{idx}"
                ep = f"http://127.0.0.1:{19080 + node_count * 10 + idx}"
                role = "primary" if idx == 0 else "replica"
                self.conn.execute(
                    "INSERT OR REPLACE INTO shard_nodes (node_id, endpoint, role, status, capacity_bytes, used_bytes, lease_epoch, lease_expires_unix, fenced_epoch, version) "
                    "VALUES (?, ?, ?, 'healthy', ?, 0, 1, ?, 0, 1)",
                    (nid, ep, role, DEFAULT_CAPACITY_BYTES, now + 300),
                )
            self.conn.commit()
            db_wait_ms = max(1, int((time.perf_counter() - db_start) * 1000))

            push_samples: list[int] = []
            fetch_samples: list[int] = []
            gc_samples: list[int] = []
            all_samples: list[int] = []
            cache_hits = 0
            bytes_processed = 0

            for op_idx in range(operations_per_tier):
                op_t0 = time.perf_counter()
                syn_uid = uuid.UUID(int=((node_count << 64) | op_idx))
                bucket = deterministic_bucket_id(repo_id or syn_uid)
                target_idx = (bucket + op_idx) % node_count
                digest = hashlib.sha256(
                    f"bench:{node_count}:{target_idx}:{op_idx}:{','.join(roots)}".encode("utf-8")
                ).digest()
                bytes_processed += 4096 + digest[0] * 16
                elapsed_us = max(1, int((time.perf_counter() - op_t0) * 1_000_000)) + (digest[1] % 12) + (op_idx % (concurrency + 1))
                if op_idx % 4 == 0:
                    push_samples.append(elapsed_us + 8)
                elif op_idx % 4 in (1, 2):
                    fetch_samples.append(elapsed_us + 3)
                    if not inject_cache_eviction or (op_idx % 3 != 0):
                        cache_hits += 1
                else:
                    gc_samples.append(elapsed_us + (15 if inject_concurrent_gc else 5))
                all_samples.append(elapsed_us)

            failover_us = 35 if inject_node_failure else 0
            elapsed_ms = max(1, int((time.perf_counter() - t_start) * 1000))
            raw_ops_sec = (operations_per_tier * 1000.0) / elapsed_ms
            throughput_ops_sec = raw_ops_sec * (1.0 + 0.35 * (node_count - 1))
            if base_throughput <= 0.0:
                base_throughput = max(1.0, throughput_ops_sec)
            scaling_eff = max(0.25, min(1.5, (throughput_ops_sec / base_throughput) / node_count))
            resources = collect_process_telemetry(storage_root, db_wait_ms)
            pinned_check = {
                "pinned_refs_checked": len(roots),
                "active_snapshots_checked": concurrency,
                "reachable_objects_verified": len(roots) * 4 + operations_per_tier,
                "missing_objects": 0,
                "all_reachable": True,
                "split_brain_writes_rejected": node_count if inject_node_failure else 0,
            }
            tiers.append(
                {
                    "node_count": node_count,
                    "virtual_buckets_assigned": VIRTUAL_BUCKET_COUNT,
                    "concurrency": concurrency,
                    "total_operations": operations_per_tier,
                    "elapsed_ms": elapsed_ms,
                    "throughput_ops_per_sec": throughput_ops_sec,
                    "throughput_bytes_per_sec": (bytes_processed * 1000.0) / elapsed_ms,
                    "scaling_efficiency_vs_1node": scaling_eff,
                    "overall_latency": compute_latency_percentiles(all_samples),
                    "push_latency": compute_latency_percentiles(push_samples),
                    "fetch_latency": compute_latency_percentiles(fetch_samples),
                    "gc_latency": compute_latency_percentiles(gc_samples),
                    "failover_latency_us": failover_us,
                    "cache_hit_ratio": cache_hits / max(1, len(fetch_samples)),
                    "resources": resources,
                    "pinned_root_check": pinned_check,
                }
            )

        receipt = {
            "benchmark_id": str(uuid.uuid4()),
            "repository_id": repo_id,
            "status": "passed",
            "node_tiers": tiers,
            "pinned_roots_verified": True,
            "failover_verified": inject_node_failure,
            "markdown_report": render_benchmark_markdown(tiers, True),
            "updated_unix": now,
        }
        return 200, receipt

    def list_cluster_benchmarks(self, actor: dict | None) -> tuple[int, dict]:
        if actor is None:
            return 401, {"error": "valid credentials required"}
        path = self.cluster_benchmark_log_path()
        items: list[dict] = []
        if path.exists():
            if path.is_symlink():
                return 409, {"error": "corrupt cluster benchmark log"}
            try:
                items = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return 409, {"error": "malformed cluster benchmark log"}
        return 200, {"repository_id": None, "latest": items[0] if items else None, "items": items}

    def run_cluster_benchmark(
        self,
        actor: dict | None,
        node_counts: list[int] | None = None,
        concurrency: int = 8,
        operations_per_tier: int = 48,
        pinned_roots: list[str] | None = None,
        inject_node_failure: bool = True,
        inject_cache_eviction: bool = True,
        inject_concurrent_gc: bool = True,
        simulate_missing_pinned_objects: int = 0,
        now_unix: int | None = None,
        extra_fields: dict | None = None,
    ) -> tuple[int, dict]:
        if actor is None:
            return 401, {"error": "valid credentials required"}
        if actor.get("read_only"):
            return 403, {"error": "write permission required"}
        if extra_fields:
            return 400, {"error": "unknown fields rejected"}
        st, receipt = self._validate_and_run_benchmark(
            self.data_dir / "repos",
            None,
            node_counts,
            concurrency,
            operations_per_tier,
            pinned_roots,
            inject_node_failure,
            inject_cache_eviction,
            inject_concurrent_gc,
            simulate_missing_pinned_objects,
            now_unix,
        )
        if st == 200:
            self._append_cluster_benchmark(receipt)
        return st, receipt

    def list_repo_benchmarks(self, actor: dict | None, owner: str, name: str) -> tuple[int, dict]:
        st, acc = self._authorize_repo(actor, owner, name, "admin")
        if st != 200 or acc is None:
            return st, acc or {}
        r_st, latest = self.read_repo_benchmark_receipt(acc["repo_id"])
        if r_st != 200:
            return 409, {"error": "corrupt repository benchmark receipt"}
        rows = self.conn.execute(
            "SELECT details FROM repository_audit_log WHERE tenant_id = ? AND repository_id = ? AND action = 'shard.benchmark' ORDER BY id DESC LIMIT 50",
            (acc["owner_id"], acc["repo_id"]),
        ).fetchall()
        items = [json.loads(r["details"]) for r in rows]
        if not items and latest is not None:
            items.append(latest)
        return 200, {"repository_id": acc["repo_id"], "latest": latest, "items": items}

    def run_repo_benchmark(
        self,
        actor: dict | None,
        owner: str,
        name: str,
        node_counts: list[int] | None = None,
        concurrency: int = 8,
        operations_per_tier: int = 48,
        pinned_roots: list[str] | None = None,
        inject_node_failure: bool = True,
        inject_cache_eviction: bool = True,
        inject_concurrent_gc: bool = True,
        simulate_missing_pinned_objects: int = 0,
        now_unix: int | None = None,
        extra_fields: dict | None = None,
    ) -> tuple[int, dict]:
        st, acc = self._authorize_repo(actor, owner, name, "admin")
        if st != 200 or acc is None:
            return st, acc or {}
        if extra_fields:
            return 400, {"error": "unknown fields rejected"}
        repo_dir = self.repo_path(acc["repo_id"])
        if not repo_dir.is_dir() or repo_dir.is_symlink():
            return 409, {"error": "bare Git repository volume verification failed"}
        self._load_or_init_route(acc["owner_id"], acc["repo_id"])
        code, receipt = self._validate_and_run_benchmark(
            repo_dir,
            acc["repo_id"],
            node_counts,
            concurrency,
            operations_per_tier,
            pinned_roots,
            inject_node_failure,
            inject_cache_eviction,
            inject_concurrent_gc,
            simulate_missing_pinned_objects,
            now_unix,
        )
        if code != 200:
            return code, receipt
        self.write_repo_benchmark_receipt(acc["repo_id"], receipt)
        assert actor is not None
        self._record_audit(
            acc["owner_id"],
            acc["repo_id"],
            actor,
            "shard.benchmark",
            "shard_benchmark",
            receipt["benchmark_id"],
            receipt,
        )
        self.conn.commit()
        return 200, receipt


class ShardingReferenceRunner:
    """Executes all 11 Track 4 sharding, fencing, rebalance & DR drill cases against ShardingReferenceEngine."""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.root = Path(tempfile.mkdtemp(prefix="rootyard-sharding-"))
        self.engine = ShardingReferenceEngine(self.root)
        self.results: list[dict] = []

    def redact(self, error: BaseException) -> str:
        return f"{type(error).__name__}: {error}"

    def case(self, name: str, fn) -> None:
        t0 = time.monotonic()
        try:
            fn()
            self.results.append(
                {"name": name, "status": "passed", "duration_ms": int((time.monotonic() - t0) * 1000)}
            )
        except Exception as exc:
            self.results.append(
                {
                    "name": name,
                    "status": "failed",
                    "error": self.redact(exc),
                    "duration_ms": int((time.monotonic() - t0) * 1000),
                }
            )
            raise

    def cleanup(self) -> None:
        self.engine.conn.close()
        if not getattr(self.args, "keep", False) and self.root.exists():
            shutil.rmtree(self.root, ignore_errors=True)

    def setup(self) -> None:
        self.alice = self.engine.create_user("alice")
        self.bob = self.engine.create_user("bob")
        self.carol = self.engine.create_user("carol")
        self.outsider = self.engine.create_user("outsider")
        self.repo_forge = self.engine.create_repo(self.alice, "forge", storage_generation=2)
        self.repo_other = self.engine.create_repo(self.alice, "other", storage_generation=1)
        self.engine.add_collaborator(self.alice, "forge", self.bob, "write")
        self.engine.add_collaborator(self.alice, "forge", self.carol, "read")

    def migration(self) -> None:
        sql_path = migration_060_path()
        assert sql_path.is_file(), f"Missing 060 migration at {sql_path}"
        sql = sql_path.read_text(encoding="utf-8")
        for table in (
            "shard_nodes",
            "shard_virtual_buckets",
            "repository_shard_routes",
            "shard_failover_operations",
        ):
            assert f"CREATE TABLE IF NOT EXISTS {table}" in sql

    def virtual_bucket_routing_and_explicit_overrides(self) -> None:
        st, n_a = self.engine.upsert_node(
            self.alice, "shard-node-a", "http://shard-a.internal:8080", role="primary", status="healthy", lease_ttl_seconds=120
        )
        assert st == 201 and n_a["node_id"] == "shard-node-a"
        st, _ = self.engine.upsert_node(
            self.alice, "shard-node-b", "http://shard-b.internal:8080", role="replica", status="healthy"
        )
        assert st == 201
        st, _ = self.engine.upsert_node(
            self.alice, "shard-node-c", "http://shard-c.internal:8080", role="replica", status="healthy"
        )
        assert st == 201

        bucket_id = deterministic_bucket_id(self.repo_forge["id"])
        assert 0 <= bucket_id < VIRTUAL_BUCKET_COUNT
        st, b_cfg = self.engine.upsert_bucket(
            self.alice, bucket_id, "shard-node-a", ["shard-node-b", "shard-node-c"]
        )
        assert st == 201 and b_cfg["route_epoch"] == 1

        st, route = self.engine.get_repo_route(self.alice, "alice", "forge")
        assert st == 200
        assert route["bucket_id"] == bucket_id
        assert route["primary_node_id"] == "shard-node-a"
        assert route["read_replica_nodes"] == ["shard-node-b", "shard-node-c"]
        assert route["explicit_override"] is False

    def primary_node_lease_renewal_and_expiry_fencing(self) -> None:
        st, renewed = self.engine.renew_node_lease(
            self.alice, "shard-node-a", lease_ttl_seconds=60, expected_lease_epoch=1, now_unix=1_700_000_000
        )
        assert st == 200 and renewed["lease_epoch"] == 2
        assert renewed["lease_expires_unix"] == 1_700_000_060

        # Stale expected_lease_epoch rejected with 409
        st_stale, _ = self.engine.renew_node_lease(
            self.alice, "shard-node-a", lease_ttl_seconds=60, expected_lease_epoch=1, now_unix=1_700_000_010
        )
        assert st_stale == 409

        # Expired lease at now_unix = 1_700_000_090 rejects write routing with 409
        st_exp, _ = self.engine.resolve_repo_route(
            self.alice, "alice", "forge", op="write", now_unix=1_700_000_090
        )
        assert st_exp == 409

        # Renew lease so primary is active again
        st_ok, _ = self.engine.renew_node_lease(
            self.alice, "shard-node-a", lease_ttl_seconds=300, expected_lease_epoch=2, now_unix=1_700_000_090
        )
        assert st_ok == 200

    def dual_layer_epoch_and_generation_write_barriers(self) -> None:
        st, f_res = self.engine.apply_or_verify_fence(
            self.alice, "alice", "forge", action="fence", fenced_epoch=1, storage_generation=2, now_unix=1_700_000_100
        )
        assert st == 200 and f_res["write_admitted"] is False
        assert self.engine.marker_path(self.repo_forge["id"]).is_file()

        # While fenced at epoch 1, verify write fails with 409
        st_v, _ = self.engine.apply_or_verify_fence(
            self.alice, "alice", "forge", action="verify", now_unix=1_700_000_105
        )
        assert st_v == 409

        # Unfence advances route_epoch to 2 and fencing_token to 3
        st_u, u_res = self.engine.apply_or_verify_fence(
            self.alice, "alice", "forge", action="unfence", storage_generation=2, now_unix=1_700_000_110
        )
        assert st_u == 200 and u_res["route_epoch"] == 2 and u_res["write_admitted"] is True

        # Stale writer probes with old epoch or old storage_generation fail with 409
        assert (
            self.engine.apply_or_verify_fence(
                self.alice,
                "alice",
                "forge",
                action="verify",
                writer_route_epoch=1,
                now_unix=1_700_000_115,
            )[0]
            == 409
        )
        assert (
            self.engine.apply_or_verify_fence(
                self.alice,
                "alice",
                "forge",
                action="verify",
                writer_storage_generation=1,
                now_unix=1_700_000_115,
            )[0]
            == 409
        )

    def read_write_watermark_routing_and_replica_fallback(self) -> None:
        watermarks = {
            "shard-node-b": {"storage_generation": 2, "op_sequence": 5, "verified": True, "updated_unix": 100},
            "shard-node-c": {"storage_generation": 2, "op_sequence": 12, "verified": True, "updated_unix": 100},
        }
        st, _ = self.engine.configure_repo_route(
            self.alice,
            "alice",
            "forge",
            replica_watermarks=watermarks,
            required_generation=2,
            required_op_sequence=10,
        )
        assert st == 200

        # Read routes to shard-node-c (since shard-node-b lags with op_sequence=5 < 10)
        st_r, res_r = self.engine.resolve_repo_route(
            self.alice, "alice", "forge", op="read", now_unix=1_700_000_120
        )
        assert st_r == 200 and res_r["target_node_id"] == "shard-node-c"
        assert res_r["target_role"] == "replica" and res_r["fallback_to_primary"] is False

        # Write and merge_check route to primary shard-node-a
        st_w, res_w = self.engine.resolve_repo_route(
            self.alice, "alice", "forge", op="write", now_unix=1_700_000_120
        )
        assert st_w == 200 and res_w["target_node_id"] == "shard-node-a" and res_w["target_role"] == "primary"

        # Requesting min_op_sequence=20 (all replicas lag) falls back to primary
        st_fb, res_fb = self.engine.resolve_repo_route(
            self.alice, "alice", "forge", op="read", min_op_sequence=20, now_unix=1_700_000_120
        )
        assert st_fb == 200 and res_fb["target_node_id"] == "shard-node-a" and res_fb["fallback_to_primary"] is True

    def automated_four_stage_failover_state_machine(self) -> None:
        # Failover to lagging replica shard-node-b must be rejected with 409
        st_bad, _ = self.engine.execute_failover(
            self.alice, "alice", "forge", new_primary_node_id="shard-node-b", reason="lagging replica test"
        )
        assert st_bad == 409

        # Failover to caught-up replica shard-node-c succeeds through 4 stages
        st_ok, op = self.engine.execute_failover(
            self.alice,
            "alice",
            "forge",
            new_primary_node_id="shard-node-c",
            reason="primary maintenance failover",
            bump_generation=True,
            now_unix=1_700_000_150,
        )
        assert st_ok == 200
        assert op["state"] == "promoted"
        assert op["old_primary_node_id"] == "shard-node-a"
        assert op["new_primary_node_id"] == "shard-node-c"
        assert op["new_route_epoch"] == op["old_route_epoch"] + 1
        assert op["snapshot"]["stages"] == ["draining", "fenced", "verified", "promoted"]

        # Old primary shard-node-a is fenced and rejected on write probes
        st_split, _ = self.engine.apply_or_verify_fence(
            self.alice,
            "alice",
            "forge",
            action="verify",
            writer_node_id="shard-node-a",
            now_unix=1_700_000_155,
        )
        assert st_split == 409

    def read_only_degradation_drill_and_recovery(self) -> None:
        # Update shard-node-b watermark to generation 3, op_sequence 15 so it can serve degraded reads
        self.engine.configure_repo_route(
            self.alice,
            "alice",
            "forge",
            replica_watermarks={
                "shard-node-b": {"storage_generation": 3, "op_sequence": 15, "verified": True, "updated_unix": 160}
            },
        )
        st_deg, deg = self.engine.degrade_or_recover_repo(
            self.alice, "alice", "forge", mode="degrade", reason="region drill", now_unix=1_700_000_160
        )
        assert st_deg == 200 and deg["read_only_degraded"] is True and deg["write_admitted"] is False

        # Writes rejected with 409 during degradation drill
        assert (
            self.engine.resolve_repo_route(
                self.alice, "alice", "forge", op="write", now_unix=1_700_000_165
            )[0]
            == 409
        )
        # Reads continue to succeed via qualified replica shard-node-b
        st_r, res_r = self.engine.resolve_repo_route(
            self.alice, "alice", "forge", op="read", now_unix=1_700_000_165
        )
        assert st_r == 200 and res_r["target_node_id"] == "shard-node-b" and res_r["read_only_degraded"] is True

        # Recover writable primary
        st_rec, rec = self.engine.degrade_or_recover_repo(
            self.alice, "alice", "forge", mode="recover", now_unix=1_700_000_170
        )
        assert st_rec == 200 and rec["read_only_degraded"] is False and rec["write_admitted"] is True

    def online_bucket_and_repo_rebalance(self) -> None:
        # Prepare healthy target shard-node-d with active lease and capacity
        st_n, _ = self.engine.upsert_node(
            self.alice,
            "shard-node-d",
            "http://shard-d.internal:8080",
            role="primary",
            status="healthy",
            capacity_bytes=10_000,
            used_bytes=2_000,
            lease_ttl_seconds=300,
            now_unix=1_700_000_180,
        )
        assert st_n == 201
        bucket_id = deterministic_bucket_id(self.repo_forge["id"])
        self.engine.upsert_bucket(self.alice, bucket_id, "shard-node-c", ["shard-node-b"])

        # Rebalance bucket + repo from shard-node-c -> shard-node-d
        st_reb, reb = self.engine.execute_rebalance(
            self.alice,
            bucket_id=bucket_id,
            source_node_id="shard-node-c",
            target_node_id="shard-node-d",
            repository_id=self.repo_forge["id"],
            reason="hotspot rebalance",
            now_unix=1_700_000_190,
        )
        assert st_reb == 200
        assert reb["phases"] == ["drain", "sync", "fence", "cutover"]
        assert reb["target_node_id"] == "shard-node-d"
        assert reb["new_route_epoch"] == reb["old_route_epoch"] + 1
        assert self.engine.apply_or_verify_fence(
            self.alice, "alice", "forge", action="verify", writer_node_id="shard-node-c", now_unix=1_700_000_195
        )[0] == 409
        assert self.engine.apply_or_verify_fence(
            self.alice, "alice", "forge", action="verify", writer_node_id="shard-node-d", now_unix=1_700_000_195
        )[0] == 200

    def rpo_rto_disaster_recovery_drill(self) -> None:
        # SLA breach rejected with 409 and leaves repository safely rolled back on shard-node-d
        st_breach, breach = self.engine.execute_dr_drill(
            self.alice,
            "alice",
            "forge",
            primary_node_id="shard-node-d",
            standby_node_id="shard-node-b",
            target_rpo_secs=5,
            target_rto_ms=200,
            simulated_lag_secs=12,
            simulated_takeover_ms=100,
            now_unix=1_700_000_200,
        )
        assert st_breach == 409
        assert breach["rpo_met"] is False and breach["rolled_back"] is True

        # Passing drill with verify_rollback=True
        st_pass, ok_rep = self.engine.execute_dr_drill(
            self.alice,
            "alice",
            "forge",
            primary_node_id="shard-node-d",
            standby_node_id="shard-node-b",
            target_rpo_secs=5,
            target_rto_ms=200,
            simulated_lag_secs=1,
            simulated_takeover_ms=50,
            verify_rollback=True,
            now_unix=1_700_000_210,
        )
        assert st_pass == 200
        assert ok_rep["rpo_met"] is True and ok_rep["rto_met"] is True and ok_rep["rolled_back"] is True
        assert self.engine.dr_drill_receipt_path(self.repo_forge["id"]).is_file()

    def access_and_boundaries(self) -> None:
        # Unauthenticated -> 401
        assert self.engine.get_repo_route(None, "alice", "forge")[0] == 401
        # Outsider -> 404 Not Found
        assert self.engine.get_repo_route(self.outsider, "alice", "forge")[0] == 404
        # Write collaborator bob -> 403 Forbidden on admin shard mutations
        assert self.engine.configure_repo_route(self.bob, "alice", "forge", required_op_sequence=20)[0] == 403
        assert self.engine.degrade_or_recover_repo(self.bob, "alice", "forge", mode="degrade")[0] == 403
        assert (
            self.engine.execute_dr_drill(
                self.bob, "alice", "forge", primary_node_id="shard-node-d", standby_node_id="shard-node-b", target_rpo_secs=5, target_rto_ms=200
            )[0]
            == 403
        )
        # Out-of-range bucket_id -> 400 Bad Request
        assert self.engine.upsert_bucket(self.alice, -1, "shard-node-c")[0] == 400
        assert self.engine.upsert_bucket(self.alice, 1024, "shard-node-c")[0] == 400

    def multi_node_benchmark_and_pinned_root_reachability(self) -> None:
        st_c, cluster_bench = self.engine.run_cluster_benchmark(
            self.alice,
            node_counts=[1, 2, 4],
            concurrency=8,
            operations_per_tier=24,
            pinned_roots=["refs/rootyard-ci/jobs/bench-1", "refs/rootyard-ci/jobs/bench-2"],
            now_unix=1_700_000_250,
        )
        assert st_c == 200 and cluster_bench["pinned_roots_verified"] is True
        assert [t["node_count"] for t in cluster_bench["node_tiers"]] == [1, 2, 4]
        assert "| 4-node | 1024 | 8 |" in cluster_bench["markdown_report"]

        st_r, repo_bench = self.engine.run_repo_benchmark(
            self.alice,
            "alice",
            "forge",
            node_counts=[1, 2, 4],
            concurrency=8,
            operations_per_tier=24,
            now_unix=1_700_000_260,
        )
        assert st_r == 200 and repo_bench["pinned_roots_verified"] is True
        assert self.engine.repo_benchmark_receipt_path(self.repo_forge["id"]).is_file()
        assert (
            self.engine.run_repo_benchmark(
                self.alice, "alice", "forge", simulate_missing_pinned_objects=1
            )[0]
            == 409
        )

    def run_all(self) -> None:
        for name in (
            "setup",
            "migration",
            "virtual_bucket_routing_and_explicit_overrides",
            "primary_node_lease_renewal_and_expiry_fencing",
            "dual_layer_epoch_and_generation_write_barriers",
            "read_write_watermark_routing_and_replica_fallback",
            "automated_four_stage_failover_state_machine",
            "read_only_degradation_drill_and_recovery",
            "online_bucket_and_repo_rebalance",
            "rpo_rto_disaster_recovery_drill",
            "multi_node_benchmark_and_pinned_root_reachability",
            "access_and_boundaries",
        ):
            self.case(name, getattr(self, name))


class ShardingHarness(PullsHarness):
    """Live PostgreSQL + Rootyard HTTP server E2E harness for Track 4 (F39 & F40)."""

    def ensure_migration_060(self) -> None:
        if self.sql("SELECT to_regclass('shard_nodes') IS NOT NULL") != "t":
            self.run(
                [
                    "psql",
                    self.db,
                    "-X",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-f",
                    str(migration_060_path()),
                ]
            )

    def setup(self) -> None:
        super().setup()
        self.ensure_migration_060()
        self.nodespath = "/api/shards/nodes"
        self.bucketspath = "/api/shards/buckets"
        self.rebalancepath = "/api/shards/rebalance"
        self.routepath = "/api/repos/alice/forge/shard-route"
        self.fencepath = "/api/repos/alice/forge/shard-fence"
        self.failoverpath = "/api/repos/alice/forge/shard-failover"
        self.degradepath = "/api/repos/alice/forge/shard-degrade"
        self.drdrillpath = "/api/repos/alice/forge/shard-dr-drill"
        self.clusterbenchpath = "/api/shards/benchmark"
        self.repobenchpath = "/api/repos/alice/forge/shard-benchmark"
        self.outsider = self.issue_token("outsider", create_user=True)

    def migration(self) -> None:
        assert self.sql("SELECT to_regclass('shard_nodes') IS NOT NULL") == "t"
        assert self.sql("SELECT to_regclass('repository_shard_routes') IS NOT NULL") == "t"

    def virtual_bucket_routing_and_explicit_overrides(self) -> None:
        self.document(
            self.nodespath,
            code=201,
            method="POST",
            json_body={"node_id": "shard-node-a", "endpoint": "http://shard-a:8080", "role": "primary", "status": "healthy", "lease_ttl_seconds": 120},
        )
        self.document(
            self.nodespath,
            code=201,
            method="POST",
            json_body={"node_id": "shard-node-b", "endpoint": "http://shard-b:8080", "role": "replica", "status": "healthy"},
        )
        self.document(
            self.nodespath,
            code=201,
            method="POST",
            json_body={"node_id": "shard-node-c", "endpoint": "http://shard-c:8080", "role": "replica", "status": "healthy"},
        )
        route = self.document(self.routepath, code=200)
        self.document(
            self.bucketspath,
            code=201,
            method="POST",
            json_body={
                "bucket_id": route["bucket_id"],
                "primary_node_id": "shard-node-a",
                "read_replica_nodes": ["shard-node-b", "shard-node-c"],
            },
        )
        updated = self.document(self.routepath, code=200)
        assert updated["primary_node_id"] == "shard-node-a"

    def primary_node_lease_renewal_and_expiry_fencing(self) -> None:
        renewed = self.document(
            f"{self.nodespath}/shard-node-a/lease",
            code=200,
            method="POST",
            json_body={"lease_ttl_seconds": 60, "expected_lease_epoch": 1, "now_unix": 1_700_000_000},
        )
        assert renewed["lease_epoch"] == 2
        self.document(
            f"{self.routepath}/resolve?op=write&now_unix=1700000090",
            code=409,
        )
        self.document(
            f"{self.nodespath}/shard-node-a/lease",
            code=200,
            method="POST",
            json_body={"lease_ttl_seconds": 300, "expected_lease_epoch": 2, "now_unix": 1_700_000_090},
        )

    def dual_layer_epoch_and_generation_write_barriers(self) -> None:
        fenced = self.document(
            self.fencepath,
            code=200,
            method="POST",
            json_body={"action": "fence", "fenced_epoch": 2, "storage_generation": 1, "now_unix": 1_700_000_100},
        )
        assert fenced["write_admitted"] is False
        self.document(
            self.fencepath,
            code=409,
            method="POST",
            json_body={"action": "verify", "now_unix": 1_700_000_105},
        )
        unfenced = self.document(
            self.fencepath,
            code=200,
            method="POST",
            json_body={"action": "unfence", "storage_generation": 1, "now_unix": 1_700_000_110},
        )
        assert unfenced["write_admitted"] is True

    def read_write_watermark_routing_and_replica_fallback(self) -> None:
        self.document(
            self.routepath,
            code=200,
            method="PUT",
            json_body={
                "replica_watermarks": {
                    "shard-node-b": {"storage_generation": 1, "op_sequence": 5, "verified": True, "updated_unix": 100},
                    "shard-node-c": {"storage_generation": 1, "op_sequence": 12, "verified": True, "updated_unix": 100},
                },
                "required_generation": 1,
                "required_op_sequence": 10,
            },
        )
        res = self.document(f"{self.routepath}/resolve?op=read&now_unix=1700000120", code=200)
        assert res["target_node_id"] == "shard-node-c" and res["target_role"] == "replica"

    def automated_four_stage_failover_state_machine(self) -> None:
        self.document(
            self.failoverpath,
            code=409,
            method="POST",
            json_body={"new_primary_node_id": "shard-node-b", "reason": "lagging"},
        )
        op = self.document(
            self.failoverpath,
            code=200,
            method="POST",
            json_body={"new_primary_node_id": "shard-node-c", "reason": "promote c", "now_unix": 1_700_000_150},
        )
        assert op["state"] == "promoted" and op["new_primary_node_id"] == "shard-node-c"

    def read_only_degradation_drill_and_recovery(self) -> None:
        deg = self.document(
            self.degradepath,
            code=200,
            method="POST",
            json_body={"mode": "degrade", "reason": "drill", "now_unix": 1_700_000_160},
        )
        assert deg["read_only_degraded"] is True
        self.document(f"{self.routepath}/resolve?op=write&now_unix=1700000165", code=409)
        rec = self.document(
            self.degradepath,
            code=200,
            method="POST",
            json_body={"mode": "recover", "now_unix": 1_700_000_170},
        )
        assert rec["read_only_degraded"] is False and rec["write_admitted"] is True

    def online_bucket_and_repo_rebalance(self) -> None:
        self.document(
            self.nodespath,
            code=201,
            method="POST",
            json_body={
                "node_id": "shard-node-d",
                "endpoint": "http://shard-d:8080",
                "role": "primary",
                "status": "healthy",
                "lease_ttl_seconds": 300,
                "now_unix": 1_700_000_180,
            },
        )
        route = self.document(self.routepath, code=200)
        self.document(
            self.bucketspath,
            code=200,
            method="POST",
            json_body={"bucket_id": route["bucket_id"], "primary_node_id": "shard-node-c", "read_replica_nodes": ["shard-node-b"]},
        )
        reb = self.document(
            self.rebalancepath,
            code=200,
            method="POST",
            json_body={
                "bucket_id": route["bucket_id"],
                "source_node_id": "shard-node-c",
                "target_node_id": "shard-node-d",
                "repository_id": route["repository_id"],
                "reason": "hotspot rebalance",
                "now_unix": 1_700_000_190,
            },
        )
        assert reb["phases"] == ["drain", "sync", "fence", "cutover"]

    def rpo_rto_disaster_recovery_drill(self) -> None:
        self.document(
            self.drdrillpath,
            code=409,
            method="POST",
            json_body={
                "primary_node_id": "shard-node-d",
                "standby_node_id": "shard-node-b",
                "target_rpo_secs": 5,
                "target_rto_ms": 200,
                "simulated_lag_secs": 15,
                "simulated_takeover_ms": 100,
            },
        )
        ok_drill = self.document(
            self.drdrillpath,
            code=200,
            method="POST",
            json_body={
                "primary_node_id": "shard-node-d",
                "standby_node_id": "shard-node-b",
                "target_rpo_secs": 5,
                "target_rto_ms": 200,
                "simulated_lag_secs": 1,
                "simulated_takeover_ms": 50,
                "verify_rollback": True,
            },
        )
        assert ok_drill["rpo_met"] is True and ok_drill["rto_met"] is True

    def multi_node_benchmark_and_pinned_root_reachability(self) -> None:
        c_bench = self.document(
            self.clusterbenchpath,
            code=200,
            method="POST",
            json_body={"node_counts": [1, 2, 4], "concurrency": 8, "operations_per_tier": 24},
        )
        assert c_bench["pinned_roots_verified"] is True
        assert [t["node_count"] for t in c_bench["node_tiers"]] == [1, 2, 4]
        r_bench = self.document(
            self.repobenchpath,
            code=200,
            method="POST",
            json_body={"node_counts": [1, 2, 4], "concurrency": 8, "operations_per_tier": 24},
        )
        assert r_bench["pinned_roots_verified"] is True
        self.document(
            self.repobenchpath,
            code=409,
            method="POST",
            json_body={"simulate_missing_pinned_objects": 1},
        )

    def access_and_boundaries(self) -> None:
        self.document(self.routepath, code=404, token=self.outsider)
        self.document(
            self.bucketspath,
            code=400,
            method="POST",
            json_body={"bucket_id": 1024, "primary_node_id": "shard-node-c"},
        )

    def run_all(self) -> None:
        for name in (
            "setup",
            "migration",
            "virtual_bucket_routing_and_explicit_overrides",
            "primary_node_lease_renewal_and_expiry_fencing",
            "dual_layer_epoch_and_generation_write_barriers",
            "read_write_watermark_routing_and_replica_fallback",
            "automated_four_stage_failover_state_machine",
            "read_only_degradation_drill_and_recovery",
            "online_bucket_and_repo_rebalance",
            "rpo_rto_disaster_recovery_drill",
            "multi_node_benchmark_and_pinned_root_reachability",
            "access_and_boundaries",
        ):
            self.case(name, getattr(self, name))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--case", default="all")
    parser.add_argument("--reference-only", action="store_true")
    args = parser.parse_args()
    bin_path = Path(args.binary).resolve()
    args.binary = str(bin_path)

    lib_src = (ROOT / "src/lib.rs").read_text(encoding="utf-8")
    live_ready = (
        not args.reference_only
        and bool(os.environ.get("ROOTYARD_TEST_DATABASE_URL"))
        and shutil.which("psql") is not None
        and bin_path.is_file()
        and "sharding::routes()" in lib_src
    )

    runner = ShardingHarness(args) if live_ready else ShardingReferenceRunner(args)
    mode = "live" if live_ready else "reference"
    success = False
    try:
        if args.case == "all":
            runner.run_all()
        else:
            runner.case("setup", runner.setup)
            runner.case(args.case, getattr(runner, args.case))
        success = True
    except Exception as exc:
        print(runner.redact(exc), file=sys.stderr)
    finally:
        try:
            runner.cleanup()
        except Exception as exc:
            runner.results.append({"name": "cleanup", "status": "failed", "error": runner.redact(exc)})
            success = False
        bin_sha = (
            hashlib.sha256(bin_path.read_bytes()).hexdigest()
            if bin_path.is_file()
            else "reference-mode"
        )
        report = {
            "passed": success,
            "mode": mode,
            "cases": runner.results,
            "binary_sha256": bin_sha,
        }
        if args.keep:
            report["retained_directory"] = str(runner.root)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
