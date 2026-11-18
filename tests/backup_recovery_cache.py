"""Owned Redis and build evidence for the browse restore recovery case."""
import hashlib
from pathlib import Path
import re
import socket
import subprocess
import time
import uuid

from cross_process import CrossProcessHarness
from native_evidence import ROOT, receipts


CASE = "browse_restore_incarnation_cache"
ENVIRONMENT = "backup-recovery"
TTL_SECONDS = 1800
HIT = (1, 1, 0)
MISS = (1, 0, 1)
COMMANDS = (b"strlen", b"getrange", b"set")
BUILD_COMMAND = [
    "cargo", "build", "--locked", "--bin", "rootyard", "--features", "state-redis",
    "--config", 'profile.dev.package.rootyard.strip="debuginfo"',
    "--message-format=json-render-diagnostics",
]


def build_binding(binary, expected_commit):
    def git(*args):
        return subprocess.check_output(
            ["git", *args], cwd=ROOT, stderr=subprocess.DEVNULL, text=True, timeout=5,
        ).strip()

    assert re.fullmatch(r"[0-9a-f]{40}", expected_commit or ""), "Exact commit required"
    assert git("rev-parse", "HEAD") == expected_commit
    tree = git("rev-parse", "HEAD^{tree}")
    assert not git("status", "--porcelain", "--untracked-files=no")
    receipt_path = Path(binary + ".build.json")
    assert receipt_path.is_file() and not receipt_path.is_symlink()
    receipt = receipts.load_receipt(
        receipt_path, source_root=ROOT, binary_path=binary, expected_commit=expected_commit,
        expected_profile="dev", expected_command=BUILD_COMMAND, forbid_implicit_build=True,
    )
    payload = receipt.payload
    assert receipt.schema == "v2" and payload.get("kind") == "native-binary"
    assert payload.get("git_head") == expected_commit
    assert payload.get("working_tree") == dict(tree=tree, status="")
    assert payload.get("features") == dict(enabled=["state-redis"], no_default_features=False)
    return dict(
        source_head=receipt.workspace_commit,
        source_tree=tree,
        source_inputs_sha256=receipt.source_inputs_sha256,
        binary_sha256=receipt.binary_sha256,
        build_receipt_sha256=receipt.receipt_sha256,
    )


class OwnedRestoreRedis:
    redis_command = CrossProcessHarness.redis_command

    def __init__(self, binary):
        self.binary = binary
        self.process = None

    def start(self, root):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.redis_port = listener.getsockname()[1]
        self.process = subprocess.Popen(
            [self.binary, "--bind", "127.0.0.1", "--port", str(self.redis_port),
             "--save", "", "--appendonly", "no", "--protected-mode", "yes",
             "--maxmemory", "16mb", "--maxmemory-policy", "allkeys-lru", "--dir", str(root)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
            env={"LC_ALL": "C"},
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                self.run_id = self.identity()
                return
            except OSError:
                time.sleep(0.05)
        raise AssertionError("Owned Redis readiness timed out")

    def identity(self):
        assert self.process.poll() is None, "Owned Redis process exited"
        fields = dict(line.split(b":", 1) for line in self.redis_command("INFO", "server").splitlines()
                      if b":" in line)
        assert int(fields[b"process_id"]) == self.process.pid, "Redis PID differs from owned process"
        run_id = fields[b"run_id"]
        assert re.fullmatch(rb"[0-9a-f]{40}", run_id), "Redis run ID missing"
        return run_id

    def keys(self):
        return set(self.redis_command("KEYS", "*"))

    def entry(self, key):
        ttl = self.redis_command("PTTL", key)
        assert 0 < ttl <= TTL_SECONDS * 1000, "Redis entry missing or outside the TTL bound"
        raw = self.redis_command("GET", key)
        assert isinstance(raw, bytes) and raw, "Redis entry missing a cached value"
        return ttl, hashlib.sha256(raw).digest()

    def counts(self):
        raw = self.redis_command("INFO", "commandstats")
        assert raw.startswith(b"# Commandstats"), "Redis command counters missing"
        calls = dict(re.findall(rb"^cmdstat_([^:]+):calls=(\d+),", raw, re.MULTILINE))
        assert not any(int(calls.get(command, b"0")) for command in (b"flushall", b"flushdb")), "Redis was flushed"
        return tuple(int(calls.get(command, b"0")) for command in COMMANDS)

    def stop(self):
        CrossProcessHarness.stop_process(self.process)
        assert self.process is None or self.process.poll() is not None, "Owned Redis did not exit"


def preview_request(redis, fetch, expected):
    before = redis.counts()
    response = fetch()
    delta = tuple(after - start for after, start in zip(redis.counts(), before, strict=True))
    assert delta == expected, "Unexpected Redis command counts for the preview request"
    return response


def preview_key_scope(key):
    parts = key.decode("ascii").split(":")
    assert len(parts) == 12 and parts[:3] == ["ry", "cache", "v2"]
    assert parts[3:6] == [ENVIRONMENT, "gitfs", "1"]
    incarnation = uuid.UUID(parts[6])
    assert incarnation.int and str(incarnation) == parts[6]
    assert parts[9:11] == ["git-object-preview", "2"]
    assert re.fullmatch(r"[0-9a-f]{16}", parts[11])
    return parts[:6] + parts[7:]


def prove_restored_preview(redis, fetch, old_key, old_entry, old_response):
    def retained():
        ttl, digest = redis.entry(old_key)
        assert ttl <= old_entry[0] and digest == old_entry[1], "Pre-restore Redis entry changed"

    assert redis.identity() == redis.run_id, "Redis process identity changed"
    assert redis.keys() == {old_key}, "Pre-restore key inventory was not retained"
    retained()
    assert preview_request(redis, fetch, MISS) == old_response, "Restored origin preview differs"
    keys = redis.keys()
    assert old_key in keys and len(keys) == 2, "Restored request did not refill a distinct key"
    new_key, = keys - {old_key}
    assert preview_key_scope(new_key) == preview_key_scope(old_key), "Non-incarnation cache scope changed"
    redis.entry(new_key)
    assert preview_request(redis, fetch, HIT) == old_response, "Restored warm preview differs"
    assert redis.keys() == keys, "Warm request changed the Redis key inventory"
    assert redis.identity() == redis.run_id, "Redis process identity changed"
    retained()
    return dict(
        redis_instance_preserved=True, original_key_retained=True, only_incarnation_changed=True,
        restored_origin_miss_and_refill=True, restored_repeat_hit=True,
    )
