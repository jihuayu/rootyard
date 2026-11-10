#!/usr/bin/env python3
"""Issue #8 ref-scale acceptance helper for the native Browse refs endpoint.

``verify_ref_scale(harness)`` runs against the bare repository and HTTP service
a ``tests/browse.py::BrowseHarness`` already created. It packs refs with the
harness Git, snapshots the canonical packed-ref records, and measures:

* a small baseline (the fixture plus synthetic 200-byte tags) and a large
  fixture (the baseline plus exactly 20,000 more 200-byte tags) whose
  ``packed-refs`` is a real file larger than 4 MiB;
* a native bounded-fallback Git scan per size, with record/byte counts, wall
  time and the peak RSS of that isolated Git child only (``wait4``);
* ``/refs?limit=1`` and ``/refs?limit=1&prefix=refs/heads/`` response bytes and
  latency per size while the app runs through a logging ``exec`` wrapper;
* one complete cursor walk at the large size, compared exactly with the
  expected public refs.

The measurements qualify behaviour and resources on this fixture. They do not
claim O(1) work: Git may still scan and sort all refs for every page, including
each repeated cursor page.
"""
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

FALLBACK_ARGS = (
    "for-each-ref",
    "--sort=refname",
    "--format=%(refname)%00%(objectname)%00%(*objectname)",
    "refs/tags",
)
# The endpoint rejects limit > 100.
WALK_PAGE_SIZE = 100
SMALL_TAG_COUNT = 128
LARGE_TAG_COUNT = 20000
TAG_SUFFIX_BYTES = 200
TAG_NAME = "refs/tags/perf-{index:05d}-"
PACKED_HEADER = "# pack-refs with: peeled fully-peeled sorted"
LARGE_PACKED_BYTES_MIN = 4 * 1024 * 1024
# Refreshing /proc costs about one scheduler tick per sample.
RSS_SAMPLE_SECONDS = 0.01
LIMITATION = (
    "Repeated cursor pages can still make total Git work grow with the total ref "
    "count: Git may scan and sort every ref for each page, so this is synthetic "
    "qualification only, not a production-throughput or O(1) claim."
)


def _tag_name(index):
    return TAG_NAME.format(index=index) + "x" * TAG_SUFFIX_BYTES


def _expected_public(records):
    """Browse's public ref set for exact packed-ref records.

    Mirrors the current fixture: heads and tags, names within 1024 bytes,
    never ``refs/rootyard-ci`` or proposal refs. Packed tags are both fixtures'
    only synthetic refs, so this set is exact here.
    """
    names = sorted(name for name, _oid in records)
    assert all(len(name) <= 1024 for name in names), "fixture has refs past the public name limit"
    return sorted(
        name
        for name in names
        if name.startswith(("refs/heads/", "refs/tags/"))
        and not name.startswith(("refs/rootyard-ci/", "refs/heads/rootyard-proposals/"))
        and not name.endswith("/rootyard-proposals")
    )


def _read_records(packed):
    """Canonical ``(name, oid)`` records; headers and peeled lines are dropped."""
    return [
        (line.split(" ", 1)[1], line.split(" ", 1)[0])
        for line in packed.read_text().splitlines()
        if line and not line.startswith(("#", "^"))
    ]


def _packed_bytes(records):
    return (
        PACKED_HEADER + "\n" + "".join(f"{oid} {name}\n" for name, oid in sorted(records))
    ).encode()


def _to_kib(ru_maxrss):
    """``wait4`` reports KB on Linux and bytes on macOS."""
    return int(ru_maxrss if sys.platform == "linux" else ru_maxrss / 1024 + 0.5)


def _read_peak_kib(pid):
    try:
        with open(f"/proc/{pid}/status") as handle:
            for line in handle:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1])
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        pass
    return None


def _native_scan(git, bare):
    """Run the bounded-fallback scan without collecting its output in memory.

    Git runs directly as the measured child: stdout goes to a temporary file, so
    nothing can cut the record/byte counts short, and ``wait4`` reports wall
    time and the peak RSS of that Git process alone (no intermediary whose
    pre-exec high-water mark could be attributed to Git).
    """
    sink = tempfile.TemporaryFile()
    argv = [git, "--git-dir", str(bare), *FALLBACK_ARGS]
    started = time.monotonic()
    child = subprocess.Popen(
        argv,
        env=dict(os.environ, LC_ALL="C"),
        stdin=subprocess.DEVNULL,
        stdout=sink,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        _pid, status, usage = os.wait4(child.pid, 0)
    except BaseException:  # pragma: no cover - only on interruption
        os.killpg(child.pid, 9)
        child.wait()
        raise
    elapsed = time.monotonic() - started
    # wait4 reaped the child, so record its status for Popen bookkeeping.
    child.returncode = os.waitstatus_to_exitcode(status)
    stderr = child.stderr.read()
    child.stderr.close()
    exit_code = child.returncode
    if exit_code != 0:
        raise AssertionError(
            "native fallback Git scan failed (exit {}) after {:.3f}s: {!r}".format(
                exit_code, elapsed, stderr[-512:].decode(errors="replace")
            )
        )
    sink.seek(0)
    lines = 0
    total = 0
    while True:
        chunk = sink.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        lines += chunk.count(b"\n")
    sink.close()
    return {
        "records": lines,
        "bytes": total,
        "wall_seconds": round(elapsed, 4),
        "peak_rss_kib": _to_kib(usage.ru_maxrss),
    }


_WRAPPER = """#!/bin/sh
for arg in "$@"; do
  [ "$arg" = for-each-ref ] && echo start >> {log}
done
exec {git} "$@"
"""


def _install_wrapper(harness, log):
    """Point only ``harness.env`` at a logging exec wrapper; return its path."""
    native = Path(harness.native_git)
    # A bare command (e.g. the "git" fallback) resolves through PATH just as
    # the harness wrapper would; given paths keep their absolute/relative form.
    if not native.is_absolute() and len(native.parts) == 1:
        located = shutil.which(harness.native_git)
        if located is None:
            raise AssertionError("harness native Git command was not found on PATH")
        native = Path(located)
    if native.is_symlink():
        native = Path(os.path.realpath(native))
    native = native.resolve()
    if not native.is_file():
        raise AssertionError("harness native Git is not a regular file")
    wrapper = harness.root / "browse-ref-scale-git-wrapper"
    wrapper.write_text(
        _WRAPPER.format(log=shlex.quote(str(log)), git=shlex.quote(str(native)))
    )
    wrapper.chmod(0o700)
    # Startup canonicalizes ROOTYARD_GIT: a hostile mount could resolve it into
    # the bare repository itself and loop the wrapper back into itself.
    resolved = wrapper.resolve()
    if resolved.is_relative_to(harness.bare.resolve()):
        raise AssertionError("Git wrapper must live outside the fixture repository")
    return resolved


def _starts(log):
    try:
        return sum(1 for line in log.read_text().splitlines() if line == "start")
    except FileNotFoundError:
        return 0


def _request(harness, query):
    """GET one refs page; return (document, status, response bytes, seconds)."""
    path = harness.repo_api("/refs?" + query)
    started = time.perf_counter()
    status, body, _headers = harness.http(path, token=harness.alice)
    elapsed = time.perf_counter() - started
    try:
        document = json.loads(body)
    except ValueError:
        document = None
    return document, status, len(body), elapsed


def _check_page(harness, query, expected_name):
    document, status, size, elapsed = _request(harness, query)
    assert status == 200, f"refs {query}: expected 200, got {status}"
    items = document["items"] if isinstance(document, dict) else []
    names = [item["name"] for item in items]
    assert names == [expected_name], f"refs {query}: expected {expected_name!r}, got {names!r}"
    return {"http_bytes": size, "latency_ms": round(elapsed * 1000, 2)}


def _walk(harness, expected):
    max_pages = 2 * (len(expected) // WALK_PAGE_SIZE + 2)
    collected, page_bytes, max_page_bytes, cursor = [], [], 0, None
    pages = 0
    while True:
        query = f"limit={WALK_PAGE_SIZE}" + (
            f"&after={urllib.parse.quote(cursor, safe='')}" if cursor else ""
        )
        document, status, size, _elapsed = _request(harness, query)
        assert status == 200, f"walk page {pages}: expected 200, got {status}"
        names = [item["name"] for item in document["items"]]
        assert len(names) <= WALK_PAGE_SIZE, f"walk page {pages}: oversized page"
        collected.extend(names)
        page_bytes.append(size)
        max_page_bytes = max(max_page_bytes, size)
        pages += 1
        following = document.get("next_after")
        if following is None:
            break
        assert cursor is None or following > cursor, f"walk cursor did not advance at page {pages}"
        cursor = following
        assert pages <= max_pages, f"walk did not terminate within {max_pages} pages"
    assert collected == sorted(collected), "walk returned refs out of sorted order"
    assert len(collected) == len(set(collected)), "walk returned duplicate refs"
    assert not set(expected) - set(collected), "walk omitted expected refs"
    assert not set(collected) - set(expected), "walk returned unexpected refs"
    assert collected == expected, "walk ref set differs from the fixture"
    return {
        "page_size": WALK_PAGE_SIZE,
        "pages": pages,
        "http_bytes": sum(page_bytes),
        "max_page_bytes": max_page_bytes,
        "refs_returned": len(collected),
    }


def verify_ref_scale(harness):
    """Measure native Browse ref paging at a small and a 20,000-tag size."""
    bare = Path(harness.bare)
    assert bare.is_dir(), "no isolated bare repository"
    git = harness.native_git
    packed = bare / "packed-refs"
    # Prior bytes are only a fallback if packing never yields a baseline; the
    # restore below prefers the complete logical refs that pack-refs --all saw.
    original = packed.read_bytes() if packed.exists() else None
    saved_env = harness.env.get("ROOTYARD_GIT")
    log = harness.root / "browse-ref-scale-for-each-ref.log"
    log.unlink(missing_ok=True)

    def write_packed(records):
        packed.write_bytes(_packed_bytes(records))

    def restore_service_env():
        """Put back the prior ``ROOTYARD_GIT``; the caller restarts the app."""
        harness.stop()
        if saved_env is None:
            harness.env.pop("ROOTYARD_GIT", None)
        else:
            harness.env["ROOTYARD_GIT"] = saved_env

    def pack_and_snapshot():
        # Never remove ``*.lock`` files: they may be live locks. pack-refs --all
        # fails closed on a held lock, and that failure is the correct verdict.
        harness.git("--git-dir=" + str(bare), "pack-refs", "--all")
        assert not any(bare.rglob("*.lock")), "pack-refs left lock files behind"
        return _read_records(packed)

    def git_checks(records, fixture, require_large):
        write_packed(records)
        size = packed.stat().st_size
        if require_large:
            assert size > LARGE_PACKED_BYTES_MIN, (
                f"{fixture}: packed-refs is {size} bytes, not > 4 MiB"
            )
        expected = _expected_public(records)
        native = _native_scan(git, bare)
        # The scan is restricted to refs/tags, so branch refs are not emitted.
        tags = sum(1 for name, _oid in records if name.startswith("refs/tags/"))
        assert native["records"] == tags, (
            f"{fixture}: native records {native['records']} != {tags} refs/tags records"
        )
        return expected, native

    baseline = None
    try:
        baseline = pack_and_snapshot()
        tag_oid = str(harness.third)

        def fixture(count):
            return baseline + [(_tag_name(index), tag_oid) for index in range(count)]

        small_records = fixture(SMALL_TAG_COUNT)
        large_records = fixture(LARGE_TAG_COUNT)
        heads = sorted(name for name, _oid in baseline if name.startswith("refs/heads/"))
        assert heads, "fixture has no main/heads ref"
        expected_large = _expected_public(large_records)
        # Every ref in these fixtures is public, so the walk must see all of them.
        assert len(expected_large) == len(large_records) == len(set(expected_large))

        _expected_small, small_native = git_checks(small_records, "small", require_large=False)
        _expected, large_native = git_checks(large_records, "large", require_large=True)
        assert packed.stat().st_size > LARGE_PACKED_BYTES_MIN, "large packed-refs is not > 4 MiB"

        wrapper = _install_wrapper(harness, log)
        try:
            harness.stop()
            harness.env["ROOTYARD_GIT"] = str(wrapper)
            harness.start()
            assert _read_peak_kib(os.getpid()) is not None, "Linux /proc VmHWM required for RSS"

            before = _starts(log)
            write_packed(small_records)
            small_all = _check_page(harness, "limit=1", heads[0])
            small_heads = _check_page(harness, "limit=1&prefix=refs/heads/", heads[0])
            small_starts = _starts(log) - before

            before = _starts(log)
            write_packed(large_records)
            large_all = _check_page(harness, "limit=1", heads[0])
            large_heads = _check_page(harness, "limit=1&prefix=refs/heads/", heads[0])
            large_starts = _starts(log) - before
            before = _starts(log)
            walk = _walk(harness, large_expected)
            walk_starts = _starts(log) - before
            assert walk_starts > 0, "walk never started for-each-ref through the wrapper"
        finally:
            restore_service_env()

        return {
            "fixture": {
                "baseline_refs": len(baseline),
                "small_synthetic_tags": SMALL_TAG_COUNT,
                "large_synthetic_tags": LARGE_TAG_COUNT,
                "tag_name_bytes": len(_tag_name(0)),
                "small_total_refs": len(small_records),
                "large_total_refs": len(large_records),
                "small_packed_refs_bytes": len(_packed_bytes(small_records)),
                "large_packed_refs_bytes": len(_packed_bytes(large_records)),
            },
            "native_fallback": {"small": small_native, "large": large_native},
            "http_limit_1": {
                "small": {"all": small_all, "heads": small_heads},
                "large": {"all": large_all, "heads": large_heads},
            },
            "for_each_ref_process_starts": {
                "small": small_starts,
                "large": large_starts,
                "walk": walk_starts,
            },
            "full_walk": walk,
            "limitation": LIMITATION,
        }
    finally:
        try:
            restore_service_env()
        finally:
            if baseline is None:
                # pack-refs never succeeded: no logical snapshot exists.
                if original is None:
                    packed.unlink(missing_ok=True)
                else:
                    packed.write_bytes(original)
            else:
                # bare, loose or already packed refs are all on disk before the
                # app is restarted, so no logical ref is dropped.
                write_packed(baseline)
            harness.start()
            if baseline is not None:
                assert _read_records(packed) == baseline, "packed refs were not restored"
