"""Offline structural and protocol contracts for Issue #85 repository lifecycle."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
REPO_ENTRY = ROOT / "src" / "repositories.rs"
REPO_DIR = ROOT / "src" / "repositories"
LIFECYCLE_DOC = ROOT / "docs" / "repository-lifecycle.md"
ORGS_DOC = ROOT / "docs" / "organizations.md"


def _find_git_http_backend() -> str | None:
    git_bin = shutil.which("git")
    if not git_bin:
        return None
    proc = subprocess.run([git_bin, "--exec-path"], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return None
    exec_dir = Path(proc.stdout.strip())
    for name in ("git-http-backend.exe", "git-http-backend"):
        candidate = exec_dir / name
        if candidate.is_file():
            return str(candidate)
    return None


class RepositoryLifecycleContractsTest(unittest.TestCase):
    def test_repository_module_boundaries_and_serde_guards(self):
        self.assertTrue(REPO_ENTRY.is_file())
        self.assertFalse((REPO_DIR / "mod.rs").exists(), "mod.rs forbidden in src/repositories/")
        entry_lines = REPO_ENTRY.read_text(encoding="utf-8").splitlines()
        self.assertLess(
            len(entry_lines),
            100,
            f"src/repositories.rs exceeded 100 lines: {len(entry_lines)}",
        )
        entry_text = "\n".join(entry_lines)
        self.assertNotIn("Command::new", entry_text)

        for required in ("lifecycle.rs", "alias.rs", "transfer_model.rs", "purge_safety.rs", "handlers.rs"):
            self.assertTrue((REPO_DIR / required).is_file(), f"missing submodule {required}")

        for path in sorted(REPO_DIR.glob("*.rs")):
            text = path.read_text(encoding="utf-8")
            lines = text.splitlines()
            self.assertLess(len(lines), 500, f"{path} exceeded 500 lines: {len(lines)}")
            self.assertNotIn("#[allow(", text, f"{path} must not suppress lints with #[allow(...)]")
            self.assertNotIn("Command::new", text, f"{path} must not shell out with Command::new")
            for match in re.finditer(
                r"#\[derive\([^]]*Deserialize[^]]*\)\](?:\s*#\[[^\]]*\])*\s*(?:pub(?:\([^)]*\))?\s+)?struct\b",
                text,
            ):
                block = match.group(0)
                self.assertIn(
                    "#[serde(deny_unknown_fields)]",
                    block,
                    f"missing #[serde(deny_unknown_fields)] in {path}:\n{block}",
                )

        lifecycle_text = (REPO_DIR / "lifecycle.rs").read_text(encoding="utf-8")
        self.assertIn("enum LifecycleAction", lifecycle_text)
        alias_text = (REPO_DIR / "alias.rs").read_text(encoding="utf-8")
        self.assertIn("fn permanent_redirect_response", alias_text)
        transfer_text = (REPO_DIR / "transfer_model.rs").read_text(encoding="utf-8")
        self.assertIn("enum TransferPhase", transfer_text)
        purge_text = (REPO_DIR / "purge_safety.rs").read_text(encoding="utf-8")
        self.assertIn("enum PurgeHoldKind", purge_text)

    def test_docs_cover_lifecycle_and_transfer_contracts(self):
        self.assertTrue(LIFECYCLE_DOC.is_file())
        self.assertTrue(ORGS_DOC.is_file())
        doc_text = LIFECYCLE_DOC.read_text(encoding="utf-8")
        for marker in (
            "308 Permanent Redirect",
            "Cache-Control: no-store",
            "copying_remote",
            "rekeying_db",
            "revoking_legacy",
            "pando_retention_roots",
            "403 Forbidden",
            "404",
            "409",
        ):
            self.assertIn(marker, doc_text, f"missing contract marker {marker!r} in docs/repository-lifecycle.md")
        org_text = ORGS_DOC.read_text(encoding="utf-8")
        self.assertIn("repository-lifecycle.md", org_text)

    def test_git_cli_follows_308_redirect_and_authz_precedes_redirect(self):
        backend = _find_git_http_backend()
        git_bin = shutil.which("git")
        if not git_bin or not backend:
            self.skipTest("git or git-http-backend not available on PATH")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bare_dir = tmp_path / "repos" / "repo.git"
            bare_dir.parent.mkdir(parents=True)
            subprocess.run([git_bin, "init", "--bare", "--initial-branch=main", str(bare_dir)], check=True, capture_output=True)
            subprocess.run([git_bin, "-C", str(bare_dir), "config", "http.receivepack", "true"], check=True)

            seed_dir = tmp_path / "seed"
            subprocess.run([git_bin, "clone", str(bare_dir), str(seed_dir)], check=True, capture_output=True)
            subprocess.run([git_bin, "-C", str(seed_dir), "config", "user.name", "Contract Test"], check=True)
            subprocess.run([git_bin, "-C", str(seed_dir), "config", "user.email", "contract@example.test"], check=True)
            subprocess.run([git_bin, "-C", str(seed_dir), "config", "commit.gpgsign", "false"], check=True)
            subprocess.run([git_bin, "-C", str(seed_dir), "config", "tag.gpgsign", "false"], check=True)
            (seed_dir / "README.md").write_text("initial\n", encoding="utf-8")
            subprocess.run([git_bin, "-C", str(seed_dir), "add", "README.md"], check=True)
            subprocess.run([git_bin, "-C", str(seed_dir), "commit", "-m", "init"], check=True, capture_output=True)
            subprocess.run([git_bin, "-C", str(seed_dir), "push", "origin", "main"], check=True, capture_output=True)

            repos_root = str(tmp_path / "repos")
            redirect_hits: list[str] = []

            class AliasHandler(BaseHTTPRequestHandler):
                def log_message(self, format, *args):
                    return

                def _handle(self, method: str):
                    if self.headers.get("X-Deny-Private") == "1":
                        self.send_response(404)
                        self.end_headers()
                        return
                    if self.path.startswith("/old-org/legacy.git"):
                        suffix = self.path[len("/old-org/legacy.git") :]
                        target = f"/new-org/renamed.git{suffix}"
                        redirect_hits.append(f"{method} {self.path} -> {target}")
                        self.send_response(308)
                        self.send_header("Location", target)
                        self.send_header("Cache-Control", "no-store")
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    if self.path.startswith("/new-org/renamed.git"):
                        path_info = "/repo.git" + self.path[len("/new-org/renamed.git") :]
                        if "?" in path_info:
                            path_info, query = path_info.split("?", 1)
                        else:
                            query = ""
                        length = int(self.headers.get("Content-Length", "0") or "0")
                        body = self.rfile.read(length) if length > 0 else b""
                        env = os.environ.copy()
                        env.update(
                            {
                                "GIT_PROJECT_ROOT": repos_root,
                                "GIT_HTTP_EXPORT_ALL": "1",
                                "REQUEST_METHOD": method,
                                "PATH_INFO": path_info,
                                "QUERY_STRING": query,
                                "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                                "CONTENT_LENGTH": str(len(body)),
                                "REMOTE_USER": "contract-user",
                            }
                        )
                        proc = subprocess.run([backend], input=body, env=env, capture_output=True, check=False)
                        raw = proc.stdout
                        sep = b"\r\n\r\n" if b"\r\n\r\n" in raw else b"\n\n"
                        head_bytes, payload = raw.split(sep, 1)
                        status_code = 200
                        hdrs: list[tuple[str, str]] = []
                        for line in head_bytes.decode("latin1").splitlines():
                            k, v = line.split(":", 1)
                            if k.lower() == "status":
                                status_code = int(v.strip().split()[0])
                            else:
                                hdrs.append((k.strip(), v.strip()))
                        self.send_response(status_code)
                        for k, v in hdrs:
                            self.send_header(k, v)
                        self.end_headers()
                        self.wfile.write(payload)
                        return
                    self.send_response(404)
                    self.end_headers()

                def do_GET(self):
                    self._handle("GET")

                def do_POST(self):
                    self._handle("POST")

            server = ThreadingHTTPServer(("127.0.0.1", 0), AliasHandler)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                # Unauthorized access must return 404 WITHOUT Location header.
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/old-org/legacy.git/info/refs?service=git-upload-pack",
                    headers={"X-Deny-Private": "1"},
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(req)
                self.assertEqual(ctx.exception.code, 404)
                self.assertIsNone(ctx.exception.headers.get("Location"))

                clone_dir = tmp_path / "clone"
                clone_proc = subprocess.run(
                    [git_bin, "clone", f"http://127.0.0.1:{port}/old-org/legacy.git", str(clone_dir)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(clone_proc.returncode, 0, clone_proc.stderr)
                self.assertIn("redirecting to", clone_proc.stderr)
                self.assertIn("/new-org/renamed.git/", clone_proc.stderr)

                subprocess.run([git_bin, "-C", str(clone_dir), "config", "user.name", "Contract Test"], check=True)
                subprocess.run([git_bin, "-C", str(clone_dir), "config", "user.email", "contract@example.test"], check=True)
                subprocess.run([git_bin, "-C", str(clone_dir), "config", "commit.gpgsign", "false"], check=True)
                subprocess.run([git_bin, "-C", str(clone_dir), "config", "tag.gpgsign", "false"], check=True)
                (clone_dir / "README.md").write_text("after rename push\n", encoding="utf-8")
                subprocess.run([git_bin, "-C", str(clone_dir), "add", "README.md"], check=True)
                subprocess.run([git_bin, "-C", str(clone_dir), "commit", "-m", "push via alias"], check=True, capture_output=True)
                push_proc = subprocess.run(
                    [git_bin, "-C", str(clone_dir), "push", "origin", "main"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(push_proc.returncode, 0, push_proc.stderr)
                self.assertIn("redirecting to", push_proc.stderr)

                fetch_proc = subprocess.run(
                    [git_bin, "-C", str(seed_dir), "remote", "set-url", "origin", f"http://127.0.0.1:{port}/old-org/legacy.git"],
                    check=True,
                )
                self.assertEqual(fetch_proc.returncode, 0)
                pull_proc = subprocess.run(
                    [git_bin, "-C", str(seed_dir), "fetch", "origin", "main"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(pull_proc.returncode, 0, pull_proc.stderr)
                self.assertGreaterEqual(len(redirect_hits), 3)
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
