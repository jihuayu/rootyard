#!/usr/bin/env python3
"""Unit and integration test suite for rootyard-view-lab decomposition, F44 history projection, and F45 provenance."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "target" / "debug" / "rootyard-view-lab"


class ViewLabDecompositionAndSemanticsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BINARY.is_file():
            env = dict(os.environ)
            env["PATH"] = f"{Path.home() / '.cargo' / 'bin'}:{env.get('PATH', '')}"
            subprocess.run(
                ["cargo", "build", "--locked", "--bin", "rootyard-view-lab"],
                cwd=ROOT,
                env=env,
                check=True,
            )
        git_bin = shutil.which(os.environ.get("ROOTYARD_VIEW_GIT", "git"))
        assert git_bin is not None, "git executable required"
        cls.git_binary = str(Path(git_bin).resolve())

    def setUp(self):
        self.tempdir = Path(tempfile.mkdtemp(prefix="rootyard-view-lab-unit-"))
        self.env = dict(os.environ)
        for key in list(self.env):
            if key.startswith("GIT_") or key.startswith("ROOTYARD_VIEW_"):
                self.env.pop(key)
        (self.tempdir / "home").mkdir()
        (self.tempdir / "xdg").mkdir()
        self.env.update({
            "HOME": str(self.tempdir / "home"),
            "XDG_CONFIG_HOME": str(self.tempdir / "xdg"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
            "ROOTYARD_VIEW_GIT": self.git_binary,
        })

    def tearDown(self):
        shutil.rmtree(self.tempdir, ignore_errors=True)

    def git(self, *args, cwd=None, check=True):
        return subprocess.run(
            [
                self.git_binary,
                "-c",
                "user.name=View Lab Unit",
                "-c",
                "user.email=unit@example.invalid",
                "-c",
                "gc.auto=0",
                "-c",
                "maintenance.auto=false",
                *[os.fspath(a) for a in args],
            ],
            cwd=cwd,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=check,
        )

    def lab(self, *args, check=True):
        return subprocess.run(
            [os.fspath(BINARY), *[os.fspath(a) for a in args]],
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=check,
        )

    def lab_json(self, *args):
        res = self.lab(*args, check=True)
        return json.loads(res.stdout.decode())

    def test_module_decomposition_and_line_caps(self):
        facade = ROOT / "src" / "view_lab.rs"
        self.assertTrue(facade.is_file(), "src/view_lab.rs must exist as a regular file")
        self.assertFalse(
            (ROOT / "src" / "view_lab" / "mod.rs").exists(),
            "src/view_lab/mod.rs must not exist",
        )
        facade_text = facade.read_text(encoding="utf-8")
        facade_lines = facade_text.splitlines()
        self.assertLess(
            len(facade_lines),
            120,
            f"src/view_lab.rs must be < 120 lines, got {len(facade_lines)}",
        )
        self.assertNotIn("Command::new", facade_text)
        for sql_kw in ("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "CREATE TABLE"):
            self.assertNotIn(sql_kw, facade_text)

        submodules = ["models.rs", "namespace.rs", "projection.rs", "changeset.rs"]
        for name in submodules:
            path = ROOT / "src" / "view_lab" / name
            self.assertTrue(path.is_file(), f"Missing submodule {path}")
            line_count = len(path.read_text(encoding="utf-8").splitlines())
            self.assertLess(
                line_count,
                500,
                f"src/view_lab/{name} must be < 500 lines, got {line_count}",
            )

        models_text = (ROOT / "src" / "view_lab" / "models.rs").read_text(encoding="utf-8")
        for struct_name in (
            "EpochCommitMap",
            "ProvenanceCommitRecord",
            "ViewProvenanceManifest",
        ):
            self.assertIn(f"pub struct {struct_name}", models_text)
        self.assertGreaterEqual(models_text.count("#[serde(deny_unknown_fields)]"), 9)

    def test_f44_history_strategies_and_incremental_epoch_map(self):
        store = self.tempdir / "store"
        repo = self.tempdir / "src-repo"
        repo.mkdir()
        self.git("init", "--initial-branch=main", cwd=repo)
        (repo / "pkg" / "core").mkdir(parents=True)
        (repo / "pkg" / "core" / "lib.rs").write_text("pub fn v1() {}\n")
        (repo / "README.md").write_text("root readme v1\n")
        self.git("add", ".", cwd=repo)
        self.git("commit", "-m", "c1: initial", cwd=repo)
        c1 = self.git("rev-parse", "HEAD", cwd=repo).stdout.decode().strip()

        # Unrelated root commit (should be folded in pkg/core projection).
        (repo / "README.md").write_text("root readme v2\n")
        self.git("add", "README.md", cwd=repo)
        self.git("commit", "-m", "c2: root readme only", cwd=repo)
        c2 = self.git("rev-parse", "HEAD", cwd=repo).stdout.decode().strip()

        # Subdir modification.
        (repo / "pkg" / "core" / "lib.rs").write_text("pub fn v2() {}\n")
        self.git("add", "pkg/core/lib.rs", cwd=repo)
        self.git("commit", "-m", "c3: core v2", cwd=repo)
        c3 = self.git("rev-parse", "HEAD", cwd=repo).stdout.decode().strip()

        self.lab_json("register-repo", store, "core-repo", repo, "--quiescent")

        e1 = self.lab_json(
            "project-history",
            store,
            "core-hist",
            "core-repo",
            "--strategy",
            "deterministic_history",
            "--subdir",
            "pkg/core",
        )
        self.assertEqual(e1["view_epoch"], 1)
        self.assertEqual(e1["projected_commits"], 2)
        self.assertEqual(e1["rewritten_history_commits"], 2)
        self.assertEqual(e1["commit_map"][c1], e1["commit_map"][c2])
        self.assertNotEqual(e1["commit_map"][c2], e1["commit_map"][c3])

        # Advance repo and project epoch 2.
        (repo / "pkg" / "core" / "lib.rs").write_text("pub fn v3() {}\n")
        self.git("add", "pkg/core/lib.rs", cwd=repo)
        self.git("commit", "-m", "c4: core v3", cwd=repo)
        c4 = self.git("rev-parse", "HEAD", cwd=repo).stdout.decode().strip()
        self.lab_json("advance-repo", store, "core-repo", repo, "--quiescent")

        e2 = self.lab_json(
            "project-history",
            store,
            "core-hist",
            "core-repo",
            "--strategy",
            "deterministic_history",
            "--subdir",
            "pkg/core",
        )
        self.assertEqual(e2["view_epoch"], 2)
        self.assertEqual(e2["newly_projected_commits"], 1)
        self.assertEqual(e2["reused_epoch_commits"], 3)
        self.assertEqual(e2["commit_map"][c1], e1["commit_map"][c1])
        self.assertEqual(e2["commit_map"][c3], e1["commit_map"][c3])
        self.assertNotEqual(e2["commit_map"][c4], e1["commit_map"][c3])

        epoch_map_path = store / "views" / e2["view_id"] / "epoch_commit_map.json"
        epoch_map = json.loads(epoch_map_path.read_text(encoding="utf-8"))
        self.assertEqual(epoch_map["view_epoch"], 2)
        self.assertIn("1", epoch_map["epochs"])
        self.assertIn("2", epoch_map["epochs"])
        self.assertEqual(epoch_map["epochs"]["1"][c3], epoch_map["epochs"]["2"][c3])

    def test_f45_signature_provenance_and_tamper_rejection(self):
        store = self.tempdir / "store"
        repo = self.tempdir / "signed-repo"
        repo.mkdir()
        self.git("init", "--initial-branch=main", cwd=repo)
        (repo / "app").mkdir()
        (repo / "app" / "main.rs").write_text("fn main() {}\n")
        self.git("add", ".", cwd=repo)
        self.git("commit", "-m", "signed commit", cwd=repo)

        raw = self.git("cat-file", "commit", "HEAD", cwd=repo).stdout.decode()
        hdr, body = raw.split("\n\n", 1)
        signed_commit = (
            f"{hdr}\n"
            "gpgsig -----BEGIN SSH SIGNATURE-----\n"
            " U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg\n"
            " -----END SSH SIGNATURE-----\n\n"
            f"{body}"
        ).encode()
        oid = (
            subprocess.run(
                [self.git_binary, "hash-object", "-t", "commit", "-w", "--stdin"],
                cwd=repo,
                env=self.env,
                input=signed_commit,
                stdout=subprocess.PIPE,
                check=True,
            )
            .stdout.decode()
            .strip()
        )
        self.git("reset", "--hard", oid, cwd=repo)

        self.lab_json("register-repo", store, "signed", repo, "--quiescent")
        view = self.lab_json(
            "project-history",
            store,
            "app-view",
            "signed",
            "--strategy",
            "deterministic_history",
            "--subdir",
            "app",
        )
        self.assertEqual(view["source_signed_commits"], 1)

        prov_path = store / "views" / view["view_id"] / "provenance.json"
        prov = json.loads(prov_path.read_text(encoding="utf-8"))
        self.assertEqual(len(prov["commits"]), 1)
        rec = prov["commits"][0]
        self.assertTrue(rec["source_signed"])
        self.assertEqual(rec["source_signature_type"], "ssh")
        self.assertFalse(rec["original_signature_covers_projected_oid"])
        self.assertTrue(rec["platform_signature"].startswith("hmac-sha256:rootyard-local-v1:"))

        ver = self.lab_json("verify-view", store, view["view_id"])
        self.assertTrue(ver["signature_verified"])
        self.assertEqual(ver["tampered_commits"], [])

        # Corrupt platform_signature in provenance.json and verify fail-closed behavior.
        prov["commits"][0]["platform_signature"] = "hmac-sha256:rootyard-local-v1:" + ("0" * 64)
        prov_path.write_text(json.dumps(prov, indent=2) + "\n", encoding="utf-8")
        bad = self.lab("verify-view", store, view["view_id"], check=False)
        self.assertNotEqual(bad.returncode, 0)
        bad_report = json.loads(bad.stdout.decode())
        self.assertFalse(bad_report["signature_verified"])
        self.assertIn(view["projected_head_oid"], bad_report["tampered_commits"])

        # Verify deny_unknown_fields rejects unknown JSON keys on provenance.json.
        prov["unexpected_field"] = True
        prov_path.write_text(json.dumps(prov, indent=2) + "\n", encoding="utf-8")
        unknown_res = self.lab("verify-view", store, view["view_id"], check=False)
        self.assertNotEqual(unknown_res.returncode, 0)


if __name__ == "__main__":
    unittest.main()
