#!/usr/bin/env python3
"""Offline unit, white-box static contract, and loopback HTTP security tests for
Part II Track 1: Web UI & Frontend Security Rendering (`F33` & `F34`).
"""
from __future__ import annotations

import ast
from pathlib import Path
import re
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_tier5_adversarial as t5  # noqa: E402
import web  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


class WebTrack1ContractTest(unittest.TestCase):
    def test_web_module_layout_and_anti_monolith_bounds(self) -> None:
        web_rs = ROOT / "src/web.rs"
        self.assertTrue(web_rs.is_file(), "src/web.rs must be a regular file")
        self.assertFalse(
            (ROOT / "src/web/mod.rs").exists(),
            "src/web/mod.rs must never exist (Rust 2024 module layout)",
        )
        web_src = web_rs.read_text(encoding="utf-8")
        web_lines = web_src.splitlines()
        self.assertLess(
            len(web_lines),
            100,
            f"src/web.rs must remain < 100 lines, got {len(web_lines)}",
        )
        self.assertIn("pub fn routes() -> Router<Arc<AppState>>", web_src)

        for sql_kw in ("SELECT ", "INSERT ", "UPDATE ", "DELETE "):
            self.assertNotIn(
                sql_kw, web_src, f"src/web.rs must not embed inline SQL ({sql_kw})"
            )
        self.assertNotIn("Command::new", web_src)
        self.assertNotIn("/:", web_src)
        self.assertNotIn("/*", web_src)
        self.assertNotIn("{*", web_src)

        for sub in ("models", "sanitize", "templates", "handlers"):
            self.assertIn(f"pub mod {sub};", web_src)
            sub_path = ROOT / "src/web" / f"{sub}.rs"
            self.assertTrue(sub_path.is_file(), f"Missing submodule {sub_path}")
            sub_text = sub_path.read_text(encoding="utf-8")
            sub_lines = sub_text.splitlines()
            self.assertGreater(
                len(sub_lines),
                50,
                f"src/web/{sub}.rs is unexpectedly small ({len(sub_lines)} lines)",
            )
            self.assertLess(
                len(sub_lines),
                550,
                f"src/web/{sub}.rs exceeds 550-line anti-monolith bound ({len(sub_lines)} lines)",
            )
            self.assertNotIn(
                ".route(",
                sub_text,
                f"src/web/{sub}.rs must not contain '.route(' (only src/web.rs registers routes)",
            )

    def test_web_routes_have_zero_wildcards_zero_collisions_and_consistent_matchit_params(
        self,
    ) -> None:
        web_rs = ROOT / "src/web.rs"
        web_src = web_rs.read_text(encoding="utf-8")
        regs = t5._extract_route_registrations(web_rs)
        self.assertEqual(len(regs), 38, f"Expected 38 route registrations (19 /web + 19 /ui), got {len(regs)}")

        # Verify e2e_tiers route_block_re matches every route in src/web.rs
        route_block_re = re.compile(
            r'\.route\(\s*"([^"]+)"\s*,([^;]+?)\)\s*(?=\.route\(|\.layer\(|\.with_state\(|;|\n\})',
            re.DOTALL,
        )
        block_matches = route_block_re.findall(web_src)
        self.assertEqual(len(block_matches), len(regs))

        # Check non-collision against all existing primary routers
        seen_bindings: dict[tuple[str, str], tuple[str, str]] = {}
        all_router_files = list(dict.fromkeys((*t5.TestTier5RouterAndParameterNonCollision.ALL_PRIMARY_ROUTER_FILES, "src/web.rs")))
        param_by_prefix: dict[tuple[str, ...], tuple[str, str, str]] = {}

        for rel in all_router_files:
            for raw_path, methods in t5._extract_route_registrations(ROOT / rel):
                self.assertTrue(raw_path.startswith("/"))
                self.assertNotIn("/:", raw_path)
                self.assertNotIn("/*", raw_path)
                if rel == "src/web.rs":
                    self.assertNotIn("{*", raw_path)
                norm = t5._normalize_route_pattern(raw_path)
                for method in methods:
                    key = (norm, method)
                    self.assertNotIn(
                        key,
                        seen_bindings,
                        f"Route collision on {key}: {rel} ({raw_path}) vs {seen_bindings.get(key)}",
                    )
                    seen_bindings[key] = (rel, raw_path)

                segments = [s for s in raw_path.strip("/").split("/") if s]
                norm_prefix: list[str] = []
                for seg in segments:
                    if seg.startswith("{") and seg.endswith("}"):
                        pkey = tuple(norm_prefix)
                        if pkey in param_by_prefix:
                            prev_seg, prev_file, prev_path = param_by_prefix[pkey]
                            self.assertEqual(
                                seg,
                                prev_seg,
                                f"Matchit param conflict at /{ '/'.join(norm_prefix) }: {seg} in {rel} vs {prev_seg} in {prev_file} ({prev_path})",
                            )
                        else:
                            param_by_prefix[pkey] = (seg, rel, raw_path)
                        norm_prefix.append("{*}" if seg.startswith("{*") else "{}")
                    else:
                        norm_prefix.append(seg)

        for prefix_root in ("web", "ui"):
            self.assertEqual(param_by_prefix[(prefix_root, "repos")][0], "{owner}")
            self.assertEqual(param_by_prefix[(prefix_root, "repos", "{}")][0], "{name}")
            self.assertEqual(param_by_prefix[(prefix_root, "repos", "{}", "{}", "tree")][0], "{oid}")
            self.assertEqual(param_by_prefix[(prefix_root, "repos", "{}", "{}", "blob")][0], "{oid}")
            self.assertEqual(param_by_prefix[(prefix_root, "repos", "{}", "{}", "commits")][0], "{oid}")
            self.assertEqual(param_by_prefix[(prefix_root, "repos", "{}", "{}", "issues")][0], "{number}")
            self.assertEqual(param_by_prefix[(prefix_root, "repos", "{}", "{}", "pulls")][0], "{number}")

    def test_rust_source_invariants_serde_auth_rbac_and_security_headers(self) -> None:
        models_src = (ROOT / "src/web/models.rs").read_text(encoding="utf-8")
        sanitize_src = (ROOT / "src/web/sanitize.rs").read_text(encoding="utf-8")
        templates_src = (ROOT / "src/web/templates.rs").read_text(encoding="utf-8")
        handlers_src = (ROOT / "src/web/handlers.rs").read_text(encoding="utf-8")

        self.assertGreaterEqual(models_src.count("#[serde(deny_unknown_fields)]"), 10)
        self.assertIn("#[cfg(test)]", models_src)
        self.assertIn("#[cfg(test)]", sanitize_src)
        self.assertIn("#[cfg(test)]", templates_src)

        for tok in (
            "CSP_HEADER_VALUE",
            "default-src 'none'",
            "X_CONTENT_TYPE_OPTIONS",
            '"nosniff"',
            "X_FRAME_OPTIONS",
            '"DENY"',
            "REFERRER_POLICY",
            '"no-referrer"',
            "CACHE_CONTROL",
            '"no-store"',
        ):
            self.assertIn(tok, templates_src, f"Missing {tok} in src/web/templates.rs")

        for h_tok in (
            "auth::authenticate",
            "auth::authorize_repo_with_role",
            "finish_tx",
            "idempotency_key",
            "tokio::spawn",
            "Role::Read",
            "Role::Triage",
            "Role::Write",
            "Role::Maintain",
            "access.owner_id",
        ):
            self.assertIn(h_tok, handlers_src, f"Missing {h_tok} in src/web/handlers.rs")

    def test_xss_sanitizer_strips_dangerous_tags_events_and_obfuscated_uris(self) -> None:
        vectors = [
            "<script>alert(1)</script>",
            "<SCRIPT SRC=https://evil.example/xss.js></SCRIPT>",
            "<script>unclosed_payload()",
            "<iframe src=\"javascript:alert(1)\" srcdoc=\"<script>alert(1)</script>\"></iframe>",
            "<object data=\"javascript:alert(1)\"></object>",
            "<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
            "<style>body{background:url(javascript:alert(1))}</style>",
            "<svg onload=alert(1)><g onmouseover=alert(1)></g></svg>",
            "<math><mtext><script>alert(1)</script></mtext></math>",
            "<form action=\"javascript:alert(1)\"><input name=x><button>go</button></form>",
            "<base href=\"https://evil.example/\">",
            "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
            "<link rel=\"import\" href=\"https://evil.example/xss.html\">",
            "<img src=x onerror=alert(1)>",
            "<div onmouseover=\"alert(1)\" onfocus=`alert(1)` onclick=alert(1) style=\"width:expression(alert(1))\">text</div>",
            "[xss1](javascript:alert(1))",
            "[xss2](JAVASCRIPT:alert(1))",
            "[xss3](jav&#x09;ascript:alert(1))",
            "[xss4](&#106;&#97;vascript:alert(1))",
            "[xss5](&#0000106avascript:alert(1))",
            "[xss6](&#x6a&#x61vascript:alert(1))",
            "[xss7](java%0ascript:alert(1))",
            "[xss8](\x01javascript:alert(1))",
            "[xss9](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)",
            "[xss10](vbscript:msgbox(1))",
            "[xss11](file:///etc/passwd)",
            "[xss12](//evil.example/x.js)",
        ]
        combined = "\n\n".join(vectors) + "\n\nSafe [link](https://example.com/safe) and **bold**."
        rendered = web.render_safe_markdown(combined)
        lower = rendered.lower()
        for bad in (
            "<script",
            "<iframe",
            "<object",
            "<embed",
            "<style",
            "<svg",
            "<math",
            "<form",
            "<input",
            "<button",
            "<base",
            "<meta",
            "<link",
            "onerror",
            "onload",
            "onmouseover",
            "onfocus",
            "onclick",
            "srcdoc",
            "style=",
            "javascript:",
            "vbscript:",
            "data:text/html",
            "file://",
            "//evil.example",
            "unclosed_payload",
        ):
            self.assertNotIn(bad, lower, f"XSS vector '{bad}' survived in: {rendered}")
        self.assertIn('href="https://example.com/safe"', rendered)
        self.assertIn("<strong>bold</strong>", rendered)

    def test_large_blob_streaming_truncation_multibyte_utf8_and_binary_hex_preview(self) -> None:
        eng = web.WebReferenceEngine()
        try:
            # 1. 120 KiB blob truncated at default 64 KiB
            st1, prev1 = eng._read_blob_streaming("HEAD", "large_120k.txt", web.DEFAULT_WEB_BLOB_PREVIEW_BYTES)
            self.assertEqual(st1, 200)
            assert prev1 is not None
            self.assertFalse(prev1["is_binary"])
            self.assertTrue(prev1["truncated"])
            self.assertLessEqual(prev1["preview_bytes"], web.DEFAULT_WEB_BLOB_PREVIEW_BYTES)
            self.assertGreater(prev1["total_size"], 120 * 1024)

            # 2. 4.5 MiB blob (> MAX_BROWSE_BLOB_BYTES = 4 MiB) returns 200 OK with bounded preview
            st2, prev2 = eng._read_blob_streaming("HEAD", "huge_4_5mb.log", 4096)
            self.assertEqual(st2, 200)
            assert prev2 is not None
            self.assertFalse(prev2["is_binary"])
            self.assertTrue(prev2["truncated"])
            self.assertLessEqual(prev2["preview_bytes"], 4096)
            self.assertGreater(prev2["total_size"], 4 * 1024 * 1024)

            # 3. Multi-byte UTF-8 boundary truncation at offsets 256..261 never misclassifies as binary
            for max_b in (256, 257, 258, 259, 260, 261):
                st_u, prev_u = eng._read_blob_streaming("HEAD", "utf8_multibyte.md", max_b)
                self.assertEqual(st_u, 200)
                assert prev_u is not None
                self.assertFalse(prev_u["is_binary"], f"max_bytes={max_b} misclassified as binary")
                self.assertTrue(prev_u["truncated"])
                self.assertIsNotNone(prev_u["text_preview"])

            # 4. Binary blob preview
            st_bin, prev_bin = eng._read_blob_streaming("HEAD", "assets.bin", 4096)
            self.assertEqual(st_bin, 200)
            assert prev_bin is not None
            self.assertTrue(prev_bin["is_binary"])
            self.assertTrue(prev_bin["truncated"])
            self.assertIsNone(prev_bin["text_preview"])
            self.assertIn("0000: 89 50 4e 47 0d 0a 1a 0a 00 01 02 ff fe fd", prev_bin["hex_preview"])
        finally:
            eng.close()

    def test_five_role_rbac_permission_parity_and_self_approval_enforcement_over_http(self) -> None:
        with web.LocalWebUiServer() as srv:
            eng = srv.engine
            eng.rbac.upsert_collaborator(eng.alice, "alice", "forge", "bob", "read")
            eng.rbac.upsert_collaborator(eng.alice, "alice", "forge", "carol", "triage")
            eng.rbac.upsert_collaborator(eng.alice, "alice", "forge", "dave", "write")
            eng.rbac.upsert_collaborator(eng.alice, "alice", "forge", "erin", "maintain")

            # Unauthenticated -> 401; outsider -> 404
            self.assertEqual(srv.request("/web/repos/alice/forge")[0], 401)
            self.assertEqual(srv.request("/web/repos/alice/forge", token=eng.outsider["token"])[0], 404)
            self.assertEqual(srv.request("/ui/repos/alice/forge/pulls", token=eng.outsider["token"])[0], 404)

            # Read vs Triage vs Write vs Maintain
            self.assertEqual(
                srv.request("/web/repos/alice/forge/issues", method="POST", token=eng.bob["token"], json_body={"title": "Bug"})[0],
                403,
            )
            self.assertEqual(
                srv.request("/web/repos/alice/forge/issues", method="POST", token=eng.carol["token"], json_body={"title": "Bug"})[0],
                201,
            )
            self.assertEqual(
                srv.request("/web/repos/alice/forge/pulls", method="POST", token=eng.carol["token"], json_body={"title": "PR", "head_ref": "feature", "base_ref": "main"})[0],
                403,
            )
            self.assertEqual(
                srv.request("/web/repos/alice/forge/pulls", method="POST", token=eng.dave["token"], json_body={"title": "PR", "head_ref": "feature", "base_ref": "main"})[0],
                201,
            )
            self.assertEqual(srv.request("/web/repos/alice/forge/audit", token=eng.dave["token"])[0], 403)
            self.assertEqual(srv.request("/web/repos/alice/forge/audit", token=eng.erin["token"])[0], 200)

            # Self-approval prohibition for PR #1 authored by dave
            self.assertEqual(
                srv.request(
                    "/web/repos/alice/forge/pulls/1/reviews",
                    method="POST",
                    token=eng.dave["token"],
                    json_body={"state": "approved", "commit_oid": eng.feat_oid},
                )[0],
                403,
            )

    def test_end_to_end_web_ui_views_and_cli_harness_contract(self) -> None:
        web_py = ROOT / "tests/web.py"
        tree = ast.parse(web_py.read_text(encoding="utf-8"), filename=str(web_py))
        class_names = {n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
        self.assertIn("WebReferenceEngine", class_names)
        self.assertIn("LocalWebUiServer", class_names)
        self.assertIn("WebHarness", class_names)

        help_proc = subprocess.run(
            [sys.executable, str(web_py), "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True,
        )
        for flag in ("--binary", "--report", "--keep", "--case"):
            self.assertIn(flag, help_proc.stdout)

        harness = web.WebHarness()
        try:
            harness.run_all()
        finally:
            harness.cleanup()


if __name__ == "__main__":
    unittest.main()
