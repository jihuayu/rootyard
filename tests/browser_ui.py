#!/usr/bin/env python3
"""Chromium end-to-end browser entry, Issue/PR workflow and session revocation."""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import sys
import threading

from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parent))
from web_sessions import BrowserHarness


class EvilOriginServer:
    """Serve a same-host, different-port page that auto-submits to Rootyard."""

    def __init__(self, target):
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = (
                    "<!doctype html><meta charset=\"utf-8\"><title>other origin</title>"
                    f"<form id=\"f\" method=\"post\" action=\"{target}\">"
                    "<input name=\"title\" value=\"cross-origin issue\"></form>"
                    "<script>document.getElementById('f').submit()</script>"
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = "http://127.0.0.1:%d/" % self.server.server_address[1]
        self.target = target

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class UiHarness(BrowserHarness):
    def browser_workflow(self):
        self.setup()
        self.api()
        self.roundtrip()
        self.git("checkout", "-b", "feature", cwd=self.work)
        (self.work / "browser-ui.txt").write_text("browser UI PR\n")
        self.git("add", "browser-ui.txt", cwd=self.work)
        self.git("commit", "-m", "browser UI feature", cwd=self.work)
        self.git("push", "origin", "HEAD:feature", cwd=self.work, token=self.alice)

        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                executable_path="/usr/bin/chromium",
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            context = browser.new_context()
            page = context.new_page()
            assert context.cookies() == []

            # Fresh profile: a locked page is a usable sign-in redirect, not a
            # raw 401 JSON body, and the API token never enters the URL.
            page.goto(self.base + "/web/repos/alice/demo")
            page.wait_for_url(lambda url: url.startswith(self.base + "/web/login?return_to="))
            assert self.alice["token"] not in page.url
            assert "return_to=" in page.url
            page.locator('input[name="username"]').fill("alice")
            page.locator('input[name="token"]').fill(self.alice["token"])
            page.get_by_role("button", name="Sign in").click()
            page.wait_for_url(self.base + "/web/repos/alice/demo")
            content = page.content()
            assert self.alice["token"] not in content
            assert self.alice["token"] not in page.url
            cookies = {cookie["name"]: cookie for cookie in context.cookies()}
            assert cookies["rootyard_session"]["httpOnly"] is True
            assert cookies["rootyard_session"]["sameSite"] == "Strict"
            assert cookies["rootyard_session"]["path"] == "/"
            assert cookies["rootyard_csrf"]["httpOnly"] is False
            session_secret = cookies["rootyard_session"]["value"]
            csrf = cookies["rootyard_csrf"]["value"]
            assert session_secret not in content and session_secret not in page.url
            assert csrf not in content

            # Cross-origin browser form submission is rejected and creates no
            # issue. Ports differ, so Origin differs while the host is the same.
            before = self.sql("SELECT count(*) FROM forge_issues")
            evil = EvilOriginServer(self.base + "/web/repos/alice/demo/issues")
            try:
                page.goto(evil.url)
                page.wait_for_url(self.base + "/web/repos/alice/demo/issues")
                assert "origin rejected" in page.evaluate("document.body.innerText")
            finally:
                evil.stop()
            assert self.sql("SELECT count(*) FROM forge_issues") == before

            # Same-origin issue workflow from the browser UI.
            page.goto(self.base + "/web/repos/alice/demo")
            page.get_by_role("link", name="Issues").click()
            page.locator('form[data-web-action="issue"] input[name="title"]').fill("Chromium issue")
            page.locator('form[data-web-action="issue"] textarea[name="body"]').fill(
                "Opened in a fresh browser"
            )
            page.get_by_role("button", name="Create issue").click()
            page.get_by_role("link", name="#1 Chromium issue").wait_for(timeout=10000)

            # Same-origin pull-request creation and merge from the browser UI.
            page.get_by_role("link", name="Pull Requests").click()
            page.locator('form[data-web-action="pull"] input[name="title"]').fill("Chromium PR")
            page.locator('form[data-web-action="pull"] input[name="head_ref"]').fill("feature")
            page.get_by_role("button", name="Create pull request").click()
            page.get_by_role("link", name="#1 Chromium PR").wait_for(timeout=10000)
            page.get_by_role("link", name="#1 Chromium PR").click()
            page.locator('form[data-web-action="merge"]').wait_for(timeout=10000)
            page.get_by_role("button", name="Merge pull request").click()
            page.locator('.pull-detail[data-pull-state="merged"]').wait_for(timeout=10000)

            # Sign-out clears the browser cookies and revokes the server-side
            # session; replaying the captured old cookie no longer works.
            page.get_by_role("button", name="Sign out").click()
            page.wait_for_url(self.base + "/web/login")
            old = {"Cookie": "rootyard_session=" + session_secret + "; rootyard_csrf=" + csrf}
            assert self.request("/web/repos", headers=old)[0] == 401
            assert self.request("/api/repos", headers={"Authorization": "Bearer " + session_secret})[0] == 401
            assert self.request(
                "/git/alice/demo.git/info/refs?service=git-upload-pack",
                headers={"Authorization": "Bearer " + session_secret},
            )[0] == 401

            def ui_login():
                page.goto(self.base + "/web/login")
                page.locator('input[name="username"]').fill("alice")
                page.locator('input[name="token"]').fill(self.alice["token"])
                page.get_by_role("button", name="Sign in").click()
                page.wait_for_url(self.base + "/web/repos")
                assert context.cookies()

            # Expired browser session navigates back to a usable sign-in page.
            ui_login()
            token_id = self.sql(
                "SELECT token_id FROM web_sessions ORDER BY created_at DESC LIMIT 1"
            )
            self.sql(
                f"UPDATE web_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE token_id='{token_id}'"
            )
            page.goto(self.base + "/web/repos")
            page.wait_for_url(lambda url: url.startswith(self.base + "/web/login"))

            # Revoked session row has the same behavior.
            ui_login()
            token_id = self.sql(
                "SELECT token_id FROM web_sessions ORDER BY created_at DESC LIMIT 1"
            )
            self.sql(f"UPDATE web_sessions SET revoked=true WHERE token_id='{token_id}'")
            page.goto(self.base + "/web/repos")
            page.wait_for_url(lambda url: url.startswith(self.base + "/web/login"))

            # Revoking the API token used at sign-in terminates the browser
            # session, and that token can no longer create a new session.
            ui_login()
            self.sql(f"UPDATE tokens SET revoked=true WHERE id='{self.alice['token_id']}'")
            page.goto(self.base + "/web/repos")
            page.wait_for_url(lambda url: url.startswith(self.base + "/web/login"))
            page.locator('input[name="username"]').fill("alice")
            page.locator('input[name="token"]').fill(self.alice["token"])
            page.get_by_role("button", name="Sign in").click()
            page.get_by_role("alert").wait_for(timeout=10000)
            assert "Invalid username or API token" in page.get_by_role("alert").inner_text()

            self.runtime = {
                "browser": browser.version,
                "chromium": "/usr/bin/chromium",
                "git_head": self.run(["git", "rev-parse", "HEAD"]).stdout.decode().strip(),
            }
            browser.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = UiHarness(args)
    harness.runtime = {}
    passed = False
    try:
        harness.case("chromium_browser_workflow", harness.browser_workflow)
        passed = True
    except Exception as exc:
        print(harness.redact(exc), file=sys.stderr)
    finally:
        harness.cleanup()
        report = {
            "passed": passed,
            "cases": harness.results,
            "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
            "runtime": harness.runtime,
        }
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
