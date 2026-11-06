#!/usr/bin/env python3
"""Chromium end-to-end browser entry and Issue/PR workflow."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

from playwright.sync_api import sync_playwright
sys.path.insert(0,str(Path(__file__).resolve().parent))
from web_sessions import BrowserHarness


class UiHarness(BrowserHarness):
    def browser_workflow(self):
        self.setup(); self.api(); self.roundtrip()
        self.git("checkout","-b","feature",cwd=self.work)
        (self.work/"browser-ui.txt").write_text("browser UI PR\n")
        self.git("add","browser-ui.txt",cwd=self.work)
        self.git("commit","-m","browser UI feature",cwd=self.work)
        self.git("push","origin","HEAD:feature",cwd=self.work,token=self.alice)
        with sync_playwright() as pw:
            browser=pw.chromium.launch(executable_path="/usr/bin/chromium",headless=True,
                                        args=["--no-sandbox","--disable-dev-shm-usage"])
            page=browser.new_page()
            page.goto(self.base+"/web/login")
            page.locator('input[name="username"]').fill("alice")
            page.locator('input[name="token"]').fill(self.alice["token"])
            page.get_by_role("button",name="Sign in").click()
            page.wait_for_url(self.base+"/web/repos")
            assert page.get_by_role("link",name="alice/demo").count()==1
            assert self.alice["token"] not in page.content()
            page.get_by_role("link",name="alice/demo").click()
            page.get_by_role("link",name="Issues").click()
            page.locator('form[data-web-action="issue"] input[name="title"]').fill("Chromium issue")
            page.locator('form[data-web-action="issue"] textarea[name="body"]').fill("Opened in a fresh browser")
            page.get_by_role("button",name="Create issue").click()
            page.get_by_role("link",name="#1 Chromium issue").wait_for(timeout=10000)
            page.get_by_role("link",name="Pull Requests").click()
            page.locator('form[data-web-action="pull"] input[name="title"]').fill("Chromium PR")
            page.locator('form[data-web-action="pull"] input[name="head_ref"]').fill("feature")
            page.get_by_role("button",name="Create pull request").click()
            page.get_by_role("link",name="#1 Chromium PR").wait_for(timeout=10000)
            page.get_by_role("link",name="#1 Chromium PR").click()
            page.locator('form[data-web-action="merge"]').wait_for(timeout=10000)
            page.get_by_role("button",name="Merge pull request").click()
            page.locator('.pull-detail[data-pull-state="merged"]').wait_for(timeout=10000)
            page.get_by_role("button",name="Sign out").click()
            page.wait_for_url(self.base+"/web/login")
            assert page.context.request.get(self.base+"/web/repos").status==401
            browser.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary",default="target/debug/rootyard")
    parser.add_argument("--report",type=Path)
    parser.add_argument("--keep",action="store_true")
    args=parser.parse_args();args.binary=str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness=UiHarness(args);passed=False
    try:
        harness.case("chromium_browser_workflow",harness.browser_workflow)
        passed=True
    except Exception as exc:
        print(harness.redact(exc),file=sys.stderr)
    finally:
        harness.cleanup()
        report={"passed":passed,"cases":harness.results,
                "binary_sha256":hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()}
        if args.report:
            args.report.parent.mkdir(parents=True,exist_ok=True)
            args.report.write_text(json.dumps(report,indent=2)+"\n")
        print(json.dumps(report,indent=2))
    return 0 if passed else 1

if __name__=="__main__":sys.exit(main())
