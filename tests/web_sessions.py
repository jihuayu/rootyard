#!/usr/bin/env python3
"""Real browser-session exchange, workflow, CSRF, expiry and revocation checks."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import sys
import urllib.parse

sys.path.insert(0,str(Path(__file__).resolve().parent))
from e2e import Harness


class BrowserHarness(Harness):
    def request(self,path,method="GET",body=None,headers=None):
        conn=http.client.HTTPConnection("127.0.0.1",self.port,timeout=20)
        conn.request(method,path,body=body,headers=headers or {})
        response=conn.getresponse()
        result=(response.status,response.read(),response.getheaders())
        conn.close()
        return result

    def sign_in(self):
        body=urllib.parse.urlencode({"username":"alice","token":self.alice["token"]})
        status,data,headers=self.request("/web/login","POST",body,
            {"Content-Type":"application/x-www-form-urlencoded","Origin":self.base})
        assert status==303,(status,data)
        cookies={}
        for key,value in headers:
            if key.lower()=="set-cookie":
                name,raw=value.split(";",1)[0].split("=",1)
                cookies[name]=raw
        assert cookies["rootyard_session"].startswith("ryt_")
        assert cookies["rootyard_csrf"]
        return cookies

    def cookie_header(self,cookies):
        return "; ".join(f"{k}={v}" for k,v in cookies.items())

    def run_flow(self):
        self.setup()
        self.api()
        self.roundtrip()
        login_page=self.request("/web/login")
        assert login_page[0]==200 and b"type=\"password\"" in login_page[1]
        cookies=self.sign_in()
        headers={"Cookie":self.cookie_header(cookies)}
        status,page,_=self.request("/web/repos",headers=headers)
        assert status==200 and b"alice/demo" in page and cookies["rootyard_session"].encode() not in page
        assert self.request("/api/repos",headers={"Authorization":"Bearer "+cookies["rootyard_session"]})[0]==401
        assert self.request("/git/alice/demo.git/info/refs?service=git-upload-pack",headers={"Authorization":"Bearer "+cookies["rootyard_session"]})[0]==401
        assert self.request("/web/repos/alice/demo",headers=headers)[0]==200

        path="/web/repos/alice/demo/issues"
        payload=json.dumps({"title":"Browser issue","body":"Started in UI"})
        mutation={**headers,"Content-Type":"application/json","Origin":self.base,"X-CSRF-Token":cookies["rootyard_csrf"]}
        assert self.request(path,"POST",payload,headers)[0]==403
        assert self.request(path,"POST",payload,{**mutation,"Origin":"https://evil.example"})[0]==403
        status,body,_=self.request(path,"POST",payload,mutation)
        assert status==201,(status,body[:300])
        assert b"Browser issue" in body

        self.git("checkout","-b","feature",cwd=self.work)
        (self.work/"browser.txt").write_text("browser PR\n")
        self.git("add","browser.txt",cwd=self.work)
        self.git("commit","-m","browser feature",cwd=self.work)
        head=self.git("rev-parse","HEAD",cwd=self.work).stdout.decode().strip()
        self.git("push","origin","HEAD:feature",cwd=self.work,token=self.alice)
        path="/web/repos/alice/demo/pulls"
        payload=json.dumps({"title":"Browser PR","head_ref":"feature","base_ref":"main"})
        status,body,_=self.request(path,"POST",payload,mutation)
        assert status==201,(status,body[:300])
        assert b"Browser PR" in body
        pull=json.loads(self.expect("/api/repos/alice/demo/pulls/1",200,token=self.alice))
        merge=json.dumps({"expected_version":pull["version"],"expected_head_oid":head,
                          "expected_base_oid":pull["base_oid"]})
        status,body,_=self.request(path+"/1/merge","POST",merge,mutation)
        assert status==200,(status,body[:300])
        assert b"merged" in body

        token_id=self.sql("SELECT token_id FROM web_sessions ORDER BY created_at DESC LIMIT 1")
        self.sql(f"UPDATE web_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE token_id='{token_id}'")
        assert self.request("/web/repos",headers=headers)[0]==401
        cookies=self.sign_in();headers={"Cookie":self.cookie_header(cookies)}
        token_id=self.sql("SELECT token_id FROM web_sessions ORDER BY created_at DESC LIMIT 1")
        self.sql(f"UPDATE web_sessions SET revoked=true WHERE token_id='{token_id}'")
        assert self.request("/web/repos",headers=headers)[0]==401
        cookies=self.sign_in();headers={"Cookie":self.cookie_header(cookies)}
        assert self.request("/web/logout","POST",headers={**headers,"Origin":self.base})[0]==303
        assert self.request("/web/repos",headers=headers)[0]==401


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary",default="target/debug/rootyard")
    parser.add_argument("--report",type=Path)
    parser.add_argument("--keep",action="store_true")
    args=parser.parse_args()
    args.binary=str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness=BrowserHarness(args)
    passed=False
    try:
        harness.case("browser_session_workflow",harness.run_flow)
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

if __name__=="__main__":
    sys.exit(main())
