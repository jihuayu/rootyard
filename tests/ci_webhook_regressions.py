#!/usr/bin/env python3
"""Native HTTP/PostgreSQL regressions for webhook batching, leases and TLS."""
import argparse
import concurrent.futures
import http.server
import json
from pathlib import Path
import ssl
import subprocess
import sys
import threading
import time
import uuid

from e2e import Harness


class Receiver:
    def __init__(self, cert=None, key=None, delay=0):
        self.requests = []
        self.delay = delay
        self.lock = threading.Lock()
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                with outer.lock:
                    outer.requests.append((self.headers.get("X-Rootyard-Delivery"), raw))
                if outer.delay:
                    time.sleep(outer.delay)
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        if cert:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def url(self, scheme="http"):
        return f"{scheme}://127.0.0.1:{self.server.server_port}/hook"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def api(h, path, code=200, **kwargs):
    status, raw, _ = h.http(path, token=h.alice, **kwargs)
    assert status == code, f"{path}: expected {code}, got {status}: {raw[:200]!r}"
    return json.loads(raw)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    h = Harness(args)
    h.env["ROOTYARD_OUTBOX_WORKER"] = "false"
    plain = delayed = tls = None
    try:
        # A local CA is installed only for this isolated service process.
        ca = h.root / "ca.pem"
        ca_key = h.root / "ca.key"
        cert = h.root / "cert.pem"
        key = h.root / "key.pem"
        csr = h.root / "leaf.csr"
        ext = h.root / "leaf.ext"
        ext.write_text("subjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(ca_key), "-out", str(ca), "-days", "1", "-subj", "/CN=Rootyard test CA",
            "-addext", "basicConstraints=critical,CA:TRUE"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(csr), "-subj", "/CN=127.0.0.1"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca),
            "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(cert), "-days", "1",
            "-extfile", str(ext)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        h.env["ROOTYARD_WEBHOOK_CA_FILE"] = str(ca)
        h.setup()
        repo = api(h, "/api/repos", 201, method="POST", body={"name": "ci"})
        repo_id = repo["id"]
        base = "/api/repos/alice/ci/webhooks"
        plain = Receiver()
        hook = api(h, base, 201, method="POST", body={"url": plain.url(),
            "secret": "synthetic-webhook-secret-123", "events": ["push"],
            "auto_ci_pin": False})
        op = uuid.uuid4()
        h.sql(f"INSERT INTO git_operations(id,repository_id,actor_id,token_id,actor_name,sequence,storage_generation,evidence,outcome) "
              f"VALUES('{op}','{repo_id}','{h.alice['user_id']}','{h.alice['token_id']}','alice',1000,1,'{{}}','recorded')")
        h.sql(f"INSERT INTO outbox_events(event_id,operation_id,repository_id,storage_generation,operation_sequence,transaction_sequence,ref_name,old_oid,new_oid) "
              f"SELECT md5(g::text)||md5('x'||g::text),'{op}','{repo_id}',1,1000,g,'refs/heads/batch-'||g,repeat('0',40),repeat('a',40) "
              f"FROM generate_series(1,201) g")
        first = api(h, base+"/dispatch", method="POST", body={"sync_pulls":False,"sync_outbox":True,"limit":200})
        second = api(h, base+"/dispatch", method="POST", body={"sync_pulls":False,"sync_outbox":True,"limit":200})
        assert first["synced_outbox_deliveries"] == 200, first
        assert second["synced_outbox_deliveries"] == 1, second
        assert h.sql(f"SELECT count(*) FROM forge_webhook_deliveries WHERE webhook_id='{hook['id']}' AND state='delivered'")=="201"
        print("201 event batches: passed", flush=True)

        delayed = Receiver(delay=.4)
        concurrent_hook = api(h, base, 201, method="POST", body={"url":delayed.url(),
            "secret":"synthetic-webhook-secret-456", "events":["ping"],
            "max_attempts":1,"auto_ci_pin":False})
        ping_path = base+"/"+concurrent_hook["id"]+"/ping"
        ping = api(h, ping_path, method="POST", body={"deliver_now":False})
        dispatch = lambda: api(h, base+"/dispatch", method="POST", body={"sync_pulls":False,"sync_outbox":False})
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            results = list(ex.map(lambda _: dispatch(), range(2)))
        assert len(delayed.requests)==1, (delayed.requests,results)
        assert h.sql(f"SELECT state FROM forge_webhook_deliveries WHERE id='{ping['id']}'")=="delivered"
        print("concurrent claim fence: passed", flush=True)

        tls = Receiver(cert,key)
        tls_hook = api(h, base, 201, method="POST", body={"url":tls.url("https"),
            "secret":"synthetic-webhook-secret-789", "events":["ping"],
            "auto_ci_pin":False,"max_attempts":1})
        delivered = api(h, base+"/"+tls_hook["id"]+"/ping", method="POST", body={})
        assert delivered["state"]=="delivered" and len(tls.requests)==1, delivered
        plaintext_as_tls = api(h, base, 201, method="POST", body={"url":plain.url("https"),
            "secret":"synthetic-webhook-secret-abc", "events":["ping"],
            "auto_ci_pin":False,"max_attempts":1})
        bad = api(h, base+"/"+plaintext_as_tls["id"]+"/ping", method="POST", body={})
        assert bad["state"]=="dead_letter" and len(plain.requests)==201, bad
        print("verified TLS and plaintext rejection: passed", flush=True)
        return 0
    finally:
        for receiver in (plain,delayed,tls):
            if receiver: receiver.close()
        h.cleanup()


if __name__ == "__main__":
    sys.exit(main())
