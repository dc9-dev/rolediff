#!/usr/bin/env python3
"""Black-box contract tests for native Go and Rust binaries; loopback only."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]

class API(BaseHTTPRequestHandler):
    vulnerable = False
    calls = []

    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        API.calls.append((self.path, auth, self.headers.get("Cookie")))
        role = {"Bearer demo-alice":"alice", "Bearer demo-bob":"bob", "Bearer demo-admin":"admin"}.get(auth)
        status, body = 200, b'{}'
        if self.path == "/redirect":
            self.send_response(302); self.send_header("Location", "/sink"); self.end_headers(); return
        if self.path == "/slow":
            time.sleep(0.2)
        if self.path == "/login": body = b'<html>login</html>'
        elif self.path == "/duplicate": body = b'{"id":"wrong","id":"alice-1"}'
        elif self.path == "/large": body = b'x' * 80
        elif self.path == "/numbers": body = b'{"count":1.0,"big":9007199254740993,"nil":null,"a/b":{"~key":[2]},"power":1e1000}'
        elif self.path.startswith("/api/"):
            if not role: status, body = 401, b'{"error":"unauthorized"}'
            elif self.path == "/api/orders/alice-1":
                status, body = (200,b'{"id":"alice-1","secret":"RESPONSE_SECRET"}') if role in ("alice","admin") or API.vulnerable else (403,b'{"error":"forbidden"}')
            elif self.path == "/api/admin/users":
                status, body = (200,b'{"users":["alice","bob"]}') if role == "admin" else (403,b'{"error":"forbidden"}')
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "session=RESPONSE_SECRET")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try: self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError): pass

    def log_message(self, *args): pass

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default=str(ROOT / "bin/rolediff"))
    parser.add_argument("--rust", default=str(ROOT / "rust/target/debug/rolediff"))
    args = parser.parse_args()
    binaries = [str(Path(args.go).resolve()), str(Path(args.rust).resolve())]
    env = dict(os.environ, ROLEDIFF_ALICE_TOKEN="demo-alice", ROLEDIFF_BOB_TOKEN="demo-bob", ROLEDIFF_ADMIN_TOKEN="demo-admin")
    server = ThreadingHTTPServer(("127.0.0.1", 0), API)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    suite = json.loads((ROOT / "testdata/suite.json").read_text()); suite["base_url"] = base
    checked = 0

    def run_case(name, config, code, flags=(), check=None, invalid=False, overrides=None):
        nonlocal checked
        reports = []
        raw = config if isinstance(config, str) else json.dumps(config)
        for binary in binaries:
            before = len(API.calls)
            proc = subprocess.run([binary,"-json","-delay-ms","0",*flags], input=raw, capture_output=True, text=True, env=env if overrides is None else overrides, timeout=10)
            assert proc.returncode == code, (name, binary, proc.returncode, proc.stdout, proc.stderr)
            for secret in ("demo-alice","demo-bob","demo-admin","RESPONSE_SECRET"):
                assert secret not in proc.stdout + proc.stderr, (name,"secret leaked")
            if invalid:
                assert proc.stdout == "" and proc.stderr and len(API.calls) == before, (name,"invalid suite performed requests")
            else:
                assert not proc.stderr, (name,proc.stderr)
                report=json.loads(proc.stdout); reports.append(report)
                if check: check(report)
        if reports: assert reports[0] == reports[1], (name,"Go/Rust mismatch",reports)
        checked += 1
        print("PASS", name)

    def one(path):
        config=copy.deepcopy(suite); config["identities"]=config["identities"][:1]; config["cases"]=config["cases"][:1]
        config["cases"][0]["path"]=path; config["cases"][0]["expect"]={"alice": config["cases"][0]["expect"]["alice"]}
        return config

    try:
        run_case("fixed authorization matrix",suite,0,check=lambda r: (r["passed"]==8) or sys.exit("wrong pass count"))
        API.vulnerable=True
        run_case("horizontal authorization regression",suite,1,check=lambda r: (r["failed"]==1) or sys.exit("missed BOLA"))
        API.vulnerable=False
        assert all(cookie is None for _,_,cookie in API.calls), "session cookie crossed identity boundaries"
        run_case("200 login page is not access",one("/login"),1)
        head=one("/health");head["cases"][0]["method"]="HEAD";head["cases"][0]["expect"]["alice"].pop("json")
        run_case("HEAD without body",head,0)
        run_case("duplicate response keys rejected",one("/duplicate"),1)
        run_case("redirect blocked",one("/redirect"),2)
        assert not any(path=="/sink" for path,_,_ in API.calls), "redirect followed"
        run_case("response size limit",one("/large"),2,flags=("-max-response-bytes","32"))
        run_case("timeout",one("/slow"),2,flags=("-timeout-ms","20"))
        numeric=one("/numbers")
        numeric["cases"][0]["expect"]["alice"]["json"]=[
            {"pointer":"/count","op":"equals","value":1},
            {"pointer":"/big","op":"equals","value":9007199254740993},
            {"pointer":"/nil","op":"equals","value":None},
            {"pointer":"/a~1b/~0key/0","op":"equals","value":2},
            {"pointer":"/missing","op":"absent"},
            {"pointer":"/big","op":"not_equals","value":9007199254740992},
            {"pointer":"/nil","op":"exists"},
        ]
        run_case("precision, pointers, null and all operators",numeric,0)
        numeric["cases"][0]["expect"]["alice"]["json"].append({"pointer":"/missing","op":"not_equals","value":1})
        run_case("not_equals requires presence",numeric,1)
        run_case("preflight request budget",suite,2,flags=("-max-requests","1"),invalid=True)
        missing=dict(env);missing.pop("ROLEDIFF_BOB_TOKEN")
        run_case("preflight missing credential",suite,2,invalid=True,overrides=missing)
        inject=dict(env);inject["ROLEDIFF_BOB_TOKEN"]="bad\r\nX-Injected: yes"
        run_case("preflight header injection",suite,2,invalid=True,overrides=inject)
        for path in ("//elsewhere.test/","/%2felsewhere.test/","/foo#fragment","/foo\\bar","/a/../b","/a/%2e%2e/b"):
            run_case("invalid path "+path,one(path),2,invalid=True)
        incomplete=copy.deepcopy(suite);del incomplete["cases"][0]["expect"]["bob"]
        run_case("incomplete matrix",incomplete,2,invalid=True)
        no_evidence=one("/");no_evidence["cases"][0]["expect"]["alice"].pop("json")
        run_case("200 needs response evidence",no_evidence,2,invalid=True)
        unknown=copy.deepcopy(suite);unknown["secret_inline"]="UNSUPPORTED"
        run_case("unknown fields",unknown,2,invalid=True)
        run_case("duplicate config keys",json.dumps(suite).replace('"base_url":', '"base_url":"https://unused.test","base_url":',1),2,invalid=True)
        run_case("validate without requests",suite,0,flags=("-validate",),check=lambda r: (r=={"valid":True,"planned_requests":8}) or sys.exit("bad validation report"))
        print(f"{checked} scenarios passed for both native binaries.")
    finally:
        server.shutdown();server.server_close();thread.join()

if __name__=="__main__": main()
