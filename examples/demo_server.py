#!/usr/bin/env python3
"""Loopback-only fictional API. Use --vulnerable to demonstrate a failed test."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Demo(BaseHTTPRequestHandler):
    vulnerable = False

    def do_GET(self):
        role = {"Bearer demo-alice": "alice", "Bearer demo-bob": "bob", "Bearer demo-admin": "admin"}.get(self.headers.get("Authorization"))
        status, body = 404, {"error": "not_found"}
        if role is None:
            status, body = 401, {"error": "unauthorized"}
        elif self.path == "/api/orders/alice-1":
            if role in ("alice", "admin") or self.vulnerable:
                status, body = 200, {"id": "alice-1", "owner": "alice"}
            else:
                status, body = 403, {"error": "forbidden"}
        elif self.path == "/api/admin/users":
            status, body = (200, {"users": ["alice", "bob"]}) if role == "admin" else (403, {"error": "forbidden"})
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vulnerable", action="store_true")
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()
    Demo.vulnerable = args.vulnerable
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Demo)
    print(f"Fictional {'vulnerable' if args.vulnerable else 'fixed'} API on http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
