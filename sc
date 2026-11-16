from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import hmac
import platform
from datetime import datetime, timezone

HOST = "127.0.0.1"
PORT = 8085
TOKEN = os.environ.get("LAB_SERVICE_TOKEN", "")

class Handler(BaseHTTPRequestHandler):
    def respond(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            return self.respond(200, {"service": "online"})

        if self.path != "/admin/status":
            return self.respond(404, {"error": "not found"})

        supplied = self.headers.get("X-Lab-Token", "")
        if not TOKEN or not hmac.compare_digest(supplied, TOKEN):
            return self.respond(403, {"error": "unauthorized"})

        return self.respond(200, {
            "hostname": platform.node(),
            "system": platform.system(),
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

if __name__ == "__main__":
    HTTPServer((HOST, PORT), Handler).serve_forever()
