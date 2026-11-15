"""Self-hosted HTTP callback catcher. No outbound traffic and no request bodies, headers or client data stored.

Run one instance per real engagement behind an operator-managed TLS endpoint. Events expire after ten minutes;
restart to clear them. This is deliberately an HTTP-only protocol, not a public callback service or DNS catcher.
"""
import json, re, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = re.compile(r"^/(callback|events)/([A-Za-z0-9_-]{6,128})$")
TTL = 600
MAX_TOKENS = 10000


class Catcher(ThreadingHTTPServer):
    def __init__(self, address):
        super().__init__(address, Handler)
        self.events, self.lock = {}, threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass   # the URL may contain a canary; keep it only in the bounded event store

    def handle_event(self):
        self.close_connection = True
        match = TOKEN.fullmatch(self.path)
        status, event = 404, {"error": "not found"}
        if match:
            kind, token = match.groups()
            with self.server.lock:
                now = time.monotonic()
                self.server.events = {t: e for t, e in self.server.events.items() if now - e[1] < TTL}
                count = self.server.events.get(token, (0, now))[0]
                status = 200
                if kind == "callback":
                    if token not in self.server.events and len(self.server.events) >= MAX_TOKENS:
                        status, event = 503, {"error": "event store full"}
                    else:
                        count += 1
                        self.server.events[token] = (count, now)
                        event = {"ok": True}
                elif self.command != "GET":
                    status, event = 405, {"error": "poll with GET"}
                else:
                    event = {"token": token, "count": count}
        body = json.dumps(event).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_HEAD = do_POST = do_PUT = handle_event


if __name__ == "__main__":
    Catcher(("0.0.0.0", 8000)).serve_forever()
