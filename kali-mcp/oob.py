"""Out-of-band callback catcher for the OOB oracle (issue #58).

A kit-operated catcher only: no public callback service, so client traffic never goes to a third party. It runs as
a daemon thread inside kali-mcp (on the rvlab network at 10.250.0.2, so lab targets can reach it, and reachable by
real targets only where the engagement's network allows it). Received callback tokens are kept in memory and in a
small file, and the oracle (oracles.oob_callback) checks whether a token arrived.

The catcher records the first path segment of every request as a token (e.g. GET /<token> or /<token>?...). Anything
that isn't a plausible token is ignored.
"""
import os, threading, time

PORT = int(os.environ.get("OOB_PORT", "8080"))
STORE = os.environ.get("OOB_STORE", "/tmp/oob-received.txt")

_RECEIVED = set()
_LOCK = threading.Lock()
_STARTED = False


def _load():
    try:
        with open(STORE) as f:
            for line in f:
                _RECEIVED.add(line.strip())
    except OSError:
        pass


def received(token):
    # The catcher runs in the kali-mcp server process, but the oracle runs in a separate process (docker exec),
    # so the in-memory set is not shared. The file is the shared medium.
    with _LOCK:
        if token in _RECEIVED:
            return True
    try:
        with open(STORE) as f:
            for line in f:
                if line.strip() == token:
                    return True
    except OSError:
        pass
    return False


def wait(token, timeout=5.0, poll=0.2):
    """Block until `token` is received or `timeout` seconds pass. Returns True if it arrived."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if received(token):
            return True
        time.sleep(poll)
    return received(token)


def mark(token):
    with _LOCK:
        if token not in _RECEIVED:
            _RECEIVED.add(token)
            try:
                with open(STORE, "a") as f:
                    f.write(token + "\n")
            except OSError:
                pass


def _serve():
    try:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    except Exception:  # noqa: BLE001
        return
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            tok = self.path.strip("/").split("/", 1)[0].split("?", 1)[0]
            if tok:
                mark(tok)
            self.send_response(204)
            self.end_headers()
        def do_POST(self):
            self.do_GET()
        def log_message(self, *a):
            pass
    try:
        httpd = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    except OSError:
        return
    httpd.serve_forever()


def start():
    global _STARTED
    if _STARTED:
        return
    _STARTED = True
    _load()
    t = threading.Thread(target=_serve, daemon=True, name="oob-catcher")
    t.start()


if __name__ == "__main__":
    start()
    # keep the process alive
    while True:
        time.sleep(3600)
