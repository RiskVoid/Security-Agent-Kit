"""Out-of-band callback catcher for the OOB oracle (issue #58).

A kit-operated catcher only: no public callback service, so client traffic never goes to a third party. It runs as
a daemon thread inside kali-mcp (on the rvlab network at 10.250.0.2, so lab targets can reach it, and reachable by
real targets only where the engagement's network allows it). The firewall drops every engagement user's traffic
to this port on any local address (core._nft_script), so an agent command cannot forge a callback: only the target
itself can reach the catcher.

Tokens: <engagement-name>.<canary>, both parts validated before anything is stored, so a scanner or a hostile
target hitting the port cannot pollute the store. A token is stored when it arrives; it becomes *evidence* (a
record under /work/<eng>/evidence/oob/ plus an audit entry) only when the oracle pre-registered it with expect()
before sending its probe, so floods of name-shaped junk never reach the audit log.

The catcher runs in the server process, but the oracle runs in a separate process (docker exec), so the in-memory
sets are not shared: the received-token and expected-token files under /tmp are the shared medium. /tmp is a
private tmpfs inside each sandbox, so the agent never sees them.
"""
import datetime, json, os, re, threading, time

PORT = int(os.environ.get("OOB_PORT", "8080"))
STORE = os.environ.get("OOB_STORE", "/tmp/oob-received.txt")
EXPECTED = os.environ.get("OOB_EXPECTED", "/tmp/oob-expected.txt")
ADVERTISE = os.environ.get("OOB_ADVERTISE", "http://10.250.0.2:8080").rstrip("/")
WORK = os.environ.get("OOB_WORK", "/work")
MAX_STORE_LINES = 20000   # a hostile target can flood name-shaped tokens; the store keeps its tail
MARKS_SINCE_CHECK = 512

# <engagement-name>.<canary>: the name part is engagement-name shaped, the canary the marker charset (6-128)
TOKEN_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.[A-Za-z0-9_.:@-]{6,128}$")
NAME_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

_RECEIVED = set()
_EXPECTED_CACHE, _EXPECTED_MTIME = set(), None
_LOCK = threading.Lock()
_STARTED = False
_MARKS = 0


def canary():
    return "rv" + os.urandom(6).hex()


def token_for(eng):
    """A callback token unique to this verification: <engagement>.<fresh canary>."""
    return f"{eng}.{canary()}"


def token_parts(token):
    """(engagement name, secret) of a token, or (None, None) when it isn't the token shape."""
    if not TOKEN_RX.match(token or ""):
        return None, None
    eng, _, secret = token.rpartition(".")
    return (eng, secret) if NAME_RX.match(eng) else (None, None)


def advertised():
    """The callback URL the agent embeds in a probe (the reminder line shows it when the rule is on)."""
    return ADVERTISE


# ---------------------------------------------------------------- expectations (the oracle's side)
def expect(token):
    """Register a token before its probe is sent: only registered tokens become evidence when they arrive."""
    eng, _ = token_parts(token)
    if not eng:
        raise ValueError(f"not a callback token: {token!r} (expected <engagement>.<canary>)")
    with _LOCK:
        with open(EXPECTED, "a") as f:
            f.write(token + "\n")
        global _EXPECTED_MTIME
        _EXPECTED_MTIME = None   # the cache reloads on the next receipt


def _expected():
    """The pre-registered tokens, re-read whenever the oracle's process may have added one."""
    global _EXPECTED_MTIME, _EXPECTED_CACHE
    try:
        mtime = os.stat(EXPECTED).st_mtime_ns
    except OSError:
        return set()
    if _EXPECTED_MTIME != mtime:
        with open(EXPECTED) as f:
            cached = {line.strip() for line in f if line.strip()}
        _EXPECTED_MTIME, _EXPECTED_CACHE = mtime, cached
    return _EXPECTED_CACHE


def _consume(token):
    """Drop a token from the expected file once its callback is recorded."""
    with _LOCK:
        try:
            with open(EXPECTED) as f:
                lines = [line.strip() for line in f if line.strip()]
        except OSError:
            return
        with open(EXPECTED, "w") as f:
            f.writelines(line + "\n" for line in lines if line != token)
        global _EXPECTED_MTIME
        _EXPECTED_MTIME = None


# ---------------------------------------------------------------- receipts
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


def wait(token, timeout=10.0, poll=0.2):
    """Block until `token` is received or `timeout` seconds pass. Returns True if it arrived."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if received(token):
            return True
        time.sleep(poll)
    return received(token)


def mark(token):
    global _MARKS
    with _LOCK:
        if token in _RECEIVED:
            return
        _RECEIVED.add(token)
        _MARKS += 1
        try:
            with open(STORE, "a") as f:
                f.write(token + "\n")
            if _MARKS >= MARKS_SINCE_CHECK:
                _MARKS = 0
                with open(STORE) as f:
                    lines = f.readlines()
                if len(lines) > MAX_STORE_LINES:
                    with open(STORE, "w") as f:
                        f.writelines(lines[-2000:])
        except OSError:
            pass


def evidence(eng, token):
    """The most recent callback record for a token, or None. The catcher names it by the token's secret part."""
    _, secret = token_parts(token)
    if not secret:
        return None
    folder = os.path.join(WORK, eng, "evidence", "oob")
    try:
        names = sorted(n for n in os.listdir(folder) if n.endswith(f"-{secret}.json"))
    except OSError:
        return None
    return os.path.join(folder, names[-1]) if names else None


def _record(eng, token, path, peer):
    """Write the callback's evidence and its audit entry. Runs in the catcher thread: never raises."""
    ts = datetime.datetime.now(datetime.timezone.utc)
    rel = os.path.join("evidence", "oob", f"{ts.strftime('%Y%m%dT%H%M%S')}-{token.rpartition('.')[2]}.json")
    full = os.path.join(WORK, eng, rel)
    try:
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            json.dump({"token": token, "at": ts.isoformat(timespec="seconds"), "from": peer,
                       "path": path, "catcher": ADVERTISE}, f, indent=1)
        import core   # the catcher runs inside the server process; core is already loaded there
        core._audit({"engagement": eng, "actor": "kit:oob-catcher", "action": "oob-callback", "token": token,
                     "outputs": {rel: core.sha256_file(full)}})
    except Exception:  # noqa: BLE001 - a callback is recorded best-effort; the oracle still decides from the token
        pass


# ---------------------------------------------------------------- the catcher
def _serve():
    try:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    except Exception:  # noqa: BLE001
        return

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.handle_callback()

        def do_POST(self):
            self.handle_callback()

        def handle_callback(self):
            token = self.path.strip("/").split("/", 1)[0].split("?", 1)[0]
            eng, _ = token_parts(token)
            if not eng:   # not the token shape: health probes, scanners and hostile junk are ignored
                self.send_response(204)
                self.end_headers()
                return
            mark(token)
            self.send_response(204)
            self.end_headers()
            if token in _expected():   # the oracle asked for this token: it is evidence, not noise
                _consume(token)
                _record(eng, token, self.path, self.client_address[0] if self.client_address else None)

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
    t = threading.Thread(target=_serve, daemon=True, name="oob-catcher")
    t.start()


if __name__ == "__main__":
    start()
    # keep the process alive
    while True:
        time.sleep(3600)
