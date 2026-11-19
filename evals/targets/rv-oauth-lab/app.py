"""RiskVoid OAuth lab: a small OAuth2 authorization server + protected resource with seeded flaws (the
vulnerable build) and a clean fixed variant (FIXED=1). Runs only on the kit's isolated lab network.

This is the lab target behind the OAuth2/OIDC playbook checks (api-security.md section 6, the `oauth` coverage
class). It implements the authorization-code flow with the four seeded flaws the playbook checks for, each with a
clean control in the fixed build:

  redirect_uri prefix    /authorize accepts any redirect_uri that merely starts with the registered one, so
                         https://client.example.com/callback.attacker.test/... is accepted (fixed: exact match)
  state not required     /authorize issues a code without a state parameter (fixed: 400 "state required")
  no PKCE enforcement    a code is issued without code_challenge and exchanged without code_verifier
                         (fixed: S256 is required at the authorize and token endpoints)
  code replay            the same authorization code is exchanged twice for two fresh token pairs
                         (fixed: the second exchange is 400 "code already used")

The protected resource (/resource) answers only with a valid access token, so an unauthenticated probe sees the
OAuth surface (authorize/token/resource) and the `oauth` coverage class applies to its map entries.
"""
import base64, hashlib, json, os, secrets, threading, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FIXED = os.environ.get("FIXED") == "1"
CLIENT_ID = "rv-oauth-client"
CLIENT_SECRET = "rv-oauth-client-secret"
REDIRECT = "https://client.example.com/callback"
LOCK = threading.Lock()

codes = {}    # code -> {client_id, redirect_uri, user, code_challenge, used}
access = {}   # access_token -> {user, client_id}
refresh = {}  # refresh_token -> {user, client_id}


def _pkce_ok(challenge, verifier):
    """S256: the challenge is the base64url SHA-256 of the verifier, as a client sends it."""
    if not challenge or not verifier:
        return False
    digest = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return digest == challenge


ROOT = """<!doctype html><html><head><title>OAuth lab</title></head>
<body><h1>OAuth2 authorization server (lab)</h1>
<p>Discovery: <a href="/.well-known/openid-configuration">/.well-known/openid-configuration</a>.</p>
<p>Start a flow: <a href="/authorize">/authorize</a>; the protected resource: <a href="/resource">/resource</a>.</p>
</body></html>"""


class H(BaseHTTPRequestHandler):
    server_version = "rv-oauth-lab/1.0"

    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json", headers=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path == "/":
            return self.send(200, ROOT, "text/html; charset=utf-8")
        if u.path == "/.well-known/openid-configuration":
            return self.send(200, json.dumps({
                "issuer": "http://oauth-lab", "authorization_endpoint": "/authorize",
                "token_endpoint": "/token", "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"]}))
        if u.path == "/authorize":
            return self._authorize(q)
        if u.path == "/resource":
            return self._resource()
        return self.send(404, json.dumps({"error": "not found"}))

    def _authorize(self, q):
        redirect_uri = q.get("redirect_uri", [""])[0]
        state = q.get("state", [""])[0]
        challenge = q.get("code_challenge", [""])[0]
        # FLAW 1 (vulnerable): redirect_uri is accepted when it only starts with the registered one.
        ok = redirect_uri == REDIRECT if FIXED else redirect_uri.startswith(REDIRECT)
        if not ok:
            return self.send(400, json.dumps({"error": "invalid redirect_uri"}))
        # FLAW 2 (vulnerable): state is optional.
        if FIXED and not state:
            return self.send(400, json.dumps({"error": "state required"}))
        # FLAW 3 (vulnerable): PKCE is optional.
        if FIXED and not challenge:
            return self.send(400, json.dumps({"error": "code_challenge required (PKCE)"}))
        code = secrets.token_urlsafe(24)
        with LOCK:
            codes[code] = {"client_id": q.get("client_id", [CLIENT_ID])[0], "redirect_uri": redirect_uri,
                           "user": "alice", "code_challenge": challenge, "used": False}
        loc = redirect_uri + ("&" if "?" in redirect_uri else "?") + \
            urllib.parse.urlencode({"code": code, **({"state": state} if state else {})})
        return self.send(302, "", ctype="text/plain", headers={"Location": loc})

    def _resource(self):
        h = self.headers.get("Authorization", "")
        tok = h[len("Bearer "):] if h.lower().startswith("bearer ") else ""
        with LOCK:
            who = access.get(tok)
        if not who:
            return self.send(401, json.dumps({"error": "invalid_token"}), headers={"WWW-Authenticate": "Bearer"})
        return self.send(200, json.dumps({"user": who["user"], "scope": "profile"}))

    def do_POST(self):
        u = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, 4000)).decode("utf-8", "replace")
        form = urllib.parse.parse_qs(body)
        if u.path == "/token":
            return self._token(form)
        return self.send(404, json.dumps({"error": "not found"}))

    def _token(self, form):
        grant = form.get("grant_type", [""])[0]
        if grant == "authorization_code":
            code = form.get("code", [""])[0]
            verifier = form.get("code_verifier", [""])[0]
            with LOCK:
                rec = codes.get(code)
                if not rec:
                    return self.send(400, json.dumps({"error": "invalid_grant"}))
                # FLAW 4 (vulnerable): the code is never marked used, so it can be replayed.
                if FIXED and rec["used"]:
                    return self.send(400, json.dumps({"error": "code already used"}))
                # FLAW 3 (vulnerable): the verifier is not checked.
                if FIXED and not _pkce_ok(rec["code_challenge"], verifier):
                    return self.send(400, json.dumps({"error": "invalid code_verifier"}))
                rec["used"] = True
                at, rt = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
                access[at] = {"user": rec["user"], "client_id": rec["client_id"]}
                refresh[rt] = {"user": rec["user"], "client_id": rec["client_id"]}
            return self.send(200, json.dumps({"access_token": at, "token_type": "Bearer", "refresh_token": rt}))
        if grant == "refresh_token":
            rt = form.get("refresh_token", [""])[0]
            with LOCK:
                who = refresh.get(rt)
                if not who:
                    return self.send(400, json.dumps({"error": "invalid_grant"}))
                at = secrets.token_urlsafe(24)
                access[at] = who
            return self.send(200, json.dumps({"access_token": at, "token_type": "Bearer"}))
        return self.send(400, json.dumps({"error": "unsupported grant_type"}))


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
