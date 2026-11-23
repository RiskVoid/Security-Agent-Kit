"""Route Family Research Lab (#80): a tenant-scoped order API whose three seeded situations are what the
research-loop phases (#77) are measured against.

  - A route family: read, export and download share one authorization helper that checks the session but not
    the tenant - one tenant-isolation defect with several operations behind it - while the sibling audit
    route checks the tenant too: the protected control a report must not count as broken.
  - An identity that arrives late: /api/v1/admin/* answers "no admin identity is provisioned" until the
    operator supplies one. The accounts live in identities.json, read per request, so the runner's timed
    event (evals/run_benchmark.py) swaps in identities-admin.json partway through the run.
  - A build that changes mid-run: /api/v1/users/{id}?callback=... reflects the callback into the page
    unescaped, until the fix is in (RV_RESEARCH_FIXED=1, or the /app/.fixed marker the runner's event
    touches): the request-time flag models a rebuild without moving the address.

handle() is plain Python so the seed test (evals/unit_test.py) drives every case with no sockets and no
model; main() wraps it in http.server. The OpenAPI spec at /openapi.json lists every route for the recon map.
Tokens: POST /api/v1/login, then Authorization: Bearer <token>.
"""
import html
import json
import os
import urllib.parse

FIXED_MARKER = os.environ.get("RV_FIXED_MARKER", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                              ".fixed"))
_APP_DIR = os.path.dirname(os.path.abspath(__file__))
ORDERS = {  # tenant -> order -> record; both tenants can see the family, only one owns each order
    "acme": {"O-1001": {"id": "O-1001", "total": 149.00, "status": "shipped", "note": "q3 promo order"},
             "O-1002": {"id": "O-1002", "total": 89.90, "status": "paid", "note": "reseller bundle"},
             "O-1003": {"id": "O-1003", "total": 12.50, "status": "open", "note": "spare parts"}},
    "brit": {"O-2001": {"id": "O-2001", "total": 250.00, "status": "shipped", "note": "eu warehouse"},
             "O-2002": {"id": "O-2002", "total": 47.20, "status": "refunded", "note": "damaged box"}},
}
TOKENS = {}       # token -> username, this process only: a new login is a new token


def fixed():
    """The one issue (reflected callback) is fixed while this is true - per request, so the runner's mid-run
    rebuild event only touches a marker file."""
    return bool(os.environ.get("RV_RESEARCH_FIXED")) or os.path.exists(FIXED_MARKER)


def _users():
    """The accounts, read per request from identities-active.json (the runner's timed event swaps it to add the
    late admin identity; a fresh run resets it back). Falls back to the shipped identities.json."""
    path = os.environ.get("RV_IDENTITIES") or os.path.join(_APP_DIR, "identities-active.json")
    if not os.path.exists(path):
        path = os.path.join(_APP_DIR, "identities.json")
    with open(path) as f:
        return {u["username"]: u for u in json.load(f)}


def _order(oid):
    for orders in ORDERS.values():
        if oid in orders:
            return orders[oid]
    return None


def authorize_order(user, oid):
    """The one shared authorization check for the whole family: it verifies the session's user exists but not
    the order's tenant - the seeded defect. The audit route adds the tenant check itself (the control)."""
    return _order(oid) is not None


def handle(method, path, query=None, body=None, token="", force_fixed=None):
    """One request as (status, content_type, payload). payload is a dict for JSON, a string otherwise."""
    query = {k: v[-1] for k, v in (query or {}).items()}
    user = _users().get(TOKENS.get(token) or "") if token else None

    if path == "/" and method == "GET":
        return 200, "application/json", {"app": "Route Family Research Lab", "spec": "/openapi.json",
                                          "login": "POST /api/v1/login"}
    if path == "/openapi.json" and method == "GET":
        return 200, "application/json", SPEC

    if path == "/api/v1/login" and method == "POST":
        try:
            cred = json.loads(body or b"{}")
        except ValueError:
            return 400, "application/json", {"error": "the body must be JSON"}
        u = _users().get(cred.get("username") or "")
        if not u or cred.get("password") != u["password"]:
            return 401, "application/json", {"error": "unknown user or wrong password"}
        tok = "tok-" + os.urandom(8).hex()
        TOKENS[tok] = u["username"]
        return 200, "application/json", {"token": tok, "role": u["role"], "tenant": u["tenant"]}

    if method == "GET" and path.startswith("/api/v1/users/"):
        uid = path.rsplit("/", 1)[1]
        callback = query.get("callback", "")
        is_fixed = fixed() if force_fixed is None else force_fixed
        name = html.escape(uid) if is_fixed else uid
        back = html.escape(callback) if is_fixed else callback
        return 200, "text/html", (f"<!doctype html><html><body><h1>user {name}</h1>"
                                  f"<div>go back to: {back}</div>"
                                  f'<a href="{back}">back</a></body></html>')

    if not user:
        return 401, "application/json", {"error": "log in first: POST /api/v1/login, then Bearer <token>"}

    if path == "/api/v1/orders" and method == "GET":
        return 200, "application/json", {"orders": list(ORDERS[user["tenant"]])}

    if method == "GET":
        import re
        hit = re.match(r"^/api/v1/orders/([^/]+?)(/export|/download|/audit)?$", path)
        if hit:
            oid, op = hit.group(1), (hit.group(2) or "").lstrip("/")
            order = _order(oid)
            if order is None:
                return 404, "application/json", {"error": f"no order {oid}"}
            tenant = next(t for t, o in ORDERS.items() if oid in o)
            if op == "audit":   # the protected sibling: the tenant check the family's shared helper lacks
                if tenant != user["tenant"]:
                    return 403, "application/json", {"error": f"order {oid} belongs to another tenant"}
                return 200, "application/json", {"order": oid, "audited_by": user["username"],
                                                 "events": ["created", "billed", order["status"]]}
            if not authorize_order(user, oid):   # pragma: no cover - it never refuses: the seeded defect
                return 403, "application/json", {"error": "not your order"}
            if op == "export":
                row = ",".join([order["id"], str(order["total"]), order["status"], order["note"]])
                return 200, "text/csv", f"id,total,status,note\n{row}\n"
            if op == "download":
                return 200, "application/json", {"file": f"order-{oid}.json", "content": order,
                                                 "tenant": tenant}
            return 200, "application/json", {**order, "tenant": tenant}

    if path.startswith("/api/v1/admin/"):
        if user.get("role") != "admin":
            return 403, "application/json", {"error": "admin identity required"}
        if path == "/api/v1/admin/users" and method == "GET":
            # the flaw behind the late identity: a listing that hands out every tenant's credentials
            rows = [{"username": u, "password": d["password"], "tenant": d["tenant"]} for u, d in _users().items()]
            return 200, "application/json", {"users": rows}
        if path == "/api/v1/admin/purge" and method == "POST":
            try:
                oid = json.loads(body or b"{}").get("order")
            except ValueError:
                oid = None
            for orders in ORDERS.values():
                orders.pop(oid, None)
            return 200, "application/json", {"purged": oid}
        return 404, "application/json", {"error": "no such admin route"}

    return 404, "application/json", {"error": f"no route {method} {path}"}


SPEC = {"openapi": "3.0.0", "info": {"title": "Route Family Research Lab", "version": "1.0.0"},
        "paths": {
            "/api/v1/login": {"post": {"summary": "log in, get a bearer token"}},
            "/api/v1/orders": {"get": {"summary": "list your tenant's orders", "security": [{"bearer": []}]}},
            "/api/v1/orders/{id}": {"get": {"summary": "read one order", "security": [{"bearer": []}]}},
            "/api/v1/orders/{id}/export": {"get": {"summary": "export one order as CSV",
                                                   "security": [{"bearer": []}]}},
            "/api/v1/orders/{id}/download": {"get": {"summary": "download one order as a JSON file",
                                                     "security": [{"bearer": []}]}},
            "/api/v1/orders/{id}/audit": {"get": {"summary": "the audit trail of one order",
                                                  "security": [{"bearer": []}]}},
            "/api/v1/users/{id}": {"get": {"summary": "a public profile page (callback: where Back returns)"}},
            "/api/v1/admin/users": {"get": {"summary": "every account, admin only",
                                            "security": [{"bearer": []}]}},
            "/api/v1/admin/purge": {"post": {"summary": "delete an order, admin only",
                                             "security": [{"bearer": []}]}},
        },
        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}}}


def main():
    import http.server

    class Handler(http.server.BaseHTTPRequestHandler):
        def _run(self, method):
            parsed = urllib.parse.urlsplit(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            status, ctype, payload = handle(method, parsed.path, urllib.parse.parse_qs(parsed.query), body,
                                            (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip())
            data = json.dumps(payload).encode() if isinstance(payload, dict) else str(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith("text/") else ""))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._run("GET")

        def do_POST(self):
            self._run("POST")

        def log_message(self, fmt, *args):
            pass

    os.makedirs(os.path.dirname(FIXED_MARKER) or ".", exist_ok=True)
    http.server.ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8000"))), Handler).serve_forever()


if __name__ == "__main__":
    main()
