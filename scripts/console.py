#!/usr/bin/env python3
"""RiskVoid Console: a local web page for engagements, approvals, findings, reports and the audit log.

Run it with ./rvkit console. It runs on the host, not in a container, and binds 127.0.0.1 only: the agent's
containers can't reach it, so the agent can't approve its own commands or widen its scope. Every action goes
through the same control commands as ./rvkit (rvctl in kali-mcp, findings_db and report.py in findings-mcp).

Access needs the session token: ./rvkit console opens /login?t=<token>, which sets an HttpOnly, SameSite=Strict
cookie. Requests with another Host header (DNS rebinding) are refused, and every change needs the X-RV-Console
header, which a cross-site form or link can't send.
Python 3.9+, standard library only.
"""
import calendar, hmac, json, mimetypes, os, re, secrets, sqlite3, subprocess, sys, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.join(KIT, "scripts", "console")
NAME_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
FID_RX = re.compile(r"^F-\d{3,}$")


def env():
    out = {}
    try:
        for line in open(os.path.join(KIT, ".env")):
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.rstrip("\n").split("=", 1)
                out.setdefault(k.strip(), v.strip())
    except OSError:
        pass
    return out


E = env()
ENG_DIR = os.path.expanduser(E.get("ENGAGEMENTS_DIR") or "~/riskvoid/engagements")
PORT = int(os.environ.get("CONSOLE_PORT") or E.get("CONSOLE_PORT") or 8100)
TOKEN_FILE = os.path.join(KIT, ".rvkit", "console.token")


def token():
    os.makedirs(os.path.dirname(TOKEN_FILE), exist_ok=True)
    try:
        t = open(TOKEN_FILE).read().strip()
        if len(t) >= 32:
            return t
    except OSError:
        pass
    t = secrets.token_urlsafe(32)
    fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, t.encode())
    os.close(fd)
    return t


TOKEN = token()


# ---------------------------------------------------------------- backends
class Fail(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


def run(args, stdin=None, timeout=120, ok=(0,)):
    r = subprocess.run(args, cwd=KIT, input=stdin, capture_output=True, text=True, timeout=timeout)
    if r.returncode not in ok:
        msg = (r.stderr or r.stdout).strip().splitlines()
        raise Fail(msg[-1] if msg else f"{args[0]} failed ({r.returncode})")
    return r.stdout


def ctl(*args, stdin=None, ok=(0,), timeout=120):
    return run(["docker", "compose", "exec", "-T", "kali-mcp", "python3", "/opt/kali-mcp/rvctl.py", *args],
               stdin=stdin, ok=ok, timeout=timeout)


def findings_py(code, payload, timeout=600):
    """Run Python in findings-mcp (its findings_db and report modules) with a JSON payload on stdin."""
    out = run(["docker", "compose", "exec", "-T", "findings-mcp", "python3", "-c", code],
              stdin=json.dumps(payload), timeout=timeout)
    return json.loads(out.strip().splitlines()[-1])


def rvkit(*args, timeout=180):
    return run([os.path.join(KIT, "rvkit"), *args], timeout=timeout)


def eng_path(eng, *parts):
    if not NAME_RX.match(eng or ""):
        raise Fail("invalid engagement name")
    return os.path.join(ENG_DIR, eng, *parts)


def read(path, limit=1_000_000):
    try:
        with open(path, errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


def findings(eng):
    p = eng_path(eng, "findings.db")
    if not os.path.exists(p):
        return []
    con = sqlite3.connect(f"file:{urllib.parse.quote(p)}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        rows = [dict(r) for r in con.execute("SELECT * FROM findings ORDER BY id")]
    except sqlite3.Error:
        rows = []
    finally:
        con.close()
    for r in rows:
        try:
            r["evidence"] = json.loads(r.get("evidence") or "[]")
        except ValueError:
            r["evidence"] = [r.get("evidence")]
    return rows


def transcript_task(d, tid):
    """Rebuild a task summary from transcript.jsonl (worker versions before 0.2 kept tasks in memory only)."""
    steps, end, first = [], {}, None
    try:
        for line in open(os.path.join(d, "transcript.jsonl"), errors="replace"):
            try:
                e = json.loads(line)
            except ValueError:
                continue
            first = first or e.get("ts")
            if "end" in e:
                end = e
            for c in (e.get("assistant") or {}).get("tool_calls") or []:
                fn = c.get("function", {})
                if fn.get("name") == "finish":
                    continue
                try:
                    a = json.loads(fn.get("arguments") or "{}")
                except ValueError:
                    a = {}
                steps.append({"tool": fn.get("name"), "args": a})
    except OSError:
        return None
    ts = lambda v: calendar.timegm(time.strptime(v[:19], "%Y-%m-%dT%H:%M:%S")) if v else None  # noqa: E731 (UTC)
    return {"id": tid, "status": end.get("end", "interrupted"), "tier": "", "goal": "(from the transcript)",
            "started": ts(first), "finished": ts(end.get("ts")), "steps": steps, "result": end.get("result"),
            "error": end.get("error"), "candidates": []}


def counts(rows):
    c = {}
    for r in rows:
        c[r["status"]] = c.get(r["status"], 0) + 1
    return c


def meta(eng):
    out = {}
    for line in read(eng_path(eng, "report", "meta.txt")).splitlines():
        if ":" in line and not line.lstrip().startswith("#"):
            k, v = line.split(":", 1)
            out[k.strip().lower()] = v.strip()
    return out


_status = {"at": 0, "text": ""}


def stack_status():
    if time.time() - _status["at"] > 20:
        try:
            _status["text"] = re.sub(r"\x1b\[[0-9;]*m", "", rvkit("status", timeout=60))
        except Exception as e:  # noqa: BLE001
            _status["text"] = f"status unavailable: {e}"
        _status["at"] = time.time()
    return _status["text"]


# ---------------------------------------------------------------- API
def api_get(path, q):
    if path == "/api/overview":
        engs = json.loads(ctl("list", "--json") or "[]")
        for e in engs:
            rows = findings(e["engagement"])
            e["findings"] = counts(rows)
            e["client"] = meta(e["engagement"]).get("client", "")
            closed = os.path.isdir(os.path.join(ENG_DIR, "_archive")) and any(
                f.startswith(e["engagement"] + "-") and f.endswith(".tar.gz")
                for f in os.listdir(os.path.join(ENG_DIR, "_archive")))
            e["closed"] = bool(closed and e["halted"])
        return {"engagements": engs, "approvals": json.loads(ctl("approvals", "--json") or "[]"),
                "ui_url": f"http://localhost:{E.get('GATEWAY_PORT') or 8000}/"}
    if path == "/api/status":
        return {"text": stack_status()}
    m = re.match(r"^/api/eng/([^/]+)(?:/(\w+))?$", path)
    if not m:
        raise Fail("not found", 404)
    eng, what = m.group(1), m.group(2) or "detail"
    eng_path(eng)
    if what == "detail":
        info = json.loads(ctl("show", eng))
        rdir = eng_path(eng, "report")
        files = sorted((f for f in os.listdir(rdir) if f.endswith((".docx", ".pdf", ".xlsx"))), reverse=True) \
            if os.path.isdir(rdir) else []
        return {"engagement": eng, "info": info, "meta": meta(eng),
                "scope_text": read(eng_path(eng, "SCOPE.md")), "rules_text": read(eng_path(eng, "RULES.md")),
                "findings": findings(eng), "report_files": files,
                "executive_summary": read(eng_path(eng, "report", "executive-summary.md")),
                "approvals": [a for a in json.loads(ctl("approvals", eng, "--json") or "[]")]}
    if what == "audit":
        n = max(1, min(int(q.get("n", ["300"])[0]), 2000))
        lines = ctl("audit", eng, str(n)).splitlines()
        return {"entries": [json.loads(l) for l in lines if l.startswith("{")][::-1]}
    if what == "tasks":  # worker tasks, saved by worker-mcp next to their evidence
        tdir = eng_path(eng, "evidence", "tasks")
        out = []
        for tid in (os.listdir(tdir) if os.path.isdir(tdir) else []):
            try:
                t = json.load(open(os.path.join(tdir, tid, "task.json")))
            except (OSError, ValueError):
                t = transcript_task(os.path.join(tdir, tid), tid)  # tasks from before task.json existed
                if not t:
                    continue
            res = t.get("result") or {}
            out.append({"id": t.get("id"), "status": t.get("status"), "tier": t.get("tier"), "goal": t.get("goal"),
                        "started": t.get("started"), "finished": t.get("finished"), "models": t.get("served_by", []),
                        "steps": [s.get("args", {}).get("command") or s.get("args", {}).get("query")
                                  or s.get("args", {}).get("url") or s.get("args", {}).get("path") or s.get("tool")
                                  for s in t.get("steps", [])],
                        "candidates": len(t.get("candidates", [])), "summary": res.get("summary"),
                        "confidence": res.get("confidence"), "error": t.get("error")})
        return {"tasks": sorted(out, key=lambda t: t.get("started") or 0, reverse=True)[:100]}
    if what == "evidence":
        return findings_py(
            "import json,sys,report,findings_db as db\n"
            "e=json.load(sys.stdin)['eng']\n"
            "f=[x for x in db.list_(e) if x['status'] not in ('false-positive','duplicate')]\n"
            "items,issues=report.evidence_index(e,f)\n"
            "print(json.dumps({'items':items,'issues':issues}))", {"eng": eng}, timeout=120)
    raise Fail("not found", 404)


def api_post(path, body):
    if path == "/api/engagements":  # create
        name = body.get("name", "")
        if not NAME_RX.match(name):
            raise Fail("Name: letters, digits, dot, dash and underscore; start with a letter or digit.")
        targets = [t.strip() for t in str(body.get("targets", "")).splitlines() if t.strip()]
        if not targets:
            raise Fail("Add at least one target.")
        tiers = [t for t in body.get("tiers", []) if t in ("passive", "active", "intrusive")] or ["passive"]
        args = ["engagement", name, "--tiers", ",".join(tiers), "--rate", str(int(body.get("rate") or 100)),
                "--network", "offline" if body.get("network") == "offline" else "online"]
        if body.get("client"):
            args += ["--client", str(body["client"])[:200]]
        if body.get("private"):
            args.append("--private")
        if any(t.startswith("-") for t in targets):
            raise Fail("A target can't start with '-'.")
        return {"output": rvkit(*args, *targets)}
    m = re.match(r"^/api/eng/([^/]+)/(\w+)$", path)
    if m:
        eng, action = m.groups()
        eng_path(eng)
        if action == "preview":
            return json.loads(ctl("preview", eng, stdin=json.dumps({"scope": body.get("scope", ""),
                                                                    "rules": body.get("rules", "")})))
        if action == "apply":
            for f, key in (("SCOPE.md", "scope"), ("RULES.md", "rules")):
                if key in body:
                    with open(eng_path(eng, f), "w") as fh:
                        fh.write(str(body[key]))
            return {"output": ctl("sync", eng, "--yes")}
        if action in ("halt", "resume", "close"):
            return {"output": ctl(action, eng, timeout=600)}
        if action == "delete":
            return {"output": ctl("delete", eng, *(["--force"] if body.get("force") else []))}
        if action == "report":
            return findings_py(
                "import json,sys,report\n"
                "try:\n print(json.dumps(report.build(json.load(sys.stdin)['eng'])))\n"
                "except ValueError as e:\n print(json.dumps({'error':str(e)}))", {"eng": eng}, timeout=900)
        if action == "meta":
            p = eng_path(eng, "report", "meta.txt")
            cur = read(p).splitlines() or []
            keys = {"client": "Client", "prepared by": "Prepared by", "version": "Version",
                    "classification": "Classification"}
            vals = {k: str(body[k]).replace("\n", " ")[:200] for k in keys if k in body}
            out, seen = [], set()
            for line in cur:
                k = line.split(":", 1)[0].strip().lower() if ":" in line else None
                if k in vals:
                    out.append(f"{keys[k]}: {vals[k]}"); seen.add(k)
                else:
                    out.append(line)
            out += [f"{keys[k]}: {v}" for k, v in vals.items() if k not in seen]
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                fh.write("\n".join(out) + "\n")
            return {"meta": meta(eng)}
        if action == "summary":
            p = eng_path(eng, "report", "executive-summary.md")
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                fh.write(str(body.get("text", ""))[:200_000])
            return {"saved": True}
        if action == "finding":
            fid = body.get("id", "")
            if not FID_RX.match(fid):
                raise Fail("invalid finding id")
            fields = {k: body[k] for k in ("status", "severity", "notes", "duplicate_of", "title") if k in body}
            if fields.get("duplicate_of") == "":
                fields.pop("duplicate_of")
            return findings_py(
                "import json,sys,findings_db as db\n"
                "d=json.load(sys.stdin)\n"
                "try:\n print(json.dumps({'finding':db.update(d['eng'],d['id'],**d['fields'])}))\n"
                "except ValueError as e:\n print(json.dumps({'error':str(e)}))",
                {"eng": eng, "id": fid, "fields": fields}, timeout=60)
    m = re.match(r"^/api/approvals/([^/]+)/([a-f0-9]{6,32})/(approve|deny)$", path)
    if m:
        eng, aid, action = m.groups()
        eng_path(eng)
        return {"output": ctl(action, eng, aid)}
    raise Fail("not found", 404)


# ---------------------------------------------------------------- HTTP
class H(BaseHTTPRequestHandler):
    server_version = "rvconsole"

    def log_message(self, fmt, *args):  # quiet; errors still print
        pass

    def _send(self, code, body, ctype="application/json", extra=None):
        data = body if isinstance(body, bytes) else (json.dumps(body) if ctype == "application/json" else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith(("text/", "application/json")) else ""))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                         "frame-ancestors 'none'; form-action 'self'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _host_ok(self):
        return self.headers.get("Host", "") in (f"127.0.0.1:{PORT}", f"localhost:{PORT}")

    def _authed(self):
        c = self.headers.get("Cookie", "")
        m = re.search(r"(?:^|;\s*)rvc=([A-Za-z0-9_-]+)", c)
        return bool(m) and hmac.compare_digest(m.group(1), TOKEN)

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, {"error": "wrong host"})
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path == "/login":
            if hmac.compare_digest(q.get("t", [""])[0], TOKEN):
                return self._send(303, b"", "text/plain", {
                    "Location": "/", "Set-Cookie": f"rvc={TOKEN}; HttpOnly; SameSite=Strict; Path=/"})
            return self._send(403, "Wrong or expired link. Run ./rvkit console again.", "text/plain")
        if not self._authed():
            return self._send(401, "Open the console with ./rvkit console (it signs you in).", "text/plain")
        if u.path in ("/", "/index.html"):
            return self._send(200, open(os.path.join(HERE, "index.html"), "rb").read(), "text/html")
        if u.path in ("/app.js", "/app.css"):
            return self._send(200, open(os.path.join(HERE, u.path[1:]), "rb").read(),
                              "text/javascript" if u.path.endswith(".js") else "text/css")
        m = re.match(r"^/files/([^/]+)/([^/]+)$", u.path)
        if m:
            eng, name = m.group(1), urllib.parse.unquote(m.group(2))
            if not NAME_RX.match(eng) or not re.match(r"^[A-Za-z0-9._-]+\.(docx|pdf|xlsx)$", name):
                return self._send(404, {"error": "not found"})
            p = eng_path(eng, "report", name)
            if not os.path.isfile(p):
                return self._send(404, {"error": "not found"})
            return self._send(200, open(p, "rb").read(), mimetypes.guess_type(name)[0] or "application/octet-stream",
                              {"Content-Disposition": f'attachment; filename="{name}"'})
        if u.path.startswith("/api/"):
            return self._api(lambda: api_get(u.path, q))
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._host_ok():
            return self._send(403, {"error": "wrong host"})
        if not self._authed() or self.headers.get("X-RV-Console") != "1":
            return self._send(401, {"error": "not signed in"})
        n = int(self.headers.get("Content-Length") or 0)
        if n > 2_000_000:
            return self._send(413, {"error": "too large"})
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, {"error": "invalid JSON"})
        self._api(lambda: api_post(urllib.parse.urlsplit(self.path).path, body))

    def _api(self, fn):
        try:
            self._send(200, fn())
        except Fail as e:
            self._send(e.code, {"error": str(e)})
        except subprocess.TimeoutExpired:
            self._send(504, {"error": "the kit didn't answer in time; is the stack up? (./rvkit status)"})
        except Exception as e:  # noqa: BLE001
            self._send(500, {"error": f"{type(e).__name__}: {e}"})


def main():
    if "--print-url-only" in sys.argv:
        print(f"http://127.0.0.1:{PORT}/login?t={TOKEN}"); return
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    srv.daemon_threads = True
    url = f"http://127.0.0.1:{PORT}/login?t={TOKEN}"
    print(f"RiskVoid Console on http://127.0.0.1:{PORT}/  (Ctrl-C to stop)", flush=True)
    if "--open" in sys.argv:
        threading.Timer(0.5, lambda: subprocess.run(
            ["open" if sys.platform == "darwin" else "xdg-open", url], capture_output=True)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
