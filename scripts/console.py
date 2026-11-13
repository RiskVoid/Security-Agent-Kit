#!/usr/bin/env python3
"""RiskVoid Console: a local web page for engagements, approvals, findings, reports and the audit log.

Run it with ./rvkit console. It runs on the host, not in a container, and binds 127.0.0.1 only: the agent's
containers can't reach it, so the agent can't approve its own commands or widen its scope. Every action goes
through the same validated operations as ./rvkit and the agent's tools: rvctl in kali-mcp for scope, approvals and
lifecycle, harness/ops.py in findings-mcp for findings, report details and the report. Each change names its actor
(console:<login>) and the revision it was based on; a record that changed in the meantime gives 409 Conflict.
Changes land in the engagement's audit log.

Access needs the session token: ./rvkit console opens /login?t=<token>, which sets an HttpOnly, SameSite=Strict
cookie. Requests with another Host header (DNS rebinding) are refused, and every change needs the X-RV-Console
header, which a cross-site form or link can't send.
Python 3.9+, standard library only.
"""
import calendar, getpass, hashlib, hmac, json, mimetypes, os, re, secrets, sqlite3, subprocess, sys, threading, time
import queue, urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import model_events  # noqa: E402  (log written by litellm/rv_events.py)
import conversations  # noqa: E402  (OpenHands conversations bound to engagements)
import agent_view  # noqa: E402  (a bound conversation as the Agent section shows it)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "litellm"))
import rv_routes  # noqa: E402  (where each model route sends data)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "evals"))
import failures  # noqa: E402  (what went wrong in engagements and benchmark runs, grouped by cause)

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.join(KIT, "scripts", "console")
ASSETS = os.path.join(KIT, "harness", "assets")   # brand logo and fonts, shared with the report
STATIC = {"/app.js": (HERE, "app.js", "text/javascript"), "/app.css": (HERE, "app.css", "text/css"),
          "/assets/riskvoid-logo.png": (ASSETS, "riskvoid-logo.png", "image/png"),
          "/assets/fonts/inter-latin.woff2": (ASSETS, "fonts/inter-latin.woff2", "font/woff2"),
          "/assets/fonts/jetbrains-mono-latin.woff2": (ASSETS, "fonts/jetbrains-mono-latin.woff2", "font/woff2")}
REPORT_EXT = (".html", ".docx", ".pdf", ".xlsx")
REPORT_NAME = re.compile(r"^[A-Za-z0-9._-]+\.(html|docx|pdf|xlsx)$")
# report revisions, exports and notices (RW-019 to RW-021): report/<sub>/<R-id or name>/<file>
DELIVERY_PATH = re.compile(r"^(revisions/R-\d{3,}(?:-rebuild-\d{8}T\d{6})?/[A-Za-z0-9._-]+\.(?:html|docx|pdf|xlsx|json)"
                           r"|exports/R-\d{3,}(?:-DRAFT)?/(?:issues/)?[A-Za-z0-9._-]+\.(?:json|sarif|md)"
                           r"|notices/N-\d{3,}-F-\d{3,}\.md)$")
# the HTML report is shown as a document: no scripts, nothing loaded from anywhere (fonts and logo are embedded)
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; sandbox"
NAME_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
FID_RX = re.compile(r"^F-\d{3,}$")


def env():
    out = {}
    try:
        with open(os.path.join(KIT, ".env")) as f:
            for line in f:
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
try:
    _login = getpass.getuser()
except Exception:  # noqa: BLE001
    _login = "host"
ACTOR = "console:" + (re.sub(r"[^A-Za-z0-9._@-]", "", _login)[:64] or "host")


def token():
    os.makedirs(os.path.dirname(TOKEN_FILE), exist_ok=True)
    try:
        with open(TOKEN_FILE) as f:
            t = f.read().strip()
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
try:
    with open(os.path.join(KIT, "VERSION")) as _f:
        VERSION = _f.read().strip()
except OSError:
    VERSION = ""


# ---------------------------------------------------------------- backends
class Fail(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


def run(args, stdin=None, timeout=120, ok=(0,), env=None):
    r = subprocess.run(args, cwd=KIT, input=stdin, capture_output=True, text=True, timeout=timeout,
                       env={**os.environ, **(env or {})})
    if r.returncode not in ok:
        msg = (r.stderr or r.stdout).strip().splitlines()
        text = msg[-1] if msg else f"{args[0]} failed ({r.returncode})"
        if r.returncode == 3:  # rvctl: the record changed since it was read
            raise Fail(re.sub(r"^conflict:\s*", "", text), 409)
        raise Fail(re.sub(r"^error:\s*", "", text))
    return r.stdout


def ctl(*args, stdin=None, ok=(0,), timeout=120):
    """rvctl in kali-mcp (scope, approvals, lifecycle, audit), acting as this console's user."""
    return run(["docker", "compose", "exec", "-T", "kali-mcp", "python3", "/opt/kali-mcp/rvctl.py", "--actor", ACTOR,
                *args], stdin=stdin, ok=ok, timeout=timeout)


def ops(name, eng, timeout=120, **req):
    """One operation of harness/ops.py in findings-mcp. A change is added to the engagement's audit log."""
    out = run(["docker", "compose", "exec", "-T", "findings-mcp", "python3", "ops.py", name],
              stdin=json.dumps({"engagement": eng, "actor": ACTOR, **req}), timeout=timeout, ok=(0, 1, 3))
    try:
        d = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Fail(f"{name}: no answer from findings-mcp", 502)
    if "error" in d:
        raise Fail(d["error"], d.get("code", 400))
    if d.get("event"):
        try:
            ctl("record", eng, stdin=json.dumps(d["event"]))
        except Fail as e:  # the change itself is saved; say that the history is missing it
            d["result"] = {**(d["result"] if isinstance(d["result"], dict) else {"value": d["result"]}),
                           "warning": f"saved, but not added to the audit log: {e}"}
    return d["result"]


def rvkit(*args, timeout=180):
    return run([os.path.join(KIT, "rvkit"), *args], timeout=timeout, env={"RVKIT_ACTOR": ACTOR})


def digest(text):
    """Same digest as harness/ops.py, so the page can say which version of a file it edited."""
    return hashlib.sha256((text or "").encode()).hexdigest()[:16]


def eng_path(eng, *parts):
    if not NAME_RX.match(eng or ""):
        raise Fail("invalid engagement name")
    return os.path.join(ENG_DIR, eng, *parts)


def read(path, limit=1_000_000):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


def findings(eng):
    p = eng_path(eng, ".rv/findings.db")   # an older kit's location until a service moves it
    if not os.path.exists(p):
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
        try:
            r["instances"] = json.loads(r.get("instances") or "[]")
        except ValueError:
            r["instances"] = []
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


def conv_list(eng):
    try:
        return conversations.listing(eng, ACTOR)
    except conversations.Fail as e:
        return {"error": str(e)}


TASK_RX = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def task_control(eng, tid, action):
    """Ask worker-mcp to cancel or resume a task (a request file only the host and worker-mcp can write)."""
    if not TASK_RX.match(tid or ""):
        raise Fail("invalid task id")
    if not os.path.isfile(eng_path(eng, "evidence", "tasks", tid, "task.json")):
        raise Fail(f"no task {tid} in {eng}", 404)
    d = os.path.join(ENG_DIR, ".control", "tasks")
    os.makedirs(d, exist_ok=True)
    res = os.path.join(d, tid + ".result")
    try:
        os.remove(res)
    except OSError:
        pass
    with open(os.path.join(d, tid + ".json.tmp"), "w") as f:
        json.dump({"action": action, "by": ACTOR}, f)
    os.replace(os.path.join(d, tid + ".json.tmp"), os.path.join(d, tid + ".json"))
    for _ in range(40):
        if os.path.exists(res):
            r = json.load(open(res))
            if not r.get("ok"):
                raise Fail(r.get("error") or "the worker refused", 409)
            return {"output": f"task {tid}: {action} requested"}
        time.sleep(0.25)
    raise Fail("the worker didn't answer (is worker-mcp running?)", 504)


CRED_RX = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")
IDENT_RX = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


def worker_tasks(eng):
    """Worker tasks, saved by worker-mcp next to their evidence, newest first."""
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
        ap = t.get("approval") or {}
        out.append({"id": t.get("id"), "status": t.get("status"), "tier": t.get("tier"), "goal": t.get("goal"),
                    "approval": {"id": ap.get("id"), "action": ap.get("action")} if ap.get("id") else None,
                    "recovery": t.get("recovery"), "depends_on": t.get("depends_on") or [],
                    "resumed": len(t.get("resumed") or []),
                    "uncertain": [s.get("args", {}).get("command") or s.get("args", {}).get("url") or s.get("tool")
                                  for s in t.get("steps", []) if s.get("state") == "uncertain"],
                    "started": t.get("started"), "finished": t.get("finished"), "models": t.get("served_by", []),
                    "steps": [s.get("args", {}).get("command") or s.get("args", {}).get("query")
                              or s.get("args", {}).get("url") or s.get("args", {}).get("path") or s.get("tool")
                              for s in t.get("steps", [])],
                    "candidates": len(t.get("candidates", [])), "summary": res.get("summary"),
                    "confidence": res.get("confidence"), "error": t.get("error")})
    return sorted(out, key=lambda t: t.get("started") or 0, reverse=True)[:100]


_spend = {"at": 0, "data": None}


def spend():
    """Today's model spend (all budgeted providers) against the daily budget, from LiteLLM (cached 15 s; None if it doesn't answer)."""
    if time.time() - _spend["at"] > 15:
        data = None
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{E.get('LITELLM_PORT') or 4000}/provider/budgets",
                                         headers={"Authorization": f"Bearer {E.get('LITELLM_MASTER_KEY', '')}"})
            with urllib.request.urlopen(req, timeout=3) as r:
                provs = json.load(r).get("providers") or {}
            # one daily budget per provider (OpenRouter, Anthropic when the planner uses it directly): show the busiest
            top = max(provs.values(), key=lambda b: float(b.get("spend") or 0), default={})
            data = {"spend": sum(float(b.get("spend") or 0) for b in provs.values()), "providers": sorted(provs),
                    "budget": float(E.get("OPENROUTER_DAILY_BUDGET") or 0) or None, "top": float(top.get("spend") or 0)}
        except (OSError, ValueError, TypeError):
            pass
        _spend.update(at=time.time(), data=data)
    return _spend["data"]


# ---------------------------------------------------------------- API
def overview():
    """Engagements with their state and finding counts, pending approvals, model problems of the last 24 h."""
    engs = json.loads(ctl("list", "--json") or "[]")
    for e in engs:
        rows = findings(e["engagement"])
        e["findings"] = counts(rows)
        e["client"] = meta(e["engagement"]).get("client", "")
        closed = os.path.isdir(os.path.join(ENG_DIR, "_archive")) and any(
            f.startswith(e["engagement"] + "-") and f.endswith(".tar.gz")
            for f in os.listdir(os.path.join(ENG_DIR, "_archive")))
        e["closed"] = bool(closed and e["halted"])
        e["model_problems"] = len(model_events.recent(86400, problems_only=True, engagement=e["engagement"]))
        # what the page notifies about once: material findings, and worker tasks that ended or need a decision
        e["notices"] = [f"finding:{r['id']}:{r['status']}:{r['severity']}" for r in rows
                        if r["severity"] in ("critical", "high") and r["status"] in ("candidate", "confirmed")]
        e["notices"] += [f"task:{t['id']}:{t['status']}" for t in worker_tasks(e["engagement"])[:20]
                         if t["status"] in ("done", "error", "interrupted", "blocked", "awaiting_approval")]
    return {"engagements": engs, "approvals": json.loads(ctl("approvals", "--json") or "[]"),
            "models": rv_routes.models(E),
            "ui_url": f"http://localhost:{E.get('GATEWAY_PORT') or 8000}/", "version": VERSION,
            # failed model calls of the last 24 h (litellm/rv_events.py): the Model log badges
            "model_problems": len(model_events.recent(86400, problems_only=True))}


def live(eng):
    """What an engagement is doing now: running commands, worker tasks, latest events, approvals, spend."""
    lv, tasks = json.loads(ctl("live", eng, "15")), worker_tasks(eng)
    busy = [t for t in tasks if t["status"] in ("running", "queued")]
    return {**lv, "now": time.time(), "events": lv["events"][::-1], "spend": spend(),
            "tasks": busy + [t for t in tasks if t not in busy][:3]}


class Hub:
    """Server-sent events for the page (/api/stream): one poller per topic, shared by every open page and running
    only while someone listens; a snapshot goes out when it differs from the last one. Topics: "overview" and
    "live:<engagement>". The sources are the same calls the page used to poll; the transport lets later sources
    (task runs, approvals) push without the page changing."""
    SOURCES = {"overview": (overview, 3.0), "live": (live, 2.0)}

    def __init__(self):
        self.lock, self.topics = threading.Lock(), {}

    def subscribe(self, topic):
        q = queue.Queue(maxsize=50)
        with self.lock:
            t = self.topics.get(topic)
            if not t:
                t = self.topics[topic] = {"subs": set(), "last": None, "msg": None}
                threading.Thread(target=self._poll, args=(topic,), daemon=True).start()
            t["subs"].add(q)
            if t["msg"]:
                q.put(t["msg"])
        return q

    def unsubscribe(self, topic, q):
        with self.lock:
            t = self.topics.get(topic)
            if t:
                t["subs"].discard(q)

    def _poll(self, topic):
        kind, _, arg = topic.partition(":")
        fn, every = self.SOURCES[kind]
        while True:
            with self.lock:
                t = self.topics[topic]
                if not t["subs"]:
                    del self.topics[topic]
                    return
            try:
                data, name = fn(arg) if arg else fn(), kind
            except Exception as e:  # noqa: BLE001 (the page shows it; polling goes on)
                data, name = {"error": str(e) if isinstance(e, Fail) else f"{type(e).__name__}: {e}"}, "problem"
            key = json.dumps({k: v for k, v in data.items() if k != "now"}, sort_keys=True, default=str)
            if key != t["last"]:
                msg = (name, json.dumps({**data, "topic": topic}, default=str))
                with self.lock:
                    t["last"], t["msg"] = key, msg
                    for q in list(t["subs"]):
                        try:
                            q.put_nowait(msg)
                        except queue.Full:  # a stalled page: drop it, the browser reconnects
                            t["subs"].discard(q)
            time.sleep(every)


HUB = Hub()


def api_get(path, q):
    if path == "/api/overview":
        return overview()
    if path == "/api/models":  # the model log: all calls, or one engagement's (eng=<name>)
        eng = q.get("eng", [None])[0]
        if eng and not NAME_RX.match(eng):
            raise Fail("bad engagement name")
        raw = (q.get("since") or ["604800"])[0]
        since = min(max(int(raw) if raw.isdigit() else 604800, 60), 30 * 86400)
        return {"events": model_events.recent(since, engagement=eng)[:300]}
    if path == "/api/failures":  # failure records by cause: engagements (ids and causes only) or benchmark runs
        bench = (q.get("source") or ["engagements"])[0] == "bench"
        return failures.overview(failures.load(failures.STORE if bench else failures.ENG_STORE), engagements=not bench)
    if path == "/api/failures/detail":  # what is behind one cause in one engagement, read from the engagement now
        eng, cause = (q.get("eng") or [""])[0], (q.get("cause") or [""])[0]
        if not NAME_RX.match(eng) or not os.path.isdir(eng_path(eng)) or not cause or len(cause) > 300:
            raise Fail("bad engagement or cause")
        return failures.engagement_details(eng, cause, ENG_DIR)
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
        files = sorted((f for f in os.listdir(rdir) if f.endswith(REPORT_EXT)), reverse=True) \
            if os.path.isdir(rdir) else []
        summary = read(eng_path(eng, "report", "executive-summary.md"))
        return {"engagement": eng, "info": info, "meta": meta(eng),
                "meta_digest": digest(read(eng_path(eng, "report", "meta.txt"))),
                "scope_text": read(eng_path(eng, "SCOPE.md")), "rules_text": read(eng_path(eng, "RULES.md")),
                "findings": findings(eng), "report_files": files,
                "executive_summary": summary, "summary_digest": digest(summary),
                "approvals": [a for a in json.loads(ctl("approvals", eng, "--json") or "[]")],
                "credentials": json.loads(ctl("cred", eng, "list", "--json") or "[]"),
                "models": rv_routes.models(E), "conversations": conv_list(eng)}
    if what == "testing":  # identities, captures and authorization matrices (RW-008 to RW-011)
        results = {}
        adir = eng_path(eng, "evidence", "authz")
        for fn in sorted(os.listdir(adir)) if os.path.isdir(adir) else []:
            if fn.endswith(".json"):
                try:
                    r = json.load(open(os.path.join(adir, fn)))
                    results[r["matrix"]] = {"at": r["at"], "summary": r["summary"], "cells": r["cells"],
                                            "file": f"evidence/authz/{fn}", "digest": r["digest"]}
                except (OSError, ValueError, KeyError):
                    continue
        return {"identities": json.loads(ctl("identity", eng, "list", "--json") or "[]"),
                "captures": json.loads(ctl("capture", eng, "list") or "[]"),
                "matrices": json.loads(ctl("authz", eng, "list") or "[]"), "results": results}
    if what == "capture":
        cid = q.get("id", [""])[0]
        if not re.fullmatch(r"[a-z0-9-]{4,40}", cid):
            raise Fail("bad capture id")
        return json.loads(ctl("capture", eng, "show", cid))
    if what == "matrix":
        name = q.get("name", [""])[0]
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,47}", name):
            raise Fail("bad matrix name")
        return json.loads(ctl("authz", eng, "show", name))
    if what == "audit":
        raw = q.get("n", ["300"])[0]
        if not raw.isdigit():
            raise Fail("n must be a number")
        n = max(1, min(int(raw), 2000))
        lines = ctl("audit", eng, str(n)).splitlines()
        return {"entries": [json.loads(l) for l in lines if l.startswith("{")][::-1]}
    if what == "tasks":
        return {"tasks": worker_tasks(eng)}
    if what == "agent":  # a bound conversation: messages and typed tool calls (read-only)
        cid, rev = q.get("id", [""])[0], q.get("rev", [""])[0]
        if not agent_view.CID_RX.match(cid):
            raise Fail("invalid conversation id")
        if rev and not re.fullmatch(r"[0-9a-f]{16}", rev):
            raise Fail("invalid rev")
        try:
            return agent_view.view(eng, cid, ACTOR, rev)
        except conversations.Fail as e:
            raise Fail(str(e), 404 if "not bound" in str(e) else 502)
    if what == "live":
        return live(eng)
    if what == "evidence":
        return ops("evidence.index", eng)
    if what == "delivery":  # report revisions, readiness, retests, cleanup, notices (RW-019 to RW-021)
        return ops("report.revisions", eng)
    if what == "investigation":  # objective, handover, coverage, observations (RW-015 to RW-018)
        return ops("investigation.get", eng)
    if what == "history":
        fid = q.get("id", [""])[0]
        if not FID_RX.match(fid):
            raise Fail("invalid finding id")
        return ops("finding.history", eng, id=fid)
    if what == "preview":
        p = q.get("path", [""])[0]
        if not p or len(p) > 500:
            raise Fail("path: a file of the engagement")
        return ops("evidence.preview", eng, path=p)
    raise Fail("not found", 404)


TARGET_RX = re.compile(r"^!?[A-Za-z0-9._:/\[\]*%@,-]+$")  # IPs, CIDRs, names (incl. *.), :ports, URLs, /src, !exclusions


def field(body, key, kind, default):
    """A request field of the expected JSON type (400 otherwise); default when absent or null."""
    v = body.get(key)
    if v is None:
        return default
    if kind is not bool and isinstance(v, bool) or not isinstance(v, kind):
        names = kind.__name__ if isinstance(kind, type) else " or ".join(k.__name__ for k in kind)
        raise Fail(f"{key}: expected {names}")
    return v


REV_RX = re.compile(r"^[0-9a-f]{16}$")


def digest_field(body):
    d = field(body, "digest", str, None)
    if d is not None and not REV_RX.match(d):
        raise Fail("digest: expected the value the page loaded")
    return d


def api_post(path, body):
    if path == "/api/failures/collect":  # read every engagement again (not a benchmark's): replaces its records
        notes, done = [], 0
        for name in failures.engagement_names(ENG_DIR):
            try:
                failures.record_engagement(name, ENG_DIR, note=notes.append)
                done += 1
            except (SystemExit, OSError, sqlite3.Error, ValueError) as e:
                notes.append(f"{name} not collected: {str(e)[:120]}")
        return {"collected": done, **({"warning": "; ".join(notes[:3])} if notes else {})}
    if path == "/api/engagements":  # create
        name = field(body, "name", str, "")
        if not NAME_RX.match(name):
            raise Fail("Name: letters, digits, dot, dash and underscore; start with a letter or digit.")
        if os.path.exists(eng_path(name)):
            raise Fail(f"An engagement folder named {name} already exists.", 409)
        targets = [t.strip() for t in field(body, "targets", str, "").splitlines() if t.strip()]
        if not targets:
            raise Fail("Add at least one target.")
        if len(targets) > 500:
            raise Fail("At most 500 targets; use networks (CIDR) or domains for larger scopes.")
        for tg in targets:
            if tg.startswith("-") or len(tg) > 253 or not TARGET_RX.match(tg):
                raise Fail(f"Not a target: {tg[:80]!r}. Use an IP, a CIDR network, a domain, a URL or a /src path.")
        check = json.loads(ctl("preview", name, stdin=json.dumps({"scope": "\n".join("- " + t for t in targets),
                                                                   "rules": ""})))
        if check["errors"]:
            raise Fail("Fix these targets first: " + "; ".join(check["errors"][:10]))
        tiers = field(body, "tiers", list, [])
        if any(x not in ("passive", "active", "intrusive") for x in tiers):
            raise Fail("Tiers are passive, active and intrusive.")
        rate = field(body, "rate", (int, str), 100)
        if not str(rate).strip().isdigit() or not 1 <= int(str(rate).strip()) <= 100_000:
            raise Fail("Max rate: a whole number of requests per second, 1 to 100000.")
        network = field(body, "network", str, "online")
        if network not in ("online", "offline"):
            raise Fail("Network: online or offline.")
        client = field(body, "client", str, "").strip()
        args = ["engagement", name, "--tiers", ",".join(tiers or ["passive"]), "--rate", str(int(str(rate).strip())),
                "--network", network]
        if client:
            args += ["--client", client.replace("\n", " ")[:200]]
        if field(body, "private", bool, False):
            args.append("--private")
        return {"output": rvkit(*args, *targets)}
    m = re.match(r"^/api/eng/([^/]+)/(\w+)$", path)
    if m:
        eng, action = m.groups()
        eng_path(eng)
        if action == "preview":
            return json.loads(ctl("preview", eng, stdin=json.dumps({"scope": body.get("scope", ""),
                                                                    "rules": body.get("rules", "")})))
        if action == "apply":  # write exactly what was previewed, unless the active scope changed since
            texts = {k: body[k] for k in ("scope", "rules") if isinstance(body.get(k), str)}
            if not texts:
                raise Fail("nothing to apply")
            args = ["sync", eng, "--yes", "--stdin"]
            rev = field(body, "revision", str, "")
            if rev:
                if not REV_RX.match(rev):
                    raise Fail("revision: expected the value the page loaded")
                args += ["--expect", rev]
            return {"output": ctl(*args, stdin=json.dumps(texts))}
        if action in ("halt", "resume", "close"):
            out = ctl(action, eng, timeout=600)
            if action in ("halt", "close"):  # bound conversations: the model gateway already refuses their calls
                try:
                    paused = conversations.pause(eng, ACTOR)
                    if paused:
                        out += f"\n{sum(1 for p in paused if p['paused'])} conversation(s) paused"
                except conversations.Fail:
                    pass
            return {"output": out}
        if action == "conversation":
            msg = field(body, "message", str, "")
            if len(msg) > 20000:
                raise Fail("message: at most 20000 characters")
            try:
                return conversations.new(eng, ACTOR, msg)
            except conversations.Fail as e:
                raise Fail(str(e), 502)
        if action == "unbind":
            cid = field(body, "id", str, "")
            if not re.fullmatch(r"[0-9a-fA-F-]{8,64}", cid):
                raise Fail("invalid conversation id")
            return {"output": ctl("unbind", eng, cid)}
        if action == "cred":
            name, value = field(body, "name", str, ""), field(body, "value", str, "")
            if not CRED_RX.match(name):
                raise Fail("Name: letters, digits and _ (start with a letter, up to 32).")
            if body.get("remove"):
                return {"output": ctl("cred", eng, "rm", name)}
            if not 4 <= len(value) <= 8192:
                raise Fail("Value: 4 to 8192 characters.")
            return {"output": ctl("cred", eng, "set", name, stdin=value)}
        if action == "identity":
            name, op = field(body, "name", str, ""), field(body, "op", str, "")
            if not IDENT_RX.match(name):
                raise Fail("Name: lower-case letters, digits, - and _ (start with a letter, up to 32).")
            if op == "set":
                spec = body.get("spec")
                if not isinstance(spec, dict):
                    raise Fail("spec: a JSON object")
                return json.loads(ctl("identity", eng, "set", name, stdin=json.dumps(spec)))
            if op == "check":
                return json.loads(ctl("identity", eng, "check", name, ok=(0, 4), timeout=180))
            if op in ("revoke", "rm"):
                return {"output": ctl("identity", eng, op, name, *(["console"] if op == "revoke" else []))}
            raise Fail("op: set, check, revoke or rm")
        if action == "capture":
            op = field(body, "op", str, "")
            if op == "import":
                import base64
                try:
                    data = base64.b64decode(field(body, "data", str, ""), validate=True)
                except ValueError:
                    raise Fail("data: the file, base64-encoded")
                if not data:
                    raise Fail("the capture is empty")
                name = field(body, "name", str, "")[:100]
                return json.loads(ctl("capture", eng, "import", "--name", name or "capture",
                                      stdin=data.decode("utf-8", "replace"), timeout=300))
            cid = field(body, "id", str, "")
            if not re.fullmatch(r"[a-z0-9-]{4,40}", cid):
                raise Fail("bad capture id")
            if op == "rm":
                return {"output": ctl("capture", eng, "rm", cid)}
            if op == "replay":
                entry = body.get("entry")
                if not isinstance(entry, int) or entry < 1:
                    raise Fail("entry: the request number")
                req = {"entry": entry, "identity": field(body, "identity", str, "") or None,
                       "changes": body.get("changes") if isinstance(body.get("changes"), dict) else None,
                       "markers": [m for m in body.get("markers") or [] if isinstance(m, str)][:10],
                       "approval_id": field(body, "approval_id", str, "") or None}
                return json.loads(ctl("capture", eng, "replay", cid, stdin=json.dumps(req), timeout=300))
            raise Fail("op: import, replay or rm")
        if action == "authz":
            name, op = field(body, "name", str, ""), field(body, "op", str, "")
            if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,47}", name):
                raise Fail("bad matrix name")
            if op == "approve":  # the digest the researcher reviewed: a matrix changed since then isn't approved
                dg = field(body, "digest", str, "")
                if not re.fullmatch(r"[0-9a-f]{32}", dg):
                    raise Fail("digest: the one shown with the matrix")
                return {"output": ctl("authz", eng, "approve", name, "--digest", dg)}
            if op == "run":
                return {"output": ctl("authz", eng, "run", name, timeout=900)}
            raise Fail("op: approve or run")
        if action == "task":
            act_ = field(body, "action", str, "")
            if act_ not in ("cancel", "resume"):
                raise Fail("action: cancel or resume")
            return task_control(eng, field(body, "id", str, ""), act_)
        if action == "delete":
            return {"output": ctl("delete", eng, *(["--force"] if body.get("force") else []))}
        if action == "report":
            return ops("report.build", eng, timeout=900)
        if action == "meta":
            fields = {k: body[k] for k in ("client", "prepared by", "version", "classification") if k in body}
            return ops("meta.set", eng, fields=fields, expected_digest=digest_field(body))
        if action == "summary":
            return ops("summary.set", eng, text=field(body, "text", str, ""), expected_digest=digest_field(body))
        if action == "finding":
            fid = body.get("id", "")
            if not isinstance(fid, str) or not FID_RX.match(fid):
                raise Fail("invalid finding id")
            if body.get("not_reproducible"):
                return {"finding": ops("finding.not_reproducible", eng, id=fid,
                                       reason=field(body, "reason", str, ""))}
            fields = {k: body[k] for k in ("status", "severity", "notes", "duplicate_of", "title", "priority",
                                           "prerequisites", "root_cause", "cvss_vector") if k in body}
            return {"finding": ops("finding.update", eng, id=fid, fields=fields,
                                   expected_revision=field(body, "revision", int, None),
                                   reason=field(body, "reason", str, None) or None,
                                   method=field(body, "method", str, None) or None)}
        if action == "observation":
            op, ids = field(body, "op", str, ""), field(body, "ids", list, [])
            if op == "import":
                return ops("observation.import", eng, timeout=300, path=field(body, "path", str, ""),
                           tool=field(body, "tool", str, "") or None)
            if op == "link":
                return {"finding": ops("observation.link", eng, ids=ids, finding_id=field(body, "finding_id", str, ""))}
            if op == "dismiss":
                return ops("observation.dismiss", eng, ids=ids, reason=field(body, "reason", str, ""))
            if op == "duplicate":
                return ops("observation.duplicate", eng, ids=ids, of=field(body, "of", str, ""))
            if op == "reopen":
                return ops("observation.reopen", eng, ids=ids)
            raise Fail("op: import, link, dismiss, duplicate or reopen")
        if action == "plan":
            op = field(body, "op", str, "")
            if op == "add":
                return ops("plan.add", eng, items=field(body, "items", list, []))
            if op == "playbook":
                return ops("plan.from_playbook", eng, playbook=field(body, "playbook", str, ""))
            if op == "update":
                f = field(body, "fields", dict, {})
                return ops("plan.update", eng, id=field(body, "id", str, ""), fields=f,
                           expected_revision=field(body, "revision", int, None))
            if op == "reassess":
                return ops("coverage.reassess", eng, build=field(body, "build", str, "") or None,
                           policy_revision=field(body, "policy_revision", str, "") or None)
            raise Fail("op: add, playbook, update or reassess")
        if action == "delivery":
            op = field(body, "op", str, "")
            rev = field(body, "revision", str, "")
            if rev and not re.fullmatch(r"R-\d{3,}", rev):
                raise Fail("revision: R-001...")
            if op == "exception":
                return ops("report.exception", eng, check=field(body, "check", str, ""),
                           rationale=field(body, "rationale", str, ""))
            if op == "revoke":
                return ops("report.exception", eng, revoke=field(body, "id", int, 0))
            if op == "approve":
                return ops("report.approve", eng, revision=rev, note=field(body, "note", str, ""))
            if op == "verify":
                return ops("report.verify", eng, revision=rev)
            if op == "rebuild":
                return ops("report.rebuild", eng, timeout=900, revision=rev)
            if op == "transmitted":
                return ops("report.transmitted", eng, revision=rev, to=field(body, "to", str, ""),
                           channel=field(body, "channel", str, ""), note=field(body, "note", str, ""))
            if op == "export":
                return ops("export.build", eng, revision=rev or None, draft=field(body, "draft", bool, False))
            if op == "cleanup_add":
                return ops("cleanup.add", eng, kind=field(body, "kind", str, ""), what=field(body, "what", str, ""))
            if op == "cleanup_update":
                return ops("cleanup.update", eng, id=field(body, "id", str, ""), state=field(body, "state", str, ""),
                           note=field(body, "note", str, ""))
            if op == "notice_prepare":
                return ops("notice.prepare", eng, finding_id=field(body, "finding_id", str, ""))
            if op == "notice_review":
                return ops("notice.review", eng, id=field(body, "id", str, ""))
            if op == "retest":
                return ops("retest.record", eng, finding_id=field(body, "finding_id", str, ""),
                           retest_build=field(body, "build", str, ""), outcome=field(body, "outcome", str, ""),
                           cases=field(body, "cases", list, []), reauthorization=field(body, "reauthorization", str, ""),
                           note=field(body, "note", str, ""))
            raise Fail("op: exception, revoke, approve, verify, rebuild, transmitted, export, cleanup_add, "
                       "cleanup_update, notice_prepare, notice_review or retest")
        if action == "objective":
            return ops("workspace.objective", eng, text=field(body, "text", str, ""), expected_digest=digest_field(body))
        if action == "handover":
            return ops("handover.save", eng, text=field(body, "text", str, ""), expected_digest=digest_field(body))
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
        extra = dict(extra or {})
        self.send_header("Content-Security-Policy", extra.pop("Content-Security-Policy", None) or
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; "
                         "frame-ancestors 'none'; form-action 'self'")
        for k, v in extra.items():
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
        if u.path in STATIC:
            base, rel, ctype = STATIC[u.path]
            with open(os.path.join(base, rel), "rb") as f:
                return self._send(200, f.read(), ctype)
        m = re.match(r"^/(files|report)/([^/]+)/(.+)$", u.path)
        if m:
            kind, eng, name = m.group(1), m.group(2), urllib.parse.unquote(m.group(3))
            if not NAME_RX.match(eng) or not (REPORT_NAME.match(name) or DELIVERY_PATH.match(name)) \
                    or (kind == "report" and not name.endswith(".html")):
                return self._send(404, {"error": "not found"})
            p = eng_path(eng, "report", *name.split("/"))
            name = name.split("/")[-1]
            if not os.path.isfile(p):
                return self._send(404, {"error": "not found"})
            with open(p, "rb") as f:
                data = f.read()
            if kind == "report":   # view in the browser, locked down
                return self._send(200, data, "text/html", {"Content-Security-Policy": REPORT_CSP})
            return self._send(200, data, mimetypes.guess_type(name)[0] or "application/octet-stream",
                              {"Content-Disposition": f'attachment; filename="{name}"'})
        if u.path.startswith("/api/") and not self._same_origin():
            return self._send(403, {"error": "cross-site request refused"})
        if u.path == "/api/stream":
            return self._stream(q)
        if u.path.startswith("/api/"):
            return self._api(lambda: api_get(u.path, q))
        self._send(404, {"error": "not found"})

    def _same_origin(self):
        """Browsers say where a request comes from; anything but this page is refused (defence in depth next to the
        SameSite cookie and the X-RV-Console header). Clients that send neither header (curl) are judged by those."""
        origin = self.headers.get("Origin")
        if origin and origin not in (f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"):
            return False
        return self.headers.get("Sec-Fetch-Site", "same-origin") in ("same-origin", "none")

    def do_POST(self):
        if not self._host_ok():
            return self._send(403, {"error": "wrong host"})
        if not self._same_origin():
            return self._send(403, {"error": "cross-site request refused"})
        if not self._authed() or self.headers.get("X-RV-Console") != "1":
            return self._send(401, {"error": "not signed in"})
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            return self._send(415, {"error": "send JSON (Content-Type: application/json)"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._send(400, {"error": "bad Content-Length"})
        if n > 2_000_000:
            return self._send(413, {"error": "too large (the console takes up to about 1.4 MB; import bigger "
                                             "captures with ./rvkit capture <engagement> import <file>)"})
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, {"error": "invalid JSON"})
        if not isinstance(body, dict):
            return self._send(400, {"error": "the request body must be a JSON object"})
        self._api(lambda: api_post(urllib.parse.urlsplit(self.path).path, body))

    def do_PUT(self):
        self._send(405, {"error": "method not allowed"}, extra={"Allow": "GET, POST"})

    do_DELETE = do_PATCH = do_PUT

    def _stream(self, q):
        """Server-sent events: "overview" always, "live" for ?eng=<name>; a comment line every 15 s keeps it open."""
        eng = (q.get("eng") or [""])[0]
        if eng and not NAME_RX.match(eng):
            return self._send(400, {"error": "invalid engagement name"})
        topics = ["overview"] + ([f"live:{eng}"] if eng else [])
        self.send_response(200)
        for k, v in (("Content-Type", "text/event-stream; charset=utf-8"), ("Cache-Control", "no-store"),
                     ("X-Content-Type-Options", "nosniff"), ("Connection", "close")):
            self.send_header(k, v)
        self.end_headers()
        inbox = queue.Queue()
        subs = [(tp, HUB.subscribe(tp)) for tp in topics]
        stop = threading.Event()

        def pump(sq):  # merge each topic's queue into one
            while not stop.is_set():
                try:
                    inbox.put(sq.get(timeout=1))
                except queue.Empty:
                    pass
        for _, sq in subs:
            threading.Thread(target=pump, args=(sq,), daemon=True).start()
        try:
            self.wfile.write(b"retry: 3000\n\n"); self.wfile.flush()
            while True:
                try:
                    name, data = inbox.get(timeout=15)
                    self.wfile.write(f"event: {name}\ndata: {data}\n\n".encode())
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            stop.set()
            for tp, sq in subs:
                HUB.unsubscribe(tp, sq)

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
