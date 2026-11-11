"""Worker MCP server (streamable HTTP on :8091/mcp).

The planner hands it one focused goal; it runs a tool-calling loop on the local Qwen model and returns a short
structured result. Raw tool output stays in /work/<engagement>/evidence/tasks/<task_id>/.

Tools the worker model gets:
  kali_run        a command in the Kali container (through kali-mcp: scope-checked and audit-logged)
  web_search      SearXNG
  fetch_url       read a public web page (research: advisories, docs); in-scope targets must go through kali_run
  read_file       read files under /src (client code, read-only) or the engagement folder
  record_candidate  store a candidate finding (the planner confirms or rejects it)
  finish          return the result

Tasks are durable (RW-007): task.json and messages.json next to the evidence hold the task's state, its
checkpoints (each action is recorded as started before it runs and done after) and the conversation so far.
  - An action that needs the user's approval pauses the task (awaiting_approval) without holding a model slot;
    once the user decides, the task continues by itself: the approved action runs exactly once (kali-mcp consumes
    the approval), a denied or stale one is reported to the model instead.
  - Cancel (cancel_task, the console) stops the task and kills its running command; halting the engagement stops
    its tasks too (and the model gateway refuses their model calls).
  - After a worker restart, queued tasks start again, tasks waiting for an approval keep waiting, and running
    tasks become interrupted with a recovery decision. resume_task continues one from its last checkpoint; an
    action that was in flight is never repeated automatically: the model is told its result is unknown.
  - depends_on: a task waits until the tasks it depends on are done (and is blocked if one of them fails).
"""
import asyncio, datetime, html, json, os, re, threading, time, urllib.error, urllib.parse, urllib.request, uuid
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.fastmcp import FastMCP
import findings_db as db

LITELLM = os.environ.get("LITELLM_URL", "http://litellm:4000/v1")
LITELLM_KEY = os.environ.get("LITELLM_MASTER_KEY", "")
WORKER_MODEL = os.environ.get("WORKER_MODEL", "colab-qwen")
KALI_MCP = os.environ.get("KALI_MCP_URL", "http://kali-mcp:8090/mcp")
WEB_MCP = os.environ.get("WEB_MCP_URL", "http://web-mcp:8094/mcp")  # search + fetch (the worker has no internet)
INTEL_MCP = os.environ.get("INTEL_MCP_URL", "http://intel-mcp:8093/mcp")
CTX_CHARS = int(os.environ.get("WORKER_CONTEXT_CHARS", "90000"))  # ~25k tokens: fits the 32K L4 profile
TOOL_CHARS = 6000          # tool output kept in context per call; full output goes to a file
TIERS = ("passive", "active", "intrusive")

# Stateless: no per-client session, so a conversation that was open when this server restarted keeps working
# (with sessions, every later tool call failed with "Session terminated" until OpenHands itself was restarted).
mcp = FastMCP("worker", host="0.0.0.0", port=8091, stateless_http=True)
TASKS: dict[str, dict] = {}
# How many tasks run at once. 1 (default) suits a single-slot llama-server on Colab; raise it for an endpoint that
# serves parallel requests (an API, or llama-server with --parallel N).
MODEL_LOCK = threading.BoundedSemaphore(max(1, int(os.environ.get("WORKER_PARALLEL_TASKS", "1") or 1)))

SYSTEM = """You are a security testing worker on an authorised engagement. You carry out ONE focused task given
by the lead consultant, using your tools, then call `finish`.

Rules:
- Engagement: {engagement}. Allowed risk tier: {tier}.
  passive = code/config review, static analysis, dependency checks, research, DNS lookups of in-scope names.
  active = also port scans, crawling, fingerprinting, non-intrusive vulnerability scans, at modest rates.
  intrusive = also exploitation attempts, brute force, high-rate fuzzing (only when this tier is given).
  Never go beyond the allowed tier. If the task needs more, stop and say so in `finish`.
- Scope: {scope}. Only touch these systems; anything else is blocked at the network level. Never try to work
  around a refusal or a block.
- Some actions need the user's approval (intrusive commands, requests that can change state). The task then
  pauses until the user decides; you get the action's result afterwards, or a note that it was denied. Never
  rephrase a denied action to get around the decision.
- Use kali_run for anything that touches a target. fetch_url is for public research only (advisories, docs).
- Prefer small, specific commands. The current directory is the engagement folder: write all output files there
  (or under ./evidence/). /src is read-only client code: never `cd /src && … > file`; pass /src paths as
  arguments instead. Read only what you need from long output.
- Scanner output is a lead, not a finding. Record a candidate only with concrete evidence (file:line, request/
  response, version + advisory). For evidence, cite the path kali_run prints after "output saved as verified
  evidence" (and any "evidence recorded" files), plus /src file:line references. Don't invent results: if a
  tool failed or you didn't check, say so.
- You have at most {max_steps} tool calls. Finish early when the goal is met.
"""

TOOLS = [
    {"type": "function", "function": {"name": "kali_run", "description":
        "Run a shell command in the Kali container (cwd = engagement folder; client code read-only at /src). "
        "Recon: nmap, naabu, dnsx, subfinder, amass, katana, httpx-toolkit, whatweb, gowitness. "
        "Web: nuclei, nikto, ffuf, feroxbuster, arjun, crlfuzz, wafw00f, wpscan, dalfox, commix, zaproxy, sqlmap, "
        "testssl, sslscan; wordlists /usr/share/seclists. "
        "API: schemathesis run <spec-url> --url <base>, jwt_tool, graphw00f -d -f -t <url>, graphql-cop -t <url>, "
        "clairvoyance. AI/LLM/MCP: rv-llm (probe | ask | mcp <url> | mcp-call | payloads; rv-llm help), garak. "
        "Code/secrets: semgrep (p/<lang> configs online; /opt/semgrep-rules offline), bandit, gitleaks, trufflehog, "
        "rv-joern taint /src/<repo> (data flows from user input to dangerous sinks, JSON in joern-flows.json). "
        "Supply chain: osv-scanner, pip-audit, trivy, syft (SBOM), grype. Prefer JSON output to files.",
        "parameters": {"type": "object", "properties": {
            "command": {"type": "string"}, "timeout_s": {"type": "integer", "default": 600}},
            "required": ["command"]}}},
    {"type": "function", "function": {"name": "http_request", "description":
        "Send one HTTP request to an in-scope URL; returns status, headers and body, saved as evidence. Use it "
        "for single requests (the only way to reach hosts limited to URL paths). GET/HEAD/OPTIONS only unless "
        "your tier is intrusive; other methods need the user's approval. identity: send it as one of the "
        "engagement's test accounts (check_identity first); the session is added for you and never shown.",
        "parameters": {"type": "object", "properties": {
            "method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]},
            "url": {"type": "string"}, "headers": {"type": "object"}, "body": {"type": "string"},
            "identity": {"type": "string"}},
            "required": ["method", "url"]}}},
    {"type": "function", "function": {"name": "check_identity", "description":
        "Is a test identity's session working? valid, expired, challenge (CAPTCHA/WAF), denied or error. Results "
        "obtained with an identity that isn't valid are blocked, not evidence that something is protected.",
        "parameters": {"type": "object", "properties": {"identity": {"type": "string"}},
                       "required": ["identity"]}}},
    {"type": "function", "function": {"name": "analyze_source", "description":
        "Run semgrep (offline rules), gitleaks, trufflehog or bandit on in-scope code with no network. "
        "path: a /src path. rulesets (semgrep only): rule folders like php, python, javascript.",
        "parameters": {"type": "object", "properties": {
            "tool": {"type": "string", "enum": ["semgrep", "gitleaks", "trufflehog", "bandit"]},
            "path": {"type": "string"}, "rulesets": {"type": "array", "items": {"type": "string"}}},
            "required": ["tool", "path"]}}},
    {"type": "function", "function": {"name": "vuln_intel", "description":
        "Rank vulnerability ids (CVE/GHSA/PYSEC) by real-world risk: CISA KEV, EPSS, CVSS, CWE, fixed versions. "
        "Use it on ids from osv-scanner, pip-audit, trivy or grype instead of searching the web.",
        "parameters": {"type": "object", "properties": {"ids": {"type": "array", "items": {"type": "string"}}},
                       "required": ["ids"]}}},
    {"type": "function", "function": {"name": "web_search", "description": "Search the web (SearXNG).",
        "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "fetch_url", "description":
        "Fetch a public web page as text for research (advisories, CVE pages, docs). Not for testing targets.",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "read_file", "description":
        "Read a text file under /src or the engagement folder. Lines are numbered.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "start": {"type": "integer", "default": 1},
            "lines": {"type": "integer", "default": 200}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "record_candidate", "description":
        "Store a candidate finding with evidence. The lead consultant verifies it.",
        "parameters": {"type": "object", "properties": {
            "title": {"type": "string"}, "severity": {"type": "string", "enum": list(db.SEVERITIES)},
            "asset": {"type": "string"}, "description": {"type": "string"},
            "evidence": {"type": "array", "items": {"type": "string"}}, "cwe": {"type": "string"}},
            "required": ["title", "severity", "asset", "description", "evidence"]}}},
    {"type": "function", "function": {"name": "finish", "description": "Finish the task and return the result.",
        "parameters": {"type": "object", "properties": {
            "summary": {"type": "string", "description": "What you did and found, 3-10 sentences."},
            "observations": {"type": "array", "items": {"type": "string"}},
            "open_questions": {"type": "array", "items": {"type": "string"}},
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]}},
            "required": ["summary", "confidence"]}}},
]

from redact import REDACT, redact  # noqa: E402,F401  (secrets stay in evidence files only)


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------- tool implementations
def _arun(coro):
    """Run a coroutine to completion from sync code, whether or not this thread already has a running event loop
    (the MCP SDK may call sync tools on its loop thread; asyncio.run would fail there)."""
    box = {}
    def target():
        try:
            box["v"] = asyncio.run(coro)
        except BaseException as e:  # noqa: BLE001 - re-raised in the caller's thread
            box["e"] = e
    t = threading.Thread(target=target, daemon=True); t.start(); t.join()
    if "e" in box:
        raise box["e"]
    return box["v"]


async def _mcp(url: str, tool: str, args: dict, timeout_s: int = 60) -> str:
    async with streamablehttp_client(url, timeout=30, sse_read_timeout=timeout_s + 120) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool(tool, args)
            return "\n".join(c.text for c in res.content if getattr(c, "text", None))


async def _kali(tool: str, args: dict, timeout_s: int = 60) -> str:
    return await _mcp(KALI_MCP, tool, args, timeout_s)


def engagement_info(engagement):
    """Authoritative scope/rules from kali-mcp (the SCOPE.md in /work is only a mirror)."""
    out = _arun(_kali("engagement_info", {"engagement": engagement}))
    if out.startswith(("REFUSED", "Error")):
        raise ValueError(out)
    return json.loads(out)


def kali_run(task, command, timeout_s=600, approval_id=""):
    """kali-mcp enforces the task's tier (max_tier), not only the prompt."""
    t = min(int(timeout_s or 600), 3600)
    return _arun(_kali("run", {"command": command, "engagement": task["engagement"], "timeout_s": t,
                               "max_tier": task["tier"], "task": task["id"], "approval_id": approval_id or ""}, t))


def http_request(task, method, url, headers=None, body="", approval_id="", identity=""):
    return _arun(_kali("http_request", {"engagement": task["engagement"], "method": method, "url": url,
                                        "headers": headers or {}, "body": body or "", "max_tier": task["tier"],
                                        "task": task["id"], "approval_id": approval_id or "",
                                        "identity": identity or ""}, 300))


def check_identity(task, identity):
    return _arun(_kali("check_identity", {"engagement": task["engagement"], "identity": identity}, 120))


def analyze_source(task, tool, path, rulesets=None):
    return _arun(_kali("analyze_source", {"engagement": task["engagement"], "tool": tool, "path": path,
                                          "rulesets": rulesets or [], "task": task["id"]}, 1900))


def vuln_intel(task, ids):
    async def go():
        async with streamablehttp_client(INTEL_MCP, timeout=30, sse_read_timeout=600) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
                res = await s.call_tool("prioritize", {"ids": list(ids)[:50]})
                return "\n".join(c.text for c in res.content if getattr(c, "text", None))
    return _arun(go())


def web_search(task, query):
    return _arun(_mcp(WEB_MCP, "web_search", {"query": query, "max_results": 8}))


def fetch_url(task, url):
    """Public pages only, through web-mcp: it refuses every engagement's targets (not only this one's) and
    non-public addresses. Targets are tested with kali_run."""
    return _arun(_mcp(WEB_MCP, "fetch", {"url": url, "max_chars": 100000}))


def read_file(task, path, start=1, lines=200):
    real = os.path.realpath(path)
    allowed = tuple(p.rstrip("/") + "/" for p in task["info"]["scope"]["paths"]) + \
        (os.path.realpath(db.engagement_dir(task["engagement"])) + "/",)
    if not real.startswith(allowed):
        return f"only files under the in-scope code paths {task['info']['scope']['paths']} or the engagement folder"
    start, lines = max(1, int(start or 1)), min(int(lines or 200), 500)
    with open(real, errors="replace") as f:
        out = [f"{i}: {l.rstrip()}" for i, l in enumerate(f, 1) if start <= i < start + lines]
    return "\n".join(out) or "(no lines in that range)"


def record_candidate(task, title, severity, asset, description, evidence, cwe=""):
    f = db.record(task["engagement"], actor="agent:worker", title=title, severity=severity, asset=asset, description=description,
                  evidence=evidence, cwe=cwe, status="candidate", source=f"worker:{task['id']}")
    task["candidates"].append(f["id"])
    return f"recorded {f['id']} (candidate)"


IMPL = {"kali_run": kali_run, "http_request": http_request, "check_identity": check_identity, "analyze_source": analyze_source, "vuln_intel": vuln_intel, "web_search": web_search, "fetch_url": fetch_url, "read_file": read_file,
        "record_candidate": record_candidate}


# ---------------------------------------------------------------- model loop
BOOT = uuid.uuid4().hex[:8]          # this worker process; a task's lease names the process running it
LEASE_S = 300                        # a lease not renewed for this long is free
CONTROL = os.path.join(db.WORK, ".control", "tasks")   # cancel/resume requests from the console (host only:
                                                       # the sandbox mounts only its engagement's folder)
APPROVAL_RX = re.compile(r"APPROVAL REQUIRED.*?Approval id: ([a-f0-9]{8})", re.S)
ACTIVE = ("queued", "waiting", "running", "awaiting_approval")
FAILED = ("error", "cancelled", "halted", "interrupted", "blocked")
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
APPROVAL_WAIT_H = 72                 # a task stops waiting for a decision after this long


class Stop(Exception):
    """The task must stop now (cancelled or halted); args: (status, reason)."""


def chat(messages, model=WORKER_MODEL, task=None):
    body = {"model": model, "messages": messages, "tools": TOOLS, "tool_choice": "auto",
            "max_tokens": 2048, "temperature": 0.3}
    hdrs = {"Authorization": f"Bearer {LITELLM_KEY}", "Content-Type": "application/json"}
    if task:  # the model gateway ties the call to the engagement: Client data rule, halt (litellm/rv_routes.py)
        hdrs.update({"x-rv-engagement": task["engagement"], "x-rv-task": task["id"]})
    req = urllib.request.Request(f"{LITELLM}/chat/completions", data=json.dumps(body).encode(), headers=hdrs)
    try:
        r = json.load(urllib.request.urlopen(req, timeout=900))
    except urllib.error.HTTPError as e:
        detail = e.read()[:2000].decode("utf-8", "replace")
        try:
            detail = json.loads(detail).get("error", {}).get("message") or detail
        except (ValueError, AttributeError):
            pass
        raise ModelRefused(e.code, str(detail)) from None
    return {**r["choices"][0]["message"], "_served_by": r.get("model")}


class ModelRefused(Exception):
    def __init__(self, code, detail):
        super().__init__(f"HTTP {code}: {detail}")
        self.code, self.detail = code, detail


def compact(messages):
    """Keep the conversation under CTX_CHARS by shrinking the oldest tool outputs (full copies are on disk)."""
    total = sum(len(json.dumps(m)) for m in messages)
    for m in messages[2:]:
        if total <= CTX_CHARS:
            break
        if m.get("role") == "tool" and not m["content"].startswith("[shrunk]"):
            before = len(m["content"])
            m["content"] = "[shrunk] " + m["content"][:400] + " …(full output in the step file)"
            total -= before - len(m["content"])


def task_dir(task):
    return os.path.join(db.WORK, task["engagement"], "evidence", "tasks", task["id"])


def _atomic(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=1, default=str)
    os.replace(tmp, path)


def save(task, messages=None):
    """Keep the task's state (and its conversation) next to its evidence, so it survives a worker restart."""
    try:
        d = task_dir(task)
        os.makedirs(d, exist_ok=True)
        if task.get("status") in ("running", "awaiting_approval"):
            task["lease"] = {"owner": BOOT, "renewed": time.time()}
        _atomic(os.path.join(d, "task.json"), {k: v for k, v in task.items() if k != "_cancel"})
        if messages is not None:
            _atomic(os.path.join(d, "messages.json"), messages)
    except OSError:
        pass  # the engagement folder may be gone (deleted); the task still runs from memory


def load_messages(task):
    try:
        return json.load(open(os.path.join(task_dir(task), "messages.json")))
    except (OSError, ValueError):
        return None


def _defaults(task):
    for k, v in (("steps", []), ("evidence", []), ("candidates", []), ("pending_calls", []), ("depends_on", []),
                 ("waited_s", 0), ("step", 0), ("served_by", [])):
        task.setdefault(k, v)
    return task


def effect(task, name, args):
    """write: an action whose repetition could change something (never replayed automatically after a crash)."""
    if name == "record_candidate":
        return "write"
    if name == "http_request" and str(args.get("method") or "GET").upper() not in SAFE_METHODS:
        return "write"
    if name == "kali_run" and task["tier"] == "intrusive":
        return "write"
    return "read"


def _stop_check(task, info=True):
    """Raise Stop when the task was cancelled or its engagement halted."""
    if task.get("_cancel"):
        raise Stop("cancelled", task.get("cancel_reason") or "cancelled")
    if info:
        try:
            i = engagement_info(task["engagement"])
        except Exception:  # noqa: BLE001 - kali-mcp briefly unreachable: the next check decides
            return
        if i.get("halted"):
            raise Stop("halted", f"engagement {task['engagement']} was halted")


def _step_file(task, step, name, args, out):
    path = os.path.join(task_dir(task), f"step-{step:02d}-{name}.txt")
    n = 1
    while os.path.exists(path):  # a resumed task can reach the same step number again
        n += 1
        path = os.path.join(task_dir(task), f"step-{step:02d}-{name}-{n}.txt")
    with open(path, "w") as f:
        f.write(f"# {name} {json.dumps(args)}\n\n{out}")
    task["evidence"].append(path)
    return path


def _do_call(task, c, messages):
    """Run one tool call of the current assistant turn. Returns ok | finish | approval."""
    name = c["function"]["name"]
    try:
        args = json.loads(c["function"].get("arguments") or "{}")
    except ValueError:
        args = {}
    args = {k: v for k, v in args.items() if k != "approval_id"}  # approvals come from the user, not the model
    if name == "finish":
        task["result"] = args
        return "finish"
    ap = task.get("approval") if (task.get("approval") or {}).get("call") == c.get("id") else None
    extra = {}
    if ap:
        if ap.get("decision") != "approved":
            why = {"denied": "The user denied this action. Don't retry it or a variant of it; continue without it, "
                             "or finish and explain what it would have shown.",
                   "stale": "The approval became invalid before it was used (the scope or rules changed: "
                            f"{ap.get('reason') or 'see the console'}). It was not run.",
                   "used": "That approval was already used by another call; this action was not run here.",
                   "expired": "No decision came in time; the action was not run."}
            out = f"NOT RUN: {why.get(ap.get('decision'), 'the action was not approved')} (approval {ap['id']})"
            rec = next((s for s in task["steps"] if s.get("id") == ap.get("step")), None)
            if rec:
                rec.update(state="not_run", decision=ap.get("decision"))
            task["approval"] = None
            messages.append({"role": "tool", "tool_call_id": c.get("id", name), "content": out})
            return "ok"
        extra = {"approval_id": ap["id"]}
    _stop_check(task, info=False)
    rec = next((s for s in task["steps"] if s.get("id") == (ap or {}).get("step")), None) if ap else None
    if rec is None:
        rec = {"id": f"{task['id']}-a{len(task['steps']) + 1}", "call": c.get("id"), "tool": name, "args": args,
               "effect": effect(task, name, args)}
        task["steps"].append(rec)
    rec.update(state="started", at=_now(), **({"approval": ap["id"]} if ap else {}))
    save(task, messages)  # checkpoint: the action may run from here on
    try:
        out = IMPL[name](task, **args, **extra) if name in IMPL else f"unknown tool {name}"
    except Exception as e:  # tool errors go back to the model
        out = f"ERROR: {type(e).__name__}: {e}"
    m = APPROVAL_RX.search(out) if name in ("kali_run", "http_request") and not extra else None
    if m:  # pause: the user decides, then the task continues by itself (await_approval)
        rec.update(state="awaiting_approval", approval=m.group(1))
        what = args.get("command") or f"{str(args.get('method', 'GET')).upper()} {args.get('url', '')}"
        task["approval"] = {"id": m.group(1), "call": c.get("id"), "step": rec["id"], "tool": name,
                            "action": what, "since": time.time()}
        task["status"] = "awaiting_approval"
        _step_file(task, task["step"], name, args, out)
        save(task, messages)
        return "approval"
    rec.update(state="done", done=_now())
    if ap:
        task["approval"] = None
    path = _step_file(task, task["step"], name, args, out)
    shown = out if len(out) <= TOOL_CHARS else out[:TOOL_CHARS] + f"\n…truncated, full output: {path}"
    messages.append({"role": "tool", "tool_call_id": c.get("id", name), "content": shown})
    save(task, messages)
    return "ok"


def _loop(task, log):
    """Run until the task finishes or pauses. Returns the new status."""
    messages = load_messages(task)
    if not messages:
        sys_prompt = SYSTEM.format(engagement=task["engagement"], tier=task["tier"], max_steps=task["max_steps"],
                                   scope=json.dumps(task["info"]["scope"]))
        messages = [{"role": "system", "content": sys_prompt}, {"role": "user", "content": task["goal"]}]
    # "Worker model: private" in RULES.md: never use the fallback model (tool output and code stay on the endpoint)
    model = "private-llm" if task["info"]["rules"].get("worker") == "private" else WORKER_MODEL
    deadline = task["started"] + task["timeout_min"] * 60 + task.get("waited_s", 0)
    while True:
        while task["pending_calls"]:  # the rest of the current assistant turn (also after an approval)
            r = _do_call(task, task["pending_calls"][0], messages)
            if r == "approval":
                return "awaiting_approval"
            if r == "finish":
                return "done"
            task["pending_calls"].pop(0)
            save(task, messages)
        _stop_check(task)
        if time.time() > deadline:
            raise TimeoutError(f"task exceeded {task['timeout_min']} min")
        task["step"] += 1
        if task["step"] > task["max_steps"] + 1:
            task["result"] = {"summary": "Stopped without calling finish.", "confidence": "low"}
            return "done"
        compact(messages)
        if task["step"] > task["max_steps"]:  # out of tool budget: force a final answer
            messages.append({"role": "user", "content": "Tool budget used up. Call finish now."})
        msg = chat(messages, model, task)
        if msg.get("_served_by") and msg["_served_by"] not in task["served_by"]:
            task["served_by"].append(msg["_served_by"])
        messages.append({k: v for k, v in msg.items() if k in ("role", "content", "tool_calls")})
        log.write(json.dumps({"ts": _now(), "step": task["step"], "assistant": msg}) + "\n"); log.flush()
        calls = msg.get("tool_calls") or []
        if not calls:
            messages.append({"role": "user", "content": "Use a tool, or call finish with your result."})
        task["pending_calls"] = calls
        save(task, messages)


def run_task(task):
    """Run (or continue) a task until it finishes, pauses for an approval or stops."""
    _defaults(task)
    os.makedirs(task_dir(task), exist_ok=True)
    TASKS[task["id"]] = task
    with MODEL_LOCK, open(os.path.join(task_dir(task), "transcript.jsonl"), "a") as log:
        status, err = None, None
        try:
            _stop_check(task)
            task["status"] = "running"
            save(task)
            status = _loop(task, log)
        except Stop as s:
            status, err = s.args[0], s.args[1]
        except ModelRefused as e:
            halted = False
            try:
                halted = engagement_info(task["engagement"]).get("halted")
            except Exception:  # noqa: BLE001
                pass
            status, err = ("halted", f"engagement {task['engagement']} was halted") if halted else \
                ("error", f"the model gateway refused the call: {e.detail}")
        except urllib.error.URLError as e:
            status, err = "error", f"worker model unreachable ({e}). Start it with /rv-start, then retry."
        except Exception as e:
            status, err = "error", f"{type(e).__name__}: {e}"
        task["status"] = status
        if err:
            task["error"] = err
        if status != "awaiting_approval":
            task["finished"] = time.time()
            task.pop("lease", None)
            log.write(json.dumps({"ts": _now(), "end": status, "result": task.get("result"),
                                  "error": task.get("error")}) + "\n")
        save(task)
    if status == "awaiting_approval":
        threading.Thread(target=await_approval, args=(task,), daemon=True).start()


def approval_status(task, aid):
    out = _arun(_kali("approval_status", {"engagement": task["engagement"], "approval_id": aid}))
    if out.startswith("REFUSED"):
        return {"status": "missing", "stale_reason": out}
    return json.loads(out)


def await_approval(task):
    """Wait (without a model slot) for the user's decision, then continue the task."""
    ap = task["approval"]
    while True:
        try:
            _stop_check(task)
        except Stop as s:
            task.update(status=s.args[0], error=s.args[1], finished=time.time())
            task.pop("lease", None)
            save(task)
            return
        try:
            st = approval_status(task, ap["id"])
        except Exception:  # noqa: BLE001 - kali-mcp restarting: try again
            st = {"status": "pending"}
        if st["status"] in ("approved", "denied", "stale", "used", "missing"):
            ap["decision"] = {"missing": "stale"}.get(st["status"], st["status"])
            ap["reason"] = st.get("stale_reason")
            ap["decided_by"] = st.get("decided_by")
            break
        if time.time() - ap["since"] > APPROVAL_WAIT_H * 3600:
            ap["decision"] = "expired"
            break
        task["lease"] = {"owner": BOOT, "renewed": time.time()}
        time.sleep(3)
    task["waited_s"] = task.get("waited_s", 0) + (time.time() - ap["since"])
    task["status"] = "queued"
    save(task)
    run_task(task)


def wait_dependencies(task):
    """Start the task once every task it depends on is done; blocked if one of them failed."""
    while True:
        if task.get("_cancel"):
            task.update(status="cancelled", error=task.get("cancel_reason") or "cancelled", finished=time.time())
            save(task)
            return
        deps = [TASKS.get(d) for d in task["depends_on"]]
        bad = [d for d, t in zip(task["depends_on"], deps) if t is None or t["status"] in FAILED]
        if bad:
            task.update(status="blocked", finished=time.time(),
                        error=f"a task it depends on did not finish: " + ", ".join(
                            f"{d} ({TASKS[d]['status'] if d in TASKS else 'unknown'})" for d in bad))
            save(task)
            return
        if all(t["status"] == "done" for t in deps):
            task["status"] = "queued"
            save(task)
            run_task(task)
            return
        time.sleep(3)


def start(task):
    if task["status"] == "waiting":
        threading.Thread(target=wait_dependencies, args=(task,), daemon=True).start()
    elif task["status"] == "awaiting_approval":
        threading.Thread(target=await_approval, args=(task,), daemon=True).start()
    else:
        threading.Thread(target=run_task, args=(task,), daemon=True).start()


def recover(task):
    """Decide what happens to a task found on disk after a restart. Never repeats an action that was in flight."""
    _defaults(task)
    st = task.get("status")
    lease = task.get("lease") or {}
    if st == "running" and lease.get("owner") not in (None, BOOT) and time.time() - lease.get("renewed", 0) < LEASE_S \
            and os.environ.get("WORKER_SHARED_TASKS") == "1":
        return None  # another live worker process holds it: never run a task twice
    if st in ("queued", "waiting") and not any(s.get("state") for s in task["steps"]):
        task["recovery"] = {"decision": "restarted", "at": _now(),
                            "note": "the worker restarted before this task ran an action; it starts again"}
        return "start"
    if st == "awaiting_approval" and task.get("approval"):
        task["recovery"] = {"decision": "still_waiting", "at": _now(),
                            "note": f"still waiting for approval {task['approval']['id']}"}
        return "start"
    if st in ACTIVE:
        uncertain = [s for s in task["steps"] if s.get("state") == "started"]
        writes = [s for s in uncertain if s.get("effect") == "write"]
        task.update(status="interrupted", finished=time.time(),
                    error="the worker restarted while this task was running. Partial evidence is kept in "
                          f"{task_dir(task)}. resume_task('{task['id']}') continues it from its last checkpoint.")
        task["recovery"] = {
            "decision": "needs_review" if writes else "resumable", "at": _now(),
            "uncertain": [{"id": s["id"], "tool": s["tool"], "effect": s.get("effect"),
                           "action": s["args"].get("command") or s["args"].get("url") or s["args"].get("title")}
                          for s in uncertain],
            "note": ("an action that can change state was in flight and may or may not have taken effect: it is "
                     "not repeated; check it before resuming" if writes else
                     "no state-changing action was in flight; resume_task continues it" if uncertain or
                     task["steps"] else "no action had started; resume_task continues it")}
        task.pop("lease", None)
    return None


def load_tasks():
    """Reload tasks saved by earlier worker runs and recover them (see recover)."""
    root = db.WORK
    found = []
    for eng in (os.listdir(root) if os.path.isdir(root) else []):
        if eng.startswith((".", "_")):
            continue
        tdir = os.path.join(root, eng, "evidence", "tasks")
        for tid in (os.listdir(tdir) if os.path.isdir(tdir) else []):
            try:
                task = json.load(open(os.path.join(tdir, tid, "task.json")))
            except (OSError, ValueError):
                continue
            TASKS[task["id"]] = task
            found.append(task)
    for task in sorted(found, key=lambda t: t.get("started") or 0):
        action = recover(task)
        if task.get("recovery"):
            save(task)
        if action == "start":
            start(task)


def resume(task_id, actor="agent:planner"):
    """Continue an interrupted task from its last checkpoint, after rechecking the engagement's policy. An action
    that was in flight gets a 'result unknown' answer instead of running again."""
    task = TASKS.get(task_id)
    if not task:
        raise ValueError(f"unknown task {task_id}")
    if task["status"] != "interrupted":
        raise ValueError(f"task {task_id} is {task['status']}; only interrupted tasks can be resumed")
    messages = load_messages(task)
    if not messages:
        raise ValueError(f"task {task_id} was saved before tasks could be resumed: delegate it again")
    info = engagement_info(task["engagement"])
    if info.get("halted"):
        raise ValueError(f"engagement {task['engagement']} is halted")
    if task["tier"] not in info["rules"]["tiers"]:
        raise ValueError(f"RULES.md for {task['engagement']} no longer allows tier '{task['tier']}'")
    task["info"] = info
    for c in task["pending_calls"]:
        rec = next((s for s in task["steps"] if s.get("call") == c.get("id")), None)
        if rec and rec.get("state") == "started":
            rec["state"] = "uncertain"
            text = ("RESULT UNKNOWN: the worker restarted while this action ran; it may or may not have taken "
                    "effect. " + ("It can change state: don't repeat it unless you have checked that it did "
                                  "not happen." if rec.get("effect") == "write" else
                                  "It only reads: run it again if you still need the result."))
        elif rec and rec.get("state") == "awaiting_approval":
            rec["state"] = "not_run"
            text = "NOT RUN: the worker restarted while this action waited for approval. Ask again if needed."
        else:
            text = "NOT RUN: the worker restarted before this call. Call it again if you still need it."
        messages.append({"role": "tool", "tool_call_id": c.get("id", "call"), "content": text})
    task["pending_calls"], task["approval"] = [], None
    task.update(status="queued", error=None, finished=None, resumed=(task.get("resumed") or []) +
                [{"at": _now(), "by": actor}])
    task["started"], task["waited_s"] = time.time(), 0  # a resumed task gets its full time budget again
    save(task, messages)
    start(task)
    return task


def cancel(task_id, reason="cancelled", actor="agent:planner"):
    task = TASKS.get(task_id)
    if not task:
        raise ValueError(f"unknown task {task_id}")
    if task["status"] not in ACTIVE:
        raise ValueError(f"task {task_id} is {task['status']}")
    task["_cancel"] = True
    task["cancel_reason"] = f"{reason} by {actor}"
    if task["status"] in ("running",):
        try:  # kill the command it is running now; the loop then stops at its next check
            _arun(_kali("cancel_task", {"engagement": task["engagement"], "task": task_id}))
        except Exception:  # noqa: BLE001
            pass
    return task


def control_watch():
    """Cancel/resume requests the console writes to /work/.control/tasks/<task-id>.json."""
    while True:
        try:
            for f in (os.listdir(CONTROL) if os.path.isdir(CONTROL) else []):
                path = os.path.join(CONTROL, f)
                if not f.endswith(".json"):
                    continue
                tid = f[:-5]
                if tid not in TASKS and time.time() - os.path.getmtime(path) < 60:
                    continue  # not this process's task (yet): leave it a minute, then answer that it's unknown
                try:
                    req = json.load(open(path))
                    act = req.get("action")
                    actor = str(req.get("by") or "console")[:80]
                    if act == "cancel":
                        cancel(tid, "cancelled from the console", actor)
                    elif act == "resume":
                        resume(tid, actor)
                    res = {"ok": True}
                except Exception as e:  # noqa: BLE001
                    res = {"ok": False, "error": str(e)}
                try:
                    _atomic(path[:-5] + ".result", {**res, "at": _now()})
                    os.remove(path)
                except OSError:
                    pass
        except OSError:
            pass
        time.sleep(2)


def report(task) -> str:
    out = {"task_id": task["id"], "status": task["status"], "engagement": task["engagement"], "tier": task["tier"],
           "elapsed_s": round((task.get("finished") or time.time()) - task["started"]),
           "commands": [s["args"].get("command") or s["args"].get("query") or s["args"].get("url")
                        or s["args"].get("path") or s["args"].get("title") for s in task["steps"]],
           "candidate_findings": task["candidates"], "evidence_dir": os.path.dirname(task["evidence"][0])
           if task["evidence"] else None}
    if task.get("served_by"):
        out["model"] = task["served_by"]  # which model did the work (the fallback model shows up here)
    if task.get("depends_on"):
        out["depends_on"] = task["depends_on"]
    if task.get("result"):
        out["result"] = task["result"]
    if task.get("error"):
        out["error"] = task["error"]
    if task.get("recovery"):
        out["recovery"] = task["recovery"]
    if task["status"] == "awaiting_approval" and task.get("approval"):
        a = task["approval"]
        out["approval"] = {"id": a["id"], "action": a["action"]}
        out["note"] = (f"paused: waiting for the user to approve {a['id']} ({a['action']}). Ask the user to approve "
                       f"or deny it in the console or with ./rvkit approve {task['engagement']} {a['id']}. The task "
                       f"continues by itself after the decision; call get_task('{task['id']}') to follow it.")
    elif task["status"] in ("queued", "running", "waiting"):
        out["note"] = f"still {task['status']}; call get_task('{task['id']}') to wait for it"
    elif task["status"] == "interrupted":
        out["note"] = f"call resume_task('{task['id']}') to continue it from its last checkpoint"
    return json.dumps(redact(out), indent=1)


def _wait(task, wait_s):
    end = time.time() + max(0, min(wait_s, 600))
    while task["status"] in ("queued", "running", "waiting") and time.time() < end:
        time.sleep(2)


# ---------------------------------------------------------------- MCP tools
@mcp.tool()
def delegate_task(goal: str, engagement: str, tier: str = "passive", max_steps: int = 15,
                  timeout_min: int = 30, wait_s: int = 240, depends_on: list[str] | None = None) -> str:
    """Hand one focused, hands-on task to the worker (local Qwen model with Kali, search, fetch and file tools).

    goal: what to do and what to return, e.g. "Run semgrep (p/django) and bandit on /src/acme, check the top
          findings by reading the code, and record candidates with file:line evidence."
    tier: passive | active | intrusive. Use the lowest tier that fits; intrusive needs the user's OK first.
    depends_on: task ids this task needs first; it waits for them (and is blocked if one fails).
    Tasks run one at a time (unless WORKER_PARALLEL_TASKS is raised). Returns the result, or a task_id if it is
    still running after wait_s seconds (then call get_task). A task that needs the user's approval pauses
    (status awaiting_approval, with the approval id) and continues by itself after the decision.
    Raw output is saved under /work/<engagement>/evidence/tasks/<task_id>/.
    Secrets are redacted from the returned summary but kept in the evidence files."""
    db.engagement_dir(engagement)
    if tier not in TIERS:
        return f"tier must be one of {TIERS}"
    try:
        einfo = engagement_info(engagement)
    except Exception as e:
        return f"REFUSED: {e}"
    if einfo.get("halted"):
        return f"REFUSED: engagement {engagement} is halted"
    if tier not in einfo["rules"]["tiers"]:
        return f"REFUSED: RULES.md for {engagement} allows tiers {einfo['rules']['tiers']}, not '{tier}'"
    deps = [d for d in (depends_on or []) if d]
    for d in deps:
        if d not in TASKS or TASKS[d]["engagement"] != engagement:
            return f"REFUSED: depends_on: no task {d} in engagement {engagement}"
    task = _defaults({"id": time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4], "goal": goal,
                      "engagement": engagement, "tier": tier, "info": einfo, "max_steps": max(1, min(max_steps, 40)),
                      "timeout_min": max(1, min(timeout_min, 180)), "depends_on": deps,
                      "status": "waiting" if deps else "queued", "started": time.time()})
    TASKS[task["id"]] = task
    save(task)
    start(task)
    _wait(task, wait_s)
    return report(task)


@mcp.tool()
def get_task(task_id: str, wait_s: int = 240) -> str:
    """Get a delegated task's result, waiting up to wait_s seconds if it is still running."""
    task = TASKS.get(task_id)
    if not task:
        return f"unknown task {task_id}"
    _wait(task, wait_s)
    return report(task)


@mcp.tool()
def cancel_task(task_id: str) -> str:
    """Stop a task: a running command is killed, a task waiting for an approval or for other tasks stops."""
    try:
        cancel(task_id)
    except ValueError as e:
        return f"REFUSED: {e}"
    _wait(TASKS[task_id], 30)
    return report(TASKS[task_id])


@mcp.tool()
def resume_task(task_id: str, wait_s: int = 240) -> str:
    """Continue an interrupted task (the worker restarted) from its last checkpoint. The engagement's policy is
    checked again first. An action that was in flight is not repeated: the model is told its result is unknown."""
    try:
        task = resume(task_id)
    except ValueError as e:
        return f"REFUSED: {e}"
    _wait(task, wait_s)
    return report(task)


@mcp.tool()
def list_tasks(engagement: str = "") -> str:
    """List delegated tasks (newest first, up to 50), optionally for one engagement. Tasks are kept across worker
    restarts; a task that was running during a restart shows as interrupted (resume_task continues it)."""
    rows = sorted((t for t in TASKS.values() if not engagement or t["engagement"] == engagement),
                  key=lambda t: t["started"], reverse=True)[:50]
    return json.dumps([{"task_id": t["id"], "status": t["status"], "engagement": t["engagement"],
                        "goal": t["goal"][:100], **({"approval": t["approval"]["id"]} if t.get("approval") else {}),
                        **({"recovery": t["recovery"]["decision"]} if t.get("recovery") else {})}
                       for t in rows], indent=1) if rows else "no tasks"


if __name__ == "__main__":
    load_tasks()
    threading.Thread(target=control_watch, daemon=True).start()
    mcp.run(transport="streamable-http")
