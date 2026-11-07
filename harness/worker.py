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
"""
import asyncio, datetime, html, json, os, re, threading, time, urllib.parse, urllib.request, uuid
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.fastmcp import FastMCP
import findings_db as db

LITELLM = os.environ.get("LITELLM_URL", "http://litellm:4000/v1")
LITELLM_KEY = os.environ.get("LITELLM_MASTER_KEY", "")
WORKER_MODEL = os.environ.get("WORKER_MODEL", "colab-qwen")
KALI_MCP = os.environ.get("KALI_MCP_URL", "http://kali-mcp:8090/mcp")
SEARXNG = os.environ.get("SEARXNG_URL", "http://searxng:8080")
INTEL_MCP = os.environ.get("INTEL_MCP_URL", "http://intel-mcp:8093/mcp")
CTX_CHARS = int(os.environ.get("WORKER_CONTEXT_CHARS", "90000"))  # ~25k tokens: fits the 32K L4 profile
TOOL_CHARS = 6000          # tool output kept in context per call; full output goes to a file
TIERS = ("passive", "active", "intrusive")

mcp = FastMCP("worker", host="0.0.0.0", port=8091)
TASKS: dict[str, dict] = {}
MODEL_LOCK = threading.Lock()  # the Qwen server handles one request at a time

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
- If kali_run answers APPROVAL REQUIRED, don't retry or rephrase the command: call finish and report the
  approval id and the exact command in open_questions. The lead consultant gets the user's approval.
- Use kali_run for anything that touches a target. fetch_url is for public research only (advisories, docs).
- Prefer small, specific commands. The current directory is the engagement folder: write all output files there
  (or under ./evidence/). /src is read-only client code: never `cd /src && … > file`; pass /src paths as
  arguments instead. Read only what you need from long output.
- Scanner output is a lead, not a finding. Record a candidate only with concrete evidence (file:line, request/
  response, version + advisory). Don't invent results: if a tool failed or you didn't check, say so.
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


async def _kali(tool: str, args: dict, timeout_s: int = 60) -> str:
    async with streamablehttp_client(KALI_MCP, timeout=30, sse_read_timeout=timeout_s + 120) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool(tool, args)
            return "\n".join(c.text for c in res.content if getattr(c, "text", None))


def engagement_info(engagement):
    """Authoritative scope/rules from kali-mcp (the SCOPE.md in /work is only a mirror)."""
    out = _arun(_kali("engagement_info", {"engagement": engagement}))
    if out.startswith(("REFUSED", "Error")):
        raise ValueError(out)
    return json.loads(out)


def kali_run(task, command, timeout_s=600):
    t = min(int(timeout_s or 600), 3600)
    return _arun(_kali("run", {"command": command, "engagement": task["engagement"], "timeout_s": t}, t))


def vuln_intel(task, ids):
    async def go():
        async with streamablehttp_client(INTEL_MCP, timeout=30, sse_read_timeout=600) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
                res = await s.call_tool("prioritize", {"ids": list(ids)[:50]})
                return "\n".join(c.text for c in res.content if getattr(c, "text", None))
    return _arun(go())


def web_search(task, query):
    url = f"{SEARXNG}/search?" + urllib.parse.urlencode({"q": query, "format": "json"})
    data = json.load(urllib.request.urlopen(url, timeout=30))
    return "\n\n".join(f"{r.get('title')}\n{r.get('url')}\n{(r.get('content') or '')[:300]}"
                       for r in data.get("results", [])[:8]) or "no results"


def _in_scope(host, task):
    sc = task["info"]["scope"]
    if any(host == d or host.endswith("." + d) for d in sc["domains"]):
        return True
    try:
        import ipaddress
        return any(ipaddress.ip_address(host) in ipaddress.ip_network(n) for n in sc["nets"])
    except ValueError:
        return False


def _fetch_refusal(url, task):
    """Why fetch_url must not open this URL, or None. Checks the name and every address it resolves to, so another
    DNS name for an in-scope IP is refused too, as is anything non-public (kit services, lab, metadata)."""
    import ipaddress, socket
    u = urllib.parse.urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        return "only http(s) URLs"
    host = u.hostname.lower()
    if _in_scope(host, task):
        return "REFUSED: this host is an engagement target. Use kali_run (scope-checked and audit-logged)."
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(host, u.port or (443 if u.scheme == "https" else 80),
                                                       proto=socket.IPPROTO_TCP)}
    except OSError as e:
        return f"cannot resolve {host}: {e}"
    for a in addrs:
        ip = ipaddress.ip_address(a.split("%")[0])
        if any(ip in ipaddress.ip_network(n) for n in task["info"]["scope"]["nets"]):
            return (f"REFUSED: {host} resolves to {ip}, which is in the engagement scope. "
                    "Use kali_run (scope-checked and audit-logged).")
        if not ip.is_global:
            return f"REFUSED: {host} resolves to non-public address {ip}; fetch_url is for public research only."
    return None


class _CheckedRedirect(urllib.request.HTTPRedirectHandler):
    """Apply the same check to every redirect, so a public page can't bounce the fetch onto a target."""
    def __init__(self, task):
        self.task = task

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        why = _fetch_refusal(newurl, self.task)
        if why:
            raise urllib.error.URLError(f"redirect to {newurl} blocked: {why}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_url(task, url):
    # Residual risk: the name is resolved again when connecting (DNS rebinding). The kali firewall is the hard
    # boundary for targets; this check keeps the worker's research tool from becoming a way around it.
    why = _fetch_refusal(url, task)
    if why:
        return why
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (rvkit research)"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _CheckedRedirect(task))
    raw = opener.open(req, timeout=30).read(2_000_000).decode("utf-8", "replace")
    text = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", raw)
    text = html.unescape(re.sub(r"(?s)<[^>]+>", " ", text))
    return re.sub(r"\s+\n", "\n", re.sub(r"[ \t]+", " ", text)).strip()


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
    f = db.record(task["engagement"], title=title, severity=severity, asset=asset, description=description,
                  evidence=evidence, cwe=cwe, status="candidate", source=f"worker:{task['id']}")
    task["candidates"].append(f["id"])
    return f"recorded {f['id']} (candidate)"


IMPL = {"kali_run": kali_run, "vuln_intel": vuln_intel, "web_search": web_search, "fetch_url": fetch_url, "read_file": read_file,
        "record_candidate": record_candidate}


# ---------------------------------------------------------------- model loop
def chat(messages, model=WORKER_MODEL):
    body = {"model": model, "messages": messages, "tools": TOOLS, "tool_choice": "auto",
            "max_tokens": 2048, "temperature": 0.3}
    req = urllib.request.Request(f"{LITELLM}/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Authorization": f"Bearer {LITELLM_KEY}", "Content-Type": "application/json"})
    r = json.load(urllib.request.urlopen(req, timeout=900))
    return {**r["choices"][0]["message"], "_served_by": r.get("model")}


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


def run_task(task):
    edir = os.path.join(db.engagement_dir(task["engagement"]), "evidence", "tasks", task["id"])
    os.makedirs(edir, exist_ok=True)
    log = open(os.path.join(edir, "transcript.jsonl"), "a")
    sys_prompt = SYSTEM.format(engagement=task["engagement"], tier=task["tier"], max_steps=task["max_steps"],
                               scope=json.dumps(task["info"]["scope"]))
    messages = [{"role": "system", "content": sys_prompt}, {"role": "user", "content": task["goal"]}]
    deadline = task["started"] + task["timeout_min"] * 60
    # "Worker model: private" in RULES.md: never use the fallback model (tool output and code stay on the endpoint)
    model = "private-llm" if task["info"]["rules"].get("worker") == "private" else WORKER_MODEL
    try:
        with MODEL_LOCK:
            task["status"] = "running"
            for step in range(1, task["max_steps"] + 2):
                if time.time() > deadline:
                    raise TimeoutError(f"task exceeded {task['timeout_min']} min")
                compact(messages)
                if step > task["max_steps"]:  # out of tool budget: force a final answer
                    messages.append({"role": "user", "content": "Tool budget used up. Call finish now."})
                msg = chat(messages, model)
                task.setdefault("served_by", [])
                if msg.get("_served_by") and msg["_served_by"] not in task["served_by"]:
                    task["served_by"].append(msg["_served_by"])
                messages.append({k: v for k, v in msg.items() if k in ("role", "content", "tool_calls")})
                log.write(json.dumps({"ts": _now(), "step": step, "assistant": msg}) + "\n"); log.flush()
                calls = msg.get("tool_calls") or []
                if not calls:
                    messages.append({"role": "user", "content": "Use a tool, or call finish with your result."})
                    continue
                for c in calls:
                    name = c["function"]["name"]
                    try:
                        args = json.loads(c["function"].get("arguments") or "{}")
                    except ValueError:
                        args = {}
                    if name == "finish":
                        task["result"] = args
                        return
                    task["steps"].append({"tool": name, "args": args})
                    try:
                        out = IMPL[name](task, **args) if name in IMPL else f"unknown tool {name}"
                    except Exception as e:  # tool errors go back to the model
                        out = f"ERROR: {type(e).__name__}: {e}"
                    path = os.path.join(edir, f"step-{step:02d}-{name}.txt")
                    open(path, "w").write(f"# {name} {json.dumps(args)}\n\n{out}")
                    task["evidence"].append(path)
                    shown = out if len(out) <= TOOL_CHARS else out[:TOOL_CHARS] + f"\n…truncated, full output: {path}"
                    messages.append({"role": "tool", "tool_call_id": c.get("id", name), "content": shown})
            task["result"] = {"summary": "Stopped without calling finish.", "confidence": "low"}
    except urllib.error.URLError as e:
        task["error"] = f"worker model unreachable ({e}). Start it with /rv-start, then retry."
    except Exception as e:
        task["error"] = f"{type(e).__name__}: {e}"
    finally:
        task["status"] = "error" if task.get("error") else "done"
        task["finished"] = time.time()
        log.write(json.dumps({"ts": _now(), "end": task["status"], "result": task.get("result"),
                              "error": task.get("error")}) + "\n")
        log.close()


def report(task) -> str:
    out = {"task_id": task["id"], "status": task["status"], "engagement": task["engagement"], "tier": task["tier"],
           "elapsed_s": round((task.get("finished") or time.time()) - task["started"]),
           "commands": [s["args"].get("command") or s["args"].get("query") or s["args"].get("url")
                        or s["args"].get("path") or s["args"].get("title") for s in task["steps"]],
           "candidate_findings": task["candidates"], "evidence_dir": os.path.dirname(task["evidence"][0])
           if task["evidence"] else None}
    if task.get("served_by"):
        out["model"] = task["served_by"]  # which model did the work (the fallback model shows up here)
    if task.get("result"):
        out["result"] = task["result"]
    if task.get("error"):
        out["error"] = task["error"]
    if task["status"] in ("queued", "running"):
        out["note"] = f"still {task['status']}; call get_task('{task['id']}') to wait for it"
    return json.dumps(redact(out), indent=1)


def _wait(task, wait_s):
    end = time.time() + max(0, min(wait_s, 600))
    while task["status"] in ("queued", "running") and time.time() < end:
        time.sleep(2)


# ---------------------------------------------------------------- MCP tools
@mcp.tool()
def delegate_task(goal: str, engagement: str, tier: str = "passive", max_steps: int = 15,
                  timeout_min: int = 30, wait_s: int = 240) -> str:
    """Hand one focused, hands-on task to the worker (local Qwen model with Kali, search, fetch and file tools).

    goal: what to do and what to return, e.g. "Run semgrep (p/django) and bandit on /src/acme, check the top
          findings by reading the code, and record candidates with file:line evidence."
    tier: passive | active | intrusive. Use the lowest tier that fits; intrusive needs the user's OK first.
    Tasks run one at a time. Returns the result, or a task_id if it is still running after wait_s seconds
    (then call get_task). Raw output is saved under /work/<engagement>/evidence/tasks/<task_id>/.
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
    task = {"id": time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4], "goal": goal, "engagement": engagement,
            "tier": tier, "info": einfo, "max_steps": max(1, min(max_steps, 40)), "timeout_min": max(1, min(timeout_min, 180)),
            "status": "queued", "started": time.time(), "steps": [], "evidence": [], "candidates": []}
    TASKS[task["id"]] = task
    threading.Thread(target=run_task, args=(task,), daemon=True).start()
    _wait(task, wait_s)
    return report(task)


@mcp.tool()
def get_task(task_id: str, wait_s: int = 240) -> str:
    """Get a delegated task's result, waiting up to wait_s seconds if it is still running."""
    task = TASKS.get(task_id)
    if not task:
        return f"unknown task {task_id} (tasks are kept in memory until the worker restarts)"
    _wait(task, wait_s)
    return report(task)


@mcp.tool()
def list_tasks() -> str:
    """List delegated tasks in this worker session."""
    return json.dumps([{"task_id": t["id"], "status": t["status"], "engagement": t["engagement"],
                        "goal": t["goal"][:100]} for t in TASKS.values()], indent=1) or "no tasks"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
