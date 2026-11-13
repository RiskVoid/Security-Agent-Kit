"""Tool-call conformance of the worker model (epic #52, issue #36): does this model, on this serving stack, call the
worker's tools correctly?

The same model calls tools differently on different servers and quantizations, and the kit can serve the worker
from Colab (Q4 on an L4, Q8 on an A100), a local server or a hosted API. 24 fixed prompts built from the worker's
own tools: a single call, several arguments, nested arguments (arrays, objects), "should finish" and "should not
call a tool". Each answer is scored on:
  json     the arguments parse as a JSON object
  schema   they fit the tool's schema: required arguments, types, enums, no unknown arguments
  tool     the expected tool (or none) was called, with the expected values
The score is the share of prompts that pass all three. Below THRESHOLD the worker is likely to waste steps on
malformed calls (the worker returns them as errors; three in a row stop a task).

Runs where the worker runs (it needs the gateway and the worker's tool list):
  docker compose exec -T worker-mcp python3 - < evals/toolcall_conformance.py      (./rvkit doctor --models)
  options after "-": --json  --model <gateway model, default the worker's>
Costs 24 short model calls.
"""
import json, os, re, sys, time, urllib.error, urllib.request

THRESHOLD = 0.85
SYSTEM = ("You are a security testing worker on an authorised engagement (engagement acme, tier active, scope "
          "10.0.0.5 and /src/app). Use your tools to do what the user asks. Call a tool only when the request needs "
          "one; answer in plain text otherwise.")

# (id, kind, prompt, expected tool or None, {argument: regex or exact value})
CASES = [
    ("run-id", "single", "Run the command `id` in the Kali container.", "kali_run", {"command": r"^\s*id\s*$"}),
    ("run-nmap", "single", "Scan ports 80 and 443 on 10.0.0.5 with nmap, service detection on.", "kali_run",
     {"command": r"nmap.*-sV.*(80,443|443,80)|nmap.*(80,443|443,80).*-sV"}),
    ("run-timeout", "several", "Run `nuclei -u http://10.0.0.5 -jsonl -o nuclei.jsonl` with a timeout of 900 seconds.",
     "kali_run", {"command": r"nuclei .*-u http://10\.0\.0\.5", "timeout_s": 900}),
    ("search", "single", "Search the web for the Flask debug console PIN bypass.", "web_search", {"query": r"(?i)flask"}),
    ("fetch", "single", "Read the page https://nvd.nist.gov/vuln/detail/CVE-2024-3094.", "fetch_url",
     {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"}),
    ("read", "several", "Read lines 40 to 89 of /src/app/views.py.", "read_file",
     {"path": "/src/app/views.py", "start": 40, "lines": 50}),
    ("read-default", "single", "Show me the start of /src/app/settings.py.", "read_file",
     {"path": "/src/app/settings.py"}),
    ("identity", "single", "Check whether the test identity alice still has a working session.", "check_identity",
     {"identity": "alice"}),
    ("http-get", "several", "Send a GET request to http://10.0.0.5/api/users/2.", "http_request",
     {"method": "GET", "url": "http://10.0.0.5/api/users/2"}),
    ("http-headers", "nested", "Send a GET to http://10.0.0.5/admin with the header X-Forwarded-For: 127.0.0.1.",
     "http_request", {"method": "GET", "url": "http://10.0.0.5/admin", "headers": {"X-Forwarded-For": "127.0.0.1"}}),
    ("http-identity", "several", "bob's session was checked a minute ago and is valid. Now, as the test identity "
     "bob, GET http://10.0.0.5/api/invoices/7.", "http_request",
     {"method": "GET", "url": "http://10.0.0.5/api/invoices/7", "identity": "bob"}),
    ("http-post", "nested", 'POST the JSON body {"name": "x"} to http://10.0.0.5/api/items with the header '
     "Content-Type: application/json.", "http_request",
     {"method": "POST", "url": "http://10.0.0.5/api/items", "body": r'"name"', "headers": {"Content-Type": r"json"}}),
    ("semgrep", "nested", "Run semgrep on /src/app with the python and flask rule folders.", "analyze_source",
     {"tool": "semgrep", "path": "/src/app", "rulesets": ["python", "flask"]}),
    ("gitleaks", "single", "Look for leaked secrets in /src/app with gitleaks.", "analyze_source",
     {"tool": "gitleaks", "path": "/src/app"}),
    ("intel", "nested", "How risky are CVE-2021-44228 and CVE-2023-4863 in practice?", "vuln_intel",
     {"ids": ["CVE-2021-44228", "CVE-2023-4863"]}),
    ("candidate", "nested", "You already read both evidence files and they show the issue. Record this candidate "
     "now: title 'SQL injection in /login', severity high, asset /login, description 'username is concatenated into "
     "the query', evidence /work/acme/evidence/runs/sqlmap.txt and /src/app/views.py:42, CWE-89.", "record_candidate",
     {"title": r"(?i)sql injection", "severity": "high", "asset": "/login", "cwe": r"^(CWE-)?89$",
      "evidence": ["/work/acme/evidence/runs/sqlmap.txt", "/src/app/views.py:42"]}),
    ("candidate-low", "nested", "You already checked the evidence. Record a low-severity candidate now: 'Server "
     "header discloses nginx version' on http://10.0.0.5/, evidence /work/acme/evidence/http/a.txt.", "record_candidate",
     {"severity": "low", "evidence": ["/work/acme/evidence/http/a.txt"]}),
    ("finish-found", "finish", "You are done. You confirmed one SQL injection in /login and nothing else. Return "
     "your result now with high confidence.", "finish", {"confidence": "high", "summary": r"(?i)sql"}),
    ("finish-nothing", "finish", "Stop now and return the result: you found nothing, and you couldn't test the "
     "admin area because it needs an account. Confidence low; list the admin area as an open question.", "finish",
     {"confidence": "low", "open_questions": r"(?i)admin"}),
    ("finish-observations", "finish", "Finish with confidence medium, summary 'Two open ports, no issues', and two "
     "observations: 'port 22 open' and 'port 80 open'.", "finish",
     {"confidence": "medium", "observations": ["port 22 open", "port 80 open"]}),
    ("no-tool-question", "none", "In one sentence, without using any tool: what does the passive tier allow?", None, {}),
    ("no-tool-thanks", "none", "Thanks, that's all I needed to know. No action needed.", None, {}),
    ("no-tool-explain", "none", "Explain in two sentences what a boolean-based blind SQL injection is. Don't run "
     "anything.", None, {}),
    ("no-tool-refuse", "none", "Without calling any tool, tell me whether you are allowed to scan 192.168.1.1 "
     "(it isn't in scope).", None, {}),
]


# ---------------------------------------------------------------- scoring (pure)
def schema_problems(args, schema):
    """What is wrong with args against a (subset of) JSON schema: types, enums, required, unknown keys."""
    out = []
    props = schema.get("properties", {})
    for k in schema.get("required", []):
        if k not in args:
            out.append(f"missing {k}")
    for k, v in args.items():
        if k not in props:
            out.append(f"unknown {k}")
            continue
        out += [f"{k}: {p}" for p in _type_problems(v, props[k])]
    return out


def _type_problems(v, spec):
    t = spec.get("type")
    ok = {"string": isinstance(v, str), "integer": isinstance(v, int) and not isinstance(v, bool),
          "number": isinstance(v, (int, float)) and not isinstance(v, bool), "boolean": isinstance(v, bool),
          "array": isinstance(v, list), "object": isinstance(v, dict)}.get(t, True)
    if not ok:
        return [f"expected {t}, got {type(v).__name__}"]
    if "enum" in spec and v not in spec["enum"]:
        return [f"{v!r} not one of {spec['enum']}"]
    if t == "array" and "items" in spec:
        return [p for x in v for p in _type_problems(x, spec["items"])]
    return []


def _is_rx(w):
    return isinstance(w, str) and bool(w) and (w[0] in "^(" or any(c in w for c in "\\*|"))


def _matches(want, got):
    """Does an argument the model gave match what the prompt asked for? A regex (any item, for a list), a dict of
    such values (keys case-insensitive), a list (same items, any order), or a string (same, ignoring case)."""
    if _is_rx(want):
        return any(isinstance(x, str) and re.search(want, x) for x in (got if isinstance(got, list) else [got]))
    if isinstance(want, dict):
        if not isinstance(got, dict):
            return False
        low = {str(k).lower(): v for k, v in got.items()}
        return all(k.lower() in low and _matches(v, low[k.lower()]) for k, v in want.items())
    if isinstance(want, list):
        return isinstance(got, list) and sorted(map(str, want)) == sorted(map(str, got))
    if isinstance(want, str) and isinstance(got, str):
        return want.lower() == got.lower() or (want.startswith("/") and got.rstrip("/") == want.rstrip("/")) or \
            want.lower() in got.lower() and len(want) > 3
    return want == got


def score_case(case, message, schemas):
    """One prompt's result: {"id", "kind", "json", "schema", "tool", "pass", "problem"}."""
    cid, kind, _, want_tool, want_args = case
    calls = (message or {}).get("tool_calls") or []
    r = {"id": cid, "kind": kind, "json": True, "schema": True, "tool": True, "problem": None}
    if want_tool is None:
        if calls:
            r.update(tool=False, problem=f"called {calls[0]['function']['name']} when no tool was needed")
    elif not calls:
        r.update(json=False, schema=False, tool=False, problem="no tool call")
    else:
        fn = calls[0]["function"]
        raw = fn.get("arguments")
        try:
            args = raw if isinstance(raw, dict) else json.loads(raw or "{}")
            if not isinstance(args, dict):
                raise ValueError("not an object")
        except ValueError as e:
            args = None
            r.update(json=False, schema=False, problem=f"arguments not valid JSON: {e}")
        if args is not None:
            probs = schema_problems(args, schemas.get(fn["name"], {}))
            if probs:
                r.update(schema=False, problem="; ".join(probs))
        if fn["name"] != want_tool:
            r.update(tool=False, problem=f"called {fn['name']}, expected {want_tool}")
        elif args is not None:
            bad = [k for k, v in want_args.items() if not _matches(v, args.get(k))]
            if bad:
                r.update(tool=False, problem=f"wrong {', '.join(bad)}: {json.dumps({k: args.get(k) for k in bad})[:160]}")
    r["pass"] = r["json"] and r["schema"] and r["tool"]
    return r


def summary(results, model):
    n = len(results) or 1
    by = lambda key: round(sum(1 for r in results if r[key]) / n, 3)
    kinds = sorted({r["kind"] for r in results})
    return {"model": model, "cases": len(results), "score": by("pass"), "json": by("json"), "schema": by("schema"),
            "right_tool": by("tool"), "threshold": THRESHOLD,
            "by_kind": {k: f"{sum(1 for r in results if r['kind'] == k and r['pass'])}/"
                           f"{sum(1 for r in results if r['kind'] == k)}" for k in kinds},
            "failures": [{k: r[k] for k in ("id", "problem")} for r in results if not r["pass"]],
            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


# ---------------------------------------------------------------- running it
def ask(base, key, model, tools, prompt):
    body = {"model": model, "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
            "tools": tools, "tool_choice": "auto", "max_tokens": 1024, "temperature": 0}
    req = urllib.request.Request(f"{base}/chat/completions", data=json.dumps(body).encode(), headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=300))["choices"][0]["message"]


def main(argv):
    sys.path.insert(0, "/opt/harness")
    import worker   # the worker's own tool list, so the check follows it
    tools = worker.TOOLS
    schemas = {t["function"]["name"]: t["function"]["parameters"] for t in tools}
    model = argv[argv.index("--model") + 1] if "--model" in argv else worker.WORKER_MODEL
    results = []
    for case in CASES:
        try:
            msg = ask(worker.LITELLM, worker.LITELLM_KEY, model, tools, case[2])
        except (urllib.error.URLError, TimeoutError, KeyError, ValueError) as e:
            msg = None
            detail = e.read()[:200].decode(errors="replace") if isinstance(e, urllib.error.HTTPError) else str(e)
            results.append({"id": case[0], "kind": case[1], "json": False, "schema": False, "tool": False,
                            "pass": False, "problem": f"model call failed: {detail[:200]}"})
            continue
        results.append(score_case(case, msg, schemas))
    s = summary(results, model)
    if "--json" in argv:
        print(json.dumps(s))
    else:
        print(f"tool-call conformance of {model}: {s['score']:.0%} ({s['cases']} prompts; valid JSON {s['json']:.0%}, "
              f"schema {s['schema']:.0%}, right tool {s['right_tool']:.0%}); by kind "
              + ", ".join(f"{k} {v}" for k, v in s["by_kind"].items()))
        for f in s["failures"]:
            print(f"  ✘ {f['id']}: {f['problem']}")
    return 0 if s["score"] >= THRESHOLD else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
