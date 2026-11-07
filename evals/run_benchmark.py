"""Unattended benchmark: run the real agent (OpenHands + MCP tools) on a known target and score its findings.

  python3 evals/run_benchmark.py <name|all> [--agent riskvoid-planner|riskvoid-local] [--keep]
  python3 evals/run_benchmark.py --history            compare past runs
  (or ./rvkit bench ...)

Benchmarks are evals/benchmarks/<name>.json: a target (code fixture in evals/targets/, or a lab host), the rules
of engagement, a task, and the expected findings. Each run:
  1. resets engagement bench-<name> and copies the code target to <PROJECTS_DIR>/rv-bench/
  2. starts an OpenHands conversation with the agent profile and an unattended-run preamble
  3. approves intrusive commands automatically, only for lab engagements (isolated practice targets)
  4. scores confirmed findings against the expected list (one-to-one matching by CWE or keyword):
       recall     expected findings found / expected
       weighted   same, weighted by severity (critical 4, high 3, medium 2, low 1)
       precision  confirmed findings that match an expected one / confirmed (unmatched ones are listed: they
                  may be real extra issues, review them)
     plus OpenRouter cost (usage delta of your key), wall time and planner tokens
  5. writes evals/results/bench/<name>-<UTC>.json and a line in evals/results/bench/history.jsonl
Cost is measured from your OpenRouter key's usage: don't use the key for anything else during a run.
"""
import datetime, hashlib, json, os, re, shutil, sqlite3, subprocess, sys, time, urllib.error, urllib.request

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OH = os.environ.get("OPENHANDS_URL", "http://127.0.0.1:8000")
BENCH = os.path.join(KIT, "evals", "benchmarks")
OUT = os.path.join(KIT, "evals", "results", "bench")
SEV_W = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
LAB_NET = "10.250.0."


def env():
    e = {}
    for line in open(os.path.join(KIT, ".env")):
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.rstrip("\n").split("=", 1)
            e[k] = v
    return e


E = env()
EXPAND = lambda p: os.path.expanduser(p or "")
ENG_DIR = EXPAND(E.get("ENGAGEMENTS_DIR") or "~/projects/engagements")
PROJ_DIR = EXPAND(E.get("PROJECTS_DIR") or "~/projects")


def http(method, url, body=None, headers=None, timeout=120):
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}


def oh(method, path, body=None):
    return http(method, OH + path, body, {"X-Session-API-Key": E.get("OPENHANDS_API_KEY", "")})


def rvkit(*args, check=True):
    r = subprocess.run([os.path.join(KIT, "rvkit"), *args], cwd=KIT, capture_output=True, text=True)
    if check and r.returncode not in (0, 2):
        raise SystemExit(f"./rvkit {' '.join(args)} failed:\n{r.stdout}{r.stderr}")
    return r.stdout


def openrouter_usage():
    key = E.get("OPENROUTER_API_KEY")
    if not key:
        return None
    try:
        return float(http("GET", "https://openrouter.ai/api/v1/key", headers={"Authorization": f"Bearer {key}"},
                          timeout=30)["data"]["usage"])
    except Exception:
        return None


def lab_running():
    r = subprocess.run(["docker", "compose", "--profile", "lab", "ps", "lab-juice-shop", "--format", "{{.State}}"],
                       cwd=KIT, capture_output=True, text=True)
    return "running" in r.stdout


# ---------------------------------------------------------------- setup
def prepare(name, b):
    eng = f"bench-{name}"
    d = os.path.join(ENG_DIR, eng)
    if os.path.isdir(d):  # reset: sandbox files may belong to engagement users, so delete inside a container
        rvkit("resume", eng, check=False)
        subprocess.run(["docker", "compose", "exec", "-T", "findings-mcp", "sh", "-c",
                        f"rm -rf /work/{eng}/* /work/{eng}/.home /work/{eng}/.[!.]*"], cwd=KIT, capture_output=True)
    if b["kind"] == "code":
        src = os.path.join(KIT, "evals", "targets", b["target"])
        dst = os.path.join(PROJ_DIR, "rv-bench", b["target"])
        shutil.rmtree(dst, ignore_errors=True)
        shutil.copytree(src, dst)
        target = f"/src/rv-bench/{b['target']}"
    else:
        target = b["target"]
    rvkit("engagement", eng, target)
    with open(os.path.join(d, "RULES.md"), "w") as f:
        f.write(f"# Rules of engagement for {eng} (benchmark)\n- Allowed tiers: {b['tiers']}\n"
                f"- Max rate: {b.get('max_rate', 50)}\n- Network: online\n")
    rvkit("scope", eng, "--yes")
    return eng, target


def preamble(eng, b, target):
    approvals = ("Intrusive commands return an approval id: the benchmark harness approves them within about "
                 "30 seconds. Wait (`sleep 30` in your terminal), then call run again with the identical command and "
                 "the approval_id." if b.get("lab") else
                 "Intrusive tools are not allowed in this engagement.")
    return (f"UNATTENDED BENCHMARK RUN. Engagement: `{eng}`. Target: {target}.\n\n"
            f"Task: {b['task'].format(src=target, url=b.get('url', target))}\n\n"
            "No human is watching this run: never ask questions or wait for answers. Make reasonable decisions "
            "yourself and note them in PLAN.md. " + approvals + "\n"
            "Record every issue you confirm with the findings tools (record_finding / update_finding, status "
            "`confirmed`), one finding per root cause, with a CWE. Triage every candidate. Do not generate the "
            f"report. You have about {b['max_minutes']} minutes. When done, reply with a one-paragraph summary.")


# ---------------------------------------------------------------- run
def approve_pending(eng):
    n = 0
    for line in rvkit("approvals", eng, check=False).splitlines():
        m = re.match(r"^([0-9a-f-]{6,})\s+\[", line.strip())
        if m:
            rvkit("approve", eng, m.group(1), check=False)
            n += 1
    return n


def run_conversation(eng, b, agent, target, log):
    prof = next((p for p in oh("GET", "/api/agent-profiles")["profiles"] if p["name"] == agent), None)
    if not prof:
        raise SystemExit(f"agent profile {agent!r} not found: run ./rvkit openhands")
    conv = oh("POST", "/api/conversations", {
        "workspace": {"working_dir": "/projects"}, "agent_profile_id": prof["id"], "max_iterations": 300,
        "max_budget_per_run": b.get("max_budget_usd", 5.0), "title": f"benchmark {eng}",
        "initial_message": {"role": "user", "content": [{"type": "text", "text": preamble(eng, b, target)}]}})
    cid = conv["id"]
    try:
        oh("POST", f"/api/conversations/{cid}/run")
    except urllib.error.HTTPError as e:
        if e.code != 409:  # 409: the initial message already started it
            raise
    log(f"  conversation {cid} (watch it at {OH}/canvas)")
    t0, approved, status = time.time(), 0, "running"
    lab_only = b.get("lab") and target.startswith(LAB_NET)
    while True:
        time.sleep(15)
        try:
            status = oh("GET", f"/api/conversations/{cid}")["execution_status"]
        except (urllib.error.URLError, TimeoutError):
            continue
        if lab_only:
            approved += approve_pending(eng)
        if status not in ("running", "idle") or (status == "idle" and time.time() - t0 > 60):
            break
        if time.time() - t0 > b["max_minutes"] * 60:
            try:
                oh("POST", f"/api/conversations/{cid}/pause")
            except Exception:
                pass
            status = "timeout"
            break
    conv = oh("GET", f"/api/conversations/{cid}")
    usage = (conv.get("stats") or {}).get("usage_to_metrics", {})
    tok = {k: sum((u.get("accumulated_token_usage") or {}).get(k, 0) or 0 for u in usage.values())
           for k in ("prompt_tokens", "completion_tokens", "cache_read_tokens")}
    try:
        final = oh("GET", f"/api/conversations/{cid}/agent_final_response").get("response", "")
    except Exception:
        final = ""
    return {"conversation_id": cid, "status": status, "seconds": round(time.time() - t0),
            "approvals_auto": approved, "tokens": tok, "final_response": final[:2000]}


# ---------------------------------------------------------------- scoring
def findings(eng):
    p = os.path.join(ENG_DIR, eng, "findings.db")
    if not os.path.exists(p):
        return []
    con = sqlite3.connect(p)
    con.row_factory = sqlite3.Row
    return [dict(r) for r in con.execute("SELECT * FROM findings")]


def match_strength(f, exp):
    """2 = keyword match (specific), 1 = CWE-only match, 0 = no match."""
    text = " ".join(str(f.get(k) or "") for k in ("title", "description", "asset", "cwe")).lower()
    if any(re.search(rx, text) for rx in exp.get("any", [])):
        return 2
    return 1 if set(re.findall(r"cwe-\d+", text)) & {c.lower() for c in exp.get("cwe", [])} else 0


def score(b, allf):
    conf = [f for f in allf if f["status"] in ("confirmed", "fixed", "accepted-risk")]
    exp = b["expected"]
    # candidate findings per expected item, keyword matches first so the specific one wins
    edges = {i: [j for st, j in sorted(((match_strength(f, e), j) for j, f in enumerate(conf)), key=lambda x: -x[0])
                 if st] for i, e in enumerate(exp)}
    owner = {}  # finding index -> expected index; augmenting paths = maximum one-to-one matching

    def assign(i, seen):
        for j in edges[i]:
            if j not in seen:
                seen.add(j)
                if j not in owner or assign(owner[j], seen):
                    owner[j] = i
                    return True
        return False
    for i in sorted(edges, key=lambda i: len(edges[i])):
        assign(i, set())
    found = {i: conf[j]["id"] for j, i in owner.items()}
    total_w = sum(SEV_W[e["severity"]] for e in exp) or 1
    return {
        "expected": len(exp), "found": len(found), "confirmed": len(conf),
        "candidates_left": sum(1 for f in allf if f["status"] == "candidate"),
        "false_positives_marked": sum(1 for f in allf if f["status"] == "false-positive"),
        "recall": round(len(found) / len(exp), 3) if exp else None,
        "weighted_recall": round(sum(SEV_W[exp[i]["severity"]] for i in found) / total_w, 3),
        "precision": round(len(owner) / len(conf), 3) if conf else None,
        "per_expected": [{"id": e["id"], "severity": e["severity"], "found_by": found.get(i)} for i, e in enumerate(exp)],
        "unmatched_findings": [{"id": conf[j]["id"], "title": conf[j]["title"], "severity": conf[j]["severity"],
                                "cwe": conf[j].get("cwe")} for j in range(len(conf)) if j not in owner],
    }


# ---------------------------------------------------------------- main
def models():
    cfg = open(os.path.join(KIT, "litellm", "config.yaml")).read()
    m = re.search(r"model_name: planner\n\s+litellm_params:\n\s+model: (\S+)", cfg)
    return {"planner": m.group(1) if m else None, "worker": E.get("WORKER_MODEL_ID"),
            "worker_endpoint": re.sub(r"//([^/]+)\.trycloudflare\.com", "//<colab-tunnel>", E.get("WORKER_API_BASE", ""))}


def run_one(name, agent, log=print):
    b = json.load(open(os.path.join(BENCH, f"{name}.json")))
    if b.get("lab") and not lab_running():
        log(f"SKIP {name}: lab not running (./rvkit lab up)")
        return None
    log(f"== {name}: {b['description']}")
    eng, target = prepare(name, b)
    before = openrouter_usage()
    run = run_conversation(eng, b, agent, target, log)
    after = openrouter_usage()
    s = score(b, findings(eng))
    prompt_sha = hashlib.sha256(open(os.path.join(KIT, "prompts", "planner.md"), "rb").read()).hexdigest()[:12]
    now = datetime.datetime.now(datetime.timezone.utc)
    res = {"benchmark": name, "at": now.isoformat(timespec="seconds"), "agent": agent, "models": models(),
           "planner_prompt_sha": prompt_sha, "engagement": eng,
           "cost_usd": round(after - before, 4) if before is not None and after is not None else None,
           **run, "score": s}
    os.makedirs(OUT, exist_ok=True)
    json.dump(res, open(os.path.join(OUT, f"{name}-{now:%Y%m%dT%H%M%SZ}.json"), "w"), indent=1)
    with open(os.path.join(OUT, "history.jsonl"), "a") as h:
        h.write(json.dumps({k: res[k] for k in ("benchmark", "at", "agent", "planner_prompt_sha", "cost_usd",
                                                 "status", "seconds")} | {"models": res["models"]}
                           | {k: s[k] for k in ("recall", "weighted_recall", "precision", "found", "expected",
                                                "confirmed")}) + "\n")
    log(f"  status {run['status']} in {run['seconds'] // 60} min, cost "
        f"{'$%.2f' % res['cost_usd'] if res['cost_usd'] is not None else 'n/a'}, "
        f"recall {s['found']}/{s['expected']} (weighted {s['weighted_recall']:.0%}), "
        f"precision {s['precision'] if s['precision'] is not None else 'n/a'}")
    for p in s["per_expected"]:
        log(f"    {'✔' if p['found_by'] else '✘'} {p['id']:26} {p['severity']:9} {p['found_by'] or ''}")
    for u in s["unmatched_findings"]:
        log(f"    ? {u['id']} {u['title'][:70]} ({u['severity']}, {u['cwe']}): not in the expected list, review")
    return res


def history():
    p = os.path.join(OUT, "history.jsonl")
    rows = [json.loads(l) for l in open(p)] if os.path.exists(p) else []
    print(f"{'when (UTC)':17} {'benchmark':15} {'agent':17} {'planner':28} {'prompt':12} {'recall':>7} "
          f"{'wtd':>5} {'prec':>5} {'cost':>7} {'min':>4} status")
    for r in rows:
        f = lambda x, p="{:.2f}": p.format(x) if x is not None else "n/a"
        print(f"{r['at'][:16]:17} {r['benchmark']:15} {r['agent']:17} {str(r['models']['planner'])[-28:]:28} "
              f"{r['planner_prompt_sha']:12} {r['found']}/{r['expected']:<5} {f(r['weighted_recall']):>5} "
              f"{f(r['precision']):>5} {f(r['cost_usd'], '${:.2f}'):>7} {r['seconds'] // 60:>4} {r['status']}")


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        print("benchmarks:", ", ".join(sorted(f[:-5] for f in os.listdir(BENCH) if f.endswith(".json"))))
        return 2
    if argv[0] == "--history":
        history()
        return 0
    agent = argv[argv.index("--agent") + 1] if "--agent" in argv else "riskvoid-planner"
    names = sorted(f[:-5] for f in os.listdir(BENCH) if f.endswith(".json") and f != "smoke.json") \
        if argv[0] == "all" else [argv[0]]
    for n in names:
        run_one(n, agent)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
