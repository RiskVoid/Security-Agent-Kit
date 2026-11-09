"""Unattended benchmark: run the real agent (OpenHands + MCP tools) on a known target and score its findings.

  python3 evals/run_benchmark.py <name|all> [--agent riskvoid-planner|riskvoid-local] [--repeat N]
  python3 evals/run_benchmark.py --history            compare past runs
  python3 evals/run_benchmark.py --score <name> <bench-engagement>   score an existing engagement, no model
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
     and on evidence (RW-022): an expected item can require the exact asset or root cause ("asset" regex on the
     asset and instances), evidence that exists, a reproduction and a recorded verification method ("requires");
       strict recall  expected findings found with every requirement met
       clean          "clean" items are controls (a fixed route, a safe pattern): reporting one is a false positive
       tool outcomes  commands run, failed, timed out and refused (from the audit log); "must_not_run" patterns
                      that ran anyway; "expected_refusals" that the policy refused
       decisions      candidates left, findings confirmed without a method, observations not triaged
     plus OpenRouter cost (usage delta of your key), wall time, planner tokens and the versions of the kit, prompt,
     playbooks, tool images and models. --repeat runs a benchmark N times (model output varies) and reports the
     spread. Results hold scores, ids and titles from the kit's own targets, never client data.
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
    if not os.path.exists(os.path.join(KIT, ".env")):  # CI and unit tests import this file without a kit
        return e
    for line in open(os.path.join(KIT, ".env")):
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.rstrip("\n").split("=", 1)
            e[k] = v
    return e


E = env()
EXPAND = lambda p: os.path.expanduser(p or "")
ENG_DIR = EXPAND(E.get("ENGAGEMENTS_DIR") or "~/riskvoid/engagements")
PROJ_DIR = EXPAND(E.get("PROJECTS_DIR") or "~/riskvoid/projects")


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


LAB_SERVICES = {"10.250.0.10": ["lab-juice-shop"], "10.250.0.11": ["lab-dvwa", "lab-dvwa-db"],
                "10.250.0.13": ["lab-vampi"], "10.250.0.14": ["lab-dvga"], "10.250.0.15": ["lab-llm"],
                "10.250.0.16": ["lab-laravel", "lab-laravel-fixed"]}


def lab_running(target):
    """True when every lab container behind this benchmark's target is running."""
    r = subprocess.run(["docker", "compose", "--profile", "lab", "ps", "--status", "running", "--services"],
                       cwd=KIT, capture_output=True, text=True)
    up = set(r.stdout.split())
    need = LAB_SERVICES.get(str(target).split(":")[0], [s for v in LAB_SERVICES.values() for s in v])
    return all(s in up for s in need)


# ---------------------------------------------------------------- setup
def prepare(name, b):
    eng = f"bench-{name}"
    d = os.path.join(ENG_DIR, eng)
    if os.path.isdir(d):  # reset: sandbox files may belong to engagement users, so delete inside a container
        rvkit("resume", eng, check=False)
        subprocess.run(["docker", "compose", "exec", "-T", "findings-mcp", "sh", "-c",
                        f"rm -rf /work/{eng}/* /work/{eng}/.home /work/{eng}/.[!.]*"], cwd=KIT, capture_output=True)
    if b["kind"] == "code":
        src = os.path.join(KIT, "evals", "targets", b["target"], b.get("source_subdir", ""))
        dst = os.path.join(PROJ_DIR, "rv-bench", b["target"])
        shutil.rmtree(dst, ignore_errors=True)
        shutil.copytree(src, dst)
        target = f"/src/rv-bench/{b['target']}"
    else:
        target = b["target"]
    rvkit("engagement", eng, "--replace", target, *b.get("extra_targets", []))
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
    try:
        pending = json.loads(rvkit("approvals", eng, "--json", check=False) or "[]")
    except ValueError:
        return 0
    for a in pending:
        rvkit("approve", eng, a["id"], check=False)
    return len(pending)


def run_conversation(eng, b, agent, target, log):
    prof = next((p for p in oh("GET", "/api/agent-profiles")["profiles"] if p["name"] == agent), None)
    if not prof:
        raise SystemExit(f"agent profile {agent!r} not found: run ./rvkit openhands")
    conv = oh("POST", "/api/conversations", {
        "workspace": {"working_dir": "/workspace/project"}, "agent_profile_id": prof["id"], "max_iterations": 300,
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
    lab_only = b.get("lab") and (target.startswith(LAB_NET) or all(
        x.startswith(LAB_NET) for x in b.get("extra_targets", [])))
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
    if status == "idle" and asked_human(final):
        status = "asked-question"  # stopped to wait for a human: an unattended run that did this has failed
    return {"conversation_id": cid, "status": status, "seconds": round(time.time() - t0),
            "approvals_auto": approved, "tokens": tok, "final_response": final[:2000]}


ASK_RX = re.compile(r"\b(would you like me to|do you want me to|shall i|should i|please confirm|can you confirm|"
                    r"could you (?:confirm|provide|clarify)|which (?:option|one) (?:do|would) you|awaiting your|"
                    r"before i (?:proceed|continue)|how would you like)\b", re.I)


def asked_human(final):
    """True when the agent's last message ends by asking the user something instead of finishing the job."""
    tail = (final or "").strip()[-600:]
    if not tail:
        return False
    last = re.split(r"(?<=[.!?])\s+", tail)[-1]
    return last.rstrip().endswith("?") or bool(ASK_RX.search(tail))


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


def _text(f):
    return " ".join(str(f.get(k) or "") for k in ("title", "description", "asset", "cwe")).lower()


def _instances(f):
    v = f.get("instances") or "[]"
    try:
        inst = json.loads(v) if isinstance(v, str) else v
    except ValueError:
        inst = []
    return [i.get("location", "") if isinstance(i, dict) else str(i) for i in inst]


def _evidence_exists(f, eng_dir):
    ev = f.get("evidence") or "[]"
    try:
        ev = json.loads(ev) if isinstance(ev, str) else ev
    except ValueError:
        ev = [ev]
    ok = []
    for e in ev:
        path = str(e).split(" ")[0]
        if path.startswith("/src/"):
            ok.append(True)  # a code reference: the report checks the line, not a file
        else:
            rel = path.removeprefix("/work/").split("/", 1)[-1] if path.startswith("/work/") else path
            ok.append(bool(eng_dir) and os.path.isfile(os.path.join(eng_dir, rel)))
    return bool(ok) and all(ok)


def requirements(f, e, eng_dir=None):
    """Which of the expected item's evidence requirements the matched finding meets."""
    out = {}
    if e.get("asset"):
        out["asset"] = any(re.search(e["asset"], x or "", re.I) for x in [f.get("asset")] + _instances(f))
    for r in e.get("requires", []):
        if r == "evidence":
            out[r] = _evidence_exists(f, eng_dir)
        elif r == "verification":
            out[r] = (f.get("verified_method") or "not stated") != "not stated"
        elif r == "reproduction":
            out[r] = bool((f.get("reproduction") or "").strip())
    return out


def score(b, allf, eng_dir=None, extra=None):
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
    req = {i: requirements(conf[j], exp[i], eng_dir) for j, i in owner.items()}
    strict = [i for i in found if all(req[i].values())]
    clean_hits = []
    for c in b.get("clean", []):  # controls: reporting one of these is a false positive
        for j, f in enumerate(conf):
            if j not in owner and (any(re.search(rx, _text(f)) for rx in c.get("any", [])) or (
                    c.get("asset") and re.search(c["asset"], f.get("asset") or "", re.I))):
                clean_hits.append({"clean": c["id"], "finding": f["id"], "title": f["title"]})
    extra = extra or {}
    return {
        "expected": len(exp), "found": len(found), "confirmed": len(conf),
        "candidates_left": sum(1 for f in allf if f["status"] == "candidate"),
        "false_positives_marked": sum(1 for f in allf if f["status"] == "false-positive"),
        "duplicates_marked": sum(1 for f in allf if f["status"] == "duplicate"),
        "recall": round(len(found) / len(exp), 3) if exp else None,
        "weighted_recall": round(sum(SEV_W[exp[i]["severity"]] for i in found) / total_w, 3),
        "precision": round(len(owner) / len(conf), 3) if conf else None,
        "strict_recall": round(len(strict) / len(exp), 3) if exp else None,
        "clean_violations": clean_hits,
        "decisions": {"candidates_left": sum(1 for f in allf if f["status"] == "candidate"),
                      "confirmed_without_method": sum(1 for f in conf if f["status"] == "confirmed" and
                                                      (f.get("verified_method") or "not stated") == "not stated"),
                      **({"observations_untriaged": extra["observations_untriaged"]}
                         if "observations_untriaged" in extra else {})},
        "per_expected": [{"id": e["id"], "severity": e["severity"], "found_by": found.get(i),
                          **({"requirements": req[i]} if i in req and req[i] else {})} for i, e in enumerate(exp)],
        "unmatched_findings": [{"id": conf[j]["id"], "title": conf[j]["title"], "severity": conf[j]["severity"],
                                "cwe": conf[j].get("cwe")} for j in range(len(conf)) if j not in owner],
    }


def tool_outcomes(eng, b, audit_path=None):
    """What the tools did, from the audit log: ran, failed, timed out, refused; and the benchmark's must_not_run
    and expected_refusals patterns."""
    audit_path = audit_path or os.path.join(ENG_DIR, "audit.log")
    rows = []
    if os.path.exists(audit_path):
        for line in open(audit_path):
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("engagement") == eng and "command" in r and "event" not in r:
                rows.append(r)
    ran = [r for r in rows if "refused" not in r]
    refused = [r for r in rows if "refused" in r]
    out = {"ran": len(ran), "failed": sum(1 for r in ran if r.get("exit") not in (0, 1, None)),
           "timed_out": sum(1 for r in ran if r.get("exit") in (124, 137) or "timed out" in str(r.get("error", ""))),
           "refused": len(refused)}
    out["must_not_run"] = [r["command"][:200] for r in ran for rx in b.get("must_not_run", [])
                           if re.search(rx, r["command"])]
    out["expected_refusals"] = {rx: any(re.search(rx, r["command"]) for r in refused)
                                for rx in b.get("expected_refusals", [])}
    return out


def observations_untriaged(eng):
    p = os.path.join(ENG_DIR, eng, "findings.db")
    try:
        con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        n = con.execute("SELECT COUNT(*) FROM observations WHERE status='new'").fetchone()[0]
        con.close()
        return n
    except sqlite3.Error:
        return None


def _sha_file(p):
    try:
        return hashlib.sha256(open(p, "rb").read()).hexdigest()[:12]
    except OSError:
        return None


def provenance():
    """Versions a result depends on. Nothing from an engagement."""
    def out(*cmd):
        r = subprocess.run(cmd, cwd=KIT, capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None
    pb = {}
    for f in sorted(os.listdir(os.path.join(KIT, "harness", "playbooks"))):
        if f.endswith(".md"):
            m = re.search(r"^version:\s*(\S+)", open(os.path.join(KIT, "harness", "playbooks", f)).read(), re.M)
            pb[f[:-3]] = m.group(1) if m else None
    images = {}
    for svc in ("kali-mcp", "findings-mcp", "worker-mcp"):
        cid = out("docker", "compose", "ps", "-q", svc)
        images[svc] = (out("docker", "inspect", "-f", "{{.Image}}", cid) or "")[7:19] if cid else None
    return {"kit": (open(os.path.join(KIT, "VERSION")).read().strip() if os.path.exists(os.path.join(KIT, "VERSION"))
                    else None),
            "commit": out("git", "rev-parse", "--short=12", "HEAD"),
            "dirty": bool(out("git", "status", "--porcelain", "--untracked-files=no")),
            "planner_prompt": _sha_file(os.path.join(KIT, "prompts", "planner.md")),
            "local_prompt": _sha_file(os.path.join(KIT, "prompts", "local.md")),
            "playbooks": pb, "images": images,
            "semgrep": out("docker", "compose", "exec", "-T", "kali-mcp", "semgrep", "--version"),
            "parser_version": 1}


# ---------------------------------------------------------------- main
def models():
    return {"planner": E.get("PLANNER_MODEL"), "worker": E.get("WORKER_MODEL_ID"),
            "worker_endpoint": re.sub(r"//([^/]+)\.trycloudflare\.com", "//<colab-tunnel>", E.get("WORKER_API_BASE", ""))}


def run_one(name, agent, log=print, group=None):
    b = json.load(open(os.path.join(BENCH, f"{name}.json")))
    if b.get("lab") and not lab_running(b.get("lab_host", b["target"])):
        log(f"SKIP {name}: lab not running (./rvkit lab up)")
        return None
    log(f"== {name}: {b['description']}")
    eng, target = prepare(name, b)
    before = openrouter_usage()
    run = run_conversation(eng, b, agent, target, log)
    after = openrouter_usage()
    s = score(b, findings(eng), os.path.join(ENG_DIR, eng), {"observations_untriaged": observations_untriaged(eng)})
    s["tools"] = tool_outcomes(eng, b)
    prompt_sha = hashlib.sha256(open(os.path.join(KIT, "prompts", "planner.md"), "rb").read()).hexdigest()[:12]
    now = datetime.datetime.now(datetime.timezone.utc)
    res = {"benchmark": name, "at": now.isoformat(timespec="seconds"), "agent": agent, "models": models(),
           "planner_prompt_sha": prompt_sha, "engagement": eng, "provenance": provenance(), "group": group,
           "note": b.get("note"),
           "cost_usd": round(after - before, 4) if before is not None and after is not None else None,
           **run, "score": s}
    os.makedirs(OUT, exist_ok=True)
    json.dump(res, open(os.path.join(OUT, f"{name}-{now:%Y%m%dT%H%M%SZ}.json"), "w"), indent=1)
    with open(os.path.join(OUT, "history.jsonl"), "a") as h:
        h.write(json.dumps({k: res[k] for k in ("benchmark", "at", "agent", "planner_prompt_sha", "cost_usd",
                                                 "status", "seconds")} | {"models": res["models"]}
                           | {k: s[k] for k in ("recall", "weighted_recall", "precision", "found", "expected",
                                                "confirmed", "strict_recall")}
                           | {"clean_violations": len(s["clean_violations"]), "group": group,
                              "commit": res["provenance"]["commit"]}) + "\n")
    log(f"  status {run['status']} in {run['seconds'] // 60} min, cost "
        f"{'$%.2f' % res['cost_usd'] if res['cost_usd'] is not None else 'n/a'}, "
        f"recall {s['found']}/{s['expected']} (weighted {s['weighted_recall']:.0%}, with evidence "
        f"{s['strict_recall'] if s['strict_recall'] is not None else 'n/a'}), "
        f"precision {s['precision'] if s['precision'] is not None else 'n/a'}, "
        f"{len(s['clean_violations'])} clean control(s) reported")
    if b.get("note"):
        log(f"  note: {b['note']}")
    t_ = s["tools"]
    log(f"  tools: {t_['ran']} ran, {t_['failed']} failed, {t_['timed_out']} timed out, {t_['refused']} refused"
        + (f"; RAN BUT MUST NOT: {t_['must_not_run']}" if t_["must_not_run"] else ""))
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
    if argv[0] == "--score":  # score an existing benchmark engagement, without running a model
        if len(argv) < 3 or not argv[2].startswith("bench-"):
            print("usage: --score <benchmark> <bench-engagement>  (benchmark engagements only)")
            return 2
        b = json.load(open(os.path.join(BENCH, f"{argv[1]}.json")))
        s = score(b, findings(argv[2]), os.path.join(ENG_DIR, argv[2]),
                  {"observations_untriaged": observations_untriaged(argv[2])})
        s["tools"] = tool_outcomes(argv[2], b)
        print(json.dumps(s, indent=1))
        return 0
    agent = argv[argv.index("--agent") + 1] if "--agent" in argv else "riskvoid-planner"
    repeat = int(argv[argv.index("--repeat") + 1]) if "--repeat" in argv else 1
    names = sorted(f[:-5] for f in os.listdir(BENCH) if f.endswith(".json") and f != "smoke.json") \
        if argv[0] == "all" else [argv[0]]
    for n in names:
        group = f"{n}-{datetime.datetime.now(datetime.timezone.utc):%Y%m%dT%H%M%SZ}" if repeat > 1 else None
        runs = [r for r in (run_one(n, agent, group=group) for _ in range(repeat)) if r]
        if len(runs) > 1:
            rec = [r["score"]["recall"] or 0 for r in runs]
            mean = sum(rec) / len(rec)
            sd = (sum((x - mean) ** 2 for x in rec) / (len(rec) - 1)) ** 0.5
            print(f"  {n} over {len(runs)} runs: recall mean {mean:.2f}, min {min(rec):.2f}, max {max(rec):.2f}, "
                  f"sd {sd:.2f}; statuses {', '.join(r['status'] for r in runs)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
