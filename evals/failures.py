"""Failure mining: keep what went wrong in each benchmark run, and group it by cause.

  python3 evals/failures.py                     groups, most widespread first
  python3 evals/failures.py --show <cause>      every record of one cause (a prefix works: missed, tool/kali_run)
  python3 evals/failures.py --rebuild           derive the records again from every saved run
  filters: --benchmark <name>  --kind <kind>  --model <text>  --since <YYYY-MM-DD>   output: --json
  (or ./rvkit bench --failures ...)

Every benchmark run adds its failures to evals/results/bench/failures.jsonl, one JSON object per line, derived
from what the run already keeps: its score, the findings database and worker tasks in engagement.tar.gz, and
conversation.json. Nothing is asked of a model. Each record has a cause, "kind/stage[/...]", built from fixed
rules, so the same failure gets the same cause in every run and the groups can be compared between kit, prompt
and model versions:

  missed/<stage>            an expected finding was not confirmed. The stage is how far the agent got:
      rejected              it recorded the issue and marked it false-positive
      merged                it marked it a duplicate
      left-candidate        it recorded a candidate and never triaged it
      credited-elsewhere    a confirmed finding has the item's keywords but counts for another expected item
      observed              an imported observation has the keywords; no finding was recorded
      seen-in-output        the keywords are in the output of a tool it ran; nothing was recorded
      probed                the keywords are only in what it sent (a command, a request, a worker goal)
      not-attempted         no trace of the item
      unknown               the run's data was not kept
  weak-proof/<requirement>  found, but the finding lacks the asset, evidence, verification or reproduction
  unexpected/<method>       confirmed, not in the expected list: a false positive or a real extra, to review
  clean-control/<method>    a protected control (fixed build, safe pattern) was reported as vulnerable
  policy/<what>             a must_not_run command ran, or an expected refusal did not happen
  run/<status>              the run ended as budget, timeout, stuck, error or asked-question
  stopped-early/<why>       the agent stopped and was sent back to work (no plan, plan unfinished, untriaged, ...)
  triage/<what>             candidates left, findings confirmed without a method, observations not triaged
  tool/<tool>/<class>       a tool call was refused, invalid, timed out or failed; the class is the reason with
                            names, ids, paths and numbers removed
  retry/<tool>/<class>      the same call was sent again after it failed the same way
  worker/<what>             a worker task was interrupted, ran out of steps or ended without calling finish

The stage of a missed item comes from keyword matches ("any" and "cwe" of the expected item), so read it as a lead:
--show lists the finding ids, plan items and tool calls behind each record. Records hold ids, titles and commands
from the kit's own targets, never client data. One "summary" line per run carries no failure: it counts the runs.

Engagements (./rvkit failures)

  python3 evals/failures.py engagements                 groups over the engagements collected so far
  python3 evals/failures.py engagements <name>|--all    collect one engagement (or every one that isn't a benchmark's),
                                                        then show its records; ./rvkit close collects too
  filters: --engagement <name>  --kind <kind>  --since <YYYY-MM-DD>  --show <cause>  --json

An engagement has no expected findings, so its failures are what the kit and the people using it recorded:

  overruled/<what>          a person changed what the agent decided: confirmed-rejected (its confirmed finding was
                            a false positive), candidate-rejected, rejected-confirmed, merged-confirmed,
                            severity-lowered, severity-raised
  approval/denied           a person denied a command or request the agent asked for
  command/<class>           a sandboxed command was refused, failed or timed out (planner and worker; audit log)
  request/<class>           the same for the request tool
  tool/<tool>/<class>, retry/...   as above, from the engagement's bound conversations, for what the audit log
                            doesn't hold (findings and worker tools, invalid calls, tool timeouts)
  worker/<what>             as above
  model/<kind>/<model>      a model call failed, was refused by the provider or was answered by the fallback
  triage/<what>             candidates left, findings confirmed without a method, observations not triaged
  coverage/<state>          planned tests with no outcome (not-run), or blocked

Records go to .rvkit/failures/engagements.jsonl on this machine, replaced each time an engagement is collected.
They hold the engagement name, ids (findings, tasks, approvals), counts and causes: no titles, commands, hosts,
requests or output. A cause keeps the wording of a refusal with names, ids, paths and numbers removed.
"""
import collections, json, os, re, sqlite3, subprocess, sys, tarfile, tempfile

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH = os.path.join(KIT, "evals", "benchmarks")
OUT = os.path.join(KIT, "evals", "results", "bench")
STORE = os.path.join(OUT, "failures.jsonl")
ENG_STORE = os.path.join(KIT, ".rvkit", "failures", "engagements.jsonl")
MODEL_LOG = os.path.join(KIT, ".rvkit", "events", "model-events.jsonl")
SEVERITY = ("info", "low", "medium", "high", "critical")
AUDITED = re.compile(r"^kali_(run|http_request|browse)$")   # their refusals and exits are in the audit log
SUMMARY = "summary"   # the kind of the one line per run that carries no failure
VERSION = 1   # of the rules that build a cause: raise it when they change, then --rebuild
CONFIRMED = ("confirmed", "fixed", "accepted-risk")
# Tools whose calls and results show contact with the target. Playbooks, plans and coverage are left out: they
# quote the checklist, so an expected item's keywords would always be "seen".
TARGET_TOOLS = re.compile(r"^(kali_(?!list_engagements|engagement_|all_scopes|approval)|worker_)")
NUDGES = (("no test plan", "no-plan"), ("have no outcome", "plan-unfinished"), ("not triaged", "untriaged"),
          ("got no answer", "no-model-answer"), ("stopped as stuck", "stuck"))
LEADS = ("no plan item", "targets not in scope", "references look like")   # messages that go on to quote the input


# ---------------------------------------------------------------- causes
def slug(text):
    """A refusal or error message as a stable reason: the detail cut off, then names, ids, paths and numbers
    removed. Two shapes are read: "<reason>: <detail>" and "<file> (<note>): <reason>"."""
    s = (text or "").strip().split("\n")[0]
    first = s.split(" ", 1)[0]
    lead = next((p for p in LEADS if s.startswith(p)), None)
    if lead:
        s = lead
    elif ("/" in first or re.fullmatch(r"[\w-]+\.\w{1,5}", first)) and ": " in s:
        s = s.rsplit(": ", 1)[1]
    else:
        m = re.search(r" \(|: |; |\[", s)
        if m and len(s[:m.start()].split()) >= 2:
            s = s[:m.start()]
    s = re.sub(r"\bbench-[\w-]+", "<eng>", s)
    s = re.sub(r"\b[A-Z]{1,2}-\d+\b", "<id>", s)
    s = re.sub(r"\b(?=[0-9a-f]*\d)(?=\d*[a-f])[0-9a-f]{6,}\b", "<id>", s)   # approval and task ids
    s = re.sub(r"\S*/\S+", "<path>", s)
    s = re.sub(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", "<METHOD>", s)
    s = re.sub(r"\d+(\.\d+)*", "#", s)
    return re.sub(r"\s+", " ", s).strip(" .:,")[:70] or "unspecified"


def tool_class(tool, body, is_error=False):
    """The failure class of a tool result, or None when the call worked."""
    first = (body or "").strip().split("\n")[0]
    if first.startswith("REFUSED"):
        return "refused: " + slug(first.split(":", 1)[-1])
    if re.match(r"MCP tool '[^']+' timed out", first):
        return "timeout"
    m = re.match(r"Error executing tool \w+: (.*)", first)
    if m:
        return "invalid-call: " + slug(m.group(1))
    m = re.match(r"exit=(-?\d+)\b", first)
    if m:
        code = int(m.group(1))
        return "command-timeout" if code in (124, 137) else None if code in (0, 1) else "command-failed"
    if first.startswith("APPROVAL REQUIRED"):
        return None   # waiting for a person is the design, not a failure
    return "error: " + slug(first) if is_error else None


def strength(f, exp):
    """2 = keyword match, 1 = CWE-only match, 0 = none (the benchmark scorer's rule)."""
    text = " ".join(str(f.get(k) or "") for k in ("title", "description", "asset", "cwe")).lower()
    if any(re.search(rx, text) for rx in exp.get("any", [])):
        return 2
    return 1 if set(re.findall(r"cwe-\d+", text)) & {c.lower() for c in exp.get("cwe", [])} else 0


def _body(event):
    parts = [c.get("text") or "" for c in (event.get("observation") or {}).get("content") or [] if isinstance(c, dict)]
    return "\n".join(p for p in parts if not p.startswith("[Tool ")).strip()


def calls(events):
    """Tool calls of a conversation, oldest first: {tool, args (text), body, is_error}."""
    args = {}
    for e in events:
        if e.get("kind") == "ActionEvent" and e.get("tool_call_id"):
            a = (e.get("tool_call") or {}).get("arguments")
            args[e["tool_call_id"]] = a if isinstance(a, str) else json.dumps(a or {}, sort_keys=True)
    return [{"tool": e.get("tool_name") or "", "args": args.get(e.get("tool_call_id"), ""), "body": _body(e),
             "is_error": bool((e.get("observation") or {}).get("is_error"))}
            for e in events if e.get("kind") == "ObservationEvent" and e.get("tool_name")]


def _short_args(args, n=200):
    try:
        a = json.loads(args)
        a = a.get("command") or a.get("url") or a.get("goal") or args
    except (ValueError, AttributeError):
        a = args
    return re.sub(r"\s+", " ", str(a))[:n]


def missed_stage(exp, data):
    """How far the agent got with an expected item it did not confirm, and what shows it."""
    if data is None:
        return "unknown", {}
    hits = sorted(((strength(f, exp), f) for f in data["findings"]), key=lambda x: -x[0])
    rxs = exp.get("any", [])
    plan = [{"id": p["id"], "state": p["state"]} for p in data["plan"]
            if any(re.search(rx, (p.get("title") or "").lower()) for rx in rxs)][:6]
    detail = {"plan": plan} if plan else {}
    for stage, statuses, need in (("rejected", ("false-positive",), 1), ("merged", ("duplicate",), 1),
                                  ("left-candidate", ("candidate",), 1), ("credited-elsewhere", CONFIRMED, 2)):
        ids = [f["id"] for st, f in hits if st >= need and f.get("status") in statuses]
        if ids:
            return stage, {**detail, "findings": ids[:6]}
    obs = [o["id"] for o in data["observations"] if any(re.search(rx, " ".join(
        str(o.get(k) or "") for k in ("title", "rule_id", "location", "detail")).lower()) for rx in rxs)]
    if obs:
        return "observed", {**detail, "observations": obs[:6]}
    target = [c for c in data["calls"] if TARGET_TOOLS.match(c["tool"])]
    seen = [c for c in target if any(re.search(rx, c["body"].lower()) for rx in rxs)]
    if seen:
        return "seen-in-output", {**detail, "calls": len(seen), "example": _short_args(seen[0]["args"])}
    sent = [c for c in target if any(re.search(rx, c["args"].lower()) for rx in rxs)]
    if sent:
        return "probed", {**detail, "calls": len(sent), "example": _short_args(sent[0]["args"])}
    return "not-attempted", detail


def collect(res, bench, data):
    """The failure records of one run. res: the saved result; bench: its benchmark definition (or None);
    data: {"findings", "observations", "plan", "calls", "tasks"} from the run's kept data, or None."""
    s = res.get("score") or {}
    prov, models = res.get("provenance") or {}, res.get("models") or {}
    base = {"v": VERSION, "run": res["run"], "benchmark": res.get("benchmark"), "at": res.get("at"),
            "agent": res.get("agent"), "planner": models.get("planner"), "worker": models.get("worker"),
            "commit": prov.get("commit"), "prompt": res.get("planner_prompt_sha"), "ended": res.get("status")}
    out = []

    def add(kind, stage, subject=None, n=1, **detail):
        out.append({**base, "kind": kind, "cause": f"{kind}/{stage}", "subject": subject, "n": n,
                    **({"detail": detail} if detail else {})})

    expected = {e["id"]: e for e in (bench or {}).get("expected", [])}
    by_id = {f["id"]: f for f in (data or {}).get("findings", [])}
    method = lambda fid: (by_id.get(fid, {}).get("verified_method") or "not stated").replace(" ", "-")
    for p in s.get("per_expected", []):
        if not p.get("found_by"):
            stage, detail = missed_stage(expected[p["id"]], data) if p["id"] in expected else ("unknown", {})
            add("missed", stage, p["id"], severity=p.get("severity"), **detail)
        for req, ok in (p.get("requirements") or {}).items():
            if not ok:
                add("weak-proof", req, p["id"], finding=p["found_by"], method=method(p["found_by"]))
    for u in s.get("unmatched_findings", []):
        add("unexpected", method(u["id"]), u["id"], title=u.get("title"), severity=u.get("severity"), cwe=u.get("cwe"))
    for c in s.get("clean_violations", []):
        add("clean-control", method(c["finding"]), c["clean"], finding=c["finding"], title=c.get("title"))
    tools = s.get("tools") or {}
    for cmd in tools.get("must_not_run", []):
        add("policy", "must-not-run", command=cmd)
    for rx, refused in (tools.get("expected_refusals") or {}).items():
        if not refused:
            add("policy", "refusal-missing", rx)
    if res.get("status") not in (None, "finished"):
        add("run", res["status"])
    for nudge in res.get("continued") or []:
        text = " ".join(nudge) if isinstance(nudge, list) else str(nudge)
        for needle, why in NUDGES:
            if needle in text:
                add("stopped-early", why)
    dec = s.get("decisions") or {}
    for key, stage in (("candidates_left", "candidates-left"), ("confirmed_without_method", "confirmed-without-method"),
                       ("observations_untriaged", "observations-untriaged")):
        if dec.get(key):
            add("triage", stage, n=dec[key])

    failed = collections.OrderedDict()   # (tool, class) -> the failing calls, in order
    for c in (data or {}).get("calls", []):
        cls = tool_class(c["tool"], c["body"], c["is_error"])
        if cls:
            failed.setdefault((c["tool"], cls), []).append(c)
    for (tool, cls), cs in failed.items():
        add("tool", f"{tool}/{cls}", tool, n=len(cs), examples=[_short_args(c["args"]) for c in cs[:2]],
            message=cs[0]["body"].split("\n")[0][:200])
        again = collections.Counter(c["args"] for c in cs)
        repeats = sum(n - 1 for n in again.values() if n > 1)
        if repeats:
            add("retry", f"{tool}/{cls}", tool, n=repeats, examples=[_short_args(a) for a, n in again.items() if n > 1][:2])
    for t in (data or {}).get("tasks", []):
        result = t.get("result") or {}
        if t.get("status") not in (None, "done"):
            add("worker", str(t["status"]), t.get("id"), goal=str(t.get("goal") or "")[:160])
        elif "without calling finish" in str(result.get("summary") or ""):
            add("worker", "no-finish", t.get("id"), goal=str(t.get("goal") or "")[:160])
        elif (t.get("step") or 0) > (t.get("max_steps") or 10 ** 6):
            add("worker", "out-of-steps", t.get("id"), goal=str(t.get("goal") or "")[:160])
    return [{**base, "kind": SUMMARY, "cause": SUMMARY, "subject": None, "n": 0, "failures": len(out)}] + out


# ---------------------------------------------------------------- a saved run
def _rows(con, sql):
    try:
        return [dict(r) for r in con.execute(sql)]
    except sqlite3.Error:   # a database from an older kit: the table isn't there
        return []


def run_data(result_path, res):
    """What a run kept, read from its folder next to the result: None when there is no folder."""
    d = os.path.join(KIT, res["data"]) if res.get("data") else result_path[:-5]
    if not os.path.isdir(d):
        return None
    data = {"findings": [], "observations": [], "plan": [], "calls": [], "tasks": []}
    arc = os.path.join(d, "engagement.tar.gz")
    if os.path.isfile(arc):
        with tarfile.open(arc) as tar:
            members = {m.name.removeprefix("./"): m for m in tar.getmembers() if m.isfile()}
            db = members.get(".rv/findings.db") or members.get("findings.db")
            if db:
                with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
                    tmp.write(tar.extractfile(db).read())
                    tmp.flush()
                    con = sqlite3.connect(f"file:{tmp.name}?mode=ro", uri=True)
                    con.row_factory = sqlite3.Row
                    data["findings"] = _rows(con, "SELECT * FROM findings")
                    data["observations"] = _rows(con, "SELECT * FROM observations")
                    data["plan"] = _rows(con, "SELECT id, title, state FROM plan_items")
                    con.close()
            for name, m in sorted(members.items()):
                if re.fullmatch(r"evidence/tasks/[^/]+/task\.json", name):
                    try:
                        data["tasks"].append(json.load(tar.extractfile(m)))
                    except ValueError:
                        pass
    conv = os.path.join(d, "conversation.json")
    if os.path.isfile(conv):
        try:
            data["calls"] = calls(json.load(open(conv)))
        except ValueError:
            pass
    return data


def collect_saved(result_path):
    res = json.load(open(result_path))
    res["run"] = os.path.basename(result_path)[:-5]
    bp = os.path.join(BENCH, f"{res.get('benchmark')}.json")
    bench = json.load(open(bp)) if os.path.isfile(bp) else None
    return collect(res, bench, run_data(result_path, res))


def load(store=None):
    store = store or STORE
    return [json.loads(l) for l in open(store) if l.strip()] if os.path.exists(store) else []


def record(result_path, store=None):
    """Add one saved run's failures to the store, replacing what the store had for that run."""
    store = store or STORE
    new = collect_saved(result_path)
    keep = [r for r in load(store) if r.get("run") != new[0]["run"]]
    tmp = store + ".tmp"
    with open(tmp, "w") as f:
        for r in keep + new:
            f.write(json.dumps(r) + "\n")
    os.replace(tmp, store)
    return new[1:]


def rebuild(out=None, store=None):
    out, store = out or OUT, store or STORE
    rows, runs = [], 0
    for name in sorted(os.listdir(out)):
        p = os.path.join(out, name)
        if not name.endswith(".json") or not os.path.isfile(p):
            continue
        try:
            if "benchmark" not in json.load(open(p)):
                continue
            rows += collect_saved(p)
            runs += 1
        except (ValueError, KeyError, OSError, tarfile.TarError) as e:
            print(f"  skipped {name}: {e}", file=sys.stderr)
    with open(store, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    return runs, len(rows) - runs


# ---------------------------------------------------------------- an engagement
def overruled(decisions):
    """Decisions where a person changed a value an agent had set: [(what, decision)]. decisions: oldest first."""
    out, last = [], {}
    agent = lambda a: str(a or "").startswith("agent:")
    for d in decisions:
        field = "status" if d["kind"] in ("recorded", "status") else d["kind"]
        if field not in ("status", "severity"):
            continue
        key, was, now = (d["finding_id"], field), d.get("from_value"), d.get("to_value")
        if d["kind"] == "recorded":
            last[key] = last[(d["finding_id"], "severity")] = d.get("actor")
            continue
        if not agent(d.get("actor")) and agent(last.get(key)) and was != now:
            if field == "severity" and was in SEVERITY and now in SEVERITY:
                out.append(("severity-lowered" if SEVERITY.index(now) < SEVERITY.index(was) else "severity-raised", d))
            what = {("confirmed", "false-positive"): "confirmed-rejected", ("candidate", "false-positive"): "candidate-rejected",
                    ("false-positive", "confirmed"): "rejected-confirmed", ("false-positive", "candidate"): "rejected-confirmed",
                    ("duplicate", "confirmed"): "merged-confirmed", ("duplicate", "candidate"): "merged-confirmed"}
            if field == "status" and (was, now) in what:
                out.append((what[(was, now)], d))
        last[key] = d.get("actor")
    return out


def engagement_items(eng, data):
    """Every failure event of an engagement, one per occurrence: {"kind", "stage", "subject", "show"}. "show" is what
    the console lists when the operator opens a cause (time, what, why): it holds client text and is never stored."""
    reason = lambda text: slug(str(text or "").replace(eng, "<eng>"))
    item = lambda kind, stage, subject=None, **show: {"kind": kind, "stage": stage, "subject": subject,
                                                      "show": {k: v for k, v in show.items() if v not in (None, "")}}
    title = {f["id"]: f.get("title") for f in data.get("findings", [])}
    for what, d in overruled(data.get("decisions", [])):
        yield item("overruled", what, d["finding_id"], at=d.get("at"), what=f"{d['finding_id']} {title.get(d['finding_id']) or ''}".strip(),
                   why=f"{d.get('from_value')} → {d.get('to_value')} by {d.get('actor')}" + (f": {d['reason']}" if d.get("reason") else ""))
    for r in data.get("audit", []):
        kind = "request" if r.get("action") == "http" or "method" in r else "command"
        what = f"{r.get('method')} {r.get('url')}" if kind == "request" else r.get("command")
        if r.get("event") == "approval-denied":
            yield item("approval", "denied", r.get("approval"), at=r.get("ts"), what=r.get("command"), why=f"denied by {r.get('actor')}")
        elif "event" in r:
            continue
        elif "refused" in r:
            yield item(kind, "refused: " + reason(r["refused"]), at=r.get("ts"), what=what, why=r["refused"], tier=r.get("tier"))
        elif kind == "command" and (r.get("exit") in (124, 137) or "timed out" in str(r.get("error", ""))):
            yield item(kind, "timeout", at=r.get("ts"), what=what, why=f"timed out after {r.get('seconds')} s", tier=r.get("tier"))
        elif kind == "command" and r.get("exit") not in (0, 1, None):
            yield item(kind, "failed", at=r.get("ts"), what=what, why=f"exit code {r.get('exit')}", tier=r.get("tier"))
    seen = collections.Counter()
    for c in data.get("calls", []):
        cls = tool_class(c["tool"], c["body"].replace(eng, "<eng>"), c["is_error"])
        if cls and not (AUDITED.match(c["tool"]) and cls.startswith(("refused", "command-"))):
            show = {"what": f"{c['tool']} {_short_args(c['args'], 300)}", "why": c["body"].split("\n")[0][:300]}
            yield item("tool", f"{c['tool']}/{cls}", **show)
            seen[(c["tool"], cls, c["args"])] += 1
            if seen[(c["tool"], cls, c["args"])] > 1:
                yield item("retry", f"{c['tool']}/{cls}", **show)
    for e in data.get("model_events", []):
        if e.get("kind") != "context":   # OpenHands summarised older turns and went on: not a failure
            yield item("model", f"{e.get('kind')}/{e.get('model')}", at=e.get("ts"), what=e.get("model_id") or e.get("model"),
                       why=e.get("message"))
    for f in data.get("findings", []):
        if f.get("status") == "candidate":
            yield item("triage", "candidates-left", what=f"{f['id']} {f.get('title') or ''}".strip(), why="still a candidate")
        if f.get("status") == "confirmed" and (f.get("verified_method") or "not stated") == "not stated":
            yield item("triage", "confirmed-without-method", what=f"{f['id']} {f.get('title') or ''}".strip(),
                       why="confirmed, no verification method recorded")
    for o in data.get("observations", []):
        if o.get("status") == "new":
            yield item("triage", "observations-untriaged", what=f"{o['id']} {o.get('title') or ''}".strip(), why="not triaged")
    for p in data.get("plan", []):
        stage = {"planned": "not-run", "blocked": "blocked"}.get(p.get("state"))
        if stage:
            yield item("coverage", stage, what=f"{p['id']} {p.get('title') or ''}".strip(),
                       why=p.get("rationale") if stage == "blocked" else "planned, no outcome recorded")
    for t in data.get("tasks", []):
        stage = (str(t["status"]) if t.get("status") not in (None, "done", "queued", "running", "waiting")
                 else "no-finish" if "without calling finish" in str((t.get("result") or {}).get("summary") or "")
                 else "out-of-steps" if t.get("status") == "done" and (t.get("step") or 0) > (t.get("max_steps") or 10 ** 6)
                 else None)
        if stage:
            yield item("worker", stage, t.get("id"), what=f"{t.get('id')} {str(t.get('goal') or '')[:300]}".strip(),
                       why=f"{stage}, step {t.get('step')} of {t.get('max_steps')}", tier=t.get("tier"))


def collect_engagement(eng, data, at=None):
    """The failure records of one engagement, with no client text: ids, counts and causes. data: {"findings",
    "decisions", "plan", "observations", "audit" (its audit rows), "tasks", "calls", "model_events"}."""
    base = {"v": VERSION, "source": "engagement", "run": eng, "engagement": eng, "at": at, "ended": data.get("state")}
    out, count = [], collections.Counter()
    for i in engagement_items(eng, data):
        if i["subject"]:   # a finding, an approval or a task: one record each
            out.append({**base, "kind": i["kind"], "cause": f"{i['kind']}/{i['stage']}", "subject": i["subject"], "n": 1})
        else:
            count[(i["kind"], i["stage"])] += 1
    out += [{**base, "kind": kind, "cause": f"{kind}/{stage}", "subject": None, "n": n} for (kind, stage), n in count.items()]
    return [{**base, "kind": SUMMARY, "cause": SUMMARY, "subject": None, "n": 0, "failures": len(out)}] + out


def engagement_details(eng, cause, root=None, limit=50):
    """What is behind one cause in one engagement, read from the engagement now (newest first, at most `limit`):
    for the console, which shows the operator their own engagement. Nothing of this is stored."""
    hit = [i["show"] for i in engagement_items(eng, engagement_data(eng, root)) if f"{i['kind']}/{i['stage']}" == cause]
    hit.sort(key=lambda x: x.get("at") or "", reverse=True)
    return {"engagement": eng, "cause": cause, "items": hit[:limit], "cut": max(0, len(hit) - limit)}


def _env():
    out = {}
    try:
        for line in open(os.path.join(KIT, ".env")):
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.rstrip("\n").split("=", 1)
                out[k] = v
    except OSError:
        pass
    return out


def eng_root():
    return os.path.expanduser(os.environ.get("ENGAGEMENTS_DIR") or _env().get("ENGAGEMENTS_DIR") or "~/riskvoid/engagements")


def audit_rows(eng, path):
    """The engagement's rows of the audit log, from its latest creation on (a deleted engagement's name can be reused)."""
    rows = []
    try:
        for line in open(path):
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("engagement") == eng:
                rows = [] if r.get("event") == "deleted" else rows + [r]
    except OSError:
        pass
    return rows


def bound_calls(eng, note=lambda m: None):
    """Tool calls of the conversations bound to the engagement. Needs the stack; without it, none."""
    sys.path.insert(0, os.path.join(KIT, "scripts"))
    sys.path.insert(0, os.path.join(KIT, "harness"))
    try:
        import agent_view, conversations
        out = []
        for c in conversations.bound(eng):
            out += calls(agent_view.events(c["id"])[0])
        return out
    except Exception as e:   # the stack is down, or a conversation is gone
        note(f"conversations of {eng} not read ({str(e)[:120]}): tool/ and retry/ causes are left out")
        return []


def engagement_data(eng, root=None, note=lambda m: None):
    root = root or eng_root()
    d = os.path.join(root, eng)
    if not os.path.isdir(d):
        raise SystemExit(f"no engagement folder {d}")
    data = {"findings": [], "decisions": [], "plan": [], "observations": [], "tasks": []}
    db = os.path.join(d, ".rv", "findings.db")
    if os.path.isfile(db):
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        data["findings"] = _rows(con, "SELECT * FROM findings")
        data["decisions"] = _rows(con, "SELECT * FROM decisions ORDER BY id")
        data["plan"] = _rows(con, "SELECT * FROM plan_items")
        data["observations"] = _rows(con, "SELECT * FROM observations")
        con.close()
    tasks = os.path.join(d, "evidence", "tasks")
    for t in sorted(os.listdir(tasks)) if os.path.isdir(tasks) else []:
        try:
            data["tasks"].append(json.load(open(os.path.join(tasks, t, "task.json"))))
        except (OSError, ValueError):
            pass
    data["audit"] = audit_rows(eng, os.path.join(root, "audit.log"))
    since = (data["audit"][0].get("ts") or "")[:19] if data["audit"] else ""
    try:
        data["model_events"] = [e for e in (json.loads(l) for l in open(MODEL_LOG) if l.strip())
                                if e.get("engagement") == eng and (e.get("ts") or "")[:19] >= since]
    except (OSError, ValueError):
        data["model_events"] = []
    data["calls"] = bound_calls(eng, note)
    ev = [r.get("event") for r in data["audit"]]
    data["state"] = "closed" if "closed" in ev else "open"
    data["at"] = max((r.get("ts") or "" for r in data["audit"]), default=None)
    return data


def record_engagement(eng, root=None, store=None, note=lambda m: None):
    store = store or ENG_STORE
    data = engagement_data(eng, root, note)
    new = collect_engagement(eng, data, data.get("at"))
    os.makedirs(os.path.dirname(store), exist_ok=True)
    keep = [r for r in load(store) if r.get("run") != eng]
    tmp = store + ".tmp"
    with open(tmp, "w") as f:
        for r in keep + new:
            f.write(json.dumps(r) + "\n")
    os.replace(tmp, store)
    return new[1:]


def engagement_names(root=None):
    root = root or eng_root()
    return sorted(n for n in os.listdir(root) if not n.startswith(("_", ".", "bench-"))
                  and os.path.isdir(os.path.join(root, n, ".rv"))) if os.path.isdir(root) else []


# ---------------------------------------------------------------- groups
def groups(rows):
    """Failure records grouped by cause, most widespread first (runs affected, then count)."""
    g = {}
    for r in rows:
        if r["kind"] == SUMMARY:
            continue
        x = g.setdefault(r["cause"], {"cause": r["cause"], "kind": r["kind"], "count": 0, "runs": set(),
                                      "ended": collections.Counter(), "subjects": collections.Counter()})
        x["count"] += r.get("n") or 1
        x["runs"].add(r["run"])
        x["ended"][r.get("ended") or "?"] += 1
        where = r.get("benchmark") or r.get("engagement")
        if r.get("subject") and r["kind"] not in ("tool", "retry"):
            x["subjects"][f"{where}: {r['subject']}"] += 1
        else:
            x["subjects"][where] += r.get("n") or 1
    return sorted(g.values(), key=lambda x: (-len(x["runs"]), -x["count"], x["cause"]))


def overview(rows, engagements=False, limit=40):
    """The stored records as the console's Failures page shows them: totals, and causes with their records (newest
    first, at most `limit` each)."""
    runs = [r for r in rows if r["kind"] == SUMMARY]
    gs = []
    for g in groups(rows):
        recs = sorted((r for r in rows if r["cause"] == g["cause"]), key=lambda r: r.get("at") or "", reverse=True)
        dates = sorted((r.get("at") or "") for r in recs)
        keep = ("run", "benchmark", "engagement", "subject", "n", "at", "ended", "planner", "worker", "prompt", "detail")
        gs.append({"cause": g["cause"], "kind": g["kind"], "count": g["count"], "runs": len(g["runs"]),
                   "first": dates[0], "last": dates[-1], "subjects": g["subjects"].most_common(8),
                   "more": max(0, len(g["subjects"]) - 8),
                   "records": [{k: r[k] for k in keep if r.get(k) is not None} for r in recs[:limit]],
                   "cut": max(0, len(recs) - limit)})
    return {"source": "engagements" if engagements else "bench", "runs": len(runs),
            "records": sum(1 for r in rows if r["kind"] != SUMMARY), "clean": sum(1 for r in runs if not r.get("failures")),
            "kinds": sorted({g["kind"] for g in gs}), "groups": gs,
            "names": sorted({r.get("engagement") or r.get("benchmark") or "" for r in runs})}


def select(rows, benchmark=None, kind=None, model=None, since=None, engagement=None):
    ok = lambda r: ((not benchmark or r.get("benchmark") == benchmark) and (not engagement or r.get("engagement") == engagement) and (not since or (r.get("at") or "") >= since)
                    and (not model or model in f"{r.get('planner')} {r.get('worker')}"))
    rows = [r for r in rows if ok(r)]
    return [r for r in rows if r["kind"] == SUMMARY or not kind or r["kind"] == kind]


def report(rows, out=print, engagements=False):
    runs = [r for r in rows if r["kind"] == SUMMARY]
    fails = [r for r in rows if r["kind"] != SUMMARY]
    if not runs:
        out("No engagements collected yet: ./rvkit failures <engagement> (or --all)." if engagements else
            "No runs recorded yet. Run a benchmark (./rvkit bench <name>), or --rebuild from saved runs.")
        return
    dates = sorted((r.get("at") or "")[:10] for r in runs)
    gs = groups(rows)
    clean = sum(1 for r in runs if not r.get("failures"))
    if engagements:
        out(f"{len(fails)} failure records in {len(runs)} engagements (last activity {dates[0] or '?'} to "
            f"{dates[-1] or '?'}), {len(gs)} causes. {clean} had none.")
    else:
        out(f"{len(fails)} failure records in {len(runs)} runs of {len({r['benchmark'] for r in runs})} benchmarks "
            f"({dates[0]} to {dates[-1]}), {len(gs)} causes. {clean} runs had none.")
    out(f"\n{'eng.' if engagements else 'runs':>7} {'count':>6}  cause")
    for g in gs:
        out(f"{len(g['runs']):>4}/{len(runs):<2} {g['count']:>6}  {g['cause']}")
        ended = {} if engagements else {k: v for k, v in g["ended"].items() if k != "finished"}
        where = ", ".join(f"{k} ×{v}" if v > 1 else k for k, v in g["subjects"].most_common(6))
        more = len(g["subjects"]) - 6
        out(f"{'':16}{where}{f', +{more} more' if more > 0 else ''}"
            + (f"   [run ended: {', '.join(f'{k} ×{v}' for k, v in sorted(ended.items()))}]" if ended else ""))
    out("\n--show <cause> lists the records of one cause." + ("" if engagements else
        " The stage of a missed item is a keyword lead: check it there."))


def show(rows, cause, out=print):
    hit = [r for r in rows if r["kind"] != SUMMARY and (r["cause"] == cause or r["cause"].startswith(cause.rstrip("/") + "/"))]
    if not hit:
        out(f"No records for {cause!r}. Causes: " + ", ".join(g["cause"] for g in groups(rows)))
        return 1
    for r in sorted(hit, key=lambda r: (r["cause"], r["run"])):
        n = f" ×{r['n']}" if (r.get("n") or 1) > 1 else ""
        if r.get("source") == "engagement":
            out(f"{r['cause']}{n}  {r['run']}  {r.get('subject') or ''}")
            continue
        out(f"{r['cause']}{n}  {r['run']}  {r.get('subject') or ''}  [ended {r.get('ended')}; planner {r.get('planner')}; "
            f"worker {r.get('worker')}; prompt {r.get('prompt')}]")
        for k, v in (r.get("detail") or {}).items():
            out(f"    {k}: {v if isinstance(v, str) else json.dumps(v)}")
    return 0


def show_all(rows, out=print):
    """Every record of the selection (one engagement), grouped by kind."""
    hit = [r for r in rows if r["kind"] != SUMMARY]
    if not hit:
        out("No failures recorded.")
    for r in sorted(hit, key=lambda r: r["cause"]):
        out(f"{r.get('n') or 1:>5}  {r['cause']}{'  ' + r['subject'] if r.get('subject') else ''}")


def main(argv):
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__)
        return 2
    opt = lambda name: argv[argv.index(name) + 1] if name in argv and argv.index(name) + 1 < len(argv) else None
    if argv and argv[0] == "engagements":
        argv = argv[1:]
        note = lambda m: print(f"  ({m})", file=sys.stderr)
        names = engagement_names() if argv[:1] == ["--all"] else argv[:1] if argv and not argv[0].startswith("--") else []
        for n in names:
            print(f"{n}: {len(record_engagement(n, note=note))} failure record(s)")
        if names:
            print()
        rows = select(load(ENG_STORE), kind=opt("--kind"), since=opt("--since"),
                      engagement=opt("--engagement") or (names[0] if len(names) == 1 else None))
        if "--show" in argv or len(names) == 1:
            return show(rows, opt("--show") or "") if "--show" in argv else (show_all(rows), 0)[1]
        if "--json" in argv:
            print(json.dumps([{**g, "runs": sorted(g["runs"]), "ended": dict(g["ended"]), "subjects": dict(g["subjects"])}
                              for g in groups(rows)], indent=1))
            return 0
        report(rows, engagements=True)
        return 0
    if "--rebuild" in argv:
        runs, n = rebuild()
        print(f"Rebuilt {os.path.relpath(STORE, KIT)}: {n} failure records from {runs} saved runs.\n")
    rows = select(load(), opt("--benchmark"), opt("--kind"), opt("--model"), opt("--since"))
    if "--show" in argv:
        return show(rows, opt("--show") or "")
    if "--json" in argv:
        print(json.dumps([{**g, "runs": sorted(g["runs"]), "ended": dict(g["ended"]), "subjects": dict(g["subjects"])}
                          for g in groups(rows)], indent=1))
        return 0
    report(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
