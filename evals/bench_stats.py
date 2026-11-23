"""Figures over benchmark runs: repeated runs of one benchmark, paired comparisons, and what a run asked of people.

Used by run_benchmark.py (and ./rvkit bench). Nothing here calls a model or the stack: every figure comes from saved
results (evals/results/bench/<name>-<UTC>.json) and the data kept next to them.

Repeated runs (a result group: one benchmark run N times with --repeat N)
  found k of n      per expected finding: in how many runs it was confirmed, and confirmed with every evidence
                    requirement met (strict)
  pass^k            the chance that k runs in a row all find an item, averaged over the expected items (tau-bench's
                    estimator C(c,k)/C(n,k), c = runs that found it). pass^n is "found every time".
  pass@k            the chance that at least one of k runs finds it: 1 - C(n-c,k)/C(n,k)
  all-found         runs that found every expected item, strict
  mean and SE       recall, strict recall, precision, cost and minutes, with the standard error of the mean
                    (sd / sqrt(n)). Two runs that differ by less than about two SEs are not a real difference.

Paired comparison (--compare A B): two labelled sets of runs (--label) on the same benchmarks. For every expected
item run in both, the difference in the share of runs that found it (strict); then the mean difference with its
standard error, clustered by benchmark (items of one benchmark move together) as in "Adding Error Bars to Evals".
With few benchmarks that SE is too small (two clusters barely estimate a spread) and it ignores that one weak run
misses several items at once, so the verdict also needs a run-level permutation test: strict recall per run, labels
shuffled among the runs of each benchmark, p = the share of shuffles with a mean difference at least as large.

Operator load (in every result as "operator"): approvals requested, granted, denied and stale (audit log, within
the run's time window); questions the agent asked the user; worker tasks by status; tool-call errors (malformed
arguments, refused, failed, timed out); cost per strictly verified finding.

Token use by role (in "operator" as "token_use", #78): planner from the OpenHands conversation (the result's
"tokens"), worker from each task's task.json ("tokens", added up by every worker model call), advisor from the advice
records in task.json, validator from the token columns of the validations table (score.validation.tokens). A role's
figure is prompt + completion tokens (cached tokens are part of prompt). A figure the run didn't record is None
("n/a"), never 0, and the total is None when any role's is.
"""
import collections, datetime, itertools, json, math, os, random, re

SEV = ("critical", "high", "medium", "low", "info")
ALPHA = 0.05   # a run-level permutation p below this, with the interval clear of zero, is a real difference


# ---------------------------------------------------------------- small statistics
def mean_se(xs):
    """(mean, standard error of the mean, n) over the values that are not None."""
    xs = [float(x) for x in xs if x is not None]
    n = len(xs)
    if not n:
        return None, None, 0
    m = sum(xs) / n
    if n < 2:
        return m, None, n
    sd = (sum((x - m) ** 2 for x in xs) / (n - 1)) ** 0.5
    return m, sd / n ** 0.5, n


def pass_hat(c, n, k):
    """tau-bench pass^k: the chance that k runs drawn from n (c of them successes) all succeed."""
    return math.comb(c, k) / math.comb(n, k) if 0 < k <= n else None


def pass_at(c, n, k):
    """pass@k: the chance that at least one of k runs drawn from n succeeds."""
    return 1 - math.comb(n - c, k) / math.comb(n, k) if 0 < k <= n else None


def fmt(m, se=None, pct=False, money=False):
    if m is None:
        return "n/a"
    if money:
        return f"${m:.2f}" + (f" ±{se:.2f}" if se is not None else "")
    if pct:
        return f"{m:.0%}" + (f" ±{se * 100:.0f}" if se is not None else "")
    return f"{m:.2f}" + (f" ±{se:.2f}" if se is not None else "")


# ---------------------------------------------------------------- one benchmark, n runs
def _strict(p):
    return bool(p.get("found_by")) and all((p.get("requirements") or {}).values())


def group_summary(runs):
    """Figures for runs of ONE benchmark (result dicts as saved). Returns a JSON-able dict."""
    runs = [r for r in runs if r and r.get("score")]
    n = len(runs)
    if not n:
        return None
    items = collections.OrderedDict()
    for r in runs:
        for p in r["score"].get("per_expected", []):
            it = items.setdefault(p["id"], {"id": p["id"], "severity": p.get("severity"), "found": 0, "strict": 0,
                                            "candidate": 0})
            it["found"] += bool(p.get("found_by"))
            it["strict"] += _strict(p)
            it["candidate"] += bool(p.get("left_candidate")) and not p.get("found_by")
    for it in items.values():
        it["of"] = n
    ks = list(range(1, n + 1))
    avg = lambda f: (sum(f(it) for it in items.values()) / len(items)) if items else None
    curve = lambda key, fn: {str(k): _r(avg(lambda it: fn(it[key], n, k))) for k in ks}
    all_found = sum(1 for r in runs if r["score"].get("per_expected") and all(_strict(p) for p in r["score"]["per_expected"]))
    figures = {}
    ev = lambda r, *path: ((r.get("efficiency") or {})  # noqa: E731  a #79 measure, None on runs without it
                            .get(path[0]) or {}).get(path[1])
    pairs = [("recall", lambda r: r["score"].get("recall")),
             ("strict_recall", lambda r: r["score"].get("strict_recall")),
             ("recorded_recall", lambda r: r["score"].get("recorded_recall")),
             ("precision", lambda r: r["score"].get("precision")),
             ("cost_usd", lambda r: r.get("cost_usd")),
             ("tokens_total", lambda r: run_tokens(r)["total"]),
             ("minutes", lambda r: (r.get("seconds") or 0) / 60),
             ("cost_per_verified", lambda r: (r.get("operator") or {}).get("cost_per_verified")),
             ("approvals_requested", lambda r: ((r.get("operator") or {}).get("approvals") or {}).get("requested")),
             ("questions", lambda r: (r.get("operator") or {}).get("questions")),
             ("tool_errors", lambda r: sum(((r.get("operator") or {}).get("tool_errors") or {}).values())
              if (r.get("operator") or {}).get("tool_errors") is not None else None),
             ("repeat_share", lambda r: ev(r, "repeated_tool_work", "share")),
             ("duplicate_experiments", lambda r: ev(r, "duplicate_experiments", "duplicates")),
             ("rebriefs", lambda r: ev(r, "rebriefs", "same_goal_again")),
             ("first_verified_min", lambda r: ev(r, "first_verified", "min")),
             ("first_verified_tokens", lambda r: ev(r, "first_verified", "tokens")),
             ("queue_delay_s", lambda r: ev(r, "queue_delay", "mean_s")),
             ("verified_cells", lambda r: ev(r, "verified_coverage", "cells")),
             ("cells_per_usd", lambda r: ev(r, "verified_coverage", "per_usd"))]
    for key, get in pairs:
        m, se, k = mean_se(get(r) for r in runs)
        figures[key] = {"mean": _r(m), "se": _r(se), "n": k}

    first = runs[0]
    return {"benchmark": first.get("benchmark"), "group": first.get("group"), "label": first.get("label"),
            "agent": first.get("agent"), "models": first.get("models"), "lookup": first.get("lookup_mode", "open"),
            "writeup_lookups": sum(len((r.get("lookup") or {}).get("writeups") or []) for r in runs),
            "runs": n, "statuses": [r.get("status") for r in runs],
            "results": [r.get("_file") for r in runs if r.get("_file")],
            "figures": figures, "items": list(items.values()),
            "pass_hat_k": curve("strict", pass_hat), "pass_at_k": curve("strict", pass_at),
            "pass_hat_k_loose": curve("found", pass_hat),
            "all_found_strict": {"runs": all_found, "of": n}}


def _r(x, d=3):
    return round(x, d) if isinstance(x, float) else x


def print_group(g, out=print):
    f = g["figures"]
    n = g["runs"]
    rec = f.get("recorded_recall") or {}
    out(f"  {g['benchmark']} over {n} runs ({g.get('label') or g.get('group') or 'no label'}, lookup "
        f"{g.get('lookup', 'open')}): recall {fmt(f['recall']['mean'], f['recall']['se'], pct=True)}, "
        f"with evidence {fmt(f['strict_recall']['mean'], f['strict_recall']['se'], pct=True)}, "
        + (f"recorded (confirmed or left as a candidate) {fmt(rec['mean'], rec['se'], pct=True)}, "
           if rec.get("mean") is not None and rec["mean"] != f["recall"]["mean"] else "") +
        f"precision {fmt(f['precision']['mean'], f['precision']['se'])}, "
        f"cost {fmt(f['cost_usd']['mean'], f['cost_usd']['se'], money=True)}, "
        f"tokens {fmt_tokens((f.get('tokens_total') or {}).get('mean'))}")
    out(f"    pass^k (with evidence) {'  '.join(f'k={k} {fmt(v, pct=True)}' for k, v in g['pass_hat_k'].items())};"
        f"  pass@{n} {fmt(g['pass_at_k'][str(n)], pct=True)}; every item in "
        f"{g['all_found_strict']['runs']} of {n} runs")
    for it in g["items"]:
        c = it.get("candidate", 0)
        bar = "█" * it["strict"] + "▒" * (it["found"] - it["strict"]) + "◌" * c + "·" * (n - it["found"] - c)
        out(f"    {bar:{max(n, 3)}} {it['id']:26} {it['severity'] or '':9} found {it['found']} of {n}, "
            f"with evidence {it['strict']} of {n}" + (f", left as a candidate {c} of {n}" if c else ""))
    out(f"    statuses {', '.join(map(str, g['statuses']))}")
    fv, qd = f.get("first_verified_min") or {}, f.get("queue_delay_s") or {}
    if (f.get("repeat_share") or {}).get("n"):   # runs saved since #79 carry the efficiency measures
        out(f"    efficiency (#79): repeated tool work {fmt(f['repeat_share']['mean'], f['repeat_share']['se'], pct=True)}"
            f" of worker calls, duplicate experiments {fmt(f['duplicate_experiments']['mean'])}, "
            f"rebriefs {fmt(f['rebriefs']['mean'])}, first verified finding {fmt(fv.get('mean'), fv.get('se'))} min "
            f"({fmt_tokens((f.get('first_verified_tokens') or {}).get('mean'))} tokens), "
            f"queue delay {fmt(qd.get('mean'))}s, verified cells {fmt((f.get('verified_cells') or {}).get('mean'))} "
            f"({fmt((f.get('cells_per_usd') or {}).get('mean'))} per $)")


# ---------------------------------------------------------------- comparing two labelled sets
def compare(runs_a, runs_b):
    """Paired comparison of two sets of runs (result dicts) on the benchmarks they share."""
    def rates(runs):
        by = collections.defaultdict(list)
        for r in runs:
            by[r.get("benchmark")].append(r)
        return {b: {it["id"]: it["strict"] / it["of"] for it in group_summary(rs)["items"]} | {
            "__recall__": group_summary(rs)["figures"]["strict_recall"]["mean"]} for b, rs in by.items()}
    a, b = rates(runs_a), rates(runs_b)
    shared = sorted(set(a) & set(b))
    rows, clusters = [], []
    for bench in shared:
        diffs = [b[bench][i] - a[bench][i] for i in a[bench] if i != "__recall__" and i in b[bench]]
        if not diffs:
            continue
        rows.append({"benchmark": bench, "items": len(diffs), "a": _r(a[bench]["__recall__"]),
                     "b": _r(b[bench]["__recall__"]), "diff": _r(sum(diffs) / len(diffs))})
        clusters.append(diffs)
    alld = [d for c in clusters for d in c]
    n = len(alld)
    if not n:
        return {"benchmarks": [], "items": 0, "diff": None, "se": None, "p_runs": None}

    def per_run(runs, bench):
        return [r["score"]["strict_recall"] for r in runs
                if r.get("benchmark") == bench and (r.get("score") or {}).get("strict_recall") is not None]
    p_runs = permutation_p([(per_run(runs_a, r["benchmark"]), per_run(runs_b, r["benchmark"])) for r in rows])
    m = sum(alld) / n
    # cluster-robust SE of the mean difference: items of one benchmark are not independent
    se = (sum(sum(d - m for d in c) ** 2 for c in clusters) / n ** 2) ** 0.5 if len(clusters) > 1 else \
        mean_se(alld)[1]
    shared_runs = lambda runs: [r for r in runs if r.get("benchmark") in {x["benchmark"] for x in rows}]  # noqa: E731
    return {"benchmarks": rows, "items": n, "diff": _r(m), "se": _r(se),
            "ci95": [_r(m - 1.96 * se), _r(m + 1.96 * se)] if se is not None else None, "p_runs": p_runs,
            "spend": {"a": spend(shared_runs(runs_a)), "b": spend(shared_runs(runs_b))}}


def spend(runs):
    """Mean billed cost and mean total tokens per run (None when no run recorded it)."""
    cost, tok = mean_se(r.get("cost_usd") for r in runs)[0], mean_se(run_tokens(r)["total"] for r in runs)[0]
    return {"cost_usd": round(cost, 4) if cost is not None else None, "tokens": round(tok) if tok is not None else None,
            "runs_with_tokens": sum(1 for r in runs if run_tokens(r)["total"] is not None), "runs": len(runs)}


def permutation_p(groups, limit=20000, seed=0):
    """Two-sided p of the mean per-benchmark difference (b minus a) when runs swap labels within their benchmark.
    groups: [(a_values, b_values)] per benchmark. Every split when there are at most `limit`, else a seeded sample."""
    groups = [(list(a), list(b)) for a, b in groups if a and b]
    if not groups:
        return None

    def stat(splits):
        return sum(sum(y) / len(y) - sum(x) / len(x) for x, y in splits) / len(splits)
    observed = abs(stat(groups)) - 1e-9
    pools = [(a + b, len(b)) for a, b in groups]
    if math.prod(math.comb(len(p), k) for p, k in pools) <= limit:
        options = [[([v for i, v in enumerate(p) if i not in c], [p[i] for i in c])
                    for c in itertools.combinations(range(len(p)), k)] for p, k in pools]
        draws = list(itertools.product(*options))
    else:
        rng = random.Random(seed)
        draws = []
        for _ in range(limit):
            one = []
            for p, k in pools:
                c = set(rng.sample(range(len(p)), k))
                one.append(([v for i, v in enumerate(p) if i not in c], [p[i] for i in c]))
            draws.append(one)
    return _r(sum(1 for d in draws if abs(stat(d)) >= observed) / len(draws))


def print_compare(c, la, lb, out=print):
    if not c["benchmarks"]:
        out(f"no benchmark has runs labelled both {la!r} and {lb!r}")
        return
    out(f"{'benchmark':20} {'items':>5} {la[:14]:>14} {lb[:14]:>14} {'diff':>7}")
    for r in c["benchmarks"]:
        out(f"{r['benchmark']:20} {r['items']:>5} {fmt(r['a'], pct=True):>14} {fmt(r['b'], pct=True):>14} "
            f"{r['diff']:+.2f}")
    if c.get("spend"):   # what each set cost: billed, and in tokens (counts roles on endpoints not billed per token)
        out("mean per run: " + "; ".join(
            f"{lab} cost {fmt(c['spend'][k]['cost_usd'], money=True)}, tokens {fmt_tokens(c['spend'][k]['tokens'])}"
            + (f" ({c['spend'][k]['runs_with_tokens']} of {c['spend'][k]['runs']} runs recorded them)"
               if c['spend'][k]['runs_with_tokens'] < c['spend'][k]['runs'] else "")
            for k, lab in (("a", la), ("b", lb))))
    sig = c["ci95"] and (c["ci95"][0] > 0 or c["ci95"][1] < 0) and c.get("p_runs") is not None and c["p_runs"] < ALPHA
    out(f"mean difference per item (found with evidence, {lb} minus {la}): {c['diff']:+.3f}, SE "
        f"{fmt(c['se'])}, 95% CI {c['ci95']} over {c['items']} items, run-level permutation p {fmt(c.get('p_runs'))}: "
        f"{'a real difference' if sig else 'within the noise'}")


# ---------------------------------------------------------------- operator load
ASK_RX = re.compile(r"\b(would you like me to|do you want me to|shall i|should i|please confirm|can you confirm|"
                    r"could you (?:confirm|provide|clarify)|which (?:option|one) (?:do|would) you|awaiting your|"
                    r"before i (?:proceed|continue)|how would you like)\b", re.I)


def asks(text):
    tail = (text or "").strip()[-600:]
    if not tail:
        return False
    last = re.split(r"(?<=[.!?])\s+", tail)[-1]
    return last.rstrip().endswith("?") or bool(ASK_RX.search(tail))


def _ts(s):
    try:
        return datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def audit_window(eng, start, end, path):
    """Audit rows of an engagement written between start and end (epoch seconds)."""
    rows = []
    if not path or not os.path.exists(path):
        return rows
    for line in open(path):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        t = _ts(r.get("ts"))
        if r.get("engagement") == eng and (t is None or start - 5 <= t <= end + 5):
            rows.append(r)
    return rows


def _message_text(e):
    m = e.get("llm_message") or e.get("message") or {}
    parts = m.get("content") if isinstance(m, dict) else None
    if isinstance(parts, list):
        return " ".join(p.get("text") or "" for p in parts if isinstance(p, dict))
    return str(parts or "")


def operator_load(res, eng, audit_path, events=None, tasks=None, calls=None, tool_class=None):
    """What one run asked of people and how its tool calls went. res: the result (cost, score, at, seconds)."""
    end = _ts(res.get("at")) or 0
    start = end - (res.get("seconds") or 0)
    rows = audit_window(eng, start, end, audit_path)
    ev = collections.Counter(r.get("event") for r in rows)
    approvals = {"requested": ev["approval-requested"], "granted": ev["approval-approved"],
                 "denied": ev["approval-denied"], "stale": ev["approval-stale"]}
    questions = None
    errors = None
    if events is not None:
        questions = sum(1 for e in events if e.get("kind") == "MessageEvent" and e.get("source") == "agent"
                        and asks(_message_text(e)))
        errors = collections.Counter()
        for e in events:
            if e.get("kind") == "AgentErrorEvent" and re.search(r"validat|arguments|JSON", str(e.get("error")), re.I):
                errors["malformed"] += 1
        for c in calls or []:
            cls = tool_class(c["tool"], c["body"], c["is_error"]) if tool_class else None
            if not cls:
                continue
            key = ("malformed" if cls.startswith("invalid-call") else "refused" if cls.startswith("refused")
                   else "timeout" if "timeout" in cls else "failed")
            errors[key] += 1
        errors = {k: errors[k] for k in ("malformed", "refused", "failed", "timeout")}
    if questions is not None and res.get("status") == "asked-question":
        questions = max(questions, 1)
    worker = dict(collections.Counter(str(t.get("status")) for t in tasks)) if tasks is not None else None
    if errors is not None and tasks:
        errors["worker_malformed"] = sum(int(t.get("malformed") or 0) for t in tasks)
    stalls = sum(len(t.get("stalls") or []) for t in tasks) if tasks is not None else None
    s = res.get("score") or {}
    verified = round((s.get("strict_recall") or 0) * (s.get("expected") or 0))
    cost = res.get("cost_usd")
    return {"approvals": approvals, "questions": questions, "worker_tasks": worker, "worker_stalls": stalls,
            "tool_errors": errors,
            "tokens": res.get("tokens"), "token_use": token_use(res, tasks), "cost_usd": cost,
            "verified_findings": verified,
            "cost_per_verified": round(cost / verified, 4) if cost is not None and verified else None}


def operator_line(op):
    if not op:
        return "operator load n/a"
    a = op.get("approvals") or {}
    te = op.get("tool_errors") or {}
    wt = op.get("worker_tasks") or {}
    return (f"approvals {a.get('requested', 0)} asked ({a.get('granted', 0)} granted, {a.get('denied', 0)} denied, "
            f"{a.get('stale', 0)} stale), {op.get('questions') if op.get('questions') is not None else 'n/a'} "
            f"question(s) to the user, worker tasks {', '.join(f'{k} {v}' for k, v in sorted(wt.items())) or 'none'}, "
            f"tool errors {', '.join(f'{k} {v}' for k, v in te.items() if v) or 'none'}, cost per verified finding "
            f"{fmt(op.get('cost_per_verified'), money=True)}")


# ---------------------------------------------------------------- efficiency measures (#79)
# What a run did with its budget besides finding things: the same work twice, the same cell delegated again, the
# goal told twice, how long the first verified finding took, and how long tasks waited for the model. Every figure
# comes from the run's kept data (failures.run_data: task records, plan items, findings; calls from the
# conversation), with no model. A figure the run didn't record is None: runs saved before #79 have no queue
# delay, and the tokens at the first verified finding need the gateway's usage rows.
STAMP_RX = re.compile(r"\d{8}T\d{6}Z?\b|\d{8}-\d{6}\b|\d{4}-\d{2}-\d{2}\b|[0-9a-f]{8}-[0-9a-f]{4}\b")


def _clean_arg(x):
    if isinstance(x, str):
        return STAMP_RX.sub("<stamp>", re.sub(r"\s+", " ", x))
    if isinstance(x, dict):
        return {str(k): _clean_arg(v) for k, v in sorted(x.items(), key=lambda kv: str(kv[0]))}
    if isinstance(x, list):
        return [_clean_arg(v) for v in x]
    return x


def _call_key(tool, args):
    """One tool call as a comparable key: tool + arguments with run stamps, uuids and dates replaced, keys
    sorted, whitespace collapsed. Two calls with the same key did the same work."""
    return f"{tool} {json.dumps(_clean_arg(args or {}), sort_keys=True, default=str)}"


def _steps_of(task):
    """The tool calls that ran: steps with a state, finish excluded (it ends the task, it isn't work)."""
    return [s for s in task.get("steps") or [] if s.get("state") and (s.get("tool") or "") != "finish"]


def _j(x):
    """A JSON column read from the findings database, or its raw self when it isn't JSON."""
    if isinstance(x, str):
        try:
            return json.loads(x)
        except ValueError:
            return x
    return x


def efficiency(res, data, usage=None):
    """The #79 measures of one run. res: the result; data: failures.run_data(result_path, res); usage: the
    gateway's per-call rows ({ts, model, engagement, prompt_tokens, completion_tokens}), or None when they
    weren't kept. Returns None when the run kept no data at all."""
    if not data:
        return None
    tasks = sorted(data.get("tasks") or [], key=lambda t: t.get("started") or 0)

    # repeated tool work: a call whose (tool, arguments) an EARLIER task in the same engagement already ran
    seen, calls, repeated = set(), 0, 0
    for t in tasks:
        own = set()
        for s in _steps_of(t):
            calls += 1
            k = _call_key(s.get("tool"), s.get("args"))
            own.add(k)
            if k in seen:
                repeated += 1
        seen |= own
    repeat = {"calls": calls or None, "repeated": repeated or None,
              "share": round(repeated / calls, 3) if calls else None}

    # duplicate experiments: a task delegated for a cell (class, entries, identity) a finished task already
    # covered - the planner paid for the same experiment twice
    plan = {p.get("id"): p for p in data.get("plan") or []}
    done, dupes, celled = set(), 0, 0
    for t in tasks:
        cell = (t.get("contract") or {}).get("cell") or {}
        if not cell.get("class"):
            continue                      # not bound to a coverage cell: the rebrief measure carries it
        celled += 1
        key = (cell.get("class"), tuple(cell.get("entries") or []),
               (plan.get(cell.get("plan_item")) or {}).get("identity"))
        if key in done:
            dupes += 1
        elif t.get("status") == "done":
            done.add(key)
    dupes = {"cells": celled or None, "duplicates": dupes or None}

    # rebriefs: the planner delegated the same goal again, and pasted `inputs` by hand (what the packet is to
    # replace, #83): counted from the conversation's delegate calls, worker-side repeats above are separate
    goals, delegates, rebriefs, pasted = {}, 0, 0, 0
    for c in data.get("calls") or []:
        if "delegate" not in (c.get("tool") or ""):
            continue
        delegates += 1
        body = c.get("body")
        if not isinstance(body, dict):
            try:
                body = json.loads(c.get("args") or "{}")
            except ValueError:
                body = {}
        g = re.sub(r"\s+", " ", str(body.get("goal") or "")).strip().lower()
        if g:
            rebriefs += 1 if g in goals else 0
            goals[g] = goals.get(g, 0) + 1
        pasted += len(body.get("inputs") or [])
    rebriefs = {"delegate_calls": delegates or None, "same_goal_again": rebriefs or None,
                "inputs_pasted": pasted or None}

    # time to first verified finding: the earliest verified_at among the findings the score confirmed with every
    # requirement met, from the run's start. Tokens at that moment need the gateway's per-call usage rows.
    start = (_ts(res.get("at")) or 0) - (res.get("seconds") or 0)
    fnd = {f.get("id"): f for f in data.get("findings") or []}
    vts = [_ts(fnd[p["found_by"]].get("verified_at")) for p in (res.get("score") or {}).get("per_expected") or []
           if _strict(p) and fnd.get(p.get("found_by"))]
    vts = [v for v in vts if v is not None and v >= start]
    first = min(vts) if vts else None
    tokens = None
    if first is not None and usage:
        eng = res.get("engagement")
        rows = [u for u in usage if u.get("engagement") == eng and (_ts(u.get("ts")) or 0) <= first]
        tokens = sum((u.get("prompt_tokens") or 0) + (u.get("completion_tokens") or 0) for u in rows) or None
    first_verified = {"s": round(first - start, 1) if first is not None else None,
                      "min": round((first - start) / 60, 1) if first is not None else None, "tokens": tokens}

    # verified coverage per budget: coverage cells (map entry x class) a tested plan item with evidence
    # covers, per dollar and per 1,000 requests the run sent to the target
    cells = set()
    for p in data.get("plan") or []:
        if p.get("state") == "tested" and _j(p.get("evidence")):
            for r in _j(p.get("refs")) or []:
                cells.add((str(r), str(p.get("area"))))
    cost, requests = res.get("cost_usd"), data.get("target_requests")
    coverage = {"cells": len(cells) or None,
                "per_usd": round(len(cells) / cost, 2) if cost and cells else None,
                "per_1k_requests": round(len(cells) / requests * 1000, 2) if requests and cells else None}

    # queue delay: how long each task waited (queued, or for the model lock) before its first model call - the
    # worker records it as queue_s since #79; runs before have None
    qs = [t["queue_s"] for t in tasks if isinstance(t.get("queue_s"), (int, float))]
    m, se, n = mean_se(qs)
    queue = {"tasks": n, "mean_s": round(m, 1) if m is not None else None,
             "max_s": round(max(qs), 1) if qs else None}
    return {"repeated_tool_work": repeat, "duplicate_experiments": dupes, "rebriefs": rebriefs,
            "first_verified": first_verified, "verified_coverage": coverage, "queue_delay": queue,
            "restarts": res.get("restarts") or 0}


def efficiency_line(e):
    """'repeated tool work 3 of 41 calls (7%), ...' - one line for the run summary, n/a where unrecorded."""
    if not e:
        return "efficiency n/a (no kept data)"
    r, d, rb = e.get("repeated_tool_work") or {}, e.get("duplicate_experiments") or {}, e.get("rebriefs") or {}
    fv, cov, q = e.get("first_verified") or {}, e.get("verified_coverage") or {}, e.get("queue_delay") or {}
    parts = [
        f"repeated tool work {fmt_pct(r.get('repeated'), r.get('calls'))}",
        f"duplicate experiments {d.get('duplicates') or 0} of {d.get('cells') or 0} celled tasks",
        f"rebriefs {rb.get('same_goal_again') or 0}" + (f" ({rb.get('inputs_pasted')} inputs pasted)"
                                                        if rb.get("inputs_pasted") else ""),
        "first verified finding " + (f"at {fv.get('min')} min ({fmt_tokens(fv.get('tokens'))} tokens)"
                                     if fv.get("min") is not None else "n/a"),
        "queue delay " + (f"mean {q.get('mean_s')}s max {q.get('max_s')}s over {q.get('tasks')} task(s)"
                          if q.get("tasks") else "n/a"),
        f"verified cells {cov.get('cells') or 0}"
        + (f" ({fmt(cov.get('per_usd'))} per $, {fmt(cov.get('per_1k_requests'))} per 1k requests)"
           if cov.get("cells") else ""),
    ]
    if e.get("restarts"):
        parts.append(f"{e['restarts']} restart(s)")
    return ", ".join(parts)


def fmt_pct(k, n):
    if not n:
        return "none"
    return f"{k or 0} of {n} calls ({fmt((k or 0) / n, pct=True)})"


# ---------------------------------------------------------------- token use by role (#78)
ROLES = ("planner", "worker", "advisor", "validator")


def _usage(u):
    """(prompt, completion, cached) of one model reply's usage, as the gateway returns it."""
    u = u or {}
    cached = (u.get("prompt_tokens_details") or {}).get("cached_tokens") or u.get("cache_read_input_tokens") or 0
    return int(u.get("prompt_tokens") or 0), int(u.get("completion_tokens") or 0), int(cached or 0)


def _sum(parts):
    p = [sum(x[i] for x in parts) for i in range(3)]
    return {"prompt": p[0], "completion": p[1], "cached": p[2]}


def token_use(res, tasks=None):
    """Tokens of one run by role: {planner, worker, advisor, validator, total, detail}. res: the result (its
    "tokens" and score.validation); tasks: the task.json records the run kept, or None when it kept none.
    A figure the run didn't record is None: a run saved before #78 has no worker or validator figures."""
    detail = dict.fromkeys(ROLES)
    t = res.get("tokens")
    if isinstance(t, dict):   # OpenHands' accumulated usage, every conversation of the run
        detail["planner"] = _sum([(int(t.get("prompt_tokens") or 0), int(t.get("completion_tokens") or 0),
                                   int(t.get("cache_read_tokens") or 0))])
    if tasks is not None:
        # every task since #78 has "tokens" (0 when it never reached the model); no task before had it
        if all(isinstance(x.get("tokens"), dict) for x in tasks):
            detail["worker"] = _sum([(int(x["tokens"].get("prompt_tokens") or 0),
                                      int(x["tokens"].get("completion_tokens") or 0),
                                      int(x["tokens"].get("cached_tokens") or 0)) for x in tasks])
        # each advice record holds its usage since the advisor exists (#37); a failed call used none
        detail["advisor"] = _sum([_usage(a.get("tokens")) for x in tasks for a in x.get("advisor") or []])
    s = res.get("score") or {}
    if "validation" in s:
        v = s["validation"]
        if v is None:   # no validations table: the validator gave no verdict
            detail["validator"] = _sum([])
        elif isinstance(v.get("tokens"), dict):
            detail["validator"] = {k: int(v["tokens"].get(k) or 0) for k in ("prompt", "completion", "cached")}
    out = {r: (d["prompt"] + d["completion"] if d else None) for r, d in detail.items()}
    out["total"] = sum(out.values()) if all(x is not None for x in out.values()) else None
    out["detail"] = detail
    return out


def run_tokens(res):
    """A saved result's token use by role. A result from before #78 gets what can be read from it: the planner's
    figure, the rest None."""
    tu = (res.get("operator") or {}).get("token_use")
    return tu if isinstance(tu, dict) else token_use(res)


def fmt_tokens(n):
    if n is None:
        return "n/a"
    n = float(n)
    return f"{n / 1e6:.2f}M" if n >= 1e6 else f"{n / 1e3:.0f}k" if n >= 1e3 else f"{n:.0f}"


def tokens_line(tu):
    """'total 1.23M (planner 1.10M, worker 120k, advisor 2k, validator 8k)', n/a where a role was not recorded."""
    return f"total {fmt_tokens(tu.get('total'))} (" + ", ".join(f"{r} {fmt_tokens(tu.get(r))}" for r in ROLES) + ")"
