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
"""
import collections, datetime, itertools, json, math, os, random, re

SEV = ("critical", "high", "medium", "low", "info")


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
    for key, get in (("recall", lambda r: r["score"].get("recall")),
                     ("strict_recall", lambda r: r["score"].get("strict_recall")),
                     ("recorded_recall", lambda r: r["score"].get("recorded_recall")),
                     ("precision", lambda r: r["score"].get("precision")),
                     ("cost_usd", lambda r: r.get("cost_usd")),
                     ("minutes", lambda r: (r.get("seconds") or 0) / 60),
                     ("cost_per_verified", lambda r: (r.get("operator") or {}).get("cost_per_verified")),
                     ("approvals_requested", lambda r: ((r.get("operator") or {}).get("approvals") or {}).get("requested")),
                     ("questions", lambda r: (r.get("operator") or {}).get("questions")),
                     ("tool_errors", lambda r: sum(((r.get("operator") or {}).get("tool_errors") or {}).values())
                      if (r.get("operator") or {}).get("tool_errors") is not None else None)):
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
        f"cost {fmt(f['cost_usd']['mean'], f['cost_usd']['se'], money=True)}")
    out(f"    pass^k (with evidence) {'  '.join(f'k={k} {fmt(v, pct=True)}' for k, v in g['pass_hat_k'].items())};"
        f"  pass@{n} {fmt(g['pass_at_k'][str(n)], pct=True)}; every item in "
        f"{g['all_found_strict']['runs']} of {n} runs")
    for it in g["items"]:
        c = it.get("candidate", 0)
        bar = "█" * it["strict"] + "▒" * (it["found"] - it["strict"]) + "◌" * c + "·" * (n - it["found"] - c)
        out(f"    {bar:{max(n, 3)}} {it['id']:26} {it['severity'] or '':9} found {it['found']} of {n}, "
            f"with evidence {it['strict']} of {n}" + (f", left as a candidate {c} of {n}" if c else ""))
    out(f"    statuses {', '.join(map(str, g['statuses']))}")


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
    return {"benchmarks": rows, "items": n, "diff": _r(m), "se": _r(se),
            "ci95": [_r(m - 1.96 * se), _r(m + 1.96 * se)] if se is not None else None, "p_runs": p_runs}


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
    sig = c["ci95"] and (c["ci95"][0] > 0 or c["ci95"][1] < 0) and c.get("p_runs") is not None and c["p_runs"] < 0.05
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
            "tokens": res.get("tokens"), "cost_usd": cost, "verified_findings": verified,
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
