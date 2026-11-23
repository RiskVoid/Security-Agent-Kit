"""The packet's no-model quality check (#86): on a labelled set of real worker tasks from saved tuning runs,
how much of what the packet selected was needed, how much of the needed it included, and what the budget cost.

The labels (evals/packet_labels.json) are reviewed data: `--label` regenerates a proposal from each task's own
outcome - its coverage cell's map entries and plan item, the findings its result recorded or cited, the earlier
tasks for its cell - and a reviewer commits the file after reading it. Only tuning-side benchmarks are read
(evals/improvement/split.json); held-out runs are never labelled.

  python3 evals/packet_check.py --label [run ...]    write the label proposal to evals/packet_labels.json
  python3 evals/packet_check.py                     check the packet against the committed labels, no model
  python3 evals/packet_check.py --budgets 3000,6000,12000

Prints per task and overall: recall (needed records the packet included), precision (how much of the packet was
needed; the rest is noise it carried), and the share of the budget used - at two or three budget sizes, so the
default WORKER_PACKET_CHARS is a number, not a guess. Exit 1 when no labels exist or recall at the default
budget falls under 0.7 (a packet that drops what a task needed is off, whatever it saves).
"""
import json, os, re, shutil, sys, tarfile, tempfile

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(KIT, "harness"))
BENCH = os.path.join(KIT, "evals", "results", "bench")
LABELS = os.path.join(KIT, "evals", "packet_labels.json")
BUDGETS = [3000, 6000, 12000]


def tuning_runs():
    split = json.load(open(os.path.join(KIT, "evals", "improvement", "split.json")))
    tuning = set(split["tuning"])
    out = []
    for d in sorted(os.listdir(BENCH)):
        p = os.path.join(BENCH, d)
        if os.path.isdir(p) and d.rsplit("-", 1)[0] in tuning and os.path.isfile(os.path.join(p, "engagement.tar.gz")):
            out.append(d)
    return out


def task_records(root, eng):
    out = []
    d = os.path.join(root, eng, "evidence", "tasks")
    for t in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        try:
            out.append(json.load(open(os.path.join(d, t, "task.json"), errors="replace")))
        except (OSError, ValueError):
            pass
    return out


def _findings_of(root, eng):
    """(id, row) of the engagement's findings, read straight from the archived database."""
    import sqlite3
    db = os.path.join(root, eng, ".rv", "findings.db")
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    rows = [dict(r) for r in con.execute("SELECT * FROM findings")]
    con.close()
    return rows


def label_run(run):
    """The label proposal for one saved run: per task, the records its own outcome shows it needed."""
    import findings_db as db
    import reconmap
    with tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, "eng")        # the archive root is the engagement folder itself
        os.makedirs(dest)
        with tarfile.open(os.path.join(BENCH, run, "engagement.tar.gz")) as tar:
            tar.extractall(dest, filter="data")
        db.WORK = tmp                          # so db.WORK/<eng>/.rv/findings.db resolves
        eng = f"bench-{run.rsplit('-', 1)[0]}"
        os.rename(dest, os.path.join(tmp, eng))
        entries = {e["id"]: e for e in reconmap.build(eng)["entries"]}
        findings = _findings_of(tmp, eng)
        labels = []
        for t in task_records(tmp, eng):
            cell = (t.get("contract") or {}).get("cell") or {}
            pid = (t.get("contract") or {}).get("plan_item") or cell.get("plan_item")
            if not (pid or cell.get("entries")):
                continue              # a task that ran on its goal alone labels nothing: no cell to select for
            needed = set(cell.get("entries") or []) | ({pid} if pid else set())
            needed |= {f["id"] for f in findings if str(f.get("source")) == f"worker:{t['id']}"}
            for f in findings:         # findings on the cell's route are the task's subject either way
                if cell.get("entries") and str(f.get("asset")) and any(
                        entries[x]["path"] in str(f["asset"]) for x in cell["entries"] if x in entries):
                    needed.add(f["id"])
            labels.append({"run": run, "task": t["id"], "goal": (t.get("goal") or "")[:160],
                           "plan_item": pid, "cell": {"class": cell.get("class"),
                                                      "entries": cell.get("entries") or []},
                           "needed": sorted(needed)})
        return labels


FIXTURES = os.path.join(KIT, "evals", "packet_fixture")


def _untar(tar_path, tmp):
    dest = os.path.join(tmp, "eng")
    os.makedirs(dest)
    with tarfile.open(tar_path) as tar:
        tar.extractall(dest, filter="data")
    eng = f"bench-{os.path.basename(tar_path).removesuffix('.tar.gz').rsplit('-', 1)[0]}"
    os.rename(dest, os.path.join(tmp, eng))
    return tmp, eng


def extract(run):
    """A saved run's engagement folder under a temp WORK root (the archive root is the engagement itself).
    The full archive when this machine has it; otherwise the committed fixture (CI), which carries only what
    the packet builder reads: the findings database, the map files and the labelled tasks' records."""
    arc = os.path.join(BENCH, run, "engagement.tar.gz")
    if os.path.isfile(arc):
        return _untar(arc, tempfile.mkdtemp(prefix="rv-packet-"))
    fx = os.path.join(FIXTURES, f"{run}.tar.gz")
    if not os.path.isfile(fx):
        raise FileNotFoundError(f"neither the saved run {run} nor its fixture exists")
    return _untar(fx, tempfile.mkdtemp(prefix="rv-packet-"))


def export(labels):
    """Write the committed fixtures the CI check reads: per labelled run, only what the packet builder needs -
    the findings database, the map evidence and the labelled tasks' records. Lab targets only, from the tuning
    side; the saved runs themselves stay uncommitted (they can carry model output about a target)."""
    os.makedirs(FIXTURES, exist_ok=True)
    runs = sorted({l["run"] for l in labels})
    for run in runs:
        tmp, eng = extract(run)
        keep_tasks = {l["task"] for l in labels if l["run"] == run}
        d = os.path.join(tmp, eng)
        for sub in sorted(os.listdir(d)):               # what the packet builder reads, nothing else
            if sub == "evidence":
                continue
            if sub not in (".rv", "captures"):           # the findings database, and the request captures the
                shutil.rmtree(os.path.join(d, sub), ignore_errors=True)   # map merge reads
        for sub in sorted(os.listdir(os.path.join(d, "evidence"))):
            if sub not in ("map", "appmap", "tasks", "http"):   # http: the map merges the agent's own requests
                shutil.rmtree(os.path.join(d, "evidence", sub), ignore_errors=True)
        for t in sorted(os.listdir(os.path.join(d, "evidence", "tasks"))):
            if t not in keep_tasks:
                shutil.rmtree(os.path.join(d, "evidence", "tasks", t), ignore_errors=True)
        out = os.path.join(FIXTURES, f"{run}.tar.gz")
        with tarfile.open(out, "w:gz") as tar:
            tar.add(d, arcname=".")
        print(f"  {run}: {os.path.getsize(out) // 1024} KB fixture (kept tasks: {', '.join(sorted(keep_tasks))})")
    return len(runs)


def check(labels, budgets):
    import findings_db as db
    import workspace
    per, overall = [], {b: {"need": 0, "got": 0, "sel": 0} for b in budgets}
    for lab in labels:
        tmp, eng = extract(lab["run"])
        db.WORK = tmp
        row = {"run": lab["run"], "task": lab["task"], "needed": len(lab["needed"])}
        for b in budgets:
            try:
                pk = workspace.packet(eng, lab["goal"], lab.get("plan_item"), chars=b,
                                      exclude_task=lab["task"])
            except Exception as e:   # noqa: BLE001  a broken archive names the run, not the check
                row[b] = {"error": str(e)[:60]}
                continue
            sel = set(sum(pk["ids"].values(), []))
            need = set(lab["needed"])
            got, sel_n = len(need & sel), max(1, len(sel))
            row[b] = {"recall": round(got / len(need), 2) if need else None,
                      "precision": round(got / sel_n, 2),
                      "chars": pk["chars"]}
            overall[b]["need"] += len(need)
            overall[b]["got"] += got
            overall[b]["sel"] += len(sel)
        per.append(row)
    return per, overall


def main(argv):
    global BUDGETS
    if "--label" in argv:
        runs = [a for a in argv[1:] if not a.startswith("-") and a != "--label"] or tuning_runs()
        labels = [l for r in runs for l in label_run(r)]
        json.dump(labels, open(LABELS, "w"), indent=1)
        print(f"label proposal for {len(labels)} task(s) over {len(runs)} tuning run(s) -> {os.path.basename(LABELS)}"
              + ("\nread it, adjust what a task needed that its outcome doesn't show, then commit it" if labels
                 else " (no task bound to a cell in those runs)"))
        return 0
    if "--export" in argv:
        if not os.path.isfile(LABELS):
            print("no labelled set: run --label first")
            return 1
        n = export(json.load(open(LABELS)))
        print(f"{n} fixture(s) in {os.path.relpath(FIXTURES, KIT)} - lab runs only; commit them with the labels")
        return 0
    if "--budgets" in argv:
        BUDGETS = [int(x) for x in argv[argv.index("--budgets") + 1].split(",")]
    if not os.path.isfile(LABELS):
        print("no labelled set: run --label first (tuning-side saved runs only)")
        return 1
    labels = json.load(open(LABELS))
    per, overall = check(labels, BUDGETS)
    print(f"packet quality over {len(labels)} labelled task(s), budgets {', '.join(map(str, BUDGETS))} chars")
    for r in per[:12]:
        cells = "  ".join(f"@{b}: recall {r[b].get('recall')} precision {r[b].get('precision')}"
                          + (f" ({r[b]['chars']} chars)" if "chars" in r[b] else f" {r[b].get('error', '')}")
                          for b in BUDGETS)
        print(f"  {r['run'][:26]:26} {r['task']}: needed {r['needed']:2}  {cells}")
    if len(per) > 12:
        print(f"  ... and {len(per) - 12} more")
    print("overall (micro-averaged):")
    worst = None
    for b in BUDGETS:
        o = overall[b]
        rec = o["got"] / o["need"] if o["need"] else None
        prec = o["got"] / o["sel"] if o["sel"] else None
        print(f"  @{b}: recall {rec:.2f}, precision {prec:.2f}, over {o['need']} needed record(s)")
        if b == BUDGETS[1] if len(BUDGETS) > 1 else b == BUDGETS[0]:
            worst = rec
    if worst is not None and worst < 0.7:
        print("recall at the middle budget under 0.7: the selection drops records tasks needed - fix before "
              "raising the budget")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
