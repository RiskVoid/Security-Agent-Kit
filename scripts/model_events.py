#!/usr/bin/env python3
"""Read the model-problem log that litellm/rv_events.py writes (.rvkit/events/model-events.jsonl).

Used by ./rvkit status, doctor and watch, and by the console. Python 3.9+, standard library only.

  python3 scripts/model_events.py [--since SECONDS] [--problems] [--json]   recent events, repeats collapsed
  python3 scripts/model_events.py --from-line N                             events from line N on (./rvkit watch)
  python3 scripts/model_events.py --count                                   number of lines in the log

Kinds: "fallback" and "refusal" mean another model answered instead (recovered, shown as info). Everything else
(no_answer, credits, budget, auth, rate_limit, worker_down, timeout, context, error) means the call failed.
"""
import calendar, json, os, sys, time

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(KIT, ".rvkit", "events", "model-events.jsonl")
RECOVERED = {"fallback", "refusal"}


def _epoch(ts):
    try:
        return calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
    except (TypeError, ValueError):
        return 0


def read(from_line=0, path=LOG):
    out = []
    try:
        with open(path) as f:
            for i, line in enumerate(f):
                if i < from_line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                e["problem"] = e.get("kind") not in RECOVERED
                # the message without its leading "planner (model id)" label, for pages that show the model apart
                label = f"{e.get('model')} ({e.get('model_id')})" if e.get("model_id") else str(e.get("model"))
                msg = e.get("message") or ""
                e["text"] = msg[len(label):].lstrip(" :") if msg.startswith(label) else msg
                e["text"] = e["text"][:1].upper() + e["text"][1:]
                out.append(e)
    except OSError:
        pass
    return out


def count(path=LOG):
    try:
        with open(path) as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def recent(since=3600, problems_only=False, path=LOG, now=None, engagement=None):
    """Events of the last `since` seconds, newest first, with repeats (same kind, model, engagement and message)
    collapsed. engagement: only that engagement's events ("" = events no engagement could be matched to)."""
    cutoff = (now or time.time()) - since
    groups = {}
    for e in read(path=path):
        if _epoch(e.get("ts")) < cutoff or (problems_only and not e["problem"]):
            continue
        if engagement is not None and (e.get("engagement") or "") != engagement:
            continue
        k = (e.get("kind"), e.get("model"), e.get("engagement"), e.get("message"))
        g = groups.get(k)
        if g:
            g["count"] += 1
            g["ts"] = max(g["ts"], e.get("ts") or "")
        else:
            groups[k] = {**e, "count": 1}
    return sorted(groups.values(), key=lambda e: e.get("ts") or "", reverse=True)


def line(e):
    t = time.strftime("%H:%M", time.localtime(_epoch(e.get("ts")))) if e.get("ts") else "--:--"
    n = f" (x{e['count']})" if e.get("count", 1) > 1 else ""
    tag = "" if e["problem"] else "recovered: "
    return f"{t}  {tag}{e.get('message', '')}{n}"


def main(argv):
    def opt(name, default=None):
        return argv[argv.index(name) + 1] if name in argv and argv.index(name) + 1 < len(argv) else default
    if "--count" in argv:
        print(count())
        return 0
    if "--from-line" in argv:
        events = read(int(opt("--from-line", 0)))
    else:
        events = recent(int(opt("--since", 3600)), "--problems" in argv)
    if "--json" in argv:
        print(json.dumps(events))
    else:
        for e in events:
            print(line(e))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
