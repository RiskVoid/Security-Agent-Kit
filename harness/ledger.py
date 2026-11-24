"""The call ledger (#115): what this engagement already ran, with each result's one-line digest and its
verified-evidence path and hash.

Built with no model from two sources that are already kept: the worker's task records (each step with its
arguments, identity, build and policy revision, the digest line the task shrank it to, and the hash of a file
read) and the audit log (every command with its exit code and the SHA-256 of the outputs it produced, including
the planner's own calls).

The rules, from the issue:
  - normalised arguments: per tool, the parts that don't change the request are ignored (whitespace, run
    stamps, uuids). Where it isn't certain two calls are the same, they're treated as different - a normaliser
    that doesn't know a tool makes its key unique, so it never reuses.
  - calls that reach the target always run (a response can change); the reply carries the earlier entry so the
    model sees what is new. Reads that can't have changed - a file whose hash is the same, a vuln_intel lookup -
    are answered from the ledger, and a fresh argument runs them anyway.
  - an entry recorded against another build or policy revision is stale: shown as such, never reused.

This is a different thing from the gateway's repeat limit (litellm/rv_repeats.py), which counts identical calls
in a row inside one conversation; the ledger is for a result another task, or an earlier turn, already has.
"""
import datetime, json, os, re

import findings_db as db

STAMP_RX = re.compile(r"\d{8}T\d{6}Z?\b|\d{8}-\d{6}\b|\d{4}-\d{2}-\d{2}\b|[0-9a-f]{8}-[0-9a-f]{4}\b")


def norm(tool, args):
    """One comparable key for a call. Empty when the tool's equality isn't known - the caller treats that as
    unique, because reusing an uncertain match is worse than running again."""
    a = args if isinstance(args, dict) else {}
    if tool == "kali_run":
        cmd = re.sub(r"\s+", " ", str(a.get("command") or "")).strip()
        return STAMP_RX.sub("<stamp>", cmd) if cmd else ""
    if tool == "http_request":
        headers = "; ".join(f"{k}: {v}" for k, v in sorted((a.get("headers") or {}).items()))
        return (f"{str(a.get('method') or 'GET').upper()} {a.get('url') or ''} {headers} "
                f"{str(a.get('body') or '')}").strip()
    if tool == "read_file":
        return f"read {a.get('path')} start={a.get('start') or 1} lines={a.get('lines') or 200}"
    if tool == "vuln_intel":
        return "intel " + " ".join(sorted(str(x) for x in a.get("ids") or []))
    return ""


def _tasks_of(eng):
    out, d = [], os.path.join(db.engagement_dir(eng), "evidence", "tasks")
    for t in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        try:
            out.append(json.load(open(os.path.join(d, t, "task.json"), errors="replace")))
        except (OSError, ValueError):
            pass
    return out


def _audit_rows(eng):
    """The audit log's run rows for this engagement (command, exit, outputs with hashes)."""
    path = os.path.join(db.WORK, "audit.log")
    out = []
    if not os.path.isfile(path):
        return out
    for line in open(path, errors="replace"):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if r.get("engagement") == eng and r.get("command") and not r.get("refused") and "exit" in r:
            out.append(r)
    return out


def _ts(s):
    try:
        return datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return 0.0


def entries(eng, exclude_task=None):
    """Every finished call of the engagement, newest last: the worker's steps (with their digest line, identity,
    build and policy revision, and a file read's hash) and the audit log's rows (with exit code and the
    verified-evidence path and hash). exclude_task: a task never starts from what itself did."""
    out = []
    for t in _tasks_of(eng):
        if exclude_task and t.get("id") == exclude_task:
            continue
        cell = (t.get("contract") or {}).get("cell") or {}
        info = t.get("info") or {}
        for s in t.get("steps") or []:
            if not s.get("state") or s.get("state") in ("started", "uncertain"):
                continue
            out.append({"tool": s.get("tool"), "key": norm(s.get("tool"), s.get("args")), "who": t.get("id"),
                        "identity": cell.get("identity") or t.get("identity"),
                        "build": info.get("revision"), "policy_revision": info.get("policy_version"),
                        "at": t.get("started"), "exit": s.get("exit"), "task_status": t.get("status"),
                        "digest": (t.get("lines") or {}).get(s.get("call")), "evidence": s.get("evidence"),
                        "sha": s.get("sha")})
    for r in _audit_rows(eng):
        if r.get("task"):
            continue                      # a worker call: its own step record carries it (with the digest)
        evidence = next(iter(r.get("outputs") or {}), None)
        out.append({"tool": "kali_run", "key": norm("kali_run", {"command": r["command"]}),
                    "who": str(r.get("actor") or "planner"), "identity": None, "build": None,
                    "policy_revision": None, "at": _ts(r.get("ts")), "exit": r.get("exit"),
                    "task_status": None, "digest": None, "evidence": evidence,
                    "sha": (r.get("outputs") or {}).get(evidence)})
    return sorted([e for e in out if e.get("key")], key=lambda e: e.get("at") or 0)


def stale(entry, build=None, policy_revision=None):
    """True when the entry was recorded against another build or policy revision (#91's rule): shown as stale,
    never reused."""
    return bool((entry.get("build") and build and str(entry["build"]) != str(build))
                or (entry.get("policy_revision") and policy_revision
                    and str(entry["policy_revision"]) != str(policy_revision)))


def find(eng, tool, args, exclude_task=None, build=None, policy_revision=None):
    """The latest usable entry for this call, or None. A stale entry is returned with its stale flag set (the
    caller shows it but never answers from it); exclude_task keeps a task from finding its own calls."""
    key = norm(tool, args)
    if not key:
        return None
    hit = None
    for e in entries(eng, exclude_task=exclude_task):
        if e["tool"] == tool and e["key"] == key:
            hit = e                        # newest last: keep the last usable one
    if hit is not None:
        hit = dict(hit, stale=stale(hit, build, policy_revision))
    return hit


def entry_line(e):
    """One ledger entry as the model sees it: who, when, what it showed, where the evidence is. Target-controlled
    text arrives through the digest line, which is already bounded by digest.one_line."""
    when = datetime.datetime.fromtimestamp(e.get("at") or 0, datetime.timezone.utc).strftime("%m-%d %H:%M") \
        if isinstance(e.get("at"), (int, float)) else str(e.get("at") or "?")
    parts = [f"run by {e.get('who') or '?'}"]
    if when and when != "?":
        parts.append(f"at {when} UTC")
    if e.get("identity"):
        parts.append(f"as {e['identity']}")
    if e.get("digest"):
        parts.append("showed: " + str(e["digest"])[:200])
    if e.get("evidence"):
        parts.append(f"evidence {e['evidence']}" + (f" (sha {str(e['sha'])[:12]})" if e.get("sha") else ""))
    if e.get("stale"):
        parts.append("STALE: recorded against another build or policy - never reused")
    return ", ".join(parts)
