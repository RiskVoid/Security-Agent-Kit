"""Verification records on the findings side (epic #52, issues #42 and #44).

kali-mcp's verify tool writes one record per oracle run under evidence/verify/. A finding confirmed with
method=oracle must cite a record whose oracle passed with a clean control; the report shows the oracle and the
control of each finding that has one.
"""
import json, os, re

import findings_db as db

ORACLES = ("marker", "identity_difference", "read_back", "browser_xss", "timing", "out_of_band")


def _path(engagement, e):
    p = re.split(r"\s", str(e or "").strip(), maxsplit=1)[0] if str(e or "").strip() else ""
    if "evidence/verify/" not in p or not p.endswith(".json"):
        return None
    base = os.path.realpath(os.path.join(db.WORK, engagement))
    if p.startswith("/work/"):
        p = os.path.join(db.WORK, p[len("/work/"):])
    full = os.path.realpath(p if os.path.isabs(p) else os.path.join(base, p))
    return full if full.startswith(base + os.sep) and os.path.isfile(full) else None


def records(engagement, evidence):
    """[(evidence path as cited, record)] for the verification records a finding cites."""
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except ValueError:
            evidence = [evidence]
    out = []
    for e in evidence or []:
        full = _path(engagement, e)
        if not full:
            continue
        try:
            rec = json.load(open(full))
        except (OSError, ValueError):
            continue
        if isinstance(rec, dict) and rec.get("oracle") in ORACLES:
            out.append((str(e).split()[0], rec))
    return out


def problem(engagement, evidence):
    """Why a finding may not be confirmed by method=oracle with this evidence (None: it may)."""
    recs = records(engagement, evidence)
    if not recs:
        return ("a finding confirmed by oracle needs the verification record of a passing oracle: the "
                "/work/<engagement>/evidence/verify/... file the kali verify tool printed")
    if not any(r.get("result") == "pass" and r.get("control_clean") for _, r in recs):
        got = "; ".join(f"{r.get('oracle')} {r.get('result')}: {r.get('reason')}" for _, r in recs)[:400]
        return f"no cited verification passed with a clean control ({got}). Record it as a candidate"
    return None


def summary(engagement, evidence):
    """What the report shows for a finding: each cited oracle, its result and its control."""
    out = []
    for path, r in records(engagement, evidence):
        ctl = [s for s in r.get("steps") or [] if "control" in str(s.get("role"))]
        out.append({"oracle": r.get("oracle"), "result": r.get("result"), "reason": r.get("reason"), "record": path,
                    "controls": [{"role": s.get("role"), "status": s.get("status"), "evidence": s.get("evidence")}
                                 for s in ctl], "at": r.get("at")})
    return out
