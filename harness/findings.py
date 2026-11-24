"""Findings MCP server (streamable HTTP on :8092/mcp), used by the planner.

The planner records, confirms, rejects and lists findings. The worker can only add candidates
(it writes through findings_db directly with status=candidate).
"""
import json, os
from mcp.server.fastmcp import FastMCP
import findings_db as db
import ops
import pins
import quotecheck
import validator
import verification

ACTOR = "agent:planner"  # changes made through this server are attributed to the planner agent

# Stateless: no per-client session, so a conversation that was open when this server restarted keeps working
# (with sessions, every later tool call failed with "Session terminated" until OpenHands itself was restarted).
mcp = FastMCP("findings", host="0.0.0.0", port=8092, stateless_http=True)


NOT_CONFIRMED = "NOT CONFIRMED: "


def _out(x) -> str:
    return json.dumps(x, indent=1)


ACK_VALUE = 200   # a field longer than this is acknowledged by its length: the model wrote it, it needn't read it back


def _ack(row, sent=(), head=("id", "title", "severity", "status", "verified_method", "revision")):
    """What a write returns: the row's identity and state, and the fields this call sent (long ones by length).
    Returning the whole finding after every update made these replies a third of the planner's context;
    get_finding still returns everything."""
    if not isinstance(row, dict):
        return row
    out = {k: row[k] for k in ("note",) if k in row}
    out.update({k: row.get(k) for k in head if k in row})
    for k in sent:
        v = row.get(k)
        if k in out or v is None:
            continue
        text = v if isinstance(v, str) else json.dumps(v)
        out[k] = v if len(text) <= ACK_VALUE else f"saved ({len(text)} characters)"
    for k in ("quotes", "validation", "previous_revision"):
        if k in row:
            out[k] = row[k]
    return out


def _repin(engagement):
    """Findings whose cited evidence was moved since they were confirmed are pointed at the moved file."""
    try:
        return pins.repair(engagement)
    except Exception:  # noqa: BLE001
        return []


def _validated(engagement, row):
    """A finding the planner just confirmed goes to the disprove-only validator (validator.py). The verdict is added
    to what the tool returns. A disproved finding stays confirmed and is flagged for the person (the default), or
    has already gone back to candidate (VALIDATOR_DISPROVE=demote)."""
    if not isinstance(row, dict) or row.get("status") != "confirmed":
        return row
    try:
        pins.pin(engagement, row)   # what it cites, by content: a file moved later is found again (pins.py)
    except Exception:  # noqa: BLE001  a pin is a convenience; the confirmation doesn't depend on it
        pass
    quotes = _quotes(engagement, row)
    try:
        v = validator.validate(engagement, row["id"])
    except Exception as e:  # noqa: BLE001  the confirmation stands; the validation is just missing
        v = {"verdict": "not_run", "reason": f"the validator failed: {type(e).__name__}: {e}"}
    if v.get("verdict") == "disproved" and v.get("action") == "back to candidate":
        row = db.get(engagement, row["id"])
        v["note"] = ("the finding is back to candidate. Look at the reason and the evidence: test again, then confirm "
                     "it with update_finding(status=\"confirmed\", method=..., evidence=[the new evidence]), or mark "
                     "it false-positive. Don't confirm it again with the same evidence.")
    elif v.get("verdict") == "disproved":
        v["note"] = (f"{row['id']} is still confirmed, and the reviewer's objection is on record for the person who "
                     "signs the report. Read the reason once. If it is right, correct the finding (cite the evidence "
                     "that shows it, narrow the claim, or mark it false-positive). If the evidence already shows "
                     "what the finding says, leave it and go on with the plan: do not send this call again.")
    missing = _missing_evidence(engagement, row)
    if missing:
        v["note"] = (str(v.get("note") or "") + " " if v.get("note") else "") + \
            (f"Evidence entry(ies) {', '.join(missing)} name no file of this engagement: cite the path a tool "
             "printed (evidence/runs/...), or a /src/<file>:<line> reference, or drop the entry.")
    dup = _duplicate_hint(engagement, row)
    if dup:
        v["note"] = (str(v.get("note") or "") + " " if v.get("note") else "") + \
            (f"Same CWE and asset as confirmed {', '.join(dup)}: if this is the same root cause, merge it "
             "(status duplicate, duplicate_of the finding to keep, after adding its evidence there); if it is a "
             "separate one, say why in the description.")
    return {**row, **({"quotes": quotes} if quotes else {}), "validation": v}


def _quotes(engagement, row):
    """Quotes of a confirmed finding that are not in its evidence (quotecheck.py): listed, never a refusal."""
    try:
        return quotecheck.flag(engagement, row.get("description"), row.get("reproduction"), row.get("evidence"))
    except Exception:  # noqa: BLE001  a list for the reader; the confirmation doesn't depend on it
        return None


def _missing_evidence(engagement, row):
    """Evidence entries that name no file (neither an engagement file nor a /src reference): a note at record time.
    The validator and the report find them later, when fixing them costs another round; a model was seen citing
    'the intel_prioritize output' — inline tool text, not a file — as evidence."""
    out = []
    for e in row.get("evidence") or []:
        p = str(e).strip()
        if not p or p.startswith("/src/"):
            continue
        try:
            if quotecheck.evidence_path(engagement, p):
                continue
        except Exception:  # noqa: BLE001  the note is a convenience, never a refusal
            continue
        out.append(p.split(" ")[0][:80])
    return out


def _duplicate_hint(engagement, row):
    """Confirmed findings that already cover the same CWE on the same asset: a likely duplicate, named at record
    time. One finding per root cause is the rule; a benchmark run recorded three SQL injection findings on the
    same endpoint and confirmed each before merging them."""
    try:
        same = [f for f in db.list_(engagement)
                if f.get("id") != row.get("id") and f.get("status") == "confirmed"
                and (f.get("cwe") or "").strip().lower() == (row.get("cwe") or "").strip().lower()
                and (f.get("asset") or "").strip().lower() == (row.get("asset") or "").strip().lower()]
    except Exception:  # noqa: BLE001  the note is a convenience, never a refusal
        return []
    return [f"{f['id']} ({str(f.get('title'))[:60]})" for f in same]


def _disproved(engagement, finding_id):
    """True when the validator's newest verdict on this finding is disproved."""
    try:
        h = validator.history(engagement, finding_id)
    except Exception:  # noqa: BLE001  no verdicts to read is not a disproval
        return False
    return bool(h) and h[0].get("verdict") == "disproved"


def _reproduction_problem(text):
    """An agent's confirmed finding needs the steps that show it: the report prints them, and a person retesting
    needs them. People confirming in the console or the CLI aren't held to this."""
    if (text or "").strip():
        return None
    return ("status=confirmed needs reproduction: the steps that show the issue (the requests or commands, in order, "
            "and what each returns), so the client can reproduce it. Commands in it are not checked as quotes")


def _confirm_problem(engagement, method, evidence, reproduction, description):
    """Why the agent may not confirm a finding with this method, evidence and text (None: it may)."""
    return db.confirm_problem(method, evidence) or _reproduction_problem(reproduction) or \
        (verification.problem(engagement, evidence or []) if method == "oracle" else None) or \
        quotecheck.refusal(engagement, description, reproduction, evidence or [])


def _confirm_call(finding_id, method):
    return (f"update_finding(finding_id=\"{finding_id}\", status=\"confirmed\", method=\"{method}\") plus what "
            f"is missing above")


@mcp.tool()
def record_finding(engagement: str, title: str, severity: str, asset: str, description: str,
                   impact: str = "", reproduction: str = "", remediation: str = "", evidence: list[str] | None = None,
                   cvss_vector: str = "", cvss_score: float | None = None, cwe: str = "",
                   status: str = "", notes: str = "", method: str = "") -> str:
    """Record a finding for an engagement. severity: critical|high|medium|low|info.
    status: candidate (not yet verified) or confirmed (you have reproduced or verified it). Left out, it is
    confirmed when you give a method and candidate when you don't.
    Confirming needs method = how you verified it (oracle, runtime-reproduction, replay, authorization-matrix,
    source-review, tool-output, retest) and reproduction (the steps that show it: requests or commands, and what
    each returns). oracle: cite the evidence/verify/ record of a kali verify run that passed
    with a clean control (the strongest method; prefer it when an oracle fits). runtime-reproduction, replay, authorization-matrix and tool-output also
    need the evidence file that shows it. Confirming is refused when a /src/<file>:<line> in the text doesn't
    exist. Text in backticks or code blocks (other than commands) that isn't in the cited evidence is listed in
    the reply (quotes): the finding is confirmed all the same.
    A method without status that can't be confirmed is saved as a candidate, and the reply's note says why.
    evidence: file paths under /work/<engagement>/evidence/. Returns the stored finding with its id (F-001...)."""
    note = None
    if not status:
        # A method says how the finding was verified, so a call that carries one means to confirm. Recording it as
        # a candidate without a word left the planner believing it was confirmed: one run recorded ten findings
        # this way and spent the rest of its budget failing to confirm the first.
        status = "confirmed" if method else "candidate"
        if method:
            problem = _confirm_problem(engagement, method, evidence, reproduction, description)
            if problem:
                status, note = "candidate", problem
    elif status == "confirmed":
        problem = _confirm_problem(engagement, method, evidence, reproduction, description)
        if problem:
            return f"REFUSED: {problem}"
    row, _ = ops.call("finding.record", {"engagement": engagement, "actor": ACTOR,
                                         "method": (method or None) if status == "confirmed" else None, "fields": dict(
        title=title, severity=severity, asset=asset, description=description, impact=impact,
        reproduction=reproduction, remediation=remediation, evidence=evidence or [], cvss_vector=cvss_vector,
        cvss_score=cvss_score, cwe=cwe, status=status, source="planner", notes=notes)})
    if note:
        row = {"note": (f"{NOT_CONFIRMED}saved as candidate {row['id']}. {note.rstrip('.')}. Don't record it again: to confirm "
                        f"it, call {_confirm_call(row['id'], method)}."), **row}
    return _out(_ack(_validated(engagement, row), ("asset", "cwe", "cvss_vector", "cvss_score", "evidence")))


@mcp.tool()
def update_finding(engagement: str, finding_id: str, status: str | None = None, severity: str | None = None,
                   title: str | None = None, description: str | None = None, impact: str | None = None,
                   reproduction: str | None = None, remediation: str | None = None,
                   evidence: list[str] | None = None, cvss_vector: str | None = None,
                   cvss_score: float | None = None, cwe: str | None = None, notes: str | None = None,
                   duplicate_of: str | None = None, reason: str | None = None, method: str | None = None,
                   priority: str | None = None, prerequisites: str | None = None, root_cause: str | None = None) -> str:
    """Update a finding. Use status=confirmed after verifying a candidate, with method = how you verified it
    (runtime-reproduction, replay, authorization-matrix, source-review, tool-output, retest; required, and
    runtime-reproduction, replay, authorization-matrix and tool-output also need the evidence file that shows
    it; quotes in backticks that aren't in the cited evidence are listed, as for record_finding) and reproduction (kept from
    before when not given). A method without status on a candidate is read as status=confirmed and gets the same
    checks: when they fail, the other fields are saved and the reply's note says why it is still a candidate.
    status=false-positive when it doesn't hold; status=duplicate with duplicate_of=<id of the finding to keep>; fixed or accepted-risk
    after client feedback. reason is required for false-positive, accepted-risk and any severity or priority
    change. Severity is the technical severity; priority (P1-P4) is the remediation order, set separately; the
    CVSS score is computed from a CVSS 3.1 cvss_vector (give cvss_score with a 4.0 vector). prerequisites:
    what a reproduction needs (an account, a role, data). Only given fields change."""
    fields = dict(status=status, severity=severity, title=title, description=description, impact=impact,
                  reproduction=reproduction, remediation=remediation, evidence=evidence, cvss_vector=cvss_vector,
                  cvss_score=cvss_score, cwe=cwe, notes=notes, duplicate_of=duplicate_of, priority=priority,
                  prerequisites=prerequisites, root_cause=root_cause)
    if reason is None and status in ("false-positive", "accepted-risk") and notes:
        reason = notes  # the reason given in notes, as before
    method_given = method
    note = None
    if status is None and method:
        # method says how a confirmation was verified, so on a candidate a call that carries one means to confirm:
        # it gets the same checks as status="confirmed". Refusing it sent the planner into a loop (it resent the
        # call 36-46 times), and saving the rest while leaving the finding a candidate left it believing it had
        # confirmed. When the checks fail, the other fields are saved and the note says why it isn't confirmed.
        try:
            cur = db.get(engagement, finding_id)
        except ValueError as e:
            return f"REFUSED: {e}"
        was = cur.get("status")
        given = [k for k, v in fields.items() if v is not None]
        if was == "candidate" and _disproved(engagement, finding_id):
            # the validator sent it back: only an explicit confirmation with new evidence may try again
            problem = ("the validator disproved it (get_finding shows the reason). Test again, then send "
                       "status=\"confirmed\" with the new evidence, or mark it false-positive")
        elif was == "candidate":
            problem = _confirm_problem(
                engagement, method, evidence if evidence is not None else cur.get("evidence"),
                reproduction if reproduction is not None else cur.get("reproduction"),
                description if description is not None else cur.get("description"))
        elif was != "confirmed":
            problem = "method is kept only with status=\"confirmed\""
        else:
            problem = None
        if was == "candidate" and not problem:
            status = fields["status"] = "confirmed"
        elif problem:
            if not given:
                return (f"REFUSED: {finding_id} is {was}, and a method without status is read as confirming it, "
                        f"which can't be done: {problem.rstrip('.')}.")
            method = None
            note = (f"{NOT_CONFIRMED}saved {', '.join(given)}, and {finding_id} is still {was}. {problem.rstrip('.')}. To "
                    f"confirm it, call {_confirm_call(finding_id, method_given)}.")
    if status == "confirmed":
        try:
            cur = db.get(engagement, finding_id)
        except ValueError as e:
            return f"REFUSED: {e}"
        # confirming again without a method keeps the one already recorded
        ev = evidence if evidence is not None else cur.get("evidence")
        how = method or cur.get("verified_method")
        repro = reproduction if reproduction is not None else cur.get("reproduction")
        problem = _confirm_problem(engagement, how, ev, repro,
                                   description if description is not None else cur.get("description"))
        if problem:
            return f"REFUSED: {problem}"
    try:
        row, _ = ops.call("finding.update", {"engagement": engagement, "actor": ACTOR, "id": finding_id,
                                             "fields": {k: v for k, v in fields.items() if v is not None},
                                             "reason": reason, "method": method})
    except ValueError as e:
        return f"REFUSED: {e}"
    if note:
        row = {"note": note, **row}
    sent = [k for k, v in fields.items() if v is not None and k != "status"]
    return _out(_ack(_validated(engagement, row) if status == "confirmed" else row, sent))


@mcp.tool()
def validate_finding(engagement: str, finding_id: str) -> str:
    """Send a confirmed finding to the disprove-only validator again (it runs on its own when you confirm one): a
    separate model with only the finding, its cited evidence and source lines and its oracle records tries to
    disprove it. Returns stands, disproved (the finding stays confirmed and is flagged for the person, with the
    reason), unclear or not_run, and the reason."""
    try:
        return _out(validator.validate(engagement, finding_id))
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
def list_findings(engagement: str, status: str | None = None, severity: str | None = None) -> str:
    """List findings, most severe first. Filter by status (candidate|confirmed|false-positive|duplicate|fixed|accepted-risk)
    and/or severity. Returns id, title, severity, status, asset for each."""
    _repin(engagement)
    rows = db.list_(engagement, status, severity)
    return _out([{k: r[k] for k in ("id", "title", "severity", "status", "asset", "source")} for r in rows]
                or "no findings")


@mcp.tool()
def get_finding(engagement: str, finding_id: str, history: bool = False) -> str:
    """Get one finding with all fields (verification, verified_by and method, priority, instances). history=true
    adds every earlier revision and the decisions made about it, with reasons."""
    f = db.get(engagement, finding_id)
    v = validator.history(engagement, finding_id)
    if v:
        f["validation"] = v[0]
    quotes = _quotes(engagement, f) if f.get("status") == "confirmed" else None
    if quotes:
        f["quotes"] = {"not_in_evidence": quotes["not_in_evidence"]}
    if history:
        f["history"] = db.history(engagement, finding_id)
        f["validations"] = v
    return _out(f)


# ---------------------------------------------------------------- investigation workspace (RW-015 to RW-018)
def _call(name, **req):
    _repin(req.get("engagement"))
    try:
        return _out(ops.call(name, {"engagement": req.pop("engagement"), "actor": ACTOR, **req})[0])
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
def import_observations(engagement: str, path: str, tool: str = "") -> str:
    """Turn a tool's output (a file of the engagement: semgrep.json, evidence/...) into observations: Semgrep,
    osv-scanner, pip-audit, bandit or gitleaks JSON, an authorization-matrix run (evidence/authz), a probe_map
    sweep (evidence/sweep), a Laravel map (evidence/appmap) or an HTTP exchange (evidence/http). tool: force a
    parser (detected otherwise). Re-importing doesn't duplicate; parser errors and the tool's limitations
    (skipped files, blocked cells) are returned and kept."""
    return _call("observation.import", engagement=engagement, path=path, tool=tool or None)


@mcp.tool()
def add_observation(engagement: str, title: str, location: str, detail: str = "", severity: str = "info",
                    evidence: list[str] | None = None) -> str:
    """Record something you noticed by hand (not from a tool output) as an observation to triage."""
    return _call("observation.add", engagement=engagement, title=title, location=location, detail=detail,
                 severity=severity, evidence=evidence or [])


@mcp.tool()
def list_observations(engagement: str, status: str = "new", tool: str = "") -> str:
    """Observations (status new, linked, duplicate, dismissed; empty for all), the imports with their parser
    errors, and grouping suggestions (observations that may share a root cause)."""
    r = ops.call("observation.list", {"engagement": engagement, "status": status or None, "tool": tool or None})[0]
    r["observations"] = [{k: o[k] for k in ("id", "tool", "rule_id", "title", "severity", "location", "status",
                                            "finding_id", "seen", "group_key")} for o in r["observations"]]
    return _out(r)


@mcp.tool()
def triage_observations(engagement: str, ids: list[str], action: str, finding_id: str = "", of: str = "",
                        reason: str = "") -> str:
    """Decide about observations. action: link (they are instances of finding_id: record the finding first),
    duplicate (the same as observation `of`), dismiss (not an issue: reason required), reopen. Grouping is your
    decision: link only observations that share the root cause."""
    if action == "link":
        return _call("observation.link", engagement=engagement, ids=ids, finding_id=finding_id)
    if action == "duplicate":
        return _call("observation.duplicate", engagement=engagement, ids=ids, of=of)
    if action == "dismiss":
        return _call("observation.dismiss", engagement=engagement, ids=ids, reason=reason)
    if action == "reopen":
        return _call("observation.reopen", engagement=engagement, ids=ids)
    return "REFUSED: action is link, duplicate, dismiss or reopen"


@mcp.tool()
def plan_tests(engagement: str, items: list[dict] | None = None, playbook: str = "") -> str:
    """Add planned tests (coverage items). playbook: add one item per checklist line of that playbook (once).
    items: [{"title", "area", "refs": ["ASVS V8.2.2", "WSTG-ATHZ-04", "API1:2023"], "hypothesis",
    "prerequisites": [...], "operation", "identity"}]. Top 10 lists are risk categories: reference ASVS/WSTG
    requirements for coverage."""
    if playbook:
        return _call("plan.from_playbook", engagement=engagement, playbook=playbook)
    return _call("plan.add", engagement=engagement, items=items or [])


COVERAGE_KEYS = ("item", "state", "rationale", "evidence", "finding_id", "build", "policy_revision")
COVERAGE_SHAPE = ('updates: [{"item": "P-001", "state": "tested", "evidence": ["evidence/runs/x.txt"]}, {"item": '
                  '"P-002", "state": "not-applicable", "rationale": "..."}], each with item and state and what that '
                  'state needs (rationale, evidence, finding_id; optional build, policy_revision); or item and '
                  'state alone for one update')


def _coverage_one(engagement, item, state, rationale="", evidence=None, finding_id="", build="", policy_revision=""):
    """One update: the saved row, or the refusal reason (a str)."""
    fields = {"state": state, "rationale": rationale or None, "evidence": evidence, "finding_id": finding_id or None,
              "build": build or None, "policy_revision": policy_revision or None}
    try:
        return ops.call("plan.update", {"engagement": engagement, "actor": ACTOR, "id": item,
                                        "fields": {k: v for k, v in fields.items() if v is not None}})[0]
    except ValueError as e:
        return str(e)


def _malformed_update(u):
    """Why an entry of updates can't be read (None: it can)."""
    if not isinstance(u, dict):
        return "an entry is not an object"
    extra = sorted(set(u) - set(COVERAGE_KEYS))
    if extra:
        return (f"unknown keys {', '.join(extra)}: an update takes {', '.join(COVERAGE_KEYS)} — refs are set "
                "when the item is planned (plan_tests), and get_coverage matrix=true shows the cells they cover")
    if not (isinstance(u.get("item"), str) and u["item"].strip() and isinstance(u.get("state"), str) and u["state"]):
        return "an entry has no item or no state"
    ev = u.get("evidence")
    if ev is not None and not (isinstance(ev, list) and all(isinstance(p, str) for p in ev)):
        return f"evidence of {u['item']} is not a list of paths"
    if any(u.get(k) is not None and not isinstance(u[k], str) for k in ("rationale", "finding_id", "build",
                                                                         "policy_revision")):
        return f"rationale, finding_id, build and policy_revision of {u['item']} must be text"
    return None


@mcp.tool()
def update_coverage(engagement: str, item: str = "", state: str = "", rationale: str = "",
                    evidence: list[str] | None = None, finding_id: str = "", build: str = "",
                    policy_revision: str = "", updates: list[dict] | None = None) -> str:
    """Record a planned test's outcome. state: tested (ran, no issue: evidence required, a tool output under
    /work/<engagement>/ or the source that shows it, /src/<repo>/<file>:<line>), failed (an issue: the
    finding_id it produced), blocked (couldn't run: rationale, and what would unblock it), excluded (out of scope
    or agreed not to test: rationale), not-applicable (rationale), planned. build: the source digest or deployed
    build it ran on; policy_revision: the engagement's policy revision (engagement_info).
    Several items in one call: leave item and state out and send updates, a list with one object per item and the
    same fields, e.g. updates=[{"item": "P-001", "state": "tested", "evidence": ["evidence/runs/x.txt"]},
    {"item": "P-002", "state": "not-applicable", "rationale": "no file upload"}]. Each one is checked and saved
    by itself: a refused one doesn't stop the others. The reply has one line per item, its state or REFUSED and
    why; send only the refused ones again."""
    _repin(engagement)
    if updates is None:
        if not (item and state):
            return f"REFUSED: send item and state, or {COVERAGE_SHAPE}"
        row = _coverage_one(engagement, item, state, rationale, evidence, finding_id, build, policy_revision)
        if isinstance(row, str):
            return f"REFUSED: {row}"
        if not isinstance(row, dict):
            return _out(row)
        return _out({k: row[k] for k in ("id", "title", "state", "evidence", "finding_id", "stale", "warning", "note")
                     if row.get(k) not in (None, "", [], False)})
    if item or state:
        return f"REFUSED: send item and state, or updates, not both. {COVERAGE_SHAPE}"
    if not isinstance(updates, list) or not updates:
        return f"REFUSED: updates is empty. {COVERAGE_SHAPE}"
    problem = next((p for p in map(_malformed_update, updates) if p), None)
    if problem:
        return f"REFUSED: {problem}; nothing was saved. {COVERAGE_SHAPE}"
    if len(updates) == 1:   # a batch of one answers as the single form does
        return update_coverage(engagement, **updates[0])
    # Each update is its own write, as if sent alone: a refusal (or a revision conflict) leaves the others saved.
    lines, refused = [], 0
    for u in updates:
        row = _coverage_one(engagement, **u)
        if isinstance(row, str):
            refused += 1
            lines.append(f"{u['item']}: REFUSED: {row}")
        else:
            lines.append(f"{row.get('id', u['item'])}: {row.get('state')}" + (" (stale)" if row.get("stale") else ""))
    n = len(updates)
    head = (f"saved {n} of {n}:" if not refused else f"REFUSED {n} of {n} (nothing was saved):" if refused == n
            else f"REFUSED {refused} of {n} (the others are saved; send only the refused ones again):")
    return "\n".join([head] + lines)


# which tier a gap's class needs: reads probe at active; the classes that write or burst are intrusive
GAP_TIER = {"mass-assignment": "intrusive", "rate-limit": "intrusive", "csrf": "intrusive"}


def gap_offer(cell):
    """#171: a coverage gap arrives pre-shaped, so filling it is two calls the planner sends (plan_tests the
    item, delegate_task the task), not a composition it writes. The offer is a suggestion in the tool result,
    never an automatic dispatch: the planner decides, exactly as the gaps rule says."""
    c = {k: cell.get(k) for k in ("entry", "method", "path", "class")}
    where = f"{c['method']} {c['path']}".strip()
    c["offer"] = {
        "plan": {"title": f"{c['class']} on {c['path']}", "area": c["class"], "refs": [c["entry"]]},
        "delegate": {"goal": f"Test {c['class']} on {where} (map entry {c['entry']}) only: probe it, and report "
                              f"candidates with the evidence files your commands produced. One class, one "
                              "endpoint - anything else you notice goes in open_questions, don't test it.",
                      "tier": GAP_TIER.get(c["class"], "active"),
                      "plan_item": "the item the plan call above returns"},
    }
    return c


@mcp.tool()
def get_coverage(engagement: str, state: str = "", matrix: bool = False) -> str:
    """Planned tests and their outcomes, counts per state and per standard, stale items (the build or policy
    changed since they ran), blocked items with the reason. matrix=true: the coverage matrix instead: each recon
    map entry x each vulnerability class that applies to it, with the plan items that cover it; "gaps" are cells
    no plan item covers, and each gap arrives pre-shaped (#171): the plan item to add and the delegate_task goal
    to send — the offer is a suggestion, the decision is yours (send it, or record why it's skipped).
    state: list only the items in that state (planned, tested, blocked, ...) — a run's full listing is long, so
    ask for the state you're working through, not everything."""
    if matrix:
        try:
            m = ops.call("coverage.matrix", {"engagement": engagement})[0]
        except ValueError as e:
            return f"REFUSED: {e}"
        open_ = [c for c in m["cells"] if c["state"] in ("gap", "planned", "blocked")]
        return _out({"entries": m["entries"], "counts": m["counts"], "complete": m["complete"],
                     "gaps": [gap_offer(c) for c in m["gaps"][:150]],
                     "open": [{k: c[k] for k in ("entry", "method", "path", "class", "state", "items")}
                              for c in open_ if c["state"] != "gap"][:150],
                     "more": max(0, len(m["gaps"]) - 150), "plan_items_without_map_refs": m["unmapped_items"][:50]})
    import workspace
    r = ops.call("plan.list", {"engagement": engagement, "state": state or None})[0]
    r["items"] = [{**{k: i[k] for k in ("id", "title", "area", "refs", "state", "rationale", "finding_id",
                                       "stale")},
                   "readiness": workspace.readiness(engagement, i["id"])}
                  #92: ready, or waiting with what it waits for - computed, so a prerequisite appearing
                  for i in r["items"]]          # (an identity checked, an observation) makes it ready alone
    return _out(r)


@mcp.tool()
def skip_coverage_cells(engagement: str, cells: list[dict], state: str, rationale: str) -> str:
    """Record coverage-matrix cells you won't test, in one call (the gap-fill pass, #47). cells: [{"entry":
    "E-1a2b3c", "class": "ssrf"}] from get_coverage(matrix=true) gaps. state: not-applicable (the class can't apply
    here: say why) or excluded (out of scope or agreed not to test). rationale is required and shown in the
    report. Each cell becomes a plan item with that outcome."""
    import reconmap
    if state not in ("not-applicable", "excluded"):
        return "REFUSED: state must be not-applicable or excluded (plan and delegate the cells you will test)"
    if not (rationale or "").strip():
        return "REFUSED: a rationale is required"
    bad = [c for c in cells or [] if not isinstance(c, dict) or c.get("class") not in reconmap.CLASSES
           or not reconmap.ENTRY_RX.match(str(c.get("entry")))]
    if bad or not cells:
        return f"REFUSED: cells: [{{entry: E-xxxxxx, class: one of {', '.join(reconmap.CLASSES)}}}]"
    try:
        ids = ops.call("plan.add", {"engagement": engagement, "actor": ACTOR, "items": [
            {"title": f"{c['class']} on {c['entry']}", "area": c["class"], "refs": [c["entry"]]} for c in cells]})[0]
        ids = ids.get("ids", ids) if isinstance(ids, dict) else ids
        for pid in ids:
            ops.call("plan.update", {"engagement": engagement, "actor": ACTOR, "id": pid,
                                     "fields": {"state": state, "rationale": rationale.strip()}})
    except ValueError as e:
        return f"REFUSED: {e}"
    return _out({"recorded": ids, "state": state})


@mcp.tool()
def get_map(engagement: str, host: str = "", path: str = "", auth: str = "", limit: int = 200) -> str:
    """The recon map (built from recon_map, laravel_map, imported captures and your own requests): each entry is a
    method and path template with its parameters, whether it needs authentication (required | none | unknown, and
    why), the sources that saw it, evidence, and the vulnerability classes that apply to it. Reference entries
    in plan_tests by id (refs: ["E-1a2b3c", "WSTG-ATHZ-04"]): one class on one entry (or a few of one route group)
    per item. Filters: host, path (substring), auth."""
    try:
        m = ops.call("map.get", {"engagement": engagement})[0]
    except ValueError as e:
        return f"REFUSED: {e}"
    ents = [e for e in m["entries"] if (not host or host in (e["host"] or "")) and (not path or path in e["path"])
            and (not auth or e["auth"] == auth)]
    keep = ("id", "method", "host", "path", "params", "auth", "auth_basis", "status", "sources", "classes", "code")
    out = {"entries": [{k: e[k] for k in keep if e.get(k) not in (None, [], {})} for e in ents[:max(1, min(limit, 500))]],
           "total": len(m["entries"]), "shown": min(len(ents), limit), "hosts": m["hosts"], "tech": m["tech"],
           "schemas": [{k: s.get(k) for k in ("kind", "url", "operations", "title", "note")} for s in m["schemas"]],
           "sources": m["sources"]}
    if not m["entries"]:
        out["note"] = "no map yet: run kali recon_map on each web target (and laravel_map on source) first"
    return _out(out)


@mcp.tool()
def set_objective(engagement: str, text: str) -> str:
    """The engagement's current objective: what it must answer (shown in the handover and the console)."""
    return _call("workspace.objective", engagement=engagement, text=text)


@mcp.tool()
def get_queue(engagement: str, limit: int = 20) -> str:
    """#96: the engagement's open work, ranked with the reason for each position - readiness, whether the
    question is already answered, the class's weight, how many experiments ran. A share of the top slots is
    reserved for hard, high-impact classes (authorization, tenant isolation, authentication), so the queue
    can't fill a budget with easy checks. Advisory: you still decide; delegate_task records what you dispatched
    against the queue so the two can be compared, and the log shows those decisions (dispatched, paused,
    escalated, reopened). Delegate the top ready question when you have no better reason of your own.
    `proposals` (#104) names related surfaces a verified method hasn't been proven on: each is the plan item
    to add (title, area, refs, identity) and the delegate_task goal to send - the method transfers, the
    result doesn't, and a protected sibling comes back refuted with its conditions, never as a finding."""
    try:
        import workspace
        return _out({"queue": workspace.queue(engagement, limit=limit),
                     "log": workspace.queue_log_rows(engagement)[-20:],
                     "proposals": workspace.method_proposals(engagement)})
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
def list_methods(engagement: str, vclass: str = "") -> str:
    """#102: the methods this engagement has proved - what worked, under which conditions, the access each
    needs, its safe procedure and its negative control - plus the related surfaces each hasn't been proven on.
    Engagement-local: a method never leaves this engagement's database, and nothing here reads another's.
    The packet of a task whose cell matches carries the same methods; `read_record` (worker) opens one."""
    return _call("method.list", engagement=engagement, **({"vclass": vclass} if vclass else {}))


@mcp.tool()
def record_method(engagement: str, title: str, vclass: str, procedure: str, assumes: str = "",
                  access: str = "", groups: list[str] | None = None, expect: str = "", control: str = "",
                  finding: str = "", experiment: str = "", id: str = "",
                  expected_revision: int | None = None) -> str:
    """#102: record or correct a method - what worked and under which conditions. The harness derives one
    from a finding you confirm with a passing oracle; use this to add one it couldn't derive, or to correct
    what it did (with `id` and `expected_revision`). `groups` are the route groups it was proven on, `control`
    the negative control that makes a result mean something, `finding`/`experiment` where it came from."""
    if id:
        return _call("method.update", engagement=engagement, id=id, fields={
            "title": title, "vclass": vclass, "procedure": procedure, "assumes": assumes, "access": access,
            "groups": groups or [], "expect": expect, "control": control}, expected_revision=expected_revision)
    return _call("method.record", engagement=engagement, title=title, vclass=vclass, procedure=procedure,
                 assumes=assumes, access=access, groups=groups or [], expect=expect, control=control,
                 **({"finding": finding} if finding else {}), **({"experiment": experiment} if experiment else {}))


@mcp.tool()
def record_instance(engagement: str, finding_id: str, where: str, evidence: list[str] | None = None,
                    experiment: str = "", note: str = "") -> str:
    """#104: record a confirmed result at a related surface as an instance of the finding that owns the root
    cause, instead of a second finding: one finding carries the extent - each instance with its location, its
    evidence and the experiment that proved it - and the count isn't inflated. Use it after re-proving the
    method at the sibling with its own negative control; the finding stays one root cause, and get_finding
    and the report show every instance."""
    return _call("finding.instance", engagement=engagement, id=finding_id, where=where,
                 evidence=evidence or [], experiment=experiment or None, note=note)


@mcp.tool()
def get_handover(engagement: str) -> str:
    """Where the investigation stands, from the records: objective, findings, material ones, observations to
    triage, coverage, blocked and stale tests, pending decisions and the next useful actions, plus the
    researcher's handover note. Read it when you resume an engagement."""
    try:
        return ops.call("handover.get", {"engagement": engagement})[0]["markdown"]
    except ValueError as e:
        return f"REFUSED: {e}"


import re  # noqa: E402

# Files the planner may write in an engagement folder. Its own workspace sees /work read-only, so PLAN.md, notes and
# the report text go through this tool; evidence is written only by kali commands (hashed in the audit log), and
# findings only through the findings tools.
WRITABLE = re.compile(r"(PLAN\.md|NOTES\.md|notes/[A-Za-z0-9._-]+\.(md|txt)|"
                      r"report/(executive-summary|methodology|conclusion)\.md|report/meta\.txt)")
MAX_WRITE = 1_000_000


@mcp.tool()
def write_file(engagement: str, path: str, content: str, append: bool = False) -> str:
    """Write a working file in the engagement folder (your workspace sees /work read-only, so use this tool).
    path is relative to /work/<engagement>/ and must be one of: PLAN.md, NOTES.md, notes/<name>.md|.txt,
    report/executive-summary.md, report/methodology.md, report/conclusion.md, report/meta.txt.
    append=true adds to the end instead of replacing. Evidence files can't be written here: produce them with
    kali commands, which hash them in the audit log."""
    base = db.engagement_dir(engagement)
    rel = path.strip().removeprefix(f"/work/{engagement}/").lstrip("/")
    if not WRITABLE.fullmatch(rel):
        return ("REFUSED: allowed paths are PLAN.md, NOTES.md, notes/<name>.md|.txt, report/executive-summary.md, "
                "report/methodology.md, report/conclusion.md, report/meta.txt")
    if len(content.encode()) > MAX_WRITE:
        return f"REFUSED: content is larger than {MAX_WRITE} bytes"
    full = os.path.join(base, rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "a" if append else "w") as f:
        f.write(content)
    return f"{'appended to' if append else 'wrote'} /work/{engagement}/{rel} ({os.path.getsize(full)} bytes)"


PLAYBOOKS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "playbooks")


@mcp.tool()
def list_playbooks() -> str:
    """Methodology playbooks (phases, required checks with exact commands, what "done" means). Pick the ones
    matching the engagement scope before writing PLAN.md."""
    out = []
    for f in sorted(os.listdir(PLAYBOOKS)):
        head = open(os.path.join(PLAYBOOKS, f)).read().split("---")[1]
        meta = dict(l.split(":", 1) for l in head.strip().splitlines() if ":" in l)
        out.append(f"{f[:-3]}: {meta.get('title', '').strip()} | {meta.get('standard', '').strip()} | "
                   f"tiers: {meta.get('tiers', '').strip()}")
    return "\n".join(out)


@mcp.tool()
def get_playbook(name: str) -> str:
    """Full text of one playbook (name from list_playbooks). Copy its checklist into PLAN.md and tick items off."""
    name = os.path.basename(name).removesuffix(".md")
    p = os.path.join(PLAYBOOKS, name + ".md")
    return open(p).read() if os.path.exists(p) else f"unknown playbook {name!r}; see list_playbooks"


@mcp.tool()
async def generate_report(engagement: str) -> str:
    """Build a new report revision (R-001, R-002...): a web page (.html), .docx + PDF and findings register
    (.xlsx) in /work/<eng>/report/revisions/<R-id>/, with the latest copied to /work/<eng>/report/. Its inputs
    are frozen and its files hashed. Includes confirmed, fixed and accepted-risk findings with their evidence
    SHA-256. Before calling it, write report/executive-summary.md (and optionally methodology.md,
    conclusion.md); the client name is in report/meta.txt. Returns the revision, its state (generated, or ready
    when no readiness check blocks it) and the readiness checks: fix what blocks it and regenerate. Approving it
    for client delivery is the researcher's decision in the console, not yours. Takes about a minute."""
    import anyio  # heavy imports (python-docx, LibreOffice) only when needed
    try:  # build() calls kali-mcp with its own event loop, so it runs in a worker thread
        r = await anyio.to_thread.run_sync(lambda: ops.call("report.build", {"engagement": engagement,
                                                                             "actor": ACTOR})[0])
        return _out(r)
    except ValueError as e:
        return f"ERROR: {e}"


@mcp.tool()
def report_readiness(engagement: str) -> str:
    """What blocks delivery now (and what a person excepted, with the rationale), plus warnings: coverage without
    outcomes, stale results, reported findings missing fields or a verification method, fixed findings without a
    retest, untriaged candidates, open cleanup obligations. The report revisions and their states."""
    _repin(engagement)
    r = ops.call("report.revisions", {"engagement": engagement})[0]
    return _out({"readiness": r["readiness"], "revisions": [{k: v[k] for k in ("id", "state", "created",
                                                                             "approved_by")} for v in r["revisions"]]})


@mcp.tool()
def record_retest(engagement: str, finding_id: str, retest_build: str, outcome: str, cases: list[dict],
                  reauthorization: str = "", note: str = "") -> str:
    """Record a retest of a confirmed or fixed finding on a new build. outcome: resolved (every case passes: the
    finding becomes fixed in a new revision; its history and original reproduction stay), partial or
    unresolved (it stays, or goes back to, confirmed). cases: [{"name", "before": [evidence], "after":
    [evidence of the retest, required], "result": "pass"|"fail"|"partial", "detail"}]; before defaults to the
    finding's evidence. reauthorization: when the retest needed scope or access re-authorized, who and when."""
    return _call("retest.record", engagement=engagement, finding_id=finding_id, retest_build=retest_build,
                 outcome=outcome, cases=cases, reauthorization=reauthorization, note=note)


@mcp.tool()
def cleanup(engagement: str, action: str, kind: str = "", what: str = "", item: str = "", state: str = "",
            note: str = "") -> str:
    """Cleanup obligations: what has to be undone or decided before close-out. action=add with kind (fixture,
    credential, data, access, retention, other) and what (e.g. "delete the test invoices created in tenant B");
    action=update with item (C-001), state=done and a note on what was done (waiving is the researcher's
    decision); action=list."""
    if action == "add":
        return _call("cleanup.add", engagement=engagement, kind=kind, what=what)
    if action == "update":
        return _call("cleanup.update", engagement=engagement, id=item, state=state, note=note)
    if action == "list":
        return _out(ops.call("report.revisions", {"engagement": engagement})[0]["obligations"])
    return "REFUSED: action is add, update or list"


@mcp.tool()
def prepare_notice(engagement: str, finding_id: str) -> str:
    """Draft a notice of a material finding (confirmed, critical or high) for the researcher to review before it
    is shared with the client: report/notices/N-NNN-<id>.md, tied to the finding's current revision. Nothing is
    sent."""
    return _call("notice.prepare", engagement=engagement, finding_id=finding_id)


@mcp.tool()
def export_findings(engagement: str, draft: bool = False) -> str:
    """Structured exports of the reported findings from the approved report revision: findings.json,
    findings.sarif (SARIF 2.1.0) and issues/<id>.md (issue-ready text) in report/exports/<R-id>/, each naming the
    finding revisions it contains. draft=true exports the latest revision, marked DRAFT. Nothing is sent."""
    return _call("export.build", engagement=engagement, draft=draft)


if __name__ == "__main__":
    mcp.run(transport="streamable-http")


@mcp.tool()
def recall(engagement: str, query: str, kind: str = "", state: str = "", limit: int = 20) -> str:
    """#116: one search across what this engagement knows - observations, findings, plan items, map entries,
    earlier worker task results (with their agent notes) and the call ledger. One line per hit with its state
    and age; ids first when the query is one, then the route group or path, then words. Same engagement only;
    ask for a kind (observation, finding, plan, map, task, ledger) or a state to narrow it."""
    import workspace
    try:
        return workspace.recall(engagement, query, kind, state, limit)
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
def get_briefing(engagement: str, plan_item: str = "", goal: str = "") -> str:
    """#117: the briefing for a cell or target - the same research packet a worker task with this goal and plan
    item would start from (#83), under the same budget and state rules, with no model call. Read it before
    delegating a cell or testing it yourself, and again after a context summary: it says what is known about
    exactly that cell (map entries, findings and observations with their states, earlier tasks with their typed
    results and agent notes), not the whole engagement - get_handover carries the engagement-wide picture."""
    import workspace
    try:
        pk = workspace.packet(engagement, goal or "", plan_item or None,
                              chars=int(os.environ.get("WORKER_PACKET_CHARS", "4000") or 4000))
        return (pk["text"] + "\n\n(Every line keeps its state - verified, candidate, dismissed, stale - and "
                "summaries and agent notes are their writers' words, not verified facts. The worker gets this "
                "same packet automatically; recall(...) searches across records, read-style tools open them.)")
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
def record_conclusion(engagement: str, claim: str, state: str, conditions: str = "", evidence: str = "",
                      plan_item: str = "", experiment: str = "") -> str:
    """#90: record a conclusion with its exact conditions - supported, refuted or unresolved. The conditions are
    never widened: "rejected for identity A on build B" stays that claim. Name the experiment it came from when
    you have one (X-...); the evidence file it rests on is pinned by hash. Your conclusions are your words: a
    rule-drawn or checked conclusion says so in its origin."""
    try:
        import workspace
        c = workspace.conclusion_record(engagement, actor="agent:planner", claim=claim, state=state,
                                        conditions=conditions, experiment=experiment or None,
                                        plan_item=plan_item or None, origin="agent:planner",
                                        evidence=[evidence] if evidence else None)
        return json.dumps(c)
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
def link_records(engagement: str, src: str, dst: str, kind: str, note: str = "") -> str:
    """#89: link two records - supports, contradicts, requires or next - between plan items (P-...),
    experiments (X-...), conclusions (C-...), observations (O-...) and findings (F-...). Both ends must exist.
    A link is data for the records to read back, never an instruction for the reader."""
    try:
        import workspace
        return json.dumps(workspace.link_record(engagement, actor="agent:planner", src=src, dst=dst,
                                                kind=kind, note=note or None))
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
def report_build(engagement: str, build: str) -> str:
    """#91: report the target's current build (a source digest, a deployed build id) when you can establish
    it - recon output, a version endpoint, a deployment note. A build change marks the conclusions recorded
    against another build stale for re-testing, and plan items tested on it; the records keep everything, the
    packet shows the stale ones as stale. The engagement's current build is remembered."""
    try:
        import workspace
        r = workspace.reassess(engagement, "agent:planner", build=str(build or "").strip())
        return json.dumps(r)
    except ValueError as e:
        return f"REFUSED: {e}"
