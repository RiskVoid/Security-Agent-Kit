"""Findings MCP server (streamable HTTP on :8092/mcp), used by the planner.

The planner records, confirms, rejects and lists findings. The worker can only add candidates
(it writes through findings_db directly with status=candidate).
"""
import functools, inspect, json, os
from mcp.server.fastmcp import FastMCP
import findings_db as db
import ops
import quotecheck
import repeatguard
import validator
import verification

ACTOR = "agent:planner"  # changes made through this server are attributed to the planner agent

# Stateless: no per-client session, so a conversation that was open when this server restarted keeps working
# (with sessions, every later tool call failed with "Session terminated" until OpenHands itself was restarted).
mcp = FastMCP("findings", host="0.0.0.0", port=8092, stateless_http=True)


def tool():
    """mcp.tool() with the repeat guard (repeatguard.py): the tool runs as it is, and a call that comes back with
    the same arguments and is turned down for the same reason gets a reply that says so."""
    def register(fn):
        sig = inspect.signature(fn)

        @functools.wraps(fn)
        def run(*a, **k):
            reply = fn(*a, **k)
            try:
                args = dict(sig.bind(*a, **k).arguments)
            except TypeError:
                return reply
            return repeatguard.observe(args.get("engagement"), fn.__name__, args, reply, params=list(sig.parameters),
                                       problem=_not_done(reply))
        return mcp.tool()(run)
    return register


NOT_CONFIRMED = "NOT CONFIRMED: "


def _not_done(reply):
    """The reason in a reply that saved something without confirming the finding (its note), else None. The row
    around it changes with every save, so the guard compares the reason, not the reply."""
    if not isinstance(reply, str) or not reply.startswith('{\n "note": "' + NOT_CONFIRMED):
        return None
    try:
        note = json.loads(reply)["note"]
    except (ValueError, KeyError, TypeError):
        return None
    return note.split(". ", 1)[-1]   # without "saved <fields>": the same reason whatever was saved with it


def _out(x) -> str:
    return json.dumps(x, indent=1)


def _validated(engagement, row):
    """A finding the planner just confirmed goes to the disprove-only validator (validator.py). The verdict is added
    to what the tool returns; disproved has already sent the finding back to candidate."""
    if not isinstance(row, dict) or row.get("status") != "confirmed":
        return row
    try:
        v = validator.validate(engagement, row["id"])
    except Exception as e:  # noqa: BLE001  the confirmation stands; the validation is just missing
        v = {"verdict": "not_run", "reason": f"the validator failed: {type(e).__name__}: {e}"}
    if v.get("verdict") == "disproved":
        row = db.get(engagement, row["id"])
        v["note"] = ("the finding is back to candidate. Look at the reason and the evidence: test again, then confirm "
                     "it with update_finding(status=\"confirmed\", method=..., evidence=[the new evidence]), or mark "
                     "it false-positive. Don't confirm it again with the same evidence.")
    return {**row, "validation": v}


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


@tool()
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
    need the evidence file that shows it. Text in backticks or code blocks (other than commands) is a quote:
    confirming is refused when a quote isn't in the cited evidence, or a /src/<file>:<line> doesn't exist.
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
    return _out(_validated(engagement, row))


@tool()
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
    it; quotes in backticks must be in the cited evidence, as for record_finding) and reproduction (kept from
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
    return _out(_validated(engagement, row) if status == "confirmed" else row)


@tool()
def validate_finding(engagement: str, finding_id: str) -> str:
    """Send a confirmed finding to the disprove-only validator again (it runs on its own when you confirm one): a
    separate model with only the finding, its cited evidence and its oracle records tries to disprove it. Returns
    stands, disproved (the finding goes back to candidate, with the reason), unclear or not_run, and the reason."""
    try:
        return _out(validator.validate(engagement, finding_id))
    except ValueError as e:
        return f"REFUSED: {e}"


@tool()
def list_findings(engagement: str, status: str | None = None, severity: str | None = None) -> str:
    """List findings, most severe first. Filter by status (candidate|confirmed|false-positive|duplicate|fixed|accepted-risk)
    and/or severity. Returns id, title, severity, status, asset for each."""
    rows = db.list_(engagement, status, severity)
    return _out([{k: r[k] for k in ("id", "title", "severity", "status", "asset", "source")} for r in rows]
                or "no findings")


@tool()
def get_finding(engagement: str, finding_id: str, history: bool = False) -> str:
    """Get one finding with all fields (verification, verified_by and method, priority, instances). history=true
    adds every earlier revision and the decisions made about it, with reasons."""
    f = db.get(engagement, finding_id)
    v = validator.history(engagement, finding_id)
    if v:
        f["validation"] = v[0]
    if history:
        f["history"] = db.history(engagement, finding_id)
        f["validations"] = v
    return _out(f)


# ---------------------------------------------------------------- investigation workspace (RW-015 to RW-018)
def _call(name, **req):
    try:
        return _out(ops.call(name, {"engagement": req.pop("engagement"), "actor": ACTOR, **req})[0])
    except ValueError as e:
        return f"REFUSED: {e}"


@tool()
def import_observations(engagement: str, path: str, tool: str = "") -> str:
    """Turn a tool's output (a file of the engagement: semgrep.json, evidence/...) into observations: Semgrep,
    osv-scanner, pip-audit, bandit or gitleaks JSON, an authorization-matrix run (evidence/authz), a Laravel map (evidence/appmap) or an HTTP exchange
    (evidence/http). tool: force a parser (detected otherwise). Re-importing doesn't duplicate; parser errors and
    the tool's limitations (skipped files, blocked cells) are returned and kept."""
    return _call("observation.import", engagement=engagement, path=path, tool=tool or None)


@tool()
def add_observation(engagement: str, title: str, location: str, detail: str = "", severity: str = "info",
                    evidence: list[str] | None = None) -> str:
    """Record something you noticed by hand (not from a tool output) as an observation to triage."""
    return _call("observation.add", engagement=engagement, title=title, location=location, detail=detail,
                 severity=severity, evidence=evidence or [])


@tool()
def list_observations(engagement: str, status: str = "new", tool: str = "") -> str:
    """Observations (status new, linked, duplicate, dismissed; empty for all), the imports with their parser
    errors, and grouping suggestions (observations that may share a root cause)."""
    r = ops.call("observation.list", {"engagement": engagement, "status": status or None, "tool": tool or None})[0]
    r["observations"] = [{k: o[k] for k in ("id", "tool", "rule_id", "title", "severity", "location", "status",
                                            "finding_id", "seen", "group_key")} for o in r["observations"]]
    return _out(r)


@tool()
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


@tool()
def plan_tests(engagement: str, items: list[dict] | None = None, playbook: str = "") -> str:
    """Add planned tests (coverage items). playbook: add one item per checklist line of that playbook (once).
    items: [{"title", "area", "refs": ["ASVS V8.2.2", "WSTG-ATHZ-04", "API1:2023"], "hypothesis",
    "prerequisites": [...], "operation", "identity"}]. Top 10 lists are risk categories: reference ASVS/WSTG
    requirements for coverage."""
    if playbook:
        return _call("plan.from_playbook", engagement=engagement, playbook=playbook)
    return _call("plan.add", engagement=engagement, items=items or [])


@tool()
def update_coverage(engagement: str, item: str, state: str, rationale: str = "", evidence: list[str] | None = None,
                    finding_id: str = "", build: str = "", policy_revision: str = "") -> str:
    """Record a planned test's outcome. state: tested (ran, no issue: evidence required), failed (an issue: the
    finding_id it produced), blocked (couldn't run: rationale, and what would unblock it), excluded (out of scope
    or agreed not to test: rationale), not-applicable (rationale), planned. build: the source digest or deployed
    build it ran on; policy_revision: the engagement's policy revision (engagement_info)."""
    fields = {"state": state, "rationale": rationale or None, "evidence": evidence, "finding_id": finding_id or None,
              "build": build or None, "policy_revision": policy_revision or None}
    return _call("plan.update", engagement=engagement, id=item, fields={k: v for k, v in fields.items()
                                                                         if v is not None})


@tool()
def get_coverage(engagement: str, state: str = "", matrix: bool = False) -> str:
    """Planned tests and their outcomes, counts per state and per standard, stale items (the build or policy
    changed since they ran), blocked items with the reason. matrix=true: the coverage matrix instead: each recon
    map entry x each vulnerability class that applies to it, with the plan items that cover it; "gaps" are cells
    no plan item covers (plan them, delegate them, or record why they're skipped)."""
    if matrix:
        try:
            m = ops.call("coverage.matrix", {"engagement": engagement})[0]
        except ValueError as e:
            return f"REFUSED: {e}"
        open_ = [c for c in m["cells"] if c["state"] in ("gap", "planned", "blocked")]
        return _out({"entries": m["entries"], "counts": m["counts"], "complete": m["complete"],
                     "gaps": [{k: c[k] for k in ("entry", "method", "path", "class")} for c in m["gaps"][:150]],
                     "open": [{k: c[k] for k in ("entry", "method", "path", "class", "state", "items")}
                              for c in open_ if c["state"] != "gap"][:150],
                     "more": max(0, len(m["gaps"]) - 150), "plan_items_without_map_refs": m["unmapped_items"][:50]})
    r = ops.call("plan.list", {"engagement": engagement, "state": state or None})[0]
    r["items"] = [{k: i[k] for k in ("id", "title", "area", "refs", "state", "rationale", "finding_id", "stale")}
                  for i in r["items"]]
    return _out(r)


@tool()
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


@tool()
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


@tool()
def set_objective(engagement: str, text: str) -> str:
    """The engagement's current objective: what it must answer (shown in the handover and the console)."""
    return _call("workspace.objective", engagement=engagement, text=text)


@tool()
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


@tool()
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


@tool()
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


@tool()
def get_playbook(name: str) -> str:
    """Full text of one playbook (name from list_playbooks). Copy its checklist into PLAN.md and tick items off."""
    name = os.path.basename(name).removesuffix(".md")
    p = os.path.join(PLAYBOOKS, name + ".md")
    return open(p).read() if os.path.exists(p) else f"unknown playbook {name!r}; see list_playbooks"


@tool()
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


@tool()
def report_readiness(engagement: str) -> str:
    """What blocks delivery now (and what a person excepted, with the rationale), plus warnings: coverage without
    outcomes, stale results, reported findings missing fields or a verification method, fixed findings without a
    retest, untriaged candidates, open cleanup obligations. The report revisions and their states."""
    r = ops.call("report.revisions", {"engagement": engagement})[0]
    return _out({"readiness": r["readiness"], "revisions": [{k: v[k] for k in ("id", "state", "created",
                                                                             "approved_by")} for v in r["revisions"]]})


@tool()
def record_retest(engagement: str, finding_id: str, retest_build: str, outcome: str, cases: list[dict],
                  reauthorization: str = "", note: str = "") -> str:
    """Record a retest of a confirmed or fixed finding on a new build. outcome: resolved (every case passes: the
    finding becomes fixed in a new revision; its history and original reproduction stay), partial or
    unresolved (it stays, or goes back to, confirmed). cases: [{"name", "before": [evidence], "after":
    [evidence of the retest, required], "result": "pass"|"fail"|"partial", "detail"}]; before defaults to the
    finding's evidence. reauthorization: when the retest needed scope or access re-authorized, who and when."""
    return _call("retest.record", engagement=engagement, finding_id=finding_id, retest_build=retest_build,
                 outcome=outcome, cases=cases, reauthorization=reauthorization, note=note)


@tool()
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


@tool()
def prepare_notice(engagement: str, finding_id: str) -> str:
    """Draft a notice of a material finding (confirmed, critical or high) for the researcher to review before it
    is shared with the client: report/notices/N-NNN-<id>.md, tied to the finding's current revision. Nothing is
    sent."""
    return _call("notice.prepare", engagement=engagement, finding_id=finding_id)


@tool()
def export_findings(engagement: str, draft: bool = False) -> str:
    """Structured exports of the reported findings from the approved report revision: findings.json,
    findings.sarif (SARIF 2.1.0) and issues/<id>.md (issue-ready text) in report/exports/<R-id>/, each naming the
    finding revisions it contains. draft=true exports the latest revision, marked DRAFT. Nothing is sent."""
    return _call("export.build", engagement=engagement, draft=draft)


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
