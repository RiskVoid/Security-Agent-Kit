"""Findings MCP server (streamable HTTP on :8092/mcp), used by the planner.

The planner records, confirms, rejects and lists findings. The worker can only add candidates
(it writes through findings_db directly with status=candidate).
"""
import json, os
from mcp.server.fastmcp import FastMCP
import findings_db as db
import ops

ACTOR = "agent:planner"  # changes made through this server are attributed to the planner agent

mcp = FastMCP("findings", host="0.0.0.0", port=8092)


def _out(x) -> str:
    return json.dumps(x, indent=1)


@mcp.tool()
def record_finding(engagement: str, title: str, severity: str, asset: str, description: str,
                   impact: str = "", reproduction: str = "", remediation: str = "", evidence: list[str] | None = None,
                   cvss_vector: str = "", cvss_score: float | None = None, cwe: str = "",
                   status: str = "candidate", notes: str = "") -> str:
    """Record a finding for an engagement. severity: critical|high|medium|low|info.
    status: candidate (default, not yet verified) or confirmed (you have reproduced or verified it).
    evidence: file paths under /work/<engagement>/evidence/. Returns the stored finding with its id (F-001...)."""
    row, _ = ops.call("finding.record", {"engagement": engagement, "actor": ACTOR, "fields": dict(
        title=title, severity=severity, asset=asset, description=description, impact=impact,
        reproduction=reproduction, remediation=remediation, evidence=evidence or [], cvss_vector=cvss_vector,
        cvss_score=cvss_score, cwe=cwe, status=status, source="planner", notes=notes)})
    return _out(row)


@mcp.tool()
def update_finding(engagement: str, finding_id: str, status: str | None = None, severity: str | None = None,
                   title: str | None = None, description: str | None = None, impact: str | None = None,
                   reproduction: str | None = None, remediation: str | None = None,
                   evidence: list[str] | None = None, cvss_vector: str | None = None,
                   cvss_score: float | None = None, cwe: str | None = None, notes: str | None = None,
                   duplicate_of: str | None = None, reason: str | None = None, method: str | None = None,
                   priority: str | None = None, prerequisites: str | None = None, root_cause: str | None = None) -> str:
    """Update a finding. Use status=confirmed after verifying a candidate, with method = how you verified it
    (runtime-reproduction, replay, authorization-matrix, source-review, tool-output, retest); status=false-positive
    when it doesn't hold; status=duplicate with duplicate_of=<id of the finding to keep>; fixed or accepted-risk
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
    try:
        row, _ = ops.call("finding.update", {"engagement": engagement, "actor": ACTOR, "id": finding_id,
                                             "fields": {k: v for k, v in fields.items() if v is not None},
                                             "reason": reason, "method": method})
    except ValueError as e:
        return f"REFUSED: {e}"
    return _out(row)


@mcp.tool()
def list_findings(engagement: str, status: str | None = None, severity: str | None = None) -> str:
    """List findings, most severe first. Filter by status (candidate|confirmed|false-positive|duplicate|fixed|accepted-risk)
    and/or severity. Returns id, title, severity, status, asset for each."""
    rows = db.list_(engagement, status, severity)
    return _out([{k: r[k] for k in ("id", "title", "severity", "status", "asset", "source")} for r in rows]
                or "no findings")


@mcp.tool()
def get_finding(engagement: str, finding_id: str, history: bool = False) -> str:
    """Get one finding with all fields (verification, verified_by and method, priority, instances). history=true
    adds every earlier revision and the decisions made about it, with reasons."""
    f = db.get(engagement, finding_id)
    if history:
        f["history"] = db.history(engagement, finding_id)
    return _out(f)


# ---------------------------------------------------------------- investigation workspace (RW-015 to RW-018)
def _call(name, **req):
    try:
        return _out(ops.call(name, {"engagement": req.pop("engagement"), "actor": ACTOR, **req})[0])
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
def import_observations(engagement: str, path: str, tool: str = "") -> str:
    """Turn a tool's output (a file of the engagement: semgrep.json, evidence/...) into observations: Semgrep,
    osv-scanner, pip-audit, bandit or gitleaks JSON, an authorization-matrix run (evidence/authz), a Laravel map (evidence/appmap) or an HTTP exchange
    (evidence/http). tool: force a parser (detected otherwise). Re-importing doesn't duplicate; parser errors and
    the tool's limitations (skipped files, blocked cells) are returned and kept."""
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


@mcp.tool()
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


@mcp.tool()
def get_coverage(engagement: str, state: str = "") -> str:
    """Planned tests and their outcomes, counts per state and per standard, stale items (the build or policy
    changed since they ran), blocked items with the reason."""
    r = ops.call("plan.list", {"engagement": engagement, "state": state or None})[0]
    r["items"] = [{k: i[k] for k in ("id", "title", "area", "refs", "state", "rationale", "finding_id", "stale")}
                  for i in r["items"]]
    return _out(r)


@mcp.tool()
def set_objective(engagement: str, text: str) -> str:
    """The engagement's current objective: what it must answer (shown in the handover and the console)."""
    return _call("workspace.objective", engagement=engagement, text=text)


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
    """Build the branded report (brand set by REPORT_BRAND) as a web page (.html), .docx + PDF, and findings register (.xlsx) in /work/<eng>/report/
    (the same path in your workspace, read-only). Includes confirmed, fixed and accepted-risk findings, each
    with its evidence SHA-256 and the audited command that produced it. Before calling it, write
    report/executive-summary.md (and optionally methodology.md, conclusion.md); the client name is in
    report/meta.txt. Returns paths, DRAFT/final status and the issues that keep it a draft (fix them and
    regenerate). Run it in a background terminal if your tool call times out: it takes about a minute."""
    import anyio, report  # heavy imports (python-docx, LibreOffice) only when needed
    try:  # build() calls kali-mcp with its own event loop, so it runs in a worker thread
        return _out(await anyio.to_thread.run_sync(report.build, engagement))
    except ValueError as e:
        return f"ERROR: {e}"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
