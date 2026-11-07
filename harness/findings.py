"""Findings MCP server (streamable HTTP on :8092/mcp), used by the planner.

The planner records, confirms, rejects and lists findings. The worker can only add candidates
(it writes through findings_db directly with status=candidate).
"""
import json, os
from mcp.server.fastmcp import FastMCP
import findings_db as db

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
    return _out(db.record(engagement, title=title, severity=severity, asset=asset, description=description,
                          impact=impact, reproduction=reproduction, remediation=remediation, evidence=evidence or [],
                          cvss_vector=cvss_vector, cvss_score=cvss_score, cwe=cwe, status=status,
                          source="planner", notes=notes))


@mcp.tool()
def update_finding(engagement: str, finding_id: str, status: str | None = None, severity: str | None = None,
                   title: str | None = None, description: str | None = None, impact: str | None = None,
                   reproduction: str | None = None, remediation: str | None = None,
                   evidence: list[str] | None = None, cvss_vector: str | None = None,
                   cvss_score: float | None = None, cwe: str | None = None, notes: str | None = None) -> str:
    """Update a finding. Use status=confirmed after verifying a candidate, status=false-positive (with the reason
    in notes) when it doesn't hold, fixed or accepted-risk after client feedback. Only given fields change."""
    return _out(db.update(engagement, finding_id, status=status, severity=severity, title=title,
                          description=description, impact=impact, reproduction=reproduction,
                          remediation=remediation, evidence=evidence, cvss_vector=cvss_vector,
                          cvss_score=cvss_score, cwe=cwe, notes=notes))


@mcp.tool()
def list_findings(engagement: str, status: str | None = None, severity: str | None = None) -> str:
    """List findings, most severe first. Filter by status (candidate|confirmed|false-positive|fixed|accepted-risk)
    and/or severity. Returns id, title, severity, status, asset for each."""
    rows = db.list_(engagement, status, severity)
    return _out([{k: r[k] for k in ("id", "title", "severity", "status", "asset", "source")} for r in rows]
                or "no findings")


@mcp.tool()
def get_finding(engagement: str, finding_id: str) -> str:
    """Get one finding with all fields."""
    return _out(db.get(engagement, finding_id))


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
    """Build the RiskVoid-branded report (.docx + PDF) and findings register (.xlsx) in /work/<eng>/report/
    (workspace: /projects/engagements/<eng>/report/). Includes confirmed, fixed and accepted-risk findings, each
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
