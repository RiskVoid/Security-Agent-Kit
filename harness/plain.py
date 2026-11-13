"""Plain-agent baseline MCP server (streamable HTTP on :8095/mcp): the kit with everything but the sandbox removed.

A plain coding agent with a shell beats many purpose-built security frameworks, so every harness result needs a
model-matched plain baseline next to it (epic #52, issue #28). The riskvoid-plain agent profile gets only this
server: the sandboxed Kali `run` tool (scope, tiers, approvals and the audit log still apply: they are enforced
by kali-mcp, not by the prompt) and `record_finding`, which stores a confirmed finding in the engagement's
findings database so the benchmark can score it. No worker, no playbooks, no test plan, no candidate and triage
workflow, no verification rule, no web search, no vulnerability intel.

Started only for baseline runs: docker compose --profile baseline up -d plain-mcp (./rvkit bench does it).
"""
import os
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.fastmcp import FastMCP
import findings_db as db

KALI_MCP = os.environ.get("KALI_MCP_URL", "http://kali-mcp:8090/mcp")
mcp = FastMCP("plain", host="0.0.0.0", port=8095, stateless_http=True)


async def _kali(tool: str, args: dict, timeout_s: int) -> str:
    async with streamablehttp_client(KALI_MCP, timeout=30, sse_read_timeout=timeout_s + 120) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool(tool, args)
            return "\n".join(c.text for c in res.content if getattr(c, "text", None))


@mcp.tool()
async def run(command: str, engagement: str, timeout_s: int = 600, approval_id: str = "") -> str:
    """Run a shell command in a Kali Linux sandbox for the engagement (cwd /work/<engagement>; client code is
    read-only under /src). The usual Kali tools are installed (nmap, ffuf, sqlmap, nuclei, semgrep, curl, ...).
    Network access is limited to the engagement's targets. Some commands need approval: they return an approval
    id; wait, then call run again with the identical command and approval_id. The full output is saved as
    evidence; the result ends with its path."""
    t = min(int(timeout_s or 600), 3600)
    return await _kali("run", {"command": command, "engagement": engagement, "timeout_s": t,
                               "approval_id": approval_id or ""}, t)


@mcp.tool()
def record_finding(engagement: str, title: str, severity: str, asset: str, description: str,
                   evidence: list[str] | None = None, cwe: str = "", reproduction: str = "") -> str:
    """Record a vulnerability you found. severity: critical|high|medium|low|info. asset: the URL, endpoint or
    file:line. evidence: paths of output files that show it. One finding per root cause."""
    try:
        f = db.record(engagement, actor="agent:plain", title=title, severity=str(severity).lower(), asset=asset,
                      description=description, evidence=evidence or [], cwe=cwe, reproduction=reproduction,
                      status="confirmed", source="plain")
    except ValueError as e:
        return f"REFUSED: {e}"
    return f"recorded {f['id']}"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
