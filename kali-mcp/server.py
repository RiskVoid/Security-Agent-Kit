"""Kali toolbox exposed to the agent as an MCP server (streamable HTTP on :8090/mcp).

Commands run sandboxed per engagement (see core.py): own folder only, unprivileged user, network limited to the
engagement scope by nftables, tiers and rate limits from RULES.md, intrusive commands need host approval, and
everything is audit-logged. Only run against systems you are authorised to test.
"""
import json, sys
from mcp.server.fastmcp import FastMCP
import core

mcp = FastMCP("kali", host="0.0.0.0", port=8090)


@mcp.tool()
def list_engagements() -> str:
    """List engagements with their authorised scope and rules of engagement. Call this first."""
    out = []
    for e in core.engagements():
        i = core.info(e)
        r = i["rules"]
        out.append(f"## {e}{'  (HALTED)' if i['halted'] else ''}\n"
                   f"scope: nets={i['scope']['nets']} domains={i['scope']['domains']} code={i['scope']['paths']}\n"
                   f"rules: tiers={r['tiers']} max_rate={r['max_rate']}/s network={r['network']}"
                   + (f" window_utc={r['window']}" if r["window"] else ""))
    return "\n".join(out) or "no engagements; the user creates them on the host with ./rvkit engagement"


@mcp.tool()
def engagement_info(engagement: str) -> str:
    """Scope, rules, halt state and allowed infrastructure domains of one engagement, as JSON."""
    return json.dumps(core.info(engagement), indent=1)


@mcp.tool()
def evidence_provenance(engagement: str, paths: list[str]) -> str:
    """Verify evidence files: current SHA-256, and the audited command (with time and tier) that produced exactly
    that content. Status is verified, MODIFIED after it was produced, not produced by an audited kali command
    (e.g. worker step files), or missing. Paths may be absolute (/work/<eng>/...) or relative to the engagement."""
    try:
        return json.dumps(core.provenance(engagement, paths), indent=1)
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
def engagement_activity(engagement: str) -> str:
    """Summary of the engagement's authoritative audit log: time range, commands run/refused, counts per tier and
    per tool, evidence files recorded, approvals and halts. Use it for the methodology section of the report."""
    try:
        return json.dumps(core.activity(engagement), indent=1)
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
def run(command: str, engagement: str, timeout_s: int = 600, approval_id: str = "") -> str:
    """Run a shell command in the Kali sandbox for an engagement.

    cwd is /work/<engagement> (write output files here). In-scope client code is read-only under /src.
    Network access is limited to the engagement scope (plus package/vulnerability-database sites when the
    engagement is online); everything else is blocked. Tools:
      recon:        nmap, naabu, dnsx, subfinder, amass, katana, httpx-toolkit, whatweb, gowitness (screenshots)
      web:          nuclei (templates in ~/nuclei-templates), nikto, ffuf, feroxbuster, gobuster, arjun, crlfuzz,
                    wafw00f, wpscan, dalfox, commix, zaproxy, sqlmap, testssl, sslscan; wordlists in /usr/share/seclists
      API:          schemathesis (`schemathesis run <openapi-or-graphql-url> --url <base>`: spec-driven fuzzing),
                    jwt_tool (decode/crack/forge offline; -t <url> sends to the target: active, with -X/-I/-S/-M intrusive), graphw00f (-d -f -t <url>),
                    graphql-cop (-t <url> -o json), clairvoyance (schema without introspection)
      AI/LLM/MCP:   rv-llm (`rv-llm help`: `probe` adversarial prompt library with canaries against a chat API,
                    `mcp <url>` audit an MCP server, `mcp-call` call one MCP tool, `payloads` indirect-injection
                    payloads), garak (LLM vulnerability scanner; `--target_type rest -G <config.json>`)
      code/secrets: semgrep (registry configs like p/python when online; offline rules in /opt/semgrep-rules),
                    bandit, gitleaks, trufflehog, rv-joern (Joern data-flow: `rv-joern taint /src/<repo>` writes
                    input-to-sink flows with full paths to joern-flows.json; `rv-joern scan` for C/C++/Java queries)
      supply chain: osv-scanner, pip-audit, trivy (fs/config/secret), syft (SBOM), grype (scan an SBOM or dir)
    Write output files (JSON where the tool supports it) to the current directory.
    Tiers: passive (code/config analysis, DNS, research), active (scans, crawling, fingerprinting),
    intrusive (exploitation, brute force, DoS-capable tools). Commands above the engagement's allowed tiers are
    refused. Intrusive commands return an approval id: ask the user to approve on the host, then call run again
    with the identical command and approval_id. Rate-limitable tools get the engagement's max rate added.
    """
    try:
        return core.run(command, engagement, timeout_s, approval_id or None)
    except ValueError as e:
        return f"REFUSED: {e}"


if __name__ == "__main__":
    try:
        core.apply_network()  # restore firewall + DNS after a container restart
    except Exception as e:
        print("WARNING: could not apply network policy:", e, file=sys.stderr)
    mcp.run(transport="streamable-http")
