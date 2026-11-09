"""Kali toolbox exposed to the agent as an MCP server (streamable HTTP on :8090/mcp).

Commands run sandboxed per engagement (see core.py): own folder only, unprivileged user, network limited to the
engagement scope by nftables, tiers and rate limits from RULES.md, intrusive commands need host approval, and
everything is audit-logged. Only run against systems you are authorised to test.
"""
import functools, json, sys
import anyio
from mcp.server.fastmcp import FastMCP
import core
import actions

mcp = FastMCP("kali", host="0.0.0.0", port=core.MCP_PORT)


async def _thread(fn, *args, **kw):
    """Run a blocking call in a worker thread. FastMCP runs plain functions on its event loop, so a long command
    would hold every other call (another task's command, cancel_task, approval_status) until it ended."""
    return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kw), limiter=_LIMIT)

_LIMIT = anyio.CapacityLimiter(64)


@mcp.tool()
def list_engagements() -> str:
    """List engagements with their authorised scope and rules of engagement. Call this first."""
    out = []
    for e in core.engagements():
        i = core.info(e)
        r = i["rules"]
        p = i["policy"]
        late = core.rvpolicy.time_refusal(r)
        out.append(f"## {e}{'  (HALTED)' if i['halted'] else ''}  policy r{i['policy_version']}\n"
                   f"scope: {'; '.join(core.rvpolicy.describe(p)) or 'nothing'}\n"
                   + (f"excluded: {json.dumps(p['exclude'])}\n" if any(p['exclude'].values()) else "")
                   + f"rules: tiers={r['tiers']} max_rate={r['max_rate']}/s network={r['network']} "
                   f"execution={r['execution']}" + (" strict_tiers=on" if r.get("strict") else "")
                   + (f" window={r['window']} timezone={r['timezone']}" if r["window"] else "")
                   + (f" dates={r['dates']}" if r["dates"] else "") + (f" days={r['days']}" if r["days"] else "")
                   + (f"\nNOT NOW: {late}" if late else "")
                   + "".join(f"\nstop condition (stop and tell the user when it happens): {s}" for s in r["stop_conditions"])
                   + "".join(f"\nlimit: {x}" for x in p["limits"]))
    return "\n".join(out) or "no engagements; the user creates them on the host with ./rvkit engagement"


@mcp.tool()
def engagement_info(engagement: str) -> str:
    """Scope, rules, halt state and allowed infrastructure domains of one engagement, as JSON."""
    return json.dumps(core.info(engagement), indent=1)


@mcp.tool()
def all_scopes() -> str:
    """Union of every registered engagement's network scope, as JSON {"nets": [...], "domains": [...]}. Used by the
    kit's web research tools to refuse fetching engagement targets (those are tested only through run)."""
    nets, domains = set(), set()
    for e in core.engagements():
        sc = core.info(e)["scope"]
        nets.update(sc["nets"]); domains.update(sc["domains"])
    return json.dumps({"nets": sorted(nets), "domains": sorted(domains)})


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
async def http_request(engagement: str, method: str, url: str, headers: dict | None = None, body: str = "",
                 approval_id: str = "", max_tier: str = "", task: str = "", body_base64: bool = False,
                 identity: str = "") -> str:
    """Send one HTTP request to an in-scope URL and get the response (status, headers, body). Prefer this over
    curl in run for single requests: it is the only way to reach hosts whose scope is limited to URL paths, it
    follows redirects only within scope, and the request and response are saved as verified evidence.
    GET, HEAD and OPTIONS are tier active. POST, PUT, PATCH and DELETE can change state: they are intrusive and
    return an approval id first; after the user approves, call again with the identical method, URL, headers and
    body plus approval_id. max_tier: the tier your task is limited to, if any. body_base64: body is base64.
    Credentials stored on the host (list_credentials): write {{cred:NAME}} in the URL, a header or the body; the
    value is filled in when the request is sent and replaced by the reference in the output and evidence.
    identity: send it as one of the engagement's test identities (list_identities); kali-mcp adds the session
    (you never see it). Approvals name the identity, so the same request as another identity needs its own."""
    try:
        return await _thread(actions.http_request, engagement, method, url, headers or {}, body, approval_id or None,
                             max_tier or None, task or None, body_base64=body_base64, identity=identity or None)
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
async def analyze_source(engagement: str, tool: str, path: str, rulesets: list[str] | None = None, task: str = "") -> str:
    """Run a source-analysis tool on in-scope code with no network access at all (it can't reach targets or the
    internet). tool: semgrep (offline rules; rulesets = folders like php, python, javascript; default: detected
    from the code), gitleaks (secrets, redacted), trufflehog (secrets, unverified), bandit (Python). path: a
    /src path from the scope or a path under /work/<engagement>. The JSON report is saved as verified evidence."""
    try:
        return await _thread(actions.analyze_source, engagement, tool, path, rulesets or None, task or None)
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
async def run(command: str, engagement: str, timeout_s: int = 600, approval_id: str = "", max_tier: str = "",
        task: str = "") -> str:
    """Run a shell command in the Kali sandbox for an engagement.

    cwd is /work/<engagement> (write output files here). In-scope client code is read-only under /src.
    The full output is saved as verified evidence in evidence/runs/ (the result ends with its path): cite that
    path rather than copying the output into a file yourself.
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
    Content discovery: give ffuf `-ac` (single-page apps answer 200 to every path) and start with
    seclists common.txt; set timeout_s above wordlist size / rate. gowitness: `gowitness scan single -u <url>
    --write-jsonl` (screenshots land in screenshots/).
    Tiers: passive (code/config analysis, DNS, research), active (scans, crawling, fingerprinting),
    intrusive (exploitation, brute force, DoS-capable tools). Commands above the engagement's allowed tiers are
    refused. Intrusive commands return an approval id: ask the user to approve on the host, then call run again
    with the identical command and approval_id. Rate-limitable tools get the engagement's max rate added (shared
    between parallel commands). Approvals are bound to the command, the programs and input files it uses and the
    current scope. max_tier: the tier your task is limited to, if any. Hosts limited to URL paths in the scope
    are reachable only through http_request; for code analysis without network use analyze_source.
    Credentials stored on the host (list_credentials) are in the environment as $RV_CRED_<NAME>; their values
    are replaced by {{cred:NAME}} in the output.
    """
    try:
        return await _thread(core.run, command, engagement, timeout_s, approval_id or None, max_tier or None,
                             task or None)
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
def approval_status(engagement: str, approval_id: str) -> str:
    """Where an approval stands: pending, approved, denied, used, or stale (the scope changed). JSON."""
    try:
        return json.dumps(core.approval_status(engagement, approval_id))
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
def list_credentials(engagement: str) -> str:
    """Credentials stored for an engagement on the host (names only; values are never shown). Use one in a run
    command as $RV_CRED_<NAME>, or in an http_request URL, header or body as {{cred:NAME}}. Values are replaced by
    the reference in output and evidence. Add or change credentials on the host: ./rvkit cred <engagement> set <NAME>."""
    try:
        return json.dumps(core.cred_list(engagement)) if core.cred_list(engagement) else \
            f"no credentials stored for {engagement}"
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
def cancel_task(engagement: str, task: str) -> str:
    """Kill the commands a worker task is running now (worker-mcp calls this when a task is cancelled)."""
    try:
        return f"killed {core.cancel_task(engagement, task)} command(s) of task {task}"
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
def list_identities(engagement: str) -> str:
    """The engagement's test identities (RW-008): name, role, tenant, hosts, allowed tiers and effects, the fixture
    records each owns (with marker text only that record contains) and session status. Secrets are never shown.
    Identities are defined by the researcher on the host (./rvkit identity); ask for one if a test needs it."""
    import identities
    try:
        rows = identities.identity_list(engagement)
        return json.dumps(rows, indent=1) if rows else f"no identities defined for {engagement}"
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
async def check_identity(engagement: str, identity: str) -> str:
    """The valid-session control: is the identity's session working? valid, expired (login page or redirect),
    challenge (CAPTCHA, WAF or rate limit), denied (authenticated but not allowed to see the check URL) or error.
    Logs in again once when the session expired. A test whose identity isn't valid is blocked, not a pass."""
    import identities
    try:
        return json.dumps(await _thread(identities.check, engagement, identity))
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
def list_captures(engagement: str, capture: str = "") -> str:
    """Request captures the researcher imported (HAR or Burp XML), sanitized: cookies, tokens and secret fields
    are [redacted]. Without capture: the list. With a capture id: its requests (method, URL, in scope or not,
    response status and an excerpt)."""
    import captures
    try:
        if not capture:
            rows = captures.listing(engagement)
            return json.dumps(rows, indent=1) if rows else f"no captures imported for {engagement}"
        doc = captures.load(engagement, capture)
        return json.dumps({**captures.summary(doc), "requests": doc["entries"]}, indent=1)[:60000]
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
async def replay_request(engagement: str, capture: str, entry: int, identity: str = "", changes: dict | None = None,
                         markers: list[str] | None = None, approval_id: str = "", max_tier: str = "",
                         task: str = "") -> str:
    """Send a captured request again (RW-009) and compare the response with the captured one. identity: whose
    session to use (the capture's own cookies and tokens are never replayed). changes: {"method", "url", "query":
    {...}, "headers": {...}, "remove_headers": [...], "body"}; use {{cred:NAME}} for stored credentials. The URL is
    checked against the current scope; a request that can change state needs an approval like http_request.
    markers: text to look for in both responses (fixture markers of list_identities)."""
    import captures
    try:
        r = await _thread(captures.replay, engagement, capture, entry, identity or None, changes or None,
                          approval_id or None, max_tier or None, task or None, tuple(markers or ()))
        return r["text"]
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
async def browse(engagement: str, url: str, steps: list[dict] | None = None, identity: str = "",
                 mask: list[str] | None = None, approval_id: str = "", max_tier: str = "", task: str = "",
                 timeout_s: int = 180) -> str:
    """Open an in-scope page in a headless browser in the engagement's sandbox, optionally signed in as an
    identity, and run steps: {"goto": url}, {"wait_for": selector}, {"wait": ms}, {"text": selector} (read text),
    {"click": selector}, {"fill": selector, "value": text or {{cred:NAME}}}, {"press": selector, "key": "Enter"}.
    Every request the page makes (navigation, redirects, assets, script requests, WebSockets) is checked against
    the scope; out-of-scope ones are blocked and listed. Navigation and reading are tier active and the run is
    read-only (requests that can change state are aborted); click, fill and press make it intrusive (approval).
    Evidence: requests.jsonl, page.html (inputs masked), screenshot.png (passwords and mask selectors masked)."""
    try:
        return await _thread(actions.browse, engagement, url, steps or [], identity or None, approval_id or None,
                             max_tier or None, task or None, timeout_s, mask or [])
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
def propose_authz_matrix(engagement: str, name: str, operations: list[dict], identities: list[str],
                         expect: dict, purpose: str = "", allow_writes: bool = False, max_writes: int = 0,
                         cleanup: list[dict] | None = None, no_cleanup_reason: str = "") -> str:
    """Propose an authorization test matrix (RW-011) for the researcher to approve. operations: [{"id", "method",
    "url", "body"?, "headers"?, "marker": text only the owner's record contains, "effect": "read"|"write"}].
    identities: identity names, plus "anonymous". expect: {operation id: {identity: "allow"|"deny"}}: the intended
    permissions (from the client's documentation or the researcher), not guesses from responses. Operations that
    change state (effect write; GET is not assumed harmless) need allow_writes, max_writes and cleanup operations.
    The matrix runs only after the researcher approves exactly this version (./rvkit authz <eng> approve <name>)."""
    import authz
    try:
        m = authz.propose(engagement, name, {"operations": operations, "identities": identities, "expect": expect,
                                             "purpose": purpose, "allow_writes": allow_writes, "max_writes": max_writes,
                                             "cleanup": cleanup or [], "no_cleanup_reason": no_cleanup_reason})
        return (f"proposed matrix {name} (digest {m['digest']}): {len(m['operations'])} operations x "
                f"{len(m['identities'])} identities. Ask the researcher to review and approve it on the host: "
                f"./rvkit authz {engagement} approve {name}   Then call run_authz_matrix.")
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
async def run_authz_matrix(engagement: str, name: str, task: str = "") -> str:
    """Run an approved authorization matrix: checks every identity first (blocked cells when a session isn't
    valid), sends each operation as each identity, compares the data returned (fixture markers, similarity to the
    owner's response), and reports pass, FAIL (allowed where deny was expected), unexpected-deny or blocked per
    cell, with evidence. A FAIL is a candidate: verify it before recording a finding."""
    import authz
    try:
        return (await _thread(authz.run, engagement, name, task or None))["text"]
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
def list_authz_matrices(engagement: str) -> str:
    """Proposed authorization matrices and whether each is approved (or changed since approval)."""
    import authz
    try:
        rows = authz.listing(engagement)
        return json.dumps(rows, indent=1) if rows else f"no authorization matrices proposed for {engagement}"
    except ValueError as e:
        return f"REFUSED: {e}"


if __name__ == "__main__":
    core.publish_routes()  # routing table for the model gateway (bindings, Client data, halt)
    try:
        core.apply_network()  # restore firewall + DNS after a container restart
    except Exception as e:
        print("WARNING: could not apply network policy:", e, file=sys.stderr)
    core.fetch_rules_background()  # semgrep community rules into their volume, first start only
    mcp.run(transport="streamable-http")
