"""Kali toolbox exposed to the agent as an MCP server (streamable HTTP on :8090/mcp).

Commands run sandboxed per engagement (see core.py): own folder only, unprivileged user, network limited to the
engagement scope by nftables, tiers and rate limits from RULES.md, intrusive commands need host approval, and
everything is audit-logged. Only run against systems you are authorised to test.
"""
import functools, inspect, json, sys
import anyio
from mcp.server.fastmcp import FastMCP
import core
import actions
import oob
oob.start()

# Stateless: no per-client session, so a conversation that was open when this server restarted keeps working
# (with sessions, every later tool call failed with "Session terminated" until OpenHands itself was restarted).
mcp = FastMCP("kali", host="0.0.0.0", port=core.MCP_PORT, stateless_http=True)


async def _thread(fn, *args, **kw):
    """Run a blocking call in a worker thread. FastMCP runs plain functions on its event loop, so a long command
    would hold every other call (another task's command, cancel_task, approval_status) until it ended."""
    return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kw), limiter=_LIMIT)

_LIMIT = anyio.CapacityLimiter(64)


def rules_line(engagement):
    """The engagement's unenforced rules as one line (policy.reminder), or "" (unknown engagement, no such rules)."""
    try:
        i = core.info(engagement)
    except Exception:  # noqa: BLE001 - a reminder never makes a result fail
        return ""
    return core.rvpolicy.reminder(i["rules"], i.get("usage"))


def with_rules(fn):
    """Action tools end their result with the rules reminder, so the rules are in the planner's recent context
    however its conversation was condensed (epic #52, issue #38)."""
    sig = inspect.signature(fn)

    @functools.wraps(fn)
    async def wrap(*args, **kw):
        out = await fn(*args, **kw)
        bound = sig.bind_partial(*args, **kw).arguments
        line = rules_line(bound.get("engagement") or "")
        extra = delegate_note(fn, bound)
        if not isinstance(out, str):
            return out
        for text in (line, extra):
            if text:
                out = f"{out}\n{text}"
        return out
    return wrap


# Scanner and recon programs a run-tool command can name. Models skip planner.md's "Delegate tool work" section
# when the first message doesn't name the worker (two benchmark runs spent 4M and 12M planner tokens with zero
# worker calls), so a run made by the planner itself ends with the reminder, up to DELEGATE_NOTE_MAX times per
# engagement: a note on every result is noise, and one the model never reads is worse.
DELEGATE_TOOLS = {
    "semgrep", "bandit", "gitleaks", "trufflehog", "rv-joern", "osv-scanner", "pip-audit", "trivy", "syft", "grype",
    "nmap", "naabu", "dnsx", "subfinder", "amass", "katana", "httpx-toolkit", "whatweb", "gowitness", "nuclei",
    "nikto", "ffuf", "feroxbuster", "gobuster", "arjun", "wafw00f", "wpscan", "dalfox", "commix", "zaproxy",
    "sqlmap", "testssl", "sslscan", "schemathesis", "jwt_tool", "graphw00f", "graphql-cop", "clairvoyance",
    "rv-llm", "garak",
}
DELEGATE_NOTES = {}   # engagement -> notes shown (this server process)
DELEGATE_NOTE_MAX = 3


def delegate_note(fn, arguments):
    """The reminder appended to a bulk scanner or recon run the planner made itself (task empty: worker calls
    carry one). Empty for everything else, and never a reason a result fails (like the rules line)."""
    if fn.__name__ != "run" or arguments.get("task"):
        return ""
    try:
        progs = [prog for prog, _ in core._segments(str(arguments.get("command") or ""))]
        if not any(prog in DELEGATE_TOOLS for prog in progs):
            return ""
    except Exception:  # noqa: BLE001 - a reminder is best effort
        return ""
    eng = str(arguments.get("engagement") or "")
    if DELEGATE_NOTES.get(eng, 0) >= DELEGATE_NOTE_MAX:
        return ""
    DELEGATE_NOTES[eng] = DELEGATE_NOTES.get(eng, 0) + 1
    return ("[delegate: scanner and recon runs belong to the worker — hand the next one over with delegate_task "
            "(one narrow task per plan item, plan_item set) and collect it with get_task; its output stays out of "
            "your context. A single check (one request, one file) is yours.]")


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
@with_rules
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
@with_rules
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
@with_rules
async def run(command: str, engagement: str, timeout_s: int = 600, approval_id: str = "", max_tier: str = "",
        task: str = "") -> str:
    """Run a shell command in the Kali sandbox for an engagement.

    cwd is /work/<engagement> (write output files here). In-scope client code is read-only under /src.
    The full output is saved as verified evidence in evidence/runs/ (the result ends with its path): cite that
    path rather than copying the output into a file yourself.
    Network access is limited to the engagement scope (plus package/vulnerability-database sites when the
    engagement is online); everything else is blocked. Tools:
      recon:        nmap, naabu, dnsx, subfinder, amass, katana, httpx-toolkit, whatweb, gowitness (screenshots)
      web:          nuclei (templates at /opt/nuclei-templates, e.g. -t /opt/nuclei-templates/vulnerabilities), nikto, ffuf, feroxbuster, gobuster, arjun, crlfuzz,
                    wafw00f, wpscan, dalfox, commix, zaproxy, sqlmap, testssl, sslscan; wordlists in /usr/share/seclists
      API:          schemathesis (`schemathesis run <openapi-or-graphql-url> --url <base>`: spec-driven fuzzing),
                    jwt_tool (decode/crack/forge offline; -t <url> sends to the target: active, with -X/-I/-S/-M intrusive), graphw00f (-d -f -t <url>),
                    graphql-cop (-t <url> -o json), clairvoyance (schema without introspection)
      AI/LLM/MCP:   rv-llm (`rv-llm help`: `probe` adversarial prompt library with canaries against a chat API,
                    `mcp <url>` audit an MCP server, `mcp-call` call one MCP tool, `payloads` indirect-injection
                    payloads), garak (LLM vulnerability scanner; `--target_type rest -G <config.json>`)
      code/secrets: semgrep (offline rules in /opt/semgrep-rules, e.g. --config /opt/semgrep-rules/python; the
                     semgrep registry is NOT reachable from the sandbox, also on online engagements),
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
@with_rules
async def verify(engagement: str, oracle: str, request: dict, marker: str = "", expect: str = "",
                 identities: list[str] | None = None, check: dict | None = None, control: dict | None = None,
                 approval_id: str = "", finding: str = "", task: str = "", samples: int = 5,
                 min_delay: float = 1.0, timeout: float = 10.0) -> str:
    """Decide whether a finding holds with a deterministic oracle and a negative control, instead of judging a
    response yourself. request: {method, url, headers?, body?, identity?}; put {{marker}} where a fresh canary goes.
      marker               the canary (or expect, e.g. "<b>{{marker}}</b>") comes back in the response. Control: the
                           same request with another token. With an explicit marker, give control yourself.
      identity_difference  identities: [attacker, owner], marker: the owner's fixture marker. The attacker gets
                           it; controls: the owner gets it, the request without an identity doesn't.
      read_back            the request is the proof (it writes or reads the marker), check: {method, url, ...}
                           reads it back. Control: check before the proof doesn't find it.
      browser_xss          a GET URL whose input calls rvMarker('{{marker}}'): the page opens in the sandboxed
                           browser and passes only if that script ran. Control: the same URL with another token.
      timing               request and control (both required): samples of each (default 5, max 10); passes when
                           every probe is slower than every control by more than min_delay and the noise.
      oob_callback         a blind issue (SSRF, blind XXE, blind command injection): put {{marker}} where the
                           target's callback URL goes, e.g. the url argument it fetches
                           (...fetch?url=<catcher>/{{marker}}) or the host/path it connects to; {{marker}} becomes
                           the callback token. Passes only when that token arrives at the kit's own catcher and
                           the control's does not (timeout seconds to wait, default 10). Needs RULES.md
                           'Out-of-band callbacks: on'; the rules line shows the catcher URL to embed.
       rate_limit           the same request N times at the engagement's own max rate, then one control after a
                            cooldown (samples: N, default 30, max 100; timeout: the cooldown, default 10s). One
                            approval names the N and the control. pass: no rate limiting at that rate (every
                            response in the record - the evidence a 'missing rate limit' finding needs); fail:
                            rate limiting IS present (the record is its proof - record that instead).
    Result: pass (holds and the control is clean), fail, or inconclusive. Each run is saved as a verification record
    (evidence/verify/...json): cite it as evidence and confirm the finding with method=oracle. Requests go through
    the same scope, tier, approval and identity checks as http_request; a write needs an approval (call again with
    the same marker and approval_id)."""
    try:
        import oracles
        r = await _thread(oracles.verify, engagement, oracle, request, marker, expect, identities, check, control,
                          approval_id or None, None, task or None, finding, None, samples, min_delay, None, timeout)
        return r["text"]
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
@with_rules
async def recon_map(engagement: str, url: str, depth: int = 2, crawl_seconds: int = 120, probe: bool = True,
                    max_tier: str = "", task: str = "", identity: str = "", max_scripts: int = 0,
                    max_probes: int = 0, sweep: bool = True) -> str:
    """Map a web target before testing it (epic #52, #46; authenticated depth #135, feedback loops #136): crawl it
    (katana: links, JavaScript, robots, sitemap), content-discovery (ffuf over the common wordlist), read the API
    paths its scripts name (source maps, GraphQL operations and a gitleaks secrets pass included), fetch its
    OpenAPI / Swagger and GraphQL schemas (clairvoyance when introspection is off), discover hidden GET parameters
    (arjun), and send one GET without credentials to each path not yet fetched, to see which need authentication.
    Only in-scope URLs are kept; every request is audited. Saves evidence/map/map-<time>.json.
    Run it once per web target before planning tests; then get_map (findings) gives the merged map with entry
    ids to reference in plan_tests. depth: crawl depth (1-5). probe=false: no unauthenticated GETs.
    identity: run an authenticated pass after the unauthenticated one, with one of the engagement's identities
    (list_identities): the surface behind login enters the map, tagged seen_by. An identity that isn't valid is
    skipped with a note, never silently. max_scripts / max_probes: raise the script and probe caps for a large app
    (defaults are sized for a typical app). sweep (default true): after the map is built, the kit's fixed checks
    run on it in the same call (#169) - injection, JWT, ReDoS, CORS and headers over every entry, and the write
    checks proposed as one authorization matrix. Approve that matrix (console or ./rvkit authz approve), then
    call probe_map with matrix=<name> for the writes. sweep=false maps only: say why when you use it."""
    import recon
    try:
        return await _thread(recon.build, engagement, url, depth, crawl_seconds, probe, max_tier or None,
                             task or None, identity or "", max_scripts or None, max_probes or None, sweep)
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
@with_rules
async def probe_map(engagement: str, matrix: str = "", max_requests: int = 400, checks: str = "",
                    task: str = "", identity: str = "") -> str:
    """Run the kit's fixed checks against the recon map (run recon_map first): the checks a model doesn't
    reliably think of on its own.
      injection        an error probe and a boolean true/false pair on every parameter of every read, path
                       parameters included; a hit only when the answers differ the way the probe predicts
      redos            string fields whose malformed value gets a validation error receive inputs of growing
                       length, timed each time; a hit needs a clear growth, and the ladder stops at the first
      jwt              every JWT seen in the evidence or this sweep is cracked offline against common secrets;
                       a forged token is tried against an authenticated endpoint
      mass-assignment  every object-creating POST with a JSON body registers a throwaway account carrying one
                       privileged field and reads it back logged in as it, against a control account
    Reads run now. The writes (throwaway registrations and logins) are proposed as ONE authorization matrix and
    send nothing until you approve it (./rvkit authz <eng> approve <name>): call probe_map again with
    matrix=<name> to run them. Every request goes through the same scope, tier, rate and budget checks as your
    own, hits are observations to triage (not findings), and the sweep's evidence file names the exact requests
    for each hit. checks: a comma-separated subset. max_requests caps the sweep.
    identity: run the reads as one of the engagement's identities (list_identities), so the checks reach the
    surface behind login (#137); an entry no identity can reach is skipped with a note, not silently."""
    import sweep
    try:
        return await _thread(sweep.probe_map, engagement, matrix, max_requests, checks, task or None, identity or "")
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
@with_rules
async def race_request(engagement: str, method: str, url: str, n: int = 10, headers: dict | None = None,
                      body: str = "", identity: str = "", approval_id: str = "", task: str = "") -> str:
    """Send the SAME state-changing request N times, as simultaneously as the kit can (W4): the test for
    race conditions where something that must happen once happens twice (a one-shot voucher, the last item in
    stock, a balance transfer, a vote).
    One approval covers the exact request x N: its text names N and the rate exemption - a race is
    simultaneous by definition, so Max rate doesn't apply to the burst; N is capped at 25 and the request
    budget pays for every shot. The request must be the same for all N (that is what makes it a race).
    Returns each shot's status and a saved evidence file with all responses. The decision is an oracle's
    afterwards: read back what changed (the count, the status of the voucher) or run response_diff - if more
    than one shot succeeded where the operation must happen once, that is the finding to verify.
    A race is intrusive: it needs the operator's approval, exactly as any state-changing request."""
    import actions
    try:
        r = await _thread(actions.race, engagement, method, url, headers or {}, body, n,
                          approval_id or None, identity or None, task or None)
        # the tool answers as text (verify's convention): actions.race returns dicts on its refused, approval
        # and success paths, and a dict against the -> str annotation fails MCP output validation - the tool
        # answered only "validation error" through the whole MCP surface, and a run missed its race item to it
        return r["text"] if isinstance(r, dict) and r.get("text") else json.dumps(r, indent=1)
    except ValueError as e:
        return f"REFUSED: {e}"


@mcp.tool()
async def laravel_map(engagement: str, path: str, build_url: str = "", routes_file: str = "", max_tier: str = "",
                      task: str = "") -> str:
    """Map a Laravel application from its source (RW-012) without running any of it: framework and PHP versions,
    routes with their effective middleware, controllers (bound models, Form Requests, authorization calls, how
    input is used), models (mass-assignable columns, global/tenant scopes), policies, views and sinks. Returns
    leads (candidate issues with the reasoning and how to verify them), controls (protections found: don't report
    those as flaws without runtime evidence) and gaps. path: an in-scope /src path. build_url: the deployment's
    version endpoint (X-Build-Id header or JSON "build"), compared with the source digest: results from a
    deployment that doesn't match the source may not apply to it. routes_file: a runtime route export
    (php artisan route:list --json) in the engagement folder, compared with the static routes."""
    try:
        return await _thread(actions.appmap, engagement, path, build_url or None, routes_file or None,
                             max_tier or None, task or None)
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
@with_rules
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
@with_rules
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
@with_rules
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
