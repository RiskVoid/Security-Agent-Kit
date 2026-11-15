"""Lookup policy for web search and fetch (web-mcp): open, or clean (allowlist only), and a log of every lookup.

A benchmark target that is public (Juice Shop, DVWA, VAmPI, DVGA, and this kit's own repository with its expected
findings) has write-ups one search away, and a model looks answers up when it can. A clean benchmark run turns
lookups down to vendor documentation and vulnerability records, so its score says what the agent found itself.

The policy is a file, written by the benchmark harness and read by web-mcp on every call:

  /lookup/policy.json   {"mode": "clean", "allow": [hosts...], "deny": [regexes...], "until": <epoch>, "run": "..."}

  open    every public page, as before (deny patterns still refuse)
  clean   web_search returns only results on allowlisted hosts; fetch reads only allowlisted hosts. A host entry
          matches the host and its subdomains; "host/path" limits it to a path prefix.
  deny    regexes (case-insensitive) on the query or URL: refused in either mode
  until   the policy expires then (a run that crashed doesn't leave web-mcp clean for good)

No policy file, or an expired one, means open with no deny list. Every call is appended to /lookup/log.jsonl with
its decision, so a run's lookups can be read back: the benchmark flags a run that searched for or fetched a
write-up of its target.
"""
import json, os, re, time, urllib.parse

DIR = os.environ.get("LOOKUP_DIR", "/lookup")
# vendor documentation and vulnerability records: what a researcher may read during a clean run
CLEAN_ALLOW = (
    "nvd.nist.gov", "cve.org", "cve.mitre.org", "cwe.mitre.org", "capec.mitre.org", "osv.dev", "www.cisa.gov",
    "github.com/advisories", "security.snyk.io", "www.first.org/epss",
    "docs.python.org", "flask.palletsprojects.com", "werkzeug.palletsprojects.com", "docs.djangoproject.com",
    "nodejs.org", "expressjs.com", "developer.mozilla.org", "www.npmjs.com/package", "pypi.org/project",
    "www.php.net", "laravel.com/docs", "symfony.com/doc", "graphql.org", "spec.graphql.org", "jwt.io",
    "datatracker.ietf.org", "www.rfc-editor.org", "cheatsheetseries.owasp.org", "owasp.org/www-project-web-security-testing-guide",
    "owasp.org/Top10", "owasp.org/API-Security", "portswigger.net/web-security", "semgrep.dev/docs",
    "nmap.org", "docs.projectdiscovery.io", "sqlmap.org", "modelcontextprotocol.io",
)
# write-ups of the kit's own targets: refused and flagged in every mode
KIT_DENY = (r"security-agent-kit", r"riskvoid", r"evals/benchmarks")


def policy(now=None, path=None):
    """The policy in force: {"mode", "allow", "deny", "run"}; open when there is none or it has expired."""
    path = path or os.path.join(DIR, "policy.json")
    try:
        p = json.load(open(path))
    except (OSError, ValueError):
        return {"mode": "open", "allow": [], "deny": [], "run": None}
    if p.get("until") and (now or time.time()) > float(p["until"]):
        return {"mode": "open", "allow": [], "deny": [], "run": None}
    mode = p.get("mode") if p.get("mode") in ("open", "clean") else "clean"   # an unknown mode fails closed
    return {"mode": mode, "allow": list(p.get("allow") or (CLEAN_ALLOW if mode == "clean" else [])),
            "deny": list(p.get("deny") or []), "run": p.get("run")}


def allowed_host(url, allow):
    u = urllib.parse.urlparse(url if "://" in url else "https://" + url)
    host, path = (u.hostname or "").lower().rstrip("."), u.path or "/"
    for a in allow:
        h, _, prefix = a.lower().partition("/")
        if (host == h or host.endswith("." + h)) and (not prefix or path.lower().startswith("/" + prefix)):
            return True
    return False


def denied(text, deny):
    return next((rx for rx in deny if re.search(rx, text or "", re.I)), None)


def check_fetch(pol, url):
    """None when the URL may be fetched, else the refusal text."""
    rx = denied(url, pol["deny"])
    if rx:
        return ("REFUSED: lookup policy: this looks like a write-up or the answers for the target under test "
                f"(matches {rx!r}). Work it out from the target itself.")
    if pol["mode"] == "clean" and not allowed_host(url, pol["allow"]):
        return ("REFUSED: lookup policy (clean run): only vendor documentation and vulnerability records can be "
                "read. Work it out from the target itself.")
    return None


def check_search(pol, query):
    rx = denied(query, pol["deny"])
    if rx:
        return ("REFUSED: lookup policy: this search looks for write-ups or answers for the target under test "
                f"(matches {rx!r}). Work it out from the target itself.")
    return None


def filter_results(pol, rows):
    """Search results the policy allows (clean: allowlisted hosts only; deny patterns removed in every mode)."""
    keep = []
    for r in rows:
        url = r.get("url") or ""
        if denied(url, pol["deny"]) or denied(r.get("title") or "", pol["deny"]):
            continue
        if pol["mode"] == "clean" and not allowed_host(url, pol["allow"]):
            continue
        keep.append(r)
    return keep


def log(entry, path=None):
    """Append one lookup to the log; never fails the call."""
    path = path or os.path.join(DIR, "log.jsonl")
    try:
        with open(path, "a") as f:
            f.write(json.dumps({"ts": time.time(), **entry}) + "\n")
    except OSError:
        pass


def read_log(start, end, path=None):
    """Lookups logged between start and end (epoch seconds), oldest first."""
    path = path or os.path.join(DIR, "log.jsonl")
    out = []
    try:
        for line in open(path):
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if start - 5 <= float(e.get("ts") or 0) <= end + 5:
                out.append(e)
    except OSError:
        pass
    return out


def flagged(entries, patterns):
    """Lookups that went for a write-up of the target: a pattern in the query, the URL or a result URL, whether
    or not the policy refused it."""
    out = []
    for e in entries:
        texts = [e.get("query") or "", e.get("url") or ""] + list(e.get("results") or [])
        rx = next((p for p in patterns for t in texts if re.search(p, t, re.I)), None)
        if rx:
            out.append({**{k: e.get(k) for k in ("tool", "query", "url", "decision")}, "pattern": rx})
    return out
