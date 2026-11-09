"""Tool outputs -> normalized observations (RW-016). Pure functions: no database, no network.

An observation is one thing a tool (or a person) noticed, before anyone has decided whether it is a finding:

  tool, rule_id    which tool and which of its rules (semgrep check id, OSV advisory, authz operation...)
  title, severity  as the tool states them (severity is the tool's opinion, not the finding's)
  location         file:line, package@version or METHOD URL
  fingerprint      stable across re-imports of the same instance (tool, rule, location, normalized snippet)
  group_key        what a root cause probably is (same rule and file, same package, same route template):
                   used to suggest grouping, never to merge automatically
  detail           the original record, trimmed (the evidence file keeps all of it)

parse(path, data) returns {"parser", "observations", "errors", "limitations"}: parser errors and what the tool
says it couldn't do (skipped files, timeouts, blocked cells) are kept, not dropped.
"""
import hashlib, json, os, re

PARSER_VERSION = 1
SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
BANDIT_SEV = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
MAX_DETAIL = 4000


def fingerprint(*parts):
    norm = "|".join(re.sub(r"\s+", " ", str(p or "")).strip() for p in parts)
    return hashlib.sha256(norm.encode()).hexdigest()[:24]


def _cvss_band(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low" if s > 0 else "info"


def _trim(obj):
    s = json.dumps(obj, default=str)
    return s if len(s) <= MAX_DETAIL else s[:MAX_DETAIL] + "...(trimmed; see the evidence file)"


def _obs(tool, rule, title, severity, location, fp_extra, group, detail, evidence=()):
    return {"tool": tool, "rule_id": rule, "title": title[:300], "severity": severity, "location": location,
            "fingerprint": fingerprint(tool, rule, location, fp_extra), "group_key": group, "detail": _trim(detail),
            "evidence": [e for e in evidence if e]}


def route_template(url):
    """/api/invoices/12?x=1 -> /api/invoices/{id}: requests to the same route share a group."""
    path = re.sub(r"^[a-z]+://[^/]+", "", url or "").split("?")[0] or "/"
    return re.sub(r"/(\d+|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{24,})(?=/|$)", "/{id}", path)


# ---------------------------------------------------------------- parsers
def semgrep(d):
    out = []
    for r in d.get("results", []):
        ex = r.get("extra", {})
        rule = r.get("check_id", "")
        loc = f"{r.get('path')}:{r.get('start', {}).get('line')}"
        lines = ex.get("lines") if ex.get("lines") not in (None, "requires login") else ""
        cwe = (ex.get("metadata") or {}).get("cwe")
        out.append(_obs("semgrep", rule, (ex.get("message") or rule).split("\n")[0], SEMGREP_SEV.get(ex.get("severity"),
                        "info"), loc, lines or loc, f"semgrep:{rule}:{r.get('path')}",
                        {"cwe": cwe, "lines": lines, "end": r.get("end", {}).get("line")}))
    errors = [{"type": e.get("type"), "message": str(e.get("message", ""))[:300],
               "path": (e.get("spans") or [{}])[0].get("file") if e.get("spans") else e.get("path")}
              for e in d.get("errors", [])]
    lim = []
    skipped = (d.get("paths") or {}).get("skipped") or []
    if skipped:
        lim.append(f"{len(skipped)} path(s) skipped by Semgrep")
    scanned = (d.get("paths") or {}).get("scanned")
    if scanned is not None:
        lim.append(f"{len(scanned)} file(s) scanned")
    return out, errors, lim


def osv(d):
    out, lim = [], []
    for res in d.get("results", []):
        src = (res.get("source") or {}).get("path", "")
        for p in res.get("packages", []):
            pkg = p.get("package", {})
            name = f"{pkg.get('ecosystem')}:{pkg.get('name')}@{pkg.get('version')}"
            vulns = {v.get("id"): v for v in p.get("vulnerabilities", [])}
            groups = p.get("groups") or [{"ids": [i]} for i in vulns]
            for g in groups:
                ids = g.get("ids") or []
                primary = next((i for i in ids if i.startswith(("GHSA", "CVE"))), ids[0] if ids else "?")
                v = next((vulns[i] for i in ids if i in vulns), {})
                aliases = g.get("aliases") or v.get("aliases") or []
                out.append(_obs("osv-scanner", primary, f"{pkg.get('name')} {pkg.get('version')}: "
                                f"{v.get('summary') or ', '.join(a for a in aliases if a.startswith('CVE')) or primary}",
                                _cvss_band(g.get("max_severity")) or "medium", f"{name} ({src})", ",".join(sorted(ids)),
                                f"package:{name}", {"ids": ids, "aliases": aliases, "max_severity": g.get("max_severity"),
                                                    "source": src}))
    return out, [], lim


def pip_audit(d):
    out, lim = [], []
    deps = d.get("dependencies", d if isinstance(d, list) else [])
    for dep in deps:
        name = f"PyPI:{dep.get('name')}@{dep.get('version')}"
        if dep.get("skip_reason"):
            lim.append(f"{dep.get('name')}: {dep['skip_reason']}")
        seen = set()
        for v in dep.get("vulns", []):
            if v.get("id") in seen:
                continue
            seen.add(v.get("id"))
            out.append(_obs("pip-audit", v.get("id"), f"{dep.get('name')} {dep.get('version')}: "
                            f"{(v.get('description') or v.get('id'))[:160]}", "medium", name, v.get("id"),
                            f"package:{name}", {"aliases": v.get("aliases"), "fix_versions": v.get("fix_versions")}))
    return out, [], lim


def bandit(d):
    out = [_obs("bandit", r.get("test_id"), r.get("issue_text", ""), BANDIT_SEV.get(r.get("issue_severity"), "low"),
                f"{r.get('filename')}:{r.get('line_number')}", r.get("code") or r.get("line_number"),
                f"bandit:{r.get('test_id')}:{r.get('filename')}",
                {"confidence": r.get("issue_confidence"), "cwe": (r.get("issue_cwe") or {}).get("id")})
           for r in d.get("results", [])]
    errors = [{"type": "bandit", "message": str(e.get("reason", ""))[:300], "path": e.get("filename")}
              for e in d.get("errors", [])]
    return out, errors, []


def gitleaks(d):
    out = [_obs("gitleaks", r.get("RuleID"), r.get("Description") or r.get("RuleID"), "high",
                f"{r.get('File')}:{r.get('StartLine')}", r.get("Fingerprint") or r.get("Match"),
                f"secret:{r.get('RuleID')}", {"commit": r.get("Commit"), "redacted": True})
           for r in (d if isinstance(d, list) else [])]
    return out, [], []


def authz(d):
    """A run of an authorization matrix (evidence/authz): FAIL and unexpected-deny cells; blocked ones are limits."""
    out, lim = [], []
    for c in d.get("cells", []):
        where = f"{c.get('method', 'GET')} {c.get('url', c.get('operation'))}"
        if c.get("verdict") == "FAIL":
            out.append(_obs("authz", f"authz:{d.get('matrix')}:{c['operation']}",
                            f"{c['identity']} was allowed {c['operation']} (expected deny)", "high", where,
                            c["identity"], f"route:{route_template(c.get('url', ''))}", c, [c.get("evidence")]))
        elif c.get("verdict") == "unexpected-deny":
            out.append(_obs("authz", f"authz:{d.get('matrix')}:{c['operation']}",
                            f"{c['identity']} was denied {c['operation']} (expected allow)", "info", where,
                            c["identity"], f"route:{route_template(c.get('url', ''))}", c, [c.get("evidence")]))
        elif c.get("verdict") == "blocked":
            lim.append(f"{c['operation']} as {c['identity']}: blocked ({c.get('reason')})")
    return out, [], lim


def appmap(d):
    out = []
    for x in d.get("leads", []):
        loc = next((f"{l['file']}:{l['line']}" for l in x.get("locations", []) if l.get("file")), x.get("route", ""))
        out.append(_obs("laravel_map", x.get("kind"), x.get("title", ""), x.get("severity_hint", "info"), loc,
                        x.get("title"), f"{x.get('kind')}:{x.get('route') or loc.split(':')[0]}",
                        {k: x.get(k) for k in ("why", "verify", "confidence", "locations", "route")}))
    return out, [], list(d.get("gaps", []))


def http(text):
    """An evidence/http (or replay, browser) exchange written by kali-mcp."""
    req = re.search(r"^> (\w+) (\S+)", text, re.M)
    if not req:
        return [], [{"type": "parse", "message": "no request line (> METHOD URL)", "path": None}], []
    statuses = re.findall(r"^< (\d{3}) ", text, re.M)
    ident = re.search(r"identity=(\S+)", text.splitlines()[0] if text else "")
    method, url = req.group(1), req.group(2)
    status = statuses[-1] if statuses else "no response"
    title = f"{method} {url} -> {status}" + (f" as {ident.group(1)}" if ident else "")
    notes = re.findall(r"^# (?!rvkit|tls|body truncated|GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)(.+)$", text, re.M)
    return [_obs("http", f"http:{method}", title, "info", f"{method} {url}", f"{status}|{ident and ident.group(1)}",
                 f"route:{route_template(url)}", {"status": status, "identity": ident and ident.group(1),
                                                  "notes": notes[:5]})], [], []


PARSERS = {"semgrep": semgrep, "osv-scanner": osv, "pip-audit": pip_audit, "bandit": bandit, "gitleaks": gitleaks,
           "authz": authz, "laravel_map": appmap}


def detect(path, data):
    """Which parser fits: by the evidence folder and the file's shape."""
    p = path.replace("\\", "/")
    if "/http/" in p or "/replay/" in p and p.endswith(".txt") or p.endswith(".txt") and data.lstrip().startswith(
            ("# rvkit http_request", "> ")):
        return "http"
    try:
        d = json.loads(data)
    except ValueError:
        return None
    if isinstance(d, dict):
        if "results" in d and isinstance(d["results"], list) and (not d["results"] or "check_id" in d["results"][0]) \
                and ("paths" in d or "errors" in d or "version" in d):
            return "semgrep"
        if "results" in d and d["results"] and "packages" in d["results"][0]:
            return "osv-scanner"
        if "dependencies" in d:
            return "pip-audit"
        if "results" in d and (not d["results"] or "test_id" in d["results"][0]) and "metrics" in d:
            return "bandit"
        if "cells" in d and "matrix" in d:
            return "authz"
        if "leads" in d and "routes" in d:
            return "laravel_map"
        if "results" in d and not d["results"]:
            return "semgrep"
    if isinstance(d, list) and (not d or "RuleID" in d[0]):
        return "gitleaks"
    return None


def parse(path, data, tool=None):
    tool = tool or detect(path, data)
    if not tool:
        return {"parser": None, "observations": [], "limitations": [],
                "errors": [{"type": "unknown-format", "message": "no parser for this file (semgrep, osv-scanner, "
                            "pip-audit, bandit, gitleaks JSON, an authz run, an app map or an HTTP exchange)",
                            "path": path}]}
    try:
        if tool == "http":
            obs, errors, lim = http(data)
        elif tool in PARSERS:
            obs, errors, lim = PARSERS[tool](json.loads(data))
        else:
            raise ValueError(f"unknown tool {tool}")
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        return {"parser": tool, "observations": [], "limitations": [],
                "errors": [{"type": "parse", "message": f"{type(e).__name__}: {e}"[:300], "path": path}]}
    return {"parser": tool, "observations": obs, "errors": errors, "limitations": lim}


def evidence_kind(rel):
    return os.path.normpath(rel).split(os.sep)[1] if rel.startswith("evidence/") else None
