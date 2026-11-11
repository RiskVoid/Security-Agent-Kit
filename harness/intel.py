"""Vulnerability intelligence MCP server (streamable HTTP on :8093/mcp).

Sources (public, no client data is sent except vulnerability ids and package name/version):
  OSV       https://api.osv.dev             ids, aliases, affected/fixed versions, references
  NVD       https://services.nvd.nist.gov   CVSS (v4.0 / v3.1) vector + score, CWE   (NVD_API_KEY raises the rate limit)
  EPSS      https://api.first.org           exploit-prediction probability + percentile
  CISA KEV  https://www.cisa.gov            known exploited in the wild, ransomware use
Responses are cached in /cache/intel.db (24 h; KEV feed 12 h).
"""
import json, os, re, sqlite3, threading, time, urllib.parse, urllib.request
from mcp.server.fastmcp import FastMCP

# Stateless: no per-client session, so a conversation that was open when this server restarted keeps working
# (with sessions, every later tool call failed with "Session terminated" until OpenHands itself was restarted).
mcp = FastMCP("intel", host="0.0.0.0", port=8093, stateless_http=True)
CACHE = os.environ.get("INTEL_CACHE", "/cache/intel.db")
NVD_KEY = os.environ.get("NVD_API_KEY", "")
TTL, KEV_TTL = 24 * 3600, 12 * 3600
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_lock, _nvd_last = threading.Lock(), [0.0]


def _db():
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    con = sqlite3.connect(CACHE)
    con.execute("CREATE TABLE IF NOT EXISTS cache (k TEXT PRIMARY KEY, v TEXT, ts REAL)")
    return con


def _get(url, key=None, ttl=TTL, data=None, headers=None):
    key = key or url + (json.dumps(data) if data else "")
    with _lock, _db() as con:
        row = con.execute("SELECT v, ts FROM cache WHERE k=?", (key,)).fetchone()
    if row and time.time() - row[1] < ttl:
        return json.loads(row[0])
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data else None,
                                 headers={"User-Agent": "rvkit-intel", "Content-Type": "application/json",
                                          **(headers or {})})
    try:
        v = json.load(urllib.request.urlopen(req, timeout=60))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            v = None
        else:
            raise
    with _lock, _db() as con:
        con.execute("REPLACE INTO cache VALUES (?,?,?)", (key, json.dumps(v), time.time()))
    return v


def osv(vid):
    return _get(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(vid)}")


def nvd(cve):
    key = f"nvd:{cve}"
    with _lock, _db() as con:
        row = con.execute("SELECT v, ts FROM cache WHERE k=?", (key,)).fetchone()
    if row and time.time() - row[1] < TTL:
        return json.loads(row[0])
    wait = (0.7 if NVD_KEY else 6.5) - (time.time() - _nvd_last[0])  # NVD: 5 req/30 s without a key
    if wait > 0:
        time.sleep(wait)
    _nvd_last[0] = time.time()
    d = _get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}", key=key,
             headers={"apiKey": NVD_KEY} if NVD_KEY else None)
    return d


def epss(cves):
    if not cves:
        return {}
    d = _get("https://api.first.org/data/v1/epss?cve=" + ",".join(sorted(cves)))
    return {r["cve"]: {"epss": float(r["epss"]), "percentile": float(r["percentile"])} for r in (d or {}).get("data", [])}


def kev():
    d = _get(KEV_URL, key="kev", ttl=KEV_TTL) or {}
    return {v["cveID"]: v for v in d.get("vulnerabilities", [])}


def _cvss(nvd_doc):
    try:
        cve = nvd_doc["vulnerabilities"][0]["cve"]
    except (TypeError, KeyError, IndexError):
        return {}
    m, out = cve.get("metrics", {}), {}
    for k, label in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        if m.get(k):
            prim = next((x for x in m[k] if x.get("type") == "Primary"), m[k][0])["cvssData"]
            out = {"cvss_version": label, "cvss_score": prim.get("baseScore"), "cvss_vector": prim.get("vectorString"),
                   "cvss_severity": prim.get("baseSeverity")}
            break
    cwes = sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                   if d.get("value", "").startswith("CWE-")})
    return {**out, "cwe": cwes, "published": cve.get("published", "")[:10]}


def _fixed(o):
    fixed = set()
    for a in (o or {}).get("affected", []):
        pkg = a.get("package", {}).get("name", "")
        for r in a.get("ranges", []):
            if r.get("type") == "GIT":  # commit hashes aren't useful in a report
                continue
            for e in r.get("events", []):
                if "fixed" in e:
                    fixed.add(f"{pkg} {e['fixed']}".strip())
    return sorted(fixed)


def enrich(ids):
    ids = [i.strip() for i in ids if i and i.strip()]
    rows, cve_of = [], {}
    for vid in ids:
        o = osv(vid) if not vid.upper().startswith("CVE-") else (osv(vid) or {})
        aliases = sorted(set((o or {}).get("aliases", []) + [vid]))
        cves = [a for a in aliases if a.upper().startswith("CVE-")]
        cve_of[vid] = cves[0] if cves else None
        fixed = _fixed(o)
        for alias in (a for a in aliases if a.startswith("GHSA-") and not fixed):  # CVE records often lack versions
            ghsa = osv(alias)
            fixed = _fixed(ghsa)
            o = o if (o or {}).get("summary") else ghsa
        rows.append({"id": vid, "aliases": [a for a in aliases if a != vid],
                     "summary": (o or {}).get("summary") or ((o or {}).get("details") or "")[:200],
                     "fixed_in": fixed})
    all_cves = {c for c in cve_of.values() if c}
    ep, kv = epss(all_cves), kev()
    for r in rows:
        c = cve_of[r["id"]]
        r["cve"] = c
        if c:
            r.update(_cvss(nvd(c)))
            r["epss"] = ep.get(c, {}).get("epss")
            r["epss_percentile"] = ep.get(c, {}).get("percentile")
            k = kv.get(c)
            r["kev"] = bool(k)
            if k:
                r["kev_added"] = k.get("dateAdded")
                r["kev_ransomware"] = k.get("knownRansomwareCampaignUse")
                r["kev_action"] = k.get("requiredAction")
    return rows


def _priority(r):
    """Sort key: known exploited first, then EPSS, then CVSS."""
    return (0 if r.get("kev") else 1, -(r.get("epss") or 0), -(r.get("cvss_score") or 0))


@mcp.tool()
def vuln_lookup(ids: list[str]) -> str:
    """Details for vulnerability ids (CVE-..., GHSA-..., PYSEC-..., other OSV ids): summary, aliases, fixed
    versions, CVSS vector/score/severity and CWE (NVD), EPSS probability/percentile, and CISA KEV status
    (known exploited in the wild, ransomware use). Up to 25 ids per call."""
    return json.dumps(enrich(ids[:25]), indent=1)


@mcp.tool()
def prioritize(ids: list[str]) -> str:
    """Rank vulnerability ids by real-world risk: CISA KEV (known exploited) first, then EPSS, then CVSS.
    Use it to order dependency findings (e.g. the ids from osv-scanner, pip-audit, trivy or grype). Up to 50 ids;
    duplicates and aliases of the same CVE are merged."""
    rows, seen = [], set()
    for r in enrich(list(dict.fromkeys(ids))[:50]):
        key = r.get("cve") or r["id"]
        if key in seen:
            continue
        seen.add(key)
        rows.append(r)
    rows.sort(key=_priority)
    return json.dumps([{k: r.get(k) for k in ("id", "cve", "kev", "kev_ransomware", "epss", "epss_percentile",
                                              "cvss_score", "cvss_severity", "cwe", "fixed_in", "summary")}
                       for r in rows], indent=1)


@mcp.tool()
def package_vulns(ecosystem: str, name: str, version: str) -> str:
    """Known vulnerabilities for one package version from OSV. ecosystem: PyPI, npm, Go, Maven, RubyGems,
    crates.io, NuGet, Packagist, Debian, Alpine, ... Returns ids with summary and fixed versions;
    pass the ids to prioritize() for KEV/EPSS/CVSS."""
    d = _get("https://api.osv.dev/v1/query", data={"package": {"ecosystem": ecosystem, "name": name},
                                                     "version": version}) or {}
    return json.dumps([{"id": v["id"], "aliases": v.get("aliases", []), "summary": v.get("summary", ""),
                        "fixed_in": _fixed(v)} for v in d.get("vulns", [])], indent=1) or "[]"


@mcp.tool()
def kev_search(query: str) -> str:
    """Search the CISA Known Exploited Vulnerabilities catalog by vendor, product or keyword (e.g. "Fortinet",
    "Confluence"). Returns matching CVEs with date added, ransomware use and required action (max 30)."""
    q = query.lower()
    hits = [v for v in kev().values() if q in (v.get("vendorProject", "") + " " + v.get("product", "") + " "
                                              + v.get("vulnerabilityName", "")).lower()]
    hits.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    return json.dumps([{k: v.get(k) for k in ("cveID", "vendorProject", "product", "vulnerabilityName",
                                              "dateAdded", "knownRansomwareCampaignUse", "requiredAction")}
                       for v in hits[:30]], indent=1) or "[]"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
