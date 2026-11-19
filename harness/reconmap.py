"""The recon map the planner plans from (epic #52, issue #46), and the coverage matrix built on it (#47).

The map is computed from evidence, never typed in, so the same evidence always gives the same map:

  evidence/map/map-*.json       recon_map (kali): crawl, scripts, OpenAPI / GraphQL schemas, unauthenticated probes
  evidence/appmap/laravel-*.json laravel_map (kali): routes from the source with their middleware
  captures/*.json               requests the researcher imported (HAR, Burp), sanitized
  evidence/http/*.txt           the agent's own requests (http_request, replays)

Requests to the same method and path template (numbers, UUIDs, hashes and {params} are one segment) are one entry,
with every source that saw it. Each entry's id (E-xxxxxx) is derived from method, host and template: it stays the same
when the map is rebuilt, so plan items can reference it. A source route without a host (Laravel) joins the entry of
the same path on any host, or stands alone.

authentication of an entry: required when a source says so (401/403/login redirect without credentials, the schema's
security, an auth middleware), none when a request without credentials got a 2xx, otherwise unknown.

The coverage matrix (#47): for each entry, the vulnerability classes that apply to it (by its method, parameters and
authentication), and the plan items that test that class on it (refs: the entry id; area or refs: the class). An
applicable cell with no plan item is a gap: the gap-fill pass delegates it or records why it's skipped.
"""
import glob, hashlib, json, os, re, urllib.parse

import findings_db as db

UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
ENTRY_RX = re.compile(r"^E-[0-9a-f]{6}$")
REQ_LINE = re.compile(r"^> ([A-Z]+) (https?://\S+)$", re.M)
STATUS_LINE = re.compile(r"^< (\d{3}) ", re.M)

# vulnerability classes of the coverage matrix: name -> (when it applies to an entry, standard reference)
CLASSES = {
    "access-control": "an object id in the path or parameters, or authentication required",
    "authentication": "authentication required, or a login / token / password endpoint",
    "injection": "any parameter (SQL, NoSQL, command, template injection)",
    "xss": "a GET with query parameters, or a body that may be shown back",
    "ssrf": "a parameter that takes a URL",
    "open-redirect": "a parameter that takes a destination",
    "mass-assignment": "a write (POST, PUT, PATCH) with a body",
    "file-upload": "a file parameter or an upload path",
    "user-enumeration": "a login, register, reset or user-lookup path, or a user-id path parameter",
    "rate-limit": "an authentication, verification or OTP endpoint (brute force)",
    "information-disclosure": "a debug, verbose, status, config, backup, metrics or graphiql path or parameter",
    "redos": "a search, filter or pattern parameter, or a path parameter (a validation regex may run on it)",
    "csrf": "a state-changing request on a page route, with no token parameter",
    "nosql-injection": "a body parameter (JSON or form)",
    "cors-misconfig": "a page a browser loads (GET, not an API or GraphQL path)",
    "security-headers": "a page a browser loads (GET, not an API or GraphQL path)",
    "graphql-depth": "a GraphQL operation (nesting without a limit)",
    "graphql-batching": "a GraphQL operation (several can be sent in one request)",
    "graphql-field-suggestions": "a GraphQL endpoint whose errors suggest field names",
}
CLASS_REFS = {"access-control": ("WSTG-ATHZ", "API1:2023", "API5:2023", "CWE-639", "CWE-284", "idor", "bola",
                                 "authorization", "authz"),
              "authentication": ("WSTG-ATHN", "API2:2023", "CWE-287", "authn", "login", "jwt", "session",
                                 "credential", "no-auth", "unauthenticated"),
              "injection": ("WSTG-INPV-05", "WSTG-INPV-12", "CWE-89", "CWE-78", "CWE-943", "sqli", "sql", "nosql",
                            "command", "ssti"),
              "xss": ("WSTG-INPV-01", "WSTG-INPV-02", "CWE-79", "xss", "cross-site scripting"),
              "ssrf": ("WSTG-INPV-19", "API7:2023", "CWE-918", "ssrf"),
              "open-redirect": ("WSTG-CLNT-04", "CWE-601", "redirect"),
              "mass-assignment": ("API3:2023", "CWE-915", "mass assignment", "mass-assignment"),
              "file-upload": ("WSTG-BUSL-08", "WSTG-BUSL-09", "CWE-434", "upload", "traversal", "inclusion"),
              "user-enumeration": ("WSTG-IDNT", "CWE-204", "CWE-203", "user enumeration", "user-enum",
                                   "enumeration"),
              "rate-limit": ("CWE-307", "rate limit", "rate-limit", "brute force", "brute-force", "throttl",
                             "lockout"),
              "information-disclosure": ("WSTG-INFO", "CWE-213", "CWE-497", "CWE-538", "information disclosure",
                                         "debug", "verbose", "exposure", "exposed"),
              "redos": ("CWE-1333", "redos", "re-dos", "regular expression denial", "resource consumption"),
              "csrf": ("CWE-352", "csrf", "cross-site request forgery"),
              "nosql-injection": ("CWE-943", "nosql", "no-sql", "mongo"),
              "cors-misconfig": ("CWE-942", "CWE-346", "cors", "cross-origin"),
              "security-headers": ("CWE-693", "security header", "missing header", "csp", "hsts"),
              "graphql-depth": ("CWE-400", "depth", "nesting", "deep"),
              "graphql-batching": ("CWE-770", "batch", "alias", "batching"),
              "graphql-field-suggestions": ("CWE-209", "field suggestion", "suggestions", "did you mean")}
URL_PARAM = re.compile(r"(^|_)(url|uri|link|href|callback|webhook|endpoint|image_url|feed|host|proxy|fetch)$", re.I)
DEST_PARAM = re.compile(r"^(to|next|return|returnto|return_to|redirect|redirect_uri|redirect_url|continue|goto|dest|"
                        r"destination|target|back|r|u)$", re.I)
ID_PARAM = re.compile(r"(^|_)(id|uuid|uid|key|ref|number|no)$|^(user|account|order|parcel|basket|item)s?$", re.I)
FILE_PARAM = re.compile(r"file|upload|attachment|avatar|image|document", re.I)
AUTH_PATH = re.compile(r"log-?in|sign-?in|auth|token|password|session|register|signup|reset|otp|2fa|mfa", re.I)
USER_PATH = re.compile(r"user|account|profile|member|customer|username", re.I)
INFO_PATH = re.compile(r"debug|verbose|trace|dump|config|backup|\.env|metrics|health|status|version|phpinfo|"
                       r"graphiql|actuator|server-status|\.git$", re.I)
INFO_PARAM = re.compile(r"(^|_)(debug|verbose|trace|test|admin|internal)$", re.I)
SEARCH_PARAM = re.compile(r"(^|_)(search|filter|match|pattern|regex|find|query|q)$", re.I)
CSRF_PARAM = re.compile(r"(^|_)csrf|token$|authenticity", re.I)
API_PATH = re.compile(r"^/(api|vapi|v\d[\w-]*|graphql|rest)(/|$)", re.I)


def template(path):
    """A path with its variable segments replaced by {}: /api/parcels/12 and /api/parcels/{id} are the same."""
    segs = []
    for s in (path or "/").split("/"):
        if re.fullmatch(r"\d+|\{[^}]*\}|:[A-Za-z_]\w*", s) or UUID.match(s) or re.fullmatch(r"[0-9a-f]{16,}", s, re.I):
            s = "{}"
        segs.append(s)
    t = "/".join(segs).rstrip("/")
    return t or "/"


def _eid(method, host, tpl):
    return "E-" + hashlib.sha1(f"{method} {host or '*'} {tpl}".encode()).hexdigest()[:6]


def _files(eng, pattern):
    return sorted(glob.glob(os.path.join(db.WORK, eng, pattern)))


def _rel(eng, p):
    return os.path.relpath(p, os.path.join(db.WORK, eng))


def _load(p):
    try:
        with open(p, errors="replace") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _body_names(head):
    """Parameter names of the request body in an http evidence file (the lines after the "> " headers and ">")."""
    m = re.search(r"^>\n(.*?)\n(?:\n# |\Z)", head, re.S | re.M)
    body = (m.group(1) if m else "").strip()
    names = []
    if body.startswith("{"):
        try:
            d = json.loads(body)
            names = sorted(d)[:40] if isinstance(d, dict) else []
        except ValueError:
            names = sorted(set(re.findall(r'"([A-Za-z_][\w.-]{0,40})"\s*:', body)))[:40]
    elif "=" in body and "\n" not in body:
        names = sorted(urllib.parse.parse_qs(body, keep_blank_values=True))[:40]
    return {"body": names} if names else {}


def observations(eng):
    """Every request any source saw, as {method, url or path, host, params, auth, auth_basis, status, source, evidence}."""
    out = []
    for p in _files(eng, "evidence/map/map-*.json"):
        d = _load(p) or {}
        for o in d.get("observations") or []:
            out.append({**o, "evidence": _rel(eng, p)})
    for p in _files(eng, "evidence/appmap/laravel-*.json"):
        d = _load(p) or {}
        for r in d.get("routes") or []:
            for m in r.get("methods") or ["GET"]:
                if m == "HEAD":
                    continue
                out.append({"method": m, "path": "/" + str(r.get("uri") or "").lstrip("/"), "host": None,
                            "source": "laravel", "params": {"path": r.get("params") or []},
                            "auth": "required" if r.get("authenticated") else "unknown",
                            "auth_basis": "auth middleware" if r.get("authenticated") else None,
                            "evidence": _rel(eng, p), "code": f"{r.get('file')}:{r.get('line')}"})
    for p in _files(eng, "captures/*.json"):
        d = _load(p) or {}
        for e in d.get("entries") or []:
            if not e.get("in_scope", True) or not e.get("url"):
                continue
            body = ((e.get("request") or {}).get("body") or "")
            names = []
            if isinstance(body, str) and body.strip().startswith("{"):
                try:
                    names = sorted(json.loads(body))[:40]
                except (ValueError, TypeError):
                    names = []
            elif isinstance(body, str) and "=" in body:
                names = sorted(urllib.parse.parse_qs(body, keep_blank_values=True))[:40]
            hdrs = {k.lower() for k, _ in ((e.get("request") or {}).get("headers") or [])} \
                if isinstance((e.get("request") or {}).get("headers"), list) else \
                {k.lower() for k in ((e.get("request") or {}).get("headers") or {})}
            st = (e.get("response") or {}).get("status")
            authed = bool(hdrs & {"cookie", "authorization", "x-api-key", "x-auth-token"})
            out.append({"method": e.get("method") or "GET", "url": e["url"], "source": "capture",
                        "params": {"body": names} if names else {}, "status": st,
                        "auth": "unknown" if authed else ("required" if st in (401, 403) else
                                                          "none" if st and 200 <= st < 300 else "unknown"),
                        "auth_basis": None if authed else (f"status {st} without credentials" if st else None),
                        "evidence": _rel(eng, p)})
    for p in _files(eng, "evidence/http/*.txt")[-2000:]:
        try:
            with open(p, errors="replace") as f:
                head = f.read(4000)
        except OSError:
            continue
        m = REQ_LINE.search(head)
        if not m:
            continue
        st = STATUS_LINE.search(head)
        ident = "identity=" in head.splitlines()[0] if head else False
        out.append({"method": m.group(1), "url": m.group(2), "source": "request", "params": _body_names(head),
                    "status": int(st.group(1)) if st else None, "auth": "unknown", "auth_basis": None,
                    "evidence": _rel(eng, p), "as_identity": ident})
    return out


def _params(o):
    p = {k: list(v) for k, v in (o.get("params") or {}).items() if v}
    if o.get("url"):
        q = sorted(urllib.parse.parse_qs(urllib.parse.urlsplit(o["url"]).query, keep_blank_values=True))
        if q:
            p["query"] = sorted(set(p.get("query", []) + q))
    return p


AUTH_RANK = {"required": 2, "none": 1, "unknown": 0}


def build(eng):
    """The merged map: {"entries": [...], "hosts", "tech", "schemas", "sources"}."""
    ents, tech, schemas = {}, set(), []
    for p in _files(eng, "evidence/map/map-*.json"):
        d = _load(p) or {}
        tech |= set(d.get("tech") or [])
        schemas += [{**s, "map": _rel(eng, p)} for s in d.get("schemas") or []]
    obs = observations(eng)
    for o in obs:
        if o.get("url"):
            u = urllib.parse.urlsplit(o["url"])
            host, path = u.netloc, u.path or "/"
        else:
            host, path = o.get("host"), o.get("path") or "/"
        method = (o.get("method") or "GET").upper()
        tpl = template(path)
        key = (method, host, tpl)
        e = ents.get(key)
        if not e:
            e = ents[key] = {"id": _eid(method, host, tpl), "method": method, "host": host, "path": tpl,
                             "example": o.get("url") or path, "params": {}, "auth": "unknown", "auth_basis": None,
                             "status": [], "sources": [], "evidence": [], "operations": []}
        for k, v in _params(o).items():
            e["params"][k] = sorted(set(e["params"].get(k, [])) | set(v))
        if AUTH_RANK.get(o.get("auth"), 0) > AUTH_RANK[e["auth"]]:
            e["auth"], e["auth_basis"] = o["auth"], o.get("auth_basis")
        if o.get("status") and o["status"] not in e["status"]:
            e["status"].append(o["status"])
        if o["source"] not in e["sources"]:
            e["sources"].append(o["source"])
        if o.get("evidence") and o["evidence"] not in e["evidence"] and len(e["evidence"]) < 5:
            e["evidence"].append(o["evidence"])
        if o.get("operation") and len(e["operations"]) < 200:
            e["operations"].append(o["operation"])
        if o.get("code"):
            e["code"] = o["code"]
        if "{" in (o.get("path") or "") and e["path"] == tpl:   # keep a source's parameter names for reading
            e["example"] = e["example"] if e["example"].startswith("http") else o["path"]
    # a source route without a host joins the entry of the same path on a host
    hosted = {(m, t): e for (m, h, t), e in ents.items() if h}
    for key in [k for k in ents if not k[1]]:
        m, _, t = key
        twin = hosted.get((m, t))
        if twin:
            e = ents.pop(key)
            for s in e["sources"]:
                if s not in twin["sources"]:
                    twin["sources"].append(s)
            twin["evidence"] = (twin["evidence"] + [x for x in e["evidence"] if x not in twin["evidence"]])[:5]
            for k, v in e["params"].items():
                twin["params"][k] = sorted(set(twin["params"].get(k, [])) | set(v))
            if AUTH_RANK[e["auth"]] > AUTH_RANK[twin["auth"]]:
                twin["auth"], twin["auth_basis"] = e["auth"], e["auth_basis"]
            if e.get("code"):
                twin["code"] = e["code"]
    out = sorted(ents.values(), key=lambda e: (e["host"] or "", e["path"], e["method"]))
    for e in out:
        e["classes"] = applicable(e)
    srcs = {}
    for o in obs:
        srcs[o["source"]] = srcs.get(o["source"], 0) + 1
    return {"entries": out, "hosts": sorted({e["host"] for e in out if e["host"]}), "tech": sorted(tech),
            "schemas": schemas, "sources": srcs}


def applicable(e):
    """The vulnerability classes that apply to a map entry (CLASSES), from its method, parameters and auth."""
    names = [n for v in e["params"].values() for n in v]
    path_names = list(e["params"].get("path") or [])
    has_params = bool(names) or "{}" in e["path"]
    page = e["method"] == "GET" and not API_PATH.search(e["path"])
    out = []
    if "{}" in e["path"] or any(ID_PARAM.search(n) for n in names) or e["auth"] == "required":
        out.append("access-control")
    if e["auth"] == "required" or AUTH_PATH.search(e["path"]):
        out.append("authentication")
    if has_params or e["operations"]:
        out.append("injection")
    if (e["method"] == "GET" and e["params"].get("query")) or (e["method"] != "GET" and e["params"].get("body")):
        out.append("xss")
    if any(URL_PARAM.search(n) for n in names):
        out.append("ssrf")
    if any(DEST_PARAM.match(n) for n in names):
        out.append("open-redirect")
    if e["method"] in ("POST", "PUT", "PATCH") and (e["params"].get("body") or e["operations"]):
        out.append("mass-assignment")
    if any(FILE_PARAM.search(n) for n in names) or re.search(r"upload|file", e["path"], re.I):
        out.append("file-upload")
    if AUTH_PATH.search(e["path"]) or ("{}" in e["path"] and USER_PATH.search(e["path"])):
        out.append("user-enumeration")
    if AUTH_PATH.search(e["path"]):
        out.append("rate-limit")
    if INFO_PATH.search(e["path"]) or any(INFO_PARAM.search(n) for n in names):
        out.append("information-disclosure")
    if any(SEARCH_PARAM.search(n) for n in names) or path_names:
        out.append("redos")
    if e["method"] in ("POST", "PUT", "PATCH", "DELETE") and not API_PATH.search(e["path"]) \
            and not any(CSRF_PARAM.search(n) for n in names):
        out.append("csrf")
    if e["params"].get("body"):
        out.append("nosql-injection")
    if page:
        out.append("cors-misconfig")
        out.append("security-headers")
    if e["operations"] or re.search(r"graphql", e["path"], re.I):
        out += ["graphql-depth", "graphql-batching", "graphql-field-suggestions"]
    return out


def _class_of(item):
    """The vulnerability classes a plan item tests: from its area and refs, or from its title when those name none."""
    def find(text):
        text = text.lower()
        return [c for c, keys in CLASS_REFS.items() if c in text or any(k.lower() in text for k in keys)]
    return find(" ".join([item.get("area") or ""] + [r for r in item.get("refs") or [] if not ENTRY_RX.match(r)])) \
        or find(item.get("title") or "")


ORDER = ["planned", "blocked", "not-applicable", "excluded", "tested", "failed"]   # a cell takes its best item
DONE = ("tested", "failed", "excluded", "not-applicable")


def matrix(eng, plan=None):
    """The coverage matrix: each map entry x each class that applies to it, with the plan items that cover the cell.
    Returns {"cells": [...], "gaps": [...], "counts": {...}, "unmapped_items": [...]}."""
    import workspace
    m = build(eng)
    plan = plan if plan is not None else workspace.plan_list(eng)
    by_entry = {}
    unmapped = []
    for it in plan:
        eids = [r for r in it.get("refs") or [] if ENTRY_RX.match(r)]
        if not eids:
            unmapped.append(it["id"])
        for eid in eids:
            by_entry.setdefault(eid, []).append(it)
    cells, gaps = [], []
    for e in m["entries"]:
        for c in e["classes"]:
            items = [it for it in by_entry.get(e["id"], []) if c in _class_of(it)]
            state = max((it["state"] for it in items), key=lambda s: ORDER.index(s) if s in ORDER else 0) \
                if items else "gap"
            cell = {"entry": e["id"], "method": e["method"], "path": e["path"], "host": e["host"], "class": c,
                    "state": state, "items": [it["id"] for it in items]}
            cells.append(cell)
            if not items:
                gaps.append(cell)
    counts = {}
    for c in cells:
        counts[c["state"]] = counts.get(c["state"], 0) + 1
    done = sum(n for s, n in counts.items() if s in DONE)
    return {"entries": len(m["entries"]), "cells": cells, "gaps": gaps, "counts": counts,
            "complete": round(done / len(cells), 3) if cells else None, "unmapped_items": unmapped}


def check_refs(eng, refs):
    """Entry ids in a plan item's refs that aren't in the map (all of them when there is no map yet)."""
    eids = [r for r in refs or [] if ENTRY_RX.match(str(r))]
    if not eids:
        return []
    known = {e["id"] for e in build(eng)["entries"]}
    return [r for r in eids if r not in known] if known else eids


def _group(path):
    """The route group of a path template: its first two segments (/api/parcels/{}/notes -> /api/parcels)."""
    return "/".join(path.split("/")[:3])


def narrow_cell(engagement, pid):
    """The one coverage-matrix cell a plan item covers (#47): one vulnerability class, one map entry or route group."""
    import workspace
    item = next((i for i in workspace.plan_list(engagement) if i["id"] == pid), None)
    if not item:
        raise ValueError(f"no plan item {pid}")
    classes = _class_of(item)
    if len(classes) != 1:
        raise ValueError(f"{pid} must name one vulnerability class in its area or refs (it names "
                         f"{', '.join(classes) or 'none'}; classes: {', '.join(CLASSES)}): split it with "
                         "plan_tests and delegate each")
    eids = [r for r in item.get("refs") or [] if ENTRY_RX.match(r)]
    if not eids:
        raise ValueError(f"{pid} references no recon map entry (refs: [\"E-xxxxxx\", ...]; get_map lists them)")
    ents = {e["id"]: e for e in build(engagement)["entries"]}
    missing = [x for x in eids if x not in ents]
    if missing:
        raise ValueError(f"{pid} references entries not in the map: {', '.join(missing)}")
    if len({(ents[x]["host"], _group(ents[x]["path"])) for x in eids}) > 1:
        raise ValueError(f"{pid} spans more than one endpoint group ({', '.join(eids)}): one endpoint or one route "
                         "group (the same path prefix) per task")
    return {"plan_item": pid, "class": classes[0], "entries": eids,
            "endpoints": [f"{ents[x]['method']} {(ents[x]['host'] or '') + ents[x]['path']} ({x})" for x in eids]}
