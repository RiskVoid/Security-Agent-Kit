"""Recon map before testing (epic #52, issue #46).

A deterministic picture of a web target before any vulnerability testing, built by the harness rather than recalled
by the model:

  crawl      katana in the sandbox (the run broker: scope, tier, rate, audit), links and JavaScript, robots and
             sitemap; only in-scope URLs are kept
  scripts    API paths the crawled JavaScript names ("/api/...", "/rest/...": single-page apps call them from code
             a crawler doesn't follow); up to MAX_SCRIPTS files
  schemas    OpenAPI / Swagger documents at the usual paths, and a GraphQL endpoint (a read-only introspection query
             by GET; a POST would need an approval)
  probe      one GET without credentials to each path the crawl didn't fetch (up to MAX_PROBES), for its status:
             401, 403 or a login redirect means it needs authentication
  tech       Server, X-Powered-By and framework cookies of the responses, and the schema's own info

Every request goes through the execution broker (actions.send) or the run broker (core.run): nothing bypasses scope,
tiers or the audit log. The result is evidence/map/map-<time>.json (audited, so its provenance verifies); the
investigation workspace merges it with the Laravel source map, imported captures and the agent's own requests into
the map the planner plans from (harness/reconmap.py).
"""
import datetime, json, os, re, urllib.parse

import actions
import core
import policy as rvpolicy

MAX_SCRIPTS, MAX_PROBES, MAX_ENTRIES = 12, 60, 2000
SCHEMA_PATHS = ("/openapi.json", "/swagger.json", "/v3/api-docs", "/v2/api-docs", "/api-docs", "/api/openapi.json",
                "/api/swagger.json", "/swagger/v1/swagger.json", "/api/docs/openapi.json", "/openapi.yaml")
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/graphiql")
STATIC = re.compile(r"\.(?:js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|webp|avif|mp4|webm|pdf)$", re.I)
API_PREFIX = r"(?:api|rest|graphql|v[1-9]|auth|oauth2?|admin|users?|accounts?|login|logout|register|signup|b2b|" \
             r"internal|private|ws|webhooks?|upload|files?|search|profile|me)"
JS_PATH = re.compile(r"""["'`](/""" + API_PREFIX + r"""(?:/[A-Za-z0-9_\-.{}:$]*)*)["'`]""")
LOGIN = re.compile(r"log-?in|sign-?in|/auth|sso|oauth", re.I)
COOKIE_TECH = {"phpsessid": "PHP", "laravel_session": "Laravel", "xsrf-token": None, "jsessionid": "Java",
               "asp.net_sessionid": "ASP.NET", "connect.sid": "Express", "csrftoken": "Django", "sessionid": None,
               "_rails_session": "Rails", "ci_session": "CodeIgniter", "symfony": "Symfony", "wordpress_": "WordPress"}
INTROSPECT = "{__schema{queryType{name}mutationType{name}types{name kind fields{name args{name}}}}}"


def auth_from(status, location=""):
    """What an unauthenticated response says about authentication: required, none or unknown."""
    if status in (401, 403):
        return "required"
    if status and 300 <= status < 400 and LOGIN.search(location or ""):
        return "required"
    if status and 200 <= status < 300:
        return "none"
    return "unknown"


def _hdr(headers, name):
    if isinstance(headers, dict):
        headers = headers.items()
    return next((v for k, v in headers or [] if k.lower() == name), "")


def tech_of(headers):
    out = []
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        v = _hdr(headers, name)
        if v:
            out.append(f"{name}: {v}"[:120])
    cookies = _hdr(headers, "set-cookie").lower()
    for k, v in COOKIE_TECH.items():
        if v and k in cookies:
            out.append(f"cookie {k}: {v}")
    return out


def openapi_entries(doc, base):
    """Operations of an OpenAPI 3 / Swagger 2 document: method, path, parameters, whether it needs authentication."""
    out = []
    prefix = ""
    if doc.get("basePath"):
        prefix = doc["basePath"].rstrip("/")
    elif doc.get("servers"):
        u = urllib.parse.urlsplit(str((doc["servers"][0] or {}).get("url") or ""))
        prefix = u.path.rstrip("/")
    top = doc.get("security")
    for path, ops in (doc.get("paths") or {}).items():
        if not isinstance(ops, dict):
            continue
        shared = ops.get("parameters") or []
        for method, op in ops.items():
            if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS") or \
                    not isinstance(op, dict):
                continue
            params = {"query": [], "path": [], "body": [], "header": []}
            for p in shared + (op.get("parameters") or []):
                if isinstance(p, dict) and p.get("name"):
                    where = {"formData": "body"}.get(p.get("in"), p.get("in"))
                    if where in params:
                        params[where].append(p["name"])
            body = (((op.get("requestBody") or {}).get("content") or {}))
            for media in body.values():
                props = ((media or {}).get("schema") or {}).get("properties") or {}
                params["body"] += list(props)[:40]
            sec = op.get("security", top)
            out.append({"method": method.upper(), "url": urllib.parse.urljoin(base, prefix + path), "source": "openapi",
                        "params": {k: sorted(set(v)) for k, v in params.items() if v},
                        "auth": "required" if sec else ("none" if sec == [] else "unknown"),
                        "auth_basis": "the schema's security" if sec is not None else None,
                        "summary": str(op.get("summary") or op.get("operationId") or "")[:120]})
    return out


def _parse(body, url):
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body or "")
    try:
        return json.loads(text)
    except ValueError:
        if url.endswith((".yaml", ".yml")):
            try:
                import yaml
                return yaml.safe_load(text)
            except Exception:  # noqa: BLE001
                return None
    return None


def build(eng, url, depth=2, crawl_seconds=120, probe=True, max_tier=None, task=None):
    """Map one web target. Returns the summary text; the map is saved as evidence/map/map-<time>.json."""
    i = core.info(eng)
    entry = {"engagement": eng, "uid": i["uid"], "action": "recon_map", "url": url, **({"task": task} if task else {})}
    pol = core.policy_of(eng)
    why = rvpolicy.check_url(pol, url)
    if why:
        core._audit({**entry, "refused": why})
        return f"REFUSED: {url} is not in scope: {why}"
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        return "REFUSED: url must be http(s)://host[:port][/path]"
    base = f"{u.scheme}://{u.netloc}"
    depth = max(1, min(int(depth or 2), 5))
    crawl_seconds = max(20, min(int(crawl_seconds or 120), 900))
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
    tag = f"{ts}-{os.urandom(2).hex()}"
    try:
        actions.work_dir(eng, "evidence", "map")
    except actions.Refused as e:
        return f"REFUSED: {e}"
    notes, obs, tech, schemas, evidence = [], [], [], [], []
    send = lambda m, target, **kw: actions.send(eng, m, target, {"Accept": kw.pop("accept", "*/*")}, b"", None,
                                                max_tier, task, evidence_kind="map")

    def add(o):
        if len(obs) < MAX_ENTRIES and not rvpolicy.check_url(pol, o["url"]):
            obs.append(o)

    # ---------------------------------------------------------------- crawl
    crawl = f"evidence/map/crawl-{tag}.jsonl"
    cmd = (f"katana -u {core.shlex.quote(url)} -d {depth} -jc -kf all -fs fqdn -silent -jsonl -omit-raw -omit-body "
           f"-ct {crawl_seconds}s -o {crawl}")
    res = core.run(cmd, eng, timeout_s=crawl_seconds + 60, max_tier=max_tier, task=task)
    if res.startswith("REFUSED") or res.startswith("APPROVAL"):
        notes.append("crawl not run: " + res.splitlines()[0][:300])
    scripts = []
    try:
        lines = open(os.path.join(core.WORK, eng, crawl), errors="replace").read().splitlines()
        evidence.append(crawl)
    except OSError:
        lines = []
        if not notes:
            notes.append("the crawl wrote no output")
    for line in lines:
        try:
            r = json.loads(line)
        except ValueError:
            continue
        req, resp = r.get("request") or {}, r.get("response") or {}
        ep = req.get("endpoint") or ""
        if not ep:
            continue
        st = resp.get("status_code")
        hdrs = resp.get("headers") or {}
        tech += tech_of(hdrs) + [f"detected: {t}" for t in resp.get("technologies") or []]
        if re.search(r"\.m?js(\?|$)", urllib.parse.urlsplit(ep).path + "?") and st == 200:
            scripts.append(ep)
        if STATIC.search(urllib.parse.urlsplit(ep).path):
            continue
        q = sorted(urllib.parse.parse_qs(urllib.parse.urlsplit(ep).query, keep_blank_values=True))
        form = sorted({x for x in re.findall(r"name=([\w\[\].-]+)", req.get("body") or "")})
        add({"method": (req.get("method") or "GET").upper(), "url": ep, "source": "crawl", "status": st,
             "params": {k: v for k, v in (("query", q), ("body", form)) if v},
             "auth": auth_from(st, _hdr(hdrs, "location")) if st else "unknown",
             "auth_basis": f"status {st} without credentials" if st else None})

    # ---------------------------------------------------------------- scripts
    seen = set()
    for js in list(dict.fromkeys(scripts))[:MAX_SCRIPTS]:
        r = send("GET", js)
        if r.get("status") != 200:
            continue
        evidence.append(r["evidence"])
        for p in JS_PATH.findall(r["body"].decode("utf-8", "replace")):
            p = re.sub(r"\$\{[^}]*\}|:\w+", "{id}", p).rstrip("/") or "/"
            if p not in seen and not STATIC.search(p):
                seen.add(p)
                add({"method": "GET", "url": urllib.parse.urljoin(base, p), "source": "script", "status": None,
                     "params": {}, "auth": "unknown", "auth_basis": None, "named_in": js})
    if len(scripts) > MAX_SCRIPTS:
        notes.append(f"{len(scripts) - MAX_SCRIPTS} more scripts not read")

    # ---------------------------------------------------------------- schemas
    found = {o["url"] for o in obs}
    cands = [p for p in SCHEMA_PATHS] + [urllib.parse.urlsplit(x).path for x in found
                                         if re.search(r"(openapi|swagger|api-docs)[^/]*\.(json|ya?ml)$", x)]
    for p in dict.fromkeys(cands):
        r = send("GET", urllib.parse.urljoin(base, p), accept="application/json")
        if r.get("status") != 200:
            continue
        doc = _parse(r.get("body") or b"", p)
        if isinstance(doc, dict) and (doc.get("openapi") or doc.get("swagger")) and doc.get("paths"):
            ents = openapi_entries(doc, base)
            schemas.append({"kind": "openapi", "url": urllib.parse.urljoin(base, p), "operations": len(ents),
                            "title": str((doc.get("info") or {}).get("title") or "")[:120],
                            "version": str((doc.get("info") or {}).get("version") or "")[:40],
                            "evidence": r["evidence"]})
            evidence.append(r["evidence"])
            for e in ents:
                add(e)
            break
    gql = [x for x in found if re.search(r"/graph(i)?ql/?$", urllib.parse.urlsplit(x).path)]
    for target in dict.fromkeys(gql + [urllib.parse.urljoin(base, p) for p in GRAPHQL_PATHS]):
        r = send("GET", target + "?query=" + urllib.parse.quote(INTROSPECT), accept="application/json")
        st = r.get("status")
        if st is None or st == 404:
            continue
        doc = _parse(r.get("body") or b"", target)
        types = (((doc or {}).get("data") or {}).get("__schema") or {}).get("types") if isinstance(doc, dict) else None
        if types or (isinstance(doc, dict) and ("errors" in doc or "data" in doc)):
            info = {"kind": "graphql", "url": target, "evidence": r["evidence"], "introspection": bool(types)}
            evidence.append(r["evidence"])
            if types:
                schema = doc["data"]["__schema"]
                roots = {(schema.get("queryType") or {}).get("name"): "query",
                         (schema.get("mutationType") or {}).get("name"): "mutation"}
                ops = [(roots[t["name"]], f["name"], [a["name"] for a in f.get("args") or []])
                       for t in types if t.get("name") in roots and t.get("fields") for f in t["fields"]]
                info["operations"] = len(ops)
                for kind, name, args in ops[:300]:
                    add({"method": "POST", "url": target, "source": "graphql", "operation": f"{kind} {name}",
                         "params": {"args": args} if args else {}, "auth": "unknown", "auth_basis": None,
                         "status": None})
            else:
                info["note"] = ("introspection by GET gave no schema; graphw00f / clairvoyance (or an approved POST) "
                                "can fingerprint it")
                add({"method": "POST", "url": target, "source": "graphql", "params": {}, "status": st,
                     "auth": auth_from(st), "auth_basis": f"status {st} without credentials"})
            schemas.append(info)
            break

    # ---------------------------------------------------------------- probe
    if probe:
        todo, done = [], {(o["method"], o["url"]) for o in obs if o.get("status")}
        for o in obs:
            if o["method"] == "GET" and o["auth"] == "unknown" and not o.get("status") and \
                    ("GET", o["url"]) not in done:
                todo.append(o)
                done.add(("GET", o["url"]))
        for o in todo[:MAX_PROBES]:
            target = re.sub(r"\{[^}/]*\}", "1", o["url"])
            r = send("GET", target)
            st = r.get("status")
            if st is None:
                continue
            o["status"] = st
            o["auth"] = auth_from(st, _hdr(r.get("headers"), "location"))
            o["auth_basis"] = f"status {st} without credentials (probe)"
            o["probe_evidence"] = r["evidence"]
            tech += tech_of(r.get("headers"))
        if len(todo) > MAX_PROBES:
            notes.append(f"{len(todo) - MAX_PROBES} paths not probed (MAX_PROBES)")

    doc = {"version": 1, "base": base, "url": url, "at": ts, "depth": depth, "observations": obs,
           "schemas": schemas, "tech": sorted(set(tech)), "notes": notes, "evidence": evidence}
    rel = f"evidence/map/map-{tag}.json"
    full = os.path.join(core.WORK, eng, rel)
    with open(full, "w") as f:
        json.dump(doc, f, indent=1)
    if os.geteuid() == 0:
        os.chown(full, i["uid"], i["uid"], follow_symlinks=False)
    core._audit({**entry, "command": f"recon_map {url}", "tier": "active", "observations": len(obs),
                 "schemas": [s["kind"] for s in schemas], "outputs": {rel: core.sha256_file(full)}})
    by = {}
    for o in obs:
        by[o["source"]] = by.get(o["source"], 0) + 1
    auth = {}
    for o in obs:
        auth[o["auth"]] = auth.get(o["auth"], 0) + 1
    text = [f"Recon map of {base}: {len(obs)} request(s) observed ("
            + ", ".join(f"{n} {k}" for k, n in sorted(by.items())) + "); authentication: "
            + ", ".join(f"{n} {k}" for k, n in sorted(auth.items())) + "."]
    for s in schemas:
        text.append(f"  {s['kind']} at {s['url']}" + (f": {s.get('operations')} operation(s)" if s.get("operations")
                                                      else "") + (f" ({s['note']})" if s.get("note") else ""))
    if doc["tech"]:
        text.append("  tech: " + "; ".join(doc["tech"][:12]))
    text += [f"  note: {n}" for n in notes]
    text.append("get_map (findings) shows the merged map with entry ids (E-xxxxxx) to reference in plan_tests.")
    text.append(f"[map saved as verified evidence: /work/{eng}/{rel}]")
    return core.scrub(eng, "\n".join(text))
