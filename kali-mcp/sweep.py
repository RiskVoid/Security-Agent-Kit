"""Harness-run checks for web and API targets (epic #76, issues #67 to #71).

The model proposes; on black-box targets the harness also checks. probe_map reads the recon map's evidence
(evidence/map/map-*.json: every request any source saw) and runs fixed checks against every entry and
parameter they apply to — the checks the error analysis showed the model doesn't reliably think of:

  injection        an error-based probe and a boolean true/false pair on every parameter of a read, path
                   parameters included. A hit is recorded only when the responses differ the way the probe
                   predicts. (#68)
  cors             an Origin-probe matrix (a foreign origin and the null origin) on entries a browser can
                   call; a hit names whether credentials are allowed too. (#W5)
  headers          the security-header checklist on pages (CSP, nosniff, framing; HSTS over https): what is
                   missing is named. (#W5)
  mass-assignment  every write with a JSON body gets a throwaway object carrying one privileged field, then the
                   object is read back logged in as it and compared with a control object without the field. (#70)
  redos            string fields the target validates get inputs of growing length built to backtrack, timed
                   each time, stopped at the first clear growth. (#71)
  jwt              every JWT the engagement's evidence or this sweep holds is cracked offline against a list of
                   common secrets; a token forged with the cracked key is tried against an authenticated
                   endpoint, with the original as the control. (#69)

Every probe and its negative control go through actions.send: scope, tiers, rate, the request budget, evidence
and the audit log, exactly as the agent's own requests. Reads run immediately. The checks that write (a
throwaway registration, a login) send nothing on the first call: probe_map computes the exact requests and
proposes them as ONE authorization matrix (authz.propose, with the throwaway accounts listed and the reason
there is no cleanup), and a second call with matrix=<name> runs only what that approval covers, every request
recorded as authorized by it. A check whose tier the rules exclude doesn't run, an out-of-scope URL is refused,
and the request count is capped (max_requests). Hits go to evidence/sweep/sweep-<ts>.json and import as
observations (parser "sweep"): the planner still triages, confirms and verifies them as findings.
"""
import datetime, hashlib, hmac, base64, json, os, re, time, urllib.parse

import core
import actions
import authz

# ---------------------------------------------------------------- the map's entries, from the recon evidence

NUM = re.compile(r"^\d+$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
VAR_SEG = re.compile(r"^\{[^}]*\}$|^:[A-Za-z_]\w*$")

SQL_ERR = re.compile(r"sqlalchemy|sqlite3|mysql|postgres|psycopg|operationalerror|syntax error|unrecognized token"
                     r"|werkzeug debugger|interactive traceback|sqli\b", re.I)
VALIDATION_ERR = re.compile(r"valid|format|proper|schema|malformed|invalid|expected", re.I)
JWT_RX = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
PRIV_FIELDS = ("admin", "is_admin", "isAdmin", "role", "user_type", "verified")
REDOS_LEN = (16, 20, 24)
SELF_PATH = re.compile(r"^/?((api|v\d)[/-])?(me|self|profile|whoami|account|user)(/|$)", re.I)
LOGIN_PATH = re.compile(r"log-?in|signin|session|token", re.I)
SAFE = ("GET", "HEAD", "OPTIONS")
API_PATH = re.compile(r"^/(api|vapi|v\d[\w-]*|graphql|rest)(/|$)", re.I)   # the page check skips API paths
JSON_HDR = {"Content-Type": "application/json"}
SECRET_WORDS = ("random", "secret", "password", "changeme", "your-256-bit-secret", "supersecret", "super-secret-key",
                "mysecretkey", "secretkey", "jwt_secret", "jwtsecret", "flask", "admin", "qwerty", "abc123",
                "letmein", "welcome", "monkey", "dragon", "secret_key", "s3cr3t", "dev", "development", "default",
                "123456", "1234567890", "hackme", "thisisasecret", "my-secret", "app_secret", "application_secret",
                "private_key", "signing_key", "key", "test")
SWEEP_PASSWORD = "Passw0rd!sweep"


def template(path):
    segs = []
    for s in (path or "/").split("/"):
        if NUM.fullmatch(s) or UUID.match(s) or VAR_SEG.fullmatch(s) or re.fullmatch(r"[0-9a-f]{16,}", s, re.I):
            s = "{}"
        segs.append(s)
    return "/".join(segs).rstrip("/") or "/"


def _eid(method, host, tpl):
    return "E-" + hashlib.sha1(f"{method} {host or '*'} {tpl}".encode()).hexdigest()[:6]


def entries(eng):
    """The map's entries from the recon evidence: {id, method, host, path, example, params, auth}."""
    import glob as _glob
    ents = {}
    for p in _glob.glob(os.path.join(core.WORK, eng, "evidence", "map", "map-*.json")):
        try:
            with open(p, errors="replace") as f:
                d = json.load(f)
        except (OSError, ValueError):
            continue
        for o in d.get("observations") or []:
            if not o.get("url"):
                continue
            u = urllib.parse.urlsplit(o["url"])
            method = (o.get("method") or "GET").upper()
            tpl = template(u.path)
            key = (method, u.netloc, tpl)
            e = ents.get(key)
            if not e:
                e = ents[key] = {"id": _eid(method, u.netloc, tpl), "method": method, "host": u.netloc,
                                 "path": tpl, "example": o["url"], "params": {}, "auth": o.get("auth") or "unknown",
                                 "seen_by": []}
            if o.get("seen_by") and o["seen_by"] not in e["seen_by"]:
                e["seen_by"].append(o["seen_by"])
            params = dict(o.get("params") or {})
            q = sorted(urllib.parse.parse_qs(u.query, keep_blank_values=True))
            if q:
                params["query"] = sorted(set(params.get("query", [])) | set(q))
            for where, names in params.items():
                e["params"][where] = sorted(set(e["params"].get(where, [])) | set(names or []))
    for e in ents.values():
        # path parameters are positions: the map's template says how many the path has
        e["params"]["path"] = list(range(e["path"].count("{}")))
        e["params"].setdefault("query", [])
        e["params"].setdefault("body", [])
    return sorted(ents.values(), key=lambda e: (e["host"], e["path"], e["method"]))


def _path_sub(url, index, value):
    parts, seen = url.split("/"), 0
    for i, s in enumerate(parts):
        if s and (NUM.fullmatch(s) or UUID.match(s) or VAR_SEG.fullmatch(s)):
            if seen == index:
                parts[i] = urllib.parse.quote(str(value), safe="")
                break
            seen += 1
    return "/".join(parts)


def _url_with(url, where, param, value):
    """The entry's URL with one parameter replaced by the probe value."""
    if where == "path":
        return _path_sub(url, int(param), value)
    u = urllib.parse.urlsplit(url)
    q = [(k, str(value) if k == param else v) for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True)] \
        or [(param, str(value))]
    return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, urllib.parse.urlencode(q), ""))


def _body_with(names, param, value):
    """A JSON body from the map's parameter names, one field carrying the probe value."""
    return {**{n: "sweep" for n in names}, param: value}


# ---------------------------------------------------------------- the request context

class Ctx:
    """One sweep run: the request budget, the evidence paths, the tokens seen and the rows recorded."""

    def __init__(self, eng, budget, task):
        self.eng, self.budget, self.task = eng, budget, task
        self.authorized_by = None      # set while the approved sweep matrix's requests run
        self.requests = 0
        self.evidence, self.tokens, self.rows, self.created = [], set(), [], []

    def send(self, method, url, headers=None, body=None, identity=None, timeout_s=30):
        """One probe or control request through the broker. Returns (status, body_text, evidence, seconds,
        resp_headers) — resp_headers as {lower-cased name: value}."""
        if self.requests >= self.budget:
            return None, "REFUSED: the sweep's request budget is used up", None, 0.0, {}
        self.requests += 1
        data = json.dumps(body).encode() if isinstance(body, (dict, list)) else str(body or "").encode()
        r = actions.send(self.eng, method, url, headers or {}, data, identity=identity, task=self.task,
                         authorized_by=self.authorized_by, evidence_kind="sweep", timeout_s=timeout_s)
        ev = f"/work/{self.eng}/{r['evidence']}" if r.get("evidence") else None
        if ev:
            self.evidence.append(ev)
        text = r.get("text") or ""
        for tok in JWT_RX.findall(text):
            self.tokens.add(tok)
        secs = sum(h.get("seconds") or 0 for h in r.get("hops") or [])
        hdrs = {str(k).lower(): str(v) for k, v in (r.get("headers") or [])}
        if r.get("refused") or r.get("approval"):
            return None, text, ev, secs, hdrs
        b = r.get("body") or b""
        return r.get("status"), (b.decode("utf-8", "replace") if isinstance(b, bytes) else str(b)), ev, secs, hdrs


def _hit(check, e, where, param, why, evidence, suggest):
    return {"check": check, "entry": e.get("id", ""), "method": e.get("method", ""), "path": e.get("path", ""),
            "where": where, "param": str(param), "result": "hit", "why": why, "evidence": [x for x in evidence if x],
            "suggest": suggest}


def _row(check, e, where, param, result, why="", evidence=()):
    return {"check": check, "entry": e.get("id", ""), "where": where, "param": str(param), "result": result,
            "why": str(why)[:300], "evidence": [x for x in evidence if x]}


# ---------------------------------------------------------------- the checks

def check_injection(eng, e, ctx, identity=None):
    """#68: an error-based probe and a boolean true/false pair on every parameter of a read, path parameters
    included. A hit is recorded only when the responses differ the way the probe predicts. identity: the
    engagement identity the reads run as (an authenticated entry the sweep couldn't reach without it, #137)."""
    out = []
    if e["method"] not in SAFE:
        return out                                   # a write parameter runs under the sweep matrix, not here
    targets = [("path", i) for i in e["params"]["path"]] + [("query", n) for n in e["params"].get("query") or []]
    for where, param in targets:
        url0 = e["example"]
        st_err, err_text, ev_err, _, _h_err = ctx.send(e["method"], _url_with(url0, where, param, "sweep'"),
                                                       identity=identity)
        st_ctl, ctl_text, ev_ctl, _, _h_ctl = ctx.send(e["method"], _url_with(url0, where, param, "sweep"),
                                                        identity=identity)
        if st_err is None and st_ctl is None:
            out.append(_row("injection", e, where, param, "skip", "the requests were refused or need an approval",
                            [ev_err, ev_ctl]))
            return out
        if SQL_ERR.search(err_text or "") and not SQL_ERR.search(ctl_text or ""):
            out.append(_hit("injection", e, where, param,
                            "error-based: the target returned a database error for a quote in the value and not "
                            "for the control", [ev_err, ev_ctl],
                            "confirm with sqlmap -u '<url>' (an intrusive command: it needs an approval)"))
            return out
        st_t, t_text, ev_t, _, _ = ctx.send(e["method"], _url_with(url0, where, param, "sweep' or '1'='1"),
                                             identity=identity)
        st_f, f_text, ev_f, _, _ = ctx.send(e["method"], _url_with(url0, where, param, "sweep' or '1'='2"),
                                             identity=identity)
        if t_text and f_text and t_text != f_text and (f_text == ctl_text or t_text != ctl_text):
            out.append(_hit("injection", e, where, param,
                            "boolean-based: the '1'='1 and '1'='2 answers differ, and the control answer matches "
                            "the false one", [ev_t, ev_f, ev_ctl],
                            "confirm with sqlmap -u '<url>' (an intrusive command: it needs an approval)"))
            return out
        out.append(_row("injection", e, where, param, "clean", "the error and boolean probes didn't change the "
                        "answer", [ev_err, ev_ctl]))
    return out


def check_redos(eng, e, ctx, token=None):
    """#71: string fields whose malformed value is answered with a validation error get inputs of growing length
    built to backtrack, timed each time. A hit needs a clear growth (later than three times the earlier steps
    and over a second), and the ladder stops at the first clear growth — never at the sizes that stop a target.
    Unauthenticated reads run in the read phase; an authenticated field runs with a session the sweep gained
    from its own logins, under the sweep matrix's authorization."""
    out = []
    if not token and (e["method"] not in SAFE or e["auth"] == "required"):
        return out
    if token and e["method"] not in SAFE and not e["params"]["path"]:
        return out                                   # a write to the app's own object creation: not the sweep's account
    hdr = {"Authorization": "Bearer " + token, **JSON_HDR} if token else JSON_HDR
    url0 = e["example"]
    if token and e["params"]["path"]:       # an authenticated path parameter: the token names whose object it is
        try:
            sub = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "==").decode()).get("sub")
        except ValueError:
            sub = None
        if sub:
            url0 = _path_sub(url0, 0, sub)
    targets = ([("query", n) for n in e["params"].get("query") or []] +
               ([("body", n) for n in e["params"].get("body") or []] if e["method"] not in SAFE else []))
    for where, param in targets:
        def send(value):
            if where == "body":
                return ctx.send(e["method"], url0, hdr, _body_with(e["params"]["body"], param, value),
                                timeout_s=10)
            return ctx.send(e["method"], _url_with(url0, where, param, value), hdr, None, timeout_s=10)
        st, text, ev, secs, _ = send("sweep{{7*7")
        if st is None or not VALIDATION_ERR.search(text or ""):
            continue                                   # not a validated field: nothing to time
        times = [(8, secs, ev)]
        for n in REDOS_LEN:
            st, text, ev, secs, _ = send("a" * n + "@")
            if secs is None:
                break
            times.append((n, secs, ev))
            before = max(t for _, t, _ in times[:-1])   # a one-off slow blip raises the bar for later steps
            if secs > 0.25 and secs > 3 * max(before, 0.1):
                series = ", ".join(f"{l}: {t:.2f}s" for l, t, _ in times)
                out.append(_hit("redos", e, where, param,
                                f"the response time grew with the input length ({series}), past three times the "
                                "earlier steps", [v for _, _, v in times],
                                "keep the input short: the timing series is the proof; a size that stops the "
                                "target is never sent"))
                return out
        out.append(_row("redos", e, where, param, "clean", "the validated field answers fast at every length",
                        [v for _, _, v in times][:2]))
    return out


def check_cors(eng, e, ctx, identity=None):
    """W5: an Origin-probe matrix on entries a browser can call (the cors-misconfig class): a foreign origin
    and the null origin. A hit when an arbitrary origin is allowed (wildcard or reflected), naming whether
    credentials are allowed too; a hostile page reading the response cross-origin is the impact."""
    out = []
    if e["method"] not in SAFE:
        return out
    url = _url_with(e["example"], "path", 0, "sweep") if e["params"]["path"] else e["example"]
    foreign = f"https://sweep-{os.urandom(3).hex()}.example.org"
    hits, evs = [], []
    for origin in (foreign, "null"):
        st, text, ev, _, hdrs = ctx.send("GET", url, {"Origin": origin}, identity=identity)
        if st is None:
            return out                                   # refused or an approval: nothing to conclude
        acao = (hdrs.get("access-control-allow-origin") or "").strip()
        acac = (hdrs.get("access-control-allow-credentials") or "").strip().lower()
        evs.append(ev)
        if acao in ("*", origin):
            hits.append(f"Origin {origin} is allowed ({'wildcard' if acao == '*' else 'reflected'}"
                        + (", with credentials" if acac == "true" else ""))
    if hits:
        cred = any("credentials" in h for h in hits)
        out.append(_hit("cors", e, "origin", foreign, "; ".join(hits)
                        + (" - a cross-origin page reads this response with the target's cookies"
                           if cred else " - a cross-origin page can read this response (cookies are not sent)"),
                        evs, "confirm by fetching the URL from another origin in the browser"))
    elif evs:
        out.append(_row("cors", e, "origin", foreign, "clean", "no arbitrary origin is allowed", evs[:1]))
    return out


SEC_HEADERS = ("content-security-policy", "x-content-type-options", "x-frame-options")
HSTS = "strict-transport-security"


def check_headers(eng, e, ctx, identity=None):
    """W5: the security-header checklist on a page a browser loads (the security-headers class): what is
    missing is named; HSTS is only required over https. A policy's presence counts here - judging its
    quality is the planner's, after the finding is confirmed."""
    out = []
    if e["method"] != "GET" or API_PATH.search(e["path"]):
        return out
    url = _path_sub(e["example"], 0, "sweep") if e["params"]["path"] else e["example"]
    st, text, ev, _, hdrs = ctx.send("GET", url, identity=identity)
    if st is None:
        return out
    want = list(SEC_HEADERS) + ([HSTS] if url.lower().startswith("https") else [])
    missing = [h for h in want if h not in hdrs]
    if missing:
        out.append(_hit("headers", e, "", url, f"missing security header(s): {', '.join(missing)}", [ev],
                        "the finding is the missing header list; the evidence file holds the response"))
    else:
        out.append(_row("headers", e, "", url, "clean", "the page sends the security headers", [ev]))
    return out


def _crack(tok):
    head, payload, sig = tok.split(".")
    for word in SECRET_WORDS:
        mac = hmac.new(word.encode(), f"{head}.{payload}".encode(), "sha256").digest()
        if base64.urlsafe_b64encode(mac).rstrip(b"=").decode() == sig:
            return word
    return None


def _forge(claims, secret):
    head = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    mac = hmac.new(secret.encode(), f"{head}.{payload}".encode(), "sha256").digest()
    return f"{head}.{payload}.{base64.urlsafe_b64encode(mac).rstrip(b'=').decode()}"


def check_jwt(eng, ents, ctx):
    """#69: crack every JWT the engagement's evidence or this sweep holds against a list of common secrets,
    then try a token forged with the cracked key against an authenticated read, with the original as control."""
    import glob as _glob
    out, toks = [], set(ctx.tokens)
    for p in _glob.glob(os.path.join(core.WORK, eng, "evidence", "http", "*.txt"))[-500:]:
        try:
            with open(p, errors="replace") as f:
                toks |= set(JWT_RX.findall(f.read(4000)))
        except OSError:
            pass
    if not toks:
        out.append({"check": "jwt", "entry": "", "where": "", "param": "", "result": "skip",
                    "why": "no JWT was seen in the evidence or in this sweep's responses", "evidence": []})
        return out
    protected = [e for e in ents if e["method"] in SAFE and e["auth"] == "required" and e["example"]]
    protected.sort(key=lambda e: not SELF_PATH.fullmatch(e["path"]))   # a self endpoint shows the account's own data
    seen_secrets = set()
    for tok in sorted(toks)[:8]:
        secret = _crack(tok)
        if secret is None:
            out.append(_row("jwt", {}, "", tok[:24], "clean", "the signature did not match any common secret"))
            continue
        if secret in seen_secrets:                    # one finding per weak key, not one per token
            continue
        seen_secrets.add(secret)
        try:
            claims = json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "==").decode())
        except ValueError:
            claims = {}
        forged = _forge(claims, secret)                # the target's own claims, our signature: acceptance proves key control
        row = _hit("jwt", protected[0] if protected else {}, "", "HS256",
                   "the token's HMAC key is a common secret (redacted here: kept in the sweep evidence); a "
                   "token forged with it was ", [], "confirm by sending the forged token (in the sweep evidence) "
                   "against the authenticated endpoint yourself")
        row["secret_in_evidence"] = secret
        row["claims"] = claims
        if protected:
            st_f, _, ev_f, _, _ = ctx.send("GET", protected[0]["example"], {"Authorization": "Bearer " + forged})
            st_o, _, ev_o, _, _ = ctx.send("GET", protected[0]["example"], {"Authorization": "Bearer " + tok})
            row["evidence"] = [ev_f, ev_o]
            if st_f == 200 and st_o == 200:
                row["entry"], row["path"] = protected[0]["id"], protected[0]["path"]
                row["why"] += "accepted where the original is accepted"
            else:
                row["why"] += ("not accepted by the authenticated endpoint here (the cracked key stands; the "
                               "acceptance needs the target's verifier)")
        out.append(row)
    return out


# ---------------------------------------------------------------- the write phase (mass assignment, #70)

def mass_targets(ents):
    """(entry, login entry, self entry, fields) for every object-creating write with a JSON body: a throwaway
    object carrying one privileged field, read back logged in as it, against a control object without the field.
    Only POSTs: a PUT or PATCH updates something that must exist, and a login endpoint isn't object creation."""
    out = []
    for e in ents:
        if e["method"] != "POST" or LOGIN_PATH.search(e["path"]) or not (e["params"].get("body") or []):
            continue
        if not any(re.search(r"username|email|account|user|name", n, re.I) for n in e["params"]["body"]):
            continue                                  # creates an object, not an account: nothing to log in as
        host = [x for x in ents if x["host"] == e["host"]]
        login = next((x for x in host if LOGIN_PATH.search(x["path"]) and x["method"] == "POST"), None)
        self_e = next((x for x in host if SELF_PATH.fullmatch(x["path"]) and x["method"] in SAFE), None)
        out.append({"entry": e, "login": login, "self": self_e, "fields": list(PRIV_FIELDS)})
    return out


def propose_writes(eng, ents, ctx):
    """One authorization matrix for the sweep's write plan: the exact register and login requests for every
    privileged field, the throwaway accounts listed, and the reason there is no cleanup (nothing exists to
    delete them with, and their credentials are in this evidence)."""
    import urllib.parse as up
    ops, users = [], []
    base = os.urandom(4).hex()
    for t_i, t in enumerate(mass_targets(ents)):
        e = t["entry"]
        for i, field in enumerate(t["fields"]):
            for kind in ("ctl", "prb"):
                user = f"sweep-{base}-{t_i}-{i}-{kind}"
                users.append(user)
                body = {"username": user, "email": f"{user}@sweep.test", "password": SWEEP_PASSWORD,
                        **{n: "sweep" for n in e["params"]["body"]
                           if n not in ("username", "email", "password")}}
                if kind == "prb":
                    body[field] = True
                ops.append({"id": f"reg-{t_i}-{i}-{kind}", "method": e["method"], "url": e["example"],
                            "headers": JSON_HDR, "body": json.dumps(body), "effect": "write"})
                if t["login"]:
                    ops.append({"id": f"login-{t_i}-{i}-{kind}", "method": "POST", "url": t["login"]["example"],
                                "headers": JSON_HDR,
                                "body": json.dumps({"username": user, "password": SWEEP_PASSWORD}), "effect": "write"})
    if not ops:
        return None
    ctx.created += users
    name = f"sweep-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
    matrix = {"operations": ops, "identities": [], "expect": {}, "allow_writes": True, "max_writes": len(ops),
              "cleanup": [],
              "no_cleanup_reason": "the sweep creates only its own throwaway accounts "
                                    f"({', '.join(users)}; credentials in the sweep evidence); the map has no "
                                    "delete for them",
              "purpose": "probe_map sweep write plan: for every object-creating POST with a JSON body, registers "
                         f"a control account and one carrying each privileged field ({', '.join(PRIV_FIELDS)}), "
                         "logs in as each, and reads the account back to see whether the field was accepted; "
                         "then, on the throwaway account's own string fields that the target validates, sends "
                         f"probe values of growing length (at most {REDOS_LEN[-1]} characters, stopping at the "
                         "first clear slowdown) to time them"}
    authz.propose(eng, name, matrix)
    return name


def _get(d, key):
    if not isinstance(d, dict):
        return None
    if key in d:
        return d[key]
    for v in d.values():
        if isinstance(v, dict) and key in v:
            return v[key]
    return None


def run_writes(eng, ents, ctx, name):
    """Run the approved sweep matrix: every request it lists (nothing else), then the read-backs with the sessions
    it gained, then the jwt and redos checks that need a session. Returns the rows."""
    m = authz.approved(eng, name)
    current = authz.proposal(eng, name)
    if authz._digest(current) != m["digest"]:
        return [{"check": "mass-assignment", "entry": "", "where": "", "param": "", "result": "skip",
                 "why": f"matrix {name} changed since it was approved; approve it again", "evidence": []}]
    if m["policy_revision"] != core.policy_version(eng):
        return [{"check": "mass-assignment", "entry": "", "where": "", "param": "", "result": "skip",
                 "why": f"the scope or rules changed since matrix {name} was approved; approve it again",
                 "evidence": []}]
    ctx.authorized_by = {"kind": "sweep-matrix", "name": name, "digest": m["digest"],
                          "approved_by": m["approved_by"]}
    out, sessions = [], {}
    for op in m["operations"]:                       # what this run created, listed from the approved ops
        if op["id"].startswith("reg-"):
            try:
                ctx.created.append(json.loads(op.get("body") or "{}").get("username") or "?")
            except ValueError:
                ctx.created.append("?")
    for op in m["operations"]:
        st, text, ev, _, _ = ctx.send(op["method"], op["url"], op.get("headers") or {}, op.get("body"))
        if op["id"].startswith("login-"):
            for tok in JWT_RX.findall(text or ""):
                sessions[op["id"][6:]] = tok          # "login-0-0-ctl" -> "0-0-ctl"
    for t_i, t in enumerate(mass_targets(ents)):
        e, self_e = t["entry"], t["self"]
        for i, field in enumerate(t["fields"]):
            tok_ctl, tok_prb = sessions.get(f"{t_i}-{i}-ctl"), sessions.get(f"{t_i}-{i}-prb")
            if not tok_ctl or not tok_prb or not self_e:
                if i == 0:
                    out.append(_row("mass-assignment", e, "body", field, "skip",
                                    "no login or no read-back (self) endpoint on the map: the write ran, its "
                                    "effect couldn't be read back"))
                continue
            _, me_ctl, ev_c, _, _ = ctx.send("GET", self_e["example"], {"Authorization": "Bearer " + tok_ctl})
            _, me_prb, ev_p, _, _ = ctx.send("GET", self_e["example"], {"Authorization": "Bearer " + tok_prb})
            ctl, prb = _parse(me_ctl), _parse(me_prb)
            a, b = _get(ctl, field), _get(prb, field)
            if str(b) not in (str(a), "None") and b not in (None, "", False, "False"):
                out.append(_hit("mass-assignment", e, "body", field,
                                f"the account registered with {field}=true reads back differently from the "
                                f"control: {field} is {_short(b)} there and {_short(a)} in the control",
                                [ev_p, ev_c], "confirm by registering an account with the field and reading it "
                                "back yourself"))
                return out
            if i == 0 and len(t["fields"]) > 1:
                out.append(_row("mass-assignment", e, "body", field, "clean", "the control and the probe account "
                                "read back the same", [ev_c, ev_p]))
    return out


def _parse(text):
    try:
        return json.loads(text or "{}")
    except ValueError:
        return {}


def _short(v):
    return json.dumps(v)[:60]


# ---------------------------------------------------------------- the tool

def _entry_identity(eng, e, identity):
    """The identity this entry's reads run as: None when the entry is reachable without a session, the identity
    when it can reach it, and a skip-note string when the entry needs a session the given identity can't provide
    (#137). An entry no identity can reach is skipped with a note, never silently."""
    needs = e.get("auth") == "required" or bool(e.get("seen_by"))
    if not needs:
        return None, ""
    if not identity:
        return None, ("the entry needs a session and no identity was given (pass identity= to sweep the surface "
                      "behind login)")
    import identities
    try:
        identities.usable(eng, identity, e["example"], "active", "read")
    except ValueError as ex:
        return None, f"identity {identity} cannot reach this entry ({ex})"
    return identity, ""


def probe_map(eng, matrix="", max_requests=400, checks="", task="", identity=""):
    """Run the fixed checks against the recon map's entries; see the module docstring for what each check does.
    matrix: the name of the approved sweep matrix, to run the write checks (proposed by the first call).
    identity: an engagement identity (./rvkit identity) whose session rides the reads, so the injection and page
    checks run on the surface behind login (#137); entries no identity can reach are skipped with a note."""
    i = core.info(eng)
    ents = entries(eng)
    if not ents:
        raise ValueError("no recon map: run recon_map first (probe_map reads evidence/map/*.json)")
    if identity:
        import identities
        identities._get(eng, identity)                   # raises a clear error for an identity that doesn't exist
    want = {x.strip() for x in checks.split(",") if x.strip()} or \
        {"injection", "jwt", "redos", "mass-assignment", "cors", "headers"}
    ctx = Ctx(eng, int(max_requests or 400), task)
    rows, proposed = [], None
    if matrix:
        rows += run_writes(eng, ents, ctx, matrix)
        for e in ents:                                  # a session the sweep gained unlocks authenticated checks
            if "redos" in want and ctx.tokens and (e["method"] not in SAFE or e["auth"] == "required"):
                rows += check_redos(eng, e, ctx, token=sorted(ctx.tokens)[0])
        if "jwt" in want:
            rows += check_jwt(eng, ents, ctx)
    else:
        for e in ents:
            rid, skip = _entry_identity(eng, e, identity)
            if skip and any(c in want for c in ("injection", "cors", "headers")):
                rows.append(_row("read", e, "", "", "skip", skip))
                continue
            if "injection" in want:
                rows += check_injection(eng, e, ctx, identity=rid)
            if "redos" in want:
                rows += check_redos(eng, e, ctx)
            if "cors" in want:
                rows += check_cors(eng, e, ctx, identity=rid)
            if "headers" in want:
                rows += check_headers(eng, e, ctx, identity=rid)
        if "jwt" in want:
            rows += check_jwt(eng, ents, ctx)
        if "mass-assignment" in want and mass_targets(ents):
            proposed = propose_writes(eng, ents, ctx)
            if proposed:
                rows.append({"check": "mass-assignment", "entry": mass_targets(ents)[0]["entry"]["id"], "where":
                             "", "param": "", "result": "approval",
                             "why": "the write checks are proposed as one authorization matrix; nothing was sent",
                             "matrix": proposed, "evidence": [f"/work/{eng}/authz/{proposed}.json"]})
    hits = [r for r in rows if r.get("result") == "hit"]
    ts = datetime.datetime.now(datetime.timezone.utc)
    rel = f"evidence/sweep/sweep-{ts.strftime('%Y%m%dT%H%M%S')}.json"
    doc = {"sweep": 1, "at": ts.isoformat(timespec="seconds"), "engagement": eng, "entries": len(ents),
           "requests": ctx.requests, "checks": sorted(want), "hits": hits, "rows": rows,
           "tokens_seen": len(ctx.tokens), "created": ctx.created,
           "identity": identity or None, "matrix": matrix or None, "matrix_proposed": proposed}
    full = os.path.join(core.WORK, eng, rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as f:
        json.dump(doc, f, indent=1)
    if os.geteuid() == 0:
        try:
            os.chown(full, i["uid"], i["uid"], follow_symlinks=False)
        except OSError:
            pass
    core._audit({"engagement": eng, "action": "sweep",
                 "command": f"probe_map{f' {matrix}' if matrix else ''}" + (f" as {identity}" if identity else ""),
                 "tier": "active", "entries": len(ents), "requests": ctx.requests, "hits": len(hits),
                 "identity": identity or None, "outputs": {rel: core.sha256_file(full)}})
    text = [f"probe_map: {len(ents)} map entries, {ctx.requests} request(s), {len(hits)} hit(s), "
            f"{len(ctx.tokens)} token(s) seen."
            + (f" Read checks ran as {identity} where a session was needed." if identity else
               " No identity: entries behind login were skipped (pass identity= to sweep them).")]
    for h in hits:
        text.append(f"  HIT {h['check']} on {h.get('method') or ''} {h.get('path') or h.get('entry')} "
                    f"({h.get('where')} {h.get('param')}): {h['why']}")
    if proposed:
        text.append(f"  The write checks are proposed as authorization matrix {proposed}. Approve it "
                    f"(./rvkit authz {eng} approve {proposed}), then call probe_map with matrix={proposed}.")
    for r in rows:
        if r.get("result") == "skip":
            text.append(f"  SKIP {r['check']} {r.get('param', '')}: {r['why']}")
    text.append(f"import_observations for the hits: /work/{eng}/{rel}")
    text.append(f"[sweep saved as verified evidence: /work/{eng}/{rel}]")
    return core.scrub(eng, "\n".join(t for t in text if t))
