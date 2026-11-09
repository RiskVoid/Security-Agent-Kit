"""Test identities for authenticated work (RW-008).

An identity is one test account of an engagement: its role and tenant, how it authenticates, the hosts its session
may be sent to, what it may be used for, and the fixture records it owns. Identities are defined on the host
(./rvkit identity, the console); the agent sees names, roles, tenants, fixtures and status, never a secret.

  kind      how the session is obtained
  bearer    Authorization: Bearer <credential>
  header    <header>: <credential>                 (an API key header)
  cookie    Cookie: <cookie>=<credential>          (a session cookie copied from a browser)
  basic     HTTP basic auth with username and credential
  form      HTML login form: GET login_url (cookies, CSRF token), POST the username and password, keep the cookies
  json      JSON login: POST login_url with a body template, take the token from the response (token_path)

Sessions obtained by logging in are encrypted in the vault (identities.json in the control volume) and refreshed
when they expire. The execution broker (actions.send) adds the session to requests to the identity's hosts only,
after the policy checks and the approval: the approval names the identity, not its secret. Session values are
scrubbed from every output, evidence file and audit entry, like credentials.

check_identity is the valid-session control: it tells a working session (valid) from an expired login (expired),
an infrastructure challenge such as a CAPTCHA or WAF page (challenge), a session that is valid but not allowed to
see the check URL (denied) and an error. Tests that need a session report blocked, not "not vulnerable", unless
the identity is valid.
"""
import datetime, json, os, re, threading, urllib.parse

import core
import policy as rvpolicy

NAME_RX = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
KINDS = ("bearer", "header", "cookie", "basic", "form", "json")
EFFECTS = ("read", "write")
STATES = ("unchecked", "valid", "expired", "challenge", "denied", "error", "revoked")
CHALLENGE = re.compile(r"captcha|cf-chl|challenge-platform|attention required|verify you are human|"
                       r"access denied by|request blocked|incapsula|akamai reference", re.I)
LOGIN_FORM = re.compile(r"<input[^>]+type=[\"']?password", re.I)
SET_COOKIE = re.compile(r"^\s*([^=;\s]+)=([^;]*)")
_LOCK = threading.RLock()


def _file(eng):
    return os.path.join(core.ctl_dir(eng), "identities.json")


def _load(eng):
    try:
        return json.load(open(_file(eng)))
    except (OSError, ValueError):
        return {}


def _save(eng, data):
    core._write_json(_file(eng), data)
    os.chmod(_file(eng), 0o600)


def _host(url):
    return (urllib.parse.urlsplit(url).hostname or "").lower().rstrip(".")


def _validate(eng, name, spec):
    if not NAME_RX.match(name or ""):
        raise ValueError("identity names are lower-case letters, digits, - and _ (start with a letter, up to 32)")
    if not isinstance(spec, dict):
        raise ValueError("the identity spec must be a JSON object")
    kind = spec.get("kind")
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(KINDS)}")
    need = {"bearer": ["secret"], "header": ["header", "secret"], "cookie": ["cookie", "secret"],
            "basic": ["username", "secret"], "form": ["login_url", "username", "secret"],
            "json": ["login_url", "body", "token_path", "secret"]}[kind]
    miss = [k for k in need if not spec.get(k)]
    if miss:
        raise ValueError(f"a {kind} identity needs {', '.join(miss)}")
    core.cred_value(eng, spec["secret"])  # exists and not expired
    pol = core.policy_of(eng)
    urls = [u for u in (spec.get("login_url"), (spec.get("check") or {}).get("url")) if u]
    if not urls:
        raise ValueError("give a check URL (check.url): the valid-session control needs one")
    for u in urls:
        why = rvpolicy.check_url(pol, u)
        if why:
            raise ValueError(f"{u}: {why}")
    hosts = spec.get("hosts") or sorted({_host(u) for u in urls})
    if not all(isinstance(h, str) and re.fullmatch(r"[a-z0-9.-]{1,253}", h) for h in hosts):
        raise ValueError("hosts must be host names")
    tiers = spec.get("tiers") or ["active"]
    effects = spec.get("effects") or ["read"]
    if not set(tiers) <= set(core.TIERS) or not set(effects) <= set(EFFECTS):
        raise ValueError(f"tiers are {core.TIERS}, effects are {EFFECTS}")
    fixtures = spec.get("fixtures") or []
    for f in fixtures:
        if not isinstance(f, dict) or not f.get("kind") or f.get("id") in (None, ""):
            raise ValueError("each fixture is {\"kind\": ..., \"id\": ..., \"marker\": optional text only it contains}")
    if spec.get("expires") and core._expired(spec["expires"]):
        raise ValueError(f"expiry {spec['expires']} is in the past")
    check = dict(spec.get("check") or {})
    check.setdefault("method", "GET")
    check.setdefault("expect_status", [200])
    allowed = {"kind", "role", "tenant", "secret", "header", "cookie", "username", "login_url", "username_field",
               "password_field", "csrf_field", "body", "token_path", "token_header", "token_prefix", "hosts", "tiers",
               "effects", "fixtures", "expires", "check", "session_minutes", "login_markers", "note"}
    extra = set(spec) - allowed
    if extra:
        raise ValueError(f"unknown identity fields: {', '.join(sorted(extra))}")
    return {**{k: spec[k] for k in spec if k in allowed}, "hosts": hosts, "tiers": tiers, "effects": effects,
            "fixtures": fixtures, "check": check}


def identity_set(eng, name, spec):
    core.require(eng)
    clean = _validate(eng, name, spec)
    with _LOCK:
        data = _load(eng)
        old = data.get(name, {})
        data[name] = {"spec": clean, "set_by": core.ACTOR, "set_at": core._now_iso(),
                      "status": {"state": "unchecked"}, "revision": old.get("revision", 0) + 1}
        _save(eng, data)
    core._audit({"engagement": eng, "event": "identity-set", "identity": name, "kind": clean["kind"],
                 "role": clean.get("role"), "tenant": clean.get("tenant"), "revision": data[name]["revision"]})
    return public(eng, name)


def identity_remove(eng, name):
    with _LOCK:
        data = _load(eng)
        if data.pop(name, None) is None:
            raise ValueError(f"no identity {name} in {eng}")
        _save(eng, data)
    core._audit({"engagement": eng, "event": "identity-removed", "identity": name})


def revoke(eng, name, reason=""):
    """Stop using an identity (the account was disabled, or the engagement is over). Its session is dropped."""
    with _LOCK:
        data = _load(eng)
        if name not in data:
            raise ValueError(f"no identity {name} in {eng}")
        data[name].pop("session", None)
        data[name]["status"] = {"state": "revoked", "reason": reason or "revoked", "checked_at": core._now_iso()}
        _save(eng, data)
    core._audit({"engagement": eng, "event": "identity-revoked", "identity": name, "reason": reason})


def _get(eng, name):
    d = _load(eng).get(name)
    if not d:
        raise ValueError(f"no identity {name} in {eng} (list them: list_identities)")
    return d


def public(eng, name, d=None):
    d = d or _get(eng, name)
    s = d["spec"]
    return {"name": name, "kind": s["kind"], "role": s.get("role"), "tenant": s.get("tenant"), "hosts": s["hosts"],
            "tiers": s["tiers"], "effects": s["effects"], "fixtures": s["fixtures"], "expires": s.get("expires"),
            "check_url": s["check"].get("url") or s.get("login_url"), "status": d.get("status", {}),
            "revision": d.get("revision", 1), "set_by": d.get("set_by"), "set_at": d.get("set_at"),
            "session": bool(d.get("session"))}


def identity_list(eng):
    core.require(eng)
    return [public(eng, n, d) for n, d in sorted(_load(eng).items())]


# ---------------------------------------------------------------- sessions
def _session(d):
    s = d.get("session")
    if not s:
        return None
    if s.get("expires") and core._expired(s["expires"]):
        return None
    try:
        return json.loads(core.unseal(s["sealed"]))
    except ValueError:
        return None


def session_secrets(eng):
    """{value: "{{session:<identity>}}"} for scrub(): stored sessions, and the values the static kinds derive from
    their credential, which are never stored as a session. Basic auth sends base64(user:secret), not the
    credential itself: a page that reflects request headers would otherwise hand the agent a decodable password."""
    out = {}
    for n, d in _load(eng).items():
        sessions, secret = [_session(d) or {}], None
        if d["spec"]["kind"] not in ("form", "json"):
            try:
                secret = core.cred_value(eng, d["spec"]["secret"])
                sessions.append(_static(d["spec"], secret) or {})
            except (ValueError, KeyError):  # the credential was removed or expired: nothing can be sent
                pass
        for sess in sessions:
            for v in list((sess.get("cookies") or {}).values()) + list((sess.get("headers") or {}).values()):
                v = str(v)
                for x in (v, v.split(" ", 1)[1]) if " " in v else (v,):  # "Basic <base64>": the value alone too
                    if len(x) >= 6 and x != secret:  # the credential itself stays {{cred:NAME}}
                        out.setdefault(x, "{{session:%s}}" % n)
    return out


def _store_session(eng, name, sess):
    minutes = int(_get(eng, name)["spec"].get("session_minutes") or 120)
    exp = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=minutes)).isoformat(
        timespec="seconds")
    with _LOCK:
        data = _load(eng)
        data[name]["session"] = {"sealed": core.seal(json.dumps(sess)), "obtained": core._now_iso(), "expires": exp}
        _save(eng, data)


def _drop_session(eng, name):
    with _LOCK:
        data = _load(eng)
        if name in data:
            data[name].pop("session", None)
            _save(eng, data)


def _cookies_from(headers, jar):
    for k, v in headers:
        if k.lower() == "set-cookie":
            m = SET_COOKIE.match(v)
            if m:
                if m.group(2) in ("", "deleted") or "max-age=0" in v.lower():
                    jar.pop(m.group(1), None)
                else:
                    jar[m.group(1)] = m.group(2)
    return jar


def _cookie_header(jar):
    return "; ".join(f"{k}={v}" for k, v in jar.items())


def _get_path(obj, path):
    for part in str(path).split("."):
        if isinstance(obj, list) and part.isdigit():
            obj = obj[int(part)]
        elif isinstance(obj, dict):
            obj = obj.get(part)
        else:
            return None
    return obj


def _static(spec, secret):
    k = spec["kind"]
    if k == "bearer":
        return {"headers": {"Authorization": f"Bearer {secret}"}}
    if k == "header":
        return {"headers": {spec["header"]: secret}}
    if k == "cookie":
        return {"cookies": {spec["cookie"]: secret}}
    if k == "basic":
        import base64
        return {"headers": {"Authorization": "Basic " + base64.b64encode(f"{spec['username']}:{secret}".encode())
                            .decode()}}
    return None


def login(eng, name):
    """Obtain a session for a form or json identity. Returns the session dict; raises ValueError on failure."""
    import actions
    d = _get(eng, name)
    spec = d["spec"]
    if d.get("status", {}).get("state") == "revoked":
        raise ValueError(f"identity {name} is revoked")
    secret = core.cred_value(eng, spec["secret"])
    static = _static(spec, secret)
    if static:
        return static
    url = spec["login_url"]
    if spec["kind"] == "json":
        body = json.dumps(spec["body"]).replace("{{secret}}", secret.replace("\\", "\\\\").replace('"', '\\"'))
        hop = actions.exchange(eng, "POST", url, {"Content-Type": "application/json", "Accept": "application/json"},
                               body.encode(), purpose="identity-login")
        try:
            token = _get_path(json.loads(hop["body"] or b"{}"), spec["token_path"])
        except ValueError:
            token = None
        if hop["status"] >= 400 or not token:
            _audit_login(eng, name, False, f"HTTP {hop['status']}, no token at {spec['token_path']}")
            raise ValueError(f"login for {name} failed: HTTP {hop['status']}"
                             + ("" if token else f", no token at {spec['token_path']}"))
        sess = {"headers": {spec.get("token_header") or "Authorization":
                            (spec.get("token_prefix", "Bearer ") or "") + str(token)}}
    else:  # form
        jar = {}
        hop = actions.exchange(eng, "GET", url, {"Accept": "text/html"}, b"", purpose="identity-login")
        _cookies_from(hop["headers"], jar)
        field = spec.get("csrf_field") or "_token"
        text = (hop["body"] or b"").decode("utf-8", "replace")
        m = re.search(r"name=[\"']" + re.escape(field) + r"[\"'][^>]*value=[\"']([^\"']+)", text) or \
            re.search(r"value=[\"']([^\"']+)[\"'][^>]*name=[\"']" + re.escape(field) + r"[\"']", text)
        fields = {spec.get("username_field") or "email": spec["username"],
                  spec.get("password_field") or "password": secret}
        if m:
            fields[field] = m.group(1)
        hop = actions.exchange(eng, "POST", url, {"Content-Type": "application/x-www-form-urlencoded",
                                                  "Accept": "text/html", "Cookie": _cookie_header(jar)},
                               urllib.parse.urlencode(fields).encode(), purpose="identity-login")
        _cookies_from(hop["headers"], jar)
        cur, final = url, hop
        for _ in range(3):  # follow the redirect after login, inside the scope, with the cookies
            loc = dict((k.lower(), v) for k, v in final["headers"]).get("location")
            if final["status"] not in (301, 302, 303, 307, 308) or not loc:
                break
            cur = urllib.parse.urljoin(cur, loc)
            if rvpolicy.check_url(core.policy_of(eng), cur):
                break
            final = actions.exchange(eng, "GET", cur, {"Accept": "text/html", "Cookie": _cookie_header(jar)}, b"",
                                     purpose="identity-login")
            _cookies_from(final["headers"], jar)
        body = (final["body"] or b"").decode("utf-8", "replace")
        login_path = urllib.parse.urlsplit(url).path.rstrip("/")
        back_on_login = urllib.parse.urlsplit(cur).path.rstrip("/") == login_path and final["status"] < 300
        if final["status"] in (401, 419, 422) or back_on_login or LOGIN_FORM.search(body) or not jar:
            _audit_login(eng, name, False, f"still on the login page (HTTP {final['status']})")
            raise ValueError(f"login for {name} failed: still on the login page (HTTP {final['status']}); check the "
                             "username, the credential and the form field names")
        sess = {"cookies": jar}
    _store_session(eng, name, sess)
    _audit_login(eng, name, True, "")
    return sess


def _audit_login(eng, name, ok, why):
    core._audit({"engagement": eng, "event": "identity-login", "identity": name, "ok": ok,
                 **({"reason": why} if why else {})})


def usable(eng, name, url, tier, effect):
    """Raise ValueError unless the identity may be used for this request (status, expiry, host, tier, effect)."""
    d = _get(eng, name)
    spec = d["spec"]
    st = d.get("status", {}).get("state")
    if st == "revoked":
        raise ValueError(f"identity {name} is revoked")
    if spec.get("expires") and core._expired(spec["expires"]):
        raise ValueError(f"identity {name} expired on {spec['expires']}")
    if _host(url) not in spec["hosts"]:
        raise ValueError(f"identity {name} is only for {', '.join(spec['hosts'])}, not {_host(url)}")
    if tier not in spec["tiers"]:
        raise ValueError(f"identity {name} may be used for tiers {spec['tiers']}, not '{tier}'")
    if effect not in spec["effects"]:
        raise ValueError(f"identity {name} may be used for {'/'.join(spec['effects'])} actions only, not {effect}")
    return d


def auth_headers(eng, name, url):
    """Headers carrying the identity's session, for a request to url (one of its hosts). Logs in when needed."""
    d = _get(eng, name)
    if _host(url) not in d["spec"]["hosts"]:
        return {}
    sess = _session(d) or login(eng, name)
    h = dict(sess.get("headers") or {})
    if sess.get("cookies"):
        h["Cookie"] = _cookie_header(sess["cookies"])
    return h


def looks_expired(eng, name, status, headers, body):
    """True when a response looks like the session ended (the caller should check_identity, not trust it)."""
    d = _get(eng, name)
    loc = dict((k.lower(), v) for k, v in headers).get("location", "")
    login_path = urllib.parse.urlsplit(d["spec"].get("login_url") or "").path
    text = (body or b"")[:200000].decode("utf-8", "replace") if isinstance(body, bytes) else str(body or "")
    return status in (401, 419) or (login_path and login_path in loc) or bool(LOGIN_FORM.search(text))


def classify(eng, name, status, headers, body, spec=None):
    """valid | expired | challenge | denied | error, with a reason."""
    spec = spec or _get(eng, name)["spec"]
    text = (body or b"")[:200000].decode("utf-8", "replace")
    if status in (429,) or CHALLENGE.search(text) or (status == 503 and "retry-after" in
                                                        {k.lower() for k, _ in headers}):
        return "challenge", f"HTTP {status}: a rate limit, CAPTCHA or WAF page answered instead of the application"
    if looks_expired(eng, name, status, headers, body):
        return "expired", f"HTTP {status}: the response is a login page or a login redirect"
    if status in (401,):
        return "expired", "HTTP 401"
    if status == 403:
        return "denied", "HTTP 403: authenticated, but not allowed to see the check URL"
    if status >= 500:
        return "error", f"HTTP {status}"
    marker = (spec.get("check") or {}).get("marker")
    if status in (spec.get("check") or {}).get("expect_status", [200]) and (not marker or marker in text):
        return "valid", f"HTTP {status}" + (f", marker {marker!r} present" if marker else "")
    if marker and marker not in text:
        return "denied", f"HTTP {status} without the marker {marker!r}: not the expected account view"
    return "error", f"unexpected HTTP {status}"


def check(eng, name, _retry=True):
    """The valid-session control. Refreshes the session once when it looks expired."""
    import actions
    d = _get(eng, name)
    spec = d["spec"]
    if d.get("status", {}).get("state") == "revoked":
        return {"identity": name, "state": "revoked", "reason": d["status"].get("reason")}
    if spec.get("expires") and core._expired(spec["expires"]):
        return _set_status(eng, name, "expired", f"the identity expired on {spec['expires']}")
    url = spec["check"].get("url") or spec.get("login_url")
    try:
        hdrs = {"Accept": spec["check"].get("accept", "text/html,application/json"), **auth_headers(eng, name, url)}
        hop = actions.exchange(eng, spec["check"].get("method", "GET"), url, hdrs, b"", purpose="identity-check")
    except ValueError as e:
        return _set_status(eng, name, "error", str(e))
    state, why = classify(eng, name, hop["status"], hop["headers"], hop["body"], spec)
    if state == "expired" and _retry and spec["kind"] in ("form", "json"):
        _drop_session(eng, name)
        try:
            login(eng, name)
        except ValueError as e:
            return _set_status(eng, name, "expired", f"{why}; logging in again failed: {e}")
        return check(eng, name, _retry=False)
    return _set_status(eng, name, state, why)


def _set_status(eng, name, state, why):
    with _LOCK:
        data = _load(eng)
        if name in data:
            data[name]["status"] = {"state": state, "reason": core.scrub(eng, why), "checked_at": core._now_iso()}
            _save(eng, data)
    core._audit({"engagement": eng, "event": "identity-check", "identity": name, "state": state,
                 "reason": core.scrub(eng, why)})
    return {"identity": name, "state": state, "reason": core.scrub(eng, why)}
