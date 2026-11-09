"""Typed actions: operations whose target, effect and inputs kali-mcp understands, so the policy can be enforced at
the level of the action rather than of a shell line.

  http_request    one HTTP request to an in-scope URL, sent by kali-mcp itself: URL path limits, exclusions,
                  ports, redirects, the engagement's request budget and max rate are enforced here. Safe methods
                  are tier active; anything that can change state is intrusive (an approval bound to the method,
                  URL, headers and body).
  analyze_source  a source-analysis tool on in-scope code, run in the sandbox with no network at all.

Raw commands through core.run stay available; Execution: controlled in RULES.md narrows them (see core.run).
"""
import base64, datetime, hashlib, http.client, json, os, re, socket, ssl, time, urllib.parse

import core
import policy as rvpolicy

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
METHODS = SAFE_METHODS + ("POST", "PUT", "PATCH", "DELETE")
MAX_BODY_OUT = 5 * 1024 * 1024   # bytes of a response kept as evidence
MAX_BODY_IN = 1024 * 1024        # bytes of a request body
SHOWN = 20_000                   # characters of the response returned to the agent
HOP = {"host", "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer", "proxy-connection",
       "keep-alive"}
SECRET_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key"}


def _blocked():
    b = core.ALWAYS_BLOCKED + core._local_subnets()
    return b + core._host_addrs(b)


class _Pinned(http.client.HTTPConnection):
    """Connects to the address that was checked, whatever the name resolves to by then (no DNS rebinding)."""

    def __init__(self, host, port, ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedTLS(http.client.HTTPSConnection):
    def __init__(self, host, port, ip, timeout):
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # test targets often use their own CA
        super().__init__(host, port, timeout=timeout, context=ctx)
        self._ip, self._ctx = ip, ctx

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._ctx.wrap_socket(sock, server_hostname=self.host)


def _resolve(pol, host, blocked):
    """(ip, None) for the address to use, or (None, reason). Every address the name has must be allowed."""
    if rvpolicy._is_ip(host):
        why = rvpolicy.check_address(pol, host, host, blocked)
        return (None, why) if why else (host, None)
    try:
        addrs = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)})
    except OSError as e:
        return None, f"{host} does not resolve ({e})"
    for ip in addrs:
        why = rvpolicy.check_address(pol, host, ip, blocked)
        if why:
            return None, why
    return addrs[0], None


def _clean_headers(headers):
    out = {}
    for k, v in (headers or {}).items():
        k, v = str(k).strip(), str(v)
        if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}", k) or "\n" in v or "\r" in v:
            raise ValueError(f"bad header {k[:40]!r}")
        if k.lower() in HOP:
            raise ValueError(f"header {k} is set by the tool itself")
        out[k] = v
    out.setdefault("User-Agent", "rvkit")
    return out


def http_action(method, url, headers, body, identity=None):
    """What an approval of a request is bound to (the body by its digest; the identity by name, never its secret)."""
    a = {"kind": "http", "method": method, "url": url,
         "headers": {k.lower(): v for k, v in sorted(headers.items())},
         "body": hashlib.sha256(body).hexdigest()}
    if identity:
        a["identity"] = identity
    return a


def _inside(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def work_dir(eng, *parts):
    """A folder of /work/<eng> that kali-mcp (root) writes into, created if needed, as its real path. The sandbox
    can write /work, so any part of it may be a link the agent made: one that leads out is refused."""
    base = os.path.realpath(os.path.join(core.WORK, eng))
    d = os.path.join(core.WORK, eng, *parts)
    for _ in range(2):  # before creating anything through a link, and after
        if not _inside(os.path.realpath(d), base):
            raise Refused(f"/work/{eng}/{'/'.join(parts)} leads outside the engagement folder (a link?)")
        os.makedirs(d, exist_ok=True)
    return os.path.realpath(d)


def _evidence_path(eng, method, host, kind="http"):
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
    rel = os.path.join("evidence", kind, f"{ts}-{method.lower()}-{re.sub(r'[^a-z0-9.-]', '_', host)[:60]}-"
                       f"{os.urandom(3).hex()}.txt")
    work_dir(eng, "evidence", kind)
    return rel


class Refused(ValueError):
    """The policy refused a request (the message says why)."""


def exchange(eng, method, url, headers, data=b"", timeout_s=30, purpose="request"):
    """One HTTP exchange, no redirects, under the engagement's policy: halt, testing time, checked URL, the address
    that was checked (pinned), the request budget and max rate. Returns {"status", "reason", "headers", "body",
    "ip", "seconds"} with the raw (unscrubbed) response, for kali-mcp's own use (identity login and checks);
    raises Refused. It doesn't ask for approval: callers decide that."""
    i = core.info(eng)
    rules = i["rules"]
    if i["halted"]:
        raise Refused("engagement is halted")
    late = rvpolicy.time_refusal(rules)
    if late:
        raise Refused(late)
    pol = core.policy_of(eng)
    why = rvpolicy.check_url(pol, url)
    if why:
        raise Refused(why)
    if not core.take_budget(eng, "requests", rules.get("max_requests")):
        raise Refused(f"the request budget is used up (Max requests: {rules['max_requests']})")
    u = urllib.parse.urlsplit(url)
    host, port = u.hostname.lower().rstrip("."), u.port or (443 if u.scheme == "https" else 80)
    ip, why = _resolve(pol, host, _blocked())
    if why:
        raise Refused(why)
    core.rate_wait(eng, rules["max_rate"])
    conn = (_PinnedTLS if u.scheme == "https" else _Pinned)(host, port, ip, min(int(timeout_s or 30), 120))
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    t0 = time.time()
    try:
        conn.request(method, path, body=data or None, headers={"User-Agent": "rvkit", **headers})
        r = conn.getresponse()
        raw = r.read(MAX_BODY_OUT + 1)
        out = {"status": r.status, "reason": r.reason, "headers": r.getheaders(), "body": raw[:MAX_BODY_OUT],
               "truncated": len(raw) > MAX_BODY_OUT, "ip": ip, "seconds": round(time.time() - t0, 2)}
    except (OSError, http.client.HTTPException) as e:
        core._audit({"engagement": eng, "action": purpose, "method": method, "url": core.scrub(eng, url),
                     "error": core.scrub(eng, f"{type(e).__name__}: {e}")})
        raise Refused(f"{type(e).__name__}: {e}")
    finally:
        conn.close()
    core._audit({"engagement": eng, "action": purpose, "method": method, "url": core.scrub(eng, url), "ip": ip,
                 "status": out["status"]})
    return out


def _mask_cookies(headers):
    """Set-Cookie values are session material: keep the cookie names and attributes, drop the values."""
    out = []
    for k, v in headers:
        if k.lower() == "set-cookie":
            v = re.sub(r"^(\s*[^=;\s]+)=[^;]*", r"\1=[redacted]", v)
        out.append((k, v))
    return out


def http_request(eng, method, url, headers=None, body="", approval_id=None, max_tier=None, task=None,
                 timeout_s=30, body_base64=False, identity=None):
    """The kali tool: one request, its result as text for the model."""
    try:
        data = base64.b64decode(body) if body_base64 else (body or "").encode()
    except (ValueError, TypeError) as e:
        data = None
        err = str(e)
    if data is None:
        core._audit({"engagement": eng, "action": "http", "method": method, "url": url, "refused": err})
        return f"REFUSED: {err}"
    return send(eng, method, url, headers, data, approval_id, max_tier, task, timeout_s, identity)["text"]


def send(eng, method, url, headers=None, data=b"", approval_id=None, max_tier=None, task=None, timeout_s=30,
         identity=None, authorized_by=None, evidence_kind="http"):
    """The execution broker for HTTP: policy, tier, approval, credentials, identity session, redirects, budget,
    rate, evidence and audit. Returns {"text"} plus, when the request was sent, "hops", "notes", "evidence",
    "status" and "body" (scrubbed); "refused" or "approval" when it wasn't.

    authorized_by: kali-mcp's own callers (an approved authorization matrix) pass the decision that covers a
    state-changing request instead of a per-request approval; it is recorded in the audit entry."""
    i = core.info(eng)
    rules = i["rules"]
    method = (method or "GET").upper()
    entry = {"engagement": eng, "action": "http", "method": method, "url": url, **({"task": task} if task else {}),
             **({"identity": identity} if identity else {})}

    def refuse(msg, **extra):
        core._audit({**entry, "refused": msg, **extra})
        return {"refused": msg, "text": f"REFUSED: {msg}"}

    if method not in METHODS:
        return refuse(f"method must be one of {', '.join(METHODS)}")
    if i["halted"]:
        return refuse("engagement is halted (./rvkit resume <engagement> on the host)")
    late = rvpolicy.time_refusal(rules)
    if late:
        return refuse(late + " (RULES.md)")
    tier = "active" if method in SAFE_METHODS else "intrusive"
    effect = "read" if method in SAFE_METHODS else "write"
    entry["tier"] = tier
    if tier not in rules["tiers"]:
        return refuse(f"{method} is tier '{tier}', RULES.md allows only {rules['tiers']}")
    if core._tier_over(tier, max_tier):
        return refuse(f"{method} is tier '{tier}' and this task may only use '{max_tier}'")
    try:
        hdrs = _clean_headers(headers)
    except ValueError as e:
        return refuse(str(e))
    if len(data) > MAX_BODY_IN:
        return refuse(f"request body over {MAX_BODY_IN} bytes")
    pol = core.policy_of(eng)
    why = rvpolicy.check_url(pol, url)
    if why:
        return refuse(why)
    if identity:
        import identities
        try:
            identities.usable(eng, identity, url, tier, effect)
        except ValueError as e:
            return refuse(str(e))
    if tier == "intrusive":
        action = http_action(method, url, hdrs, data, identity)
        if authorized_by:
            entry["authorized_by"] = authorized_by
        elif not approval_id:
            shown = f"HTTP {method} {url}" + (f" as {identity}" if identity else "") + \
                (f" ({len(data)} byte body)" if data else "")
            a = core.request_approval(eng, action, tier, shown, task)
            return {"approval": a["id"],
                    "text": f"APPROVAL REQUIRED ({method} can change state). Approval id: {a['id']}. Ask the user to "
                            f"review and run on the host:  ./rvkit approve {eng} {a['id']}   Then call http_request "
                            f"again with the same method, URL, headers, body and identity and approval_id='{a['id']}'."}
        else:
            err = core.consume_approval(eng, approval_id, action, rules)
            if err:
                return refuse(err, approval=approval_id)
            entry["approval"] = approval_id

    # credential references ({{cred:NAME}}) and the identity's session are added only now: the approval, the audit
    # entry and the evidence file keep the reference or the identity's name, the target gets the value
    used = core.cred_used(eng, url + json.dumps(hdrs) + data.decode("utf-8", "replace"))
    try:
        send_url = core.cred_expand(eng, url)
        send_hdrs = {k: core.cred_expand(eng, v) for k, v in hdrs.items()}
        send_data = core.cred_expand(eng, data.decode("utf-8", "surrogateescape")).encode("utf-8", "surrogateescape") \
            if used else data
        if identity:
            auth = identities.auth_headers(eng, identity, send_url)
            if "Cookie" in auth and "Cookie" in send_hdrs:
                auth["Cookie"] = send_hdrs["Cookie"] + "; " + auth["Cookie"]
            send_hdrs = {**{k: v for k, v in send_hdrs.items() if k.lower() not in {a.lower() for a in auth}}, **auth}
    except ValueError as e:
        return refuse(core.scrub(eng, str(e)))
    if used:
        entry["credentials"] = used
        why = rvpolicy.check_url(pol, send_url)
        if why:
            return refuse(why)
    secret_hdrs = send_hdrs != hdrs
    blocked, hops, notes = _blocked(), [], []
    cur, cur_method, cur_data = send_url, method, send_data
    for hop in range(6):
        if core.info(eng)["halted"]:
            notes.append("stopped: the engagement was halted")
            break
        if not core.take_budget(eng, "requests", rules.get("max_requests")):
            notes.append(f"stopped: the request budget is used up (Max requests: {rules['max_requests']})")
            break
        u = urllib.parse.urlsplit(cur)
        host, port = u.hostname.lower().rstrip("."), u.port or (443 if u.scheme == "https" else 80)
        ip, why = _resolve(pol, host, blocked)
        if why:
            notes.append(f"stopped: {why}")
            break
        core.rate_wait(eng, rules["max_rate"])
        conn = (_PinnedTLS if u.scheme == "https" else _Pinned)(host, port, ip, min(int(timeout_s or 30), 120))
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        t0 = time.time()
        try:
            conn.request(cur_method, path, body=cur_data or None, headers=send_hdrs)
            r = conn.getresponse()
            raw = r.read(MAX_BODY_OUT + 1)
            rh = r.getheaders()
            hop_rec = {"url": core.scrub(eng, cur), "method": cur_method, "ip": ip, "status": r.status,
                       "reason": r.reason, "headers": [(k, core.scrub(eng, v)) for k, v in
                                                       (_mask_cookies(rh) if secret_hdrs or identity else rh)],
                       "body": core.scrub(eng, raw[:MAX_BODY_OUT]), "truncated": len(raw) > MAX_BODY_OUT,
                       "seconds": round(time.time() - t0, 2), "_raw_headers": rh}
            if u.scheme == "https" and conn.sock:
                der = conn.sock.getpeercert(binary_form=True)
                hop_rec["tls"] = {"version": conn.sock.version(), "cert_sha256": hashlib.sha256(der).hexdigest()
                                  if der else None, "verified": False}
        except (OSError, http.client.HTTPException) as e:
            hops.append({"url": core.scrub(eng, cur), "method": cur_method, "ip": ip,
                         "error": core.scrub(eng, f"{type(e).__name__}: {e}")})
            break
        finally:
            conn.close()
        hops.append(hop_rec)
        loc = dict((k.lower(), v) for k, v in rh).get("location")
        if hop_rec["status"] not in (301, 302, 303, 307, 308) or not loc:
            break
        nxt = urllib.parse.urljoin(cur, loc)
        if secret_hdrs and urllib.parse.urlsplit(nxt).netloc != urllib.parse.urlsplit(cur).netloc:
            send_hdrs, secret_hdrs = hdrs, False  # credentials and sessions are not sent on to another host
            notes.append(f"credentials and the identity session were not sent on to {urllib.parse.urlsplit(nxt).netloc}")
        if rules.get("redirects") == "none" or cur_method not in ("GET", "HEAD"):
            notes.append(f"redirect to {nxt} not followed (" + ("Redirects: none" if rules.get("redirects") == "none"
                         else f"{cur_method} is not repeated automatically") + ")")
            break
        why = rvpolicy.check_url(pol, nxt)
        if why:
            notes.append(f"redirect to {nxt} not followed: {why}")
            break
        if hop == 5:
            notes.append("stopped after 5 redirects")
            break
        cur = nxt

    last = hops[-1] if hops else None
    if identity and last and "error" not in last and \
            identities.looks_expired(eng, identity, last["status"], last["_raw_headers"], last["body"]):
        notes.append(f"the response looks like a login page or a login redirect: the session of {identity} may have "
                     f"ended (check_identity tells; a test result is not reliable until it says valid)")
    notes = [core.scrub(eng, n) for n in notes]
    rel = _evidence_path(eng, method, urllib.parse.urlsplit(url).hostname or "host", evidence_kind)
    full = os.path.join(core.WORK, eng, rel)
    with open(full, "wb") as f:
        f.write(f"# rvkit http_request {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')} "
                f"tier={tier}".encode() + (f" identity={identity}".encode() if identity else b"") + b"\n")
        f.write(f"> {method} {url}\n".encode())
        for k, v in hdrs.items():
            f.write(f"> {k}: {v}\n".encode())
        if identity:
            f.write(f"> [session of identity {identity} added by kali-mcp]\n".encode())
        if data:
            f.write(b">\n" + data + b"\n")
        for h in hops:
            f.write(f"\n# {h['method']} {h['url']} ({h['ip']})\n".encode())
            if "error" in h:
                f.write(f"! {h['error']}\n".encode())
                continue
            f.write(f"< {h['status']} {h['reason']}\n".encode())
            for k, v in h["headers"]:
                f.write(f"< {k}: {v}\n".encode())
            if h.get("tls"):
                f.write(f"# tls {json.dumps(h['tls'])}\n".encode())
            f.write(b"<\n" + h["body"] + (b"\n# body truncated\n" if h["truncated"] else b"\n"))
        for n in notes:
            f.write(f"# {n}\n".encode())
    digest = core.sha256_file(full)
    redacted = {k: ("[redacted]" if k.lower() in SECRET_HEADERS else v) for k, v in hdrs.items()}
    core._audit({**entry, "headers": redacted, "body_sha256": hashlib.sha256(data).hexdigest() if data else None,
                 "hops": [{k: h.get(k) for k in ("url", "method", "ip", "status", "error", "seconds")} for h in hops],
                 "notes": notes, "outputs": {rel: digest}})
    out = [f"{method} {url}" + (f"  (as {identity})" if identity else "")]
    for h in hops:
        out.append(f"  {h['method']} {h['url']} -> " + (h["error"] if "error" in h else f"{h['status']} {h['reason']}"))
    out += [f"  {n}" for n in notes]
    if last and "error" not in last:
        out.append("")
        out += [f"{k}: {v}" for k, v in last["headers"]]
        text = last["body"].decode("utf-8", "replace")
        out.append("")
        out.append(text[:SHOWN] + (f"\n... {len(text) - SHOWN} more characters in the evidence file"
                                   if len(text) > SHOWN else ""))
    out.append(f"[request and response saved as verified evidence: /work/{eng}/{rel}]")
    for h in hops:
        h.pop("_raw_headers", None)
    return {"text": core.scrub(eng, "\n".join(out)), "hops": hops, "notes": notes, "evidence": rel,
            "status": last.get("status") if last else None, "body": last.get("body", b"") if last else b"",
            "headers": last.get("headers", []) if last else [], "url": last.get("url") if last else url,
            "error": last.get("error") if last else "not sent: " + "; ".join(notes)}


# ---------------------------------------------------------------- browser (RW-010)
READ_STEPS = {"goto", "wait", "wait_for", "text"}
WRITE_STEPS = {"click", "fill", "press"}
BROWSER = "/opt/browser/bin/python"


def browse(eng, url, steps=None, identity=None, approval_id=None, max_tier=None, task=None, timeout_s=180,
           mask=None, max_requests=300):
    """Open url in a headless browser in the engagement's sandbox, optionally as an identity, and run steps.
    Navigation and reading are tier active; clicking, filling or pressing keys can submit forms, so a run with
    any of them is intrusive (an approval bound to the URL, the steps and the identity). The URL policy is
    enforced on every request the page makes; a read-only run also aborts every request that can change state."""
    i = core.info(eng)
    rules = i["rules"]
    steps = list(steps or [])
    entry = {"engagement": eng, "action": "browser", "url": url, **({"task": task} if task else {}),
             **({"identity": identity} if identity else {})}

    def refuse(msg):
        core._audit({**entry, "refused": msg})
        return f"REFUSED: {msg}"

    if not os.path.exists(BROWSER):
        return refuse("the browser runtime isn't installed in this kali-mcp image (rebuild it: ./rvkit update)")
    if i["halted"]:
        return refuse("engagement is halted (./rvkit resume <engagement> on the host)")
    late = rvpolicy.time_refusal(rules)
    if late:
        return refuse(late + " (RULES.md)")
    if len(steps) > 30:
        return refuse("at most 30 steps")
    for st in steps:
        if not isinstance(st, dict) or len(set(st) & (READ_STEPS | WRITE_STEPS)) != 1 or \
                set(st) - READ_STEPS - WRITE_STEPS - {"value", "key"}:
            return refuse(f"bad step {json.dumps(st)[:120]}: one of {sorted(READ_STEPS | WRITE_STEPS)} per step")
        if "goto" in st:
            why = rvpolicy.check_url(core.policy_of(eng), st["goto"])
            if why:
                return refuse(f"step goto {st['goto']}: {why}")
    writes = any(set(st) & WRITE_STEPS for st in steps)
    tier, effect = ("intrusive", "write") if writes else ("active", "read")
    entry["tier"] = tier
    if tier not in rules["tiers"]:
        return refuse(f"this browser run is tier '{tier}', RULES.md allows only {rules['tiers']}")
    if core._tier_over(tier, max_tier):
        return refuse(f"this browser run is tier '{tier}' and this task may only use '{max_tier}'")
    pol = core.policy_of(eng)
    why = rvpolicy.check_url(pol, url)
    if why:
        return refuse(why)
    sess, hosts = {}, []
    if identity:
        import identities
        try:
            d = identities.usable(eng, identity, url, tier, effect)
            hosts = d["spec"]["hosts"]
        except ValueError as e:
            return refuse(str(e))
    if writes:
        action = {"kind": "browser", "url": url, "steps": steps, "identity": identity or None}
        if not approval_id:
            shown = f"browser {url}" + (f" as {identity}" if identity else "") + " then " + \
                ", ".join(next(iter(set(s) & (READ_STEPS | WRITE_STEPS))) + " " + str(next(iter(
                    v for k, v in s.items() if k in READ_STEPS | WRITE_STEPS)))[:60] for s in steps)
            a = core.request_approval(eng, action, tier, shown[:500], task)
            return (f"APPROVAL REQUIRED (the steps click, fill or press keys, which can change state). Approval id: "
                    f"{a['id']}. Ask the user to review and run on the host:  ./rvkit approve {eng} {a['id']}   "
                    f"Then call browse again with the same URL, steps and identity and approval_id='{a['id']}'.")
        err = core.consume_approval(eng, approval_id, action, rules)
        if err:
            return refuse(err)
        entry["approval"] = approval_id
    if core.usage(eng).get("requests", 0) >= (rules.get("max_requests") or 10 ** 12):
        return refuse(f"the request budget is used up (Max requests: {rules['max_requests']})")
    fills = {}
    try:
        for st in steps:
            for m in core.CRED_REF.finditer(str(st.get("value", ""))):
                fills[m.group(0)] = core.cred_value(eng, m.group(1))
        if identity:
            sess = identities._session(identities._get(eng, identity)) or identities.login(eng, identity)
    except ValueError as e:
        return refuse(core.scrub(eng, str(e)))
    scrub_map = {v: r for v, r in core.secret_values(eng).items()}
    bid = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + os.urandom(3).hex()
    rel = os.path.join("evidence", "browser", bid)
    try:
        out = work_dir(eng, "evidence", "browser", bid)  # chowned below: never through a link
        jobdir = work_dir(eng, ".browser")
    except Refused as e:
        return refuse(str(e))
    job = {"url": url, "steps": steps, "policy": pol, "out": f"/work/{eng}/{rel}", "writes": writes,
           "identity_hosts": hosts, "support": rules.get("browser_support") or [], "mask": mask or [],
           "max_requests": min(int(max_requests or 300), 2000)}
    job_path = os.path.join(jobdir, f"{bid}.json")
    core._write_json(job_path, job)
    os.chmod(job_path, 0o644)
    try:
        uid = i["uid"]
        os.chown(out, uid, uid, follow_symlinks=False)
    except (OSError, KeyError):
        pass
    command = f"{BROWSER} /opt/kali-mcp/browser_runner.py /work/{eng}/.browser/{bid}.json"
    entry["command"] = command
    env = {"RV_BROWSER_SESSION": json.dumps({"headers": sess.get("headers") or {}, "cookies": sess.get("cookies") or {},
                                             "fills": fills, "scrub": scrub_map})}
    if core._busy(eng) >= rules["max_parallel"]:
        return refuse(f"{core._busy(eng)} network command(s) already running for {eng} (Max parallel: "
                      f"{rules['max_parallel']}); wait for one to finish")
    with core._PAR_LOCK:
        core._RESERVED[eng] = core._RESERVED.get(eng, 0) + 1
    res = core._execute(eng, i, entry, command, tier, timeout_s, True, approval_id, task=task, reserved=True,
                        extra_env=env)
    try:
        summ = json.load(open(os.path.join(out, "summary.json")))
        for _ in range(int(summ.get("sent") or 0)):
            core.take_budget(eng, "requests", rules.get("max_requests"))
    except (OSError, ValueError):
        pass
    try:
        os.remove(job_path)
    except OSError:
        pass
    return res + f"\n[browser evidence: /work/{eng}/{rel}/ (requests.jsonl, page.html, screenshot.png, summary.json)]"


# ---------------------------------------------------------------- source analysis, no network
SOURCE_TOOLS = ("semgrep", "gitleaks", "trufflehog", "bandit")
EXT_RULES = {".php": "php", ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript",
             ".tsx": "typescript", ".java": "java", ".go": "go", ".rb": "ruby", ".cs": "csharp", ".kt": "kotlin",
             ".scala": "scala", ".c": "c", ".rs": "rust", ".swift": "swift", ".yaml": "yaml", ".yml": "yaml",
             ".tf": "terraform", ".sol": "solidity", ".html": "html", ".json": "json"}


def _source_path(eng, i, path):
    """The real path of an in-scope /src path or a path under /work/<eng>. Resolved before the check: the agent can
    make links in /work (ln -s /src/<other-client> /work/<eng>/x), and kali-mcp reads as root."""
    if not str(path or "").startswith("/"):
        raise ValueError(f"{path} is not in scope: use a /src path from SCOPE.md or a path under /work/{eng}")
    p = os.path.realpath(path)
    allowed = [os.path.realpath(a) for a in list(i["scope"]["paths"]) + [os.path.join(core.WORK, eng)]]
    if not any(_inside(p, a) for a in allowed):
        raise ValueError(f"{path} is not in scope: use a /src path from SCOPE.md or a path under /work/{eng}"
                         + (f" (it leads to {p})" if p != os.path.normpath(path) else ""))
    if not os.path.exists(p):
        raise ValueError(f"{path} does not exist")
    return p


def _languages(path, limit=20000):
    seen, n = set(), 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "vendor", ".venv")]
        for f in files:
            r = EXT_RULES.get(os.path.splitext(f)[1].lower())
            if r and os.path.isdir(os.path.join(core.RULES_DIR, r)):
                seen.add(r)
            n += 1
            if n > limit:
                return sorted(seen)
    return sorted(seen)


def analyze_source(eng, tool, path, rulesets=None, task=None, timeout_s=1800):
    i = core.info(eng)
    entry = {"engagement": eng, "uid": i["uid"], "action": "analyze_source", "tool": tool,
             **({"task": task} if task else {})}

    def refuse(msg):
        core._audit({**entry, "refused": msg})
        return f"REFUSED: {msg}"

    if i["halted"]:
        return refuse("engagement is halted (./rvkit resume <engagement> on the host)")
    if tool not in SOURCE_TOOLS:
        return refuse(f"tool must be one of {', '.join(SOURCE_TOOLS)}")
    try:
        p = _source_path(eng, i, path)
    except ValueError as e:
        return refuse(str(e))
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
    out = f"evidence/source/{tool}-{ts}-{os.urandom(2).hex()}.json"
    try:
        work_dir(eng, "evidence", "source")
    except Refused as e:
        return refuse(str(e))
    q = core.shlex.quote
    if tool == "semgrep":
        names = rulesets or _languages(p)
        bad = [r for r in names if not re.fullmatch(r"[a-z0-9_-]{1,40}", r)
               or not os.path.isdir(os.path.join(core.RULES_DIR, r))]
        if bad or not names:
            return refuse(f"no offline semgrep rules for {bad or 'this code'}; rulesets are folders of "
                          f"{core.RULES_DIR}")
        cmd = ("semgrep scan --metrics=off --disable-version-check --quiet --json "
               + " ".join(f"--config {q(os.path.join(core.RULES_DIR, r))}" for r in names)
               + f" --output {out} {q(p)}")
    elif tool == "gitleaks":
        cmd = f"gitleaks dir {q(p)} --report-format json --report-path {out} --redact --no-banner --exit-code 0"
    elif tool == "trufflehog":
        cmd = f"trufflehog filesystem {q(p)} --no-verification --no-update --json > {out}"
    else:
        cmd = f"bandit -r {q(p)} -f json -o {out} -q --exit-zero"
    entry.update(command=cmd, tier="passive", network="none")
    res = core._execute(eng, i, entry, cmd, "passive", timeout_s, False, None, task=task)
    full = os.path.join(core.WORK, eng, out)
    count = None
    try:
        raw = open(full).read()
        if tool == "trufflehog":
            count = sum(1 for line in raw.splitlines() if line.strip().startswith("{"))
        else:
            d = json.loads(raw or "null")
            count = len(d.get("results", [])) if isinstance(d, dict) else len(d or [])
    except (OSError, ValueError):
        pass
    head = (f"{tool}: {count} result(s) in /work/{eng}/{out} (no network was available to the tool)\n"
            if count is not None else f"{tool}: no report was written; see the output below\n")
    return head + res


# ---------------------------------------------------------------- application map (RW-012)
def _deployed_build(eng, url, max_tier, task):
    """The deployed build identity from a version endpoint: the X-Build-Id header or a JSON "build" field."""
    r = send(eng, "GET", url, {"Accept": "application/json"}, b"", None, max_tier, task, evidence_kind="appmap")
    if "status" not in r or r.get("status") is None:
        return None, r.get("refused") or r["text"].splitlines()[-1][:200], None
    hdr = {k.lower(): v for k, v in (r.get("headers") or [])}
    build = hdr.get("x-build-id")
    how = "X-Build-Id header"
    if not build:
        try:
            d = json.loads(r["body"] or b"{}")
            build = d.get("build") or d.get("commit") or d.get("version")
            how = "JSON build field"
        except ValueError:
            pass
    if not build:
        return None, f"HTTP {r['status']} without an X-Build-Id header or a JSON build field", r.get("evidence")
    return str(build).strip()[:128], how, r.get("evidence")


def appmap(eng, path, build_url=None, routes_file=None, max_tier=None, task=None):
    """Map a Laravel application's source (no code runs) and compare its build identity with the deployment.
    Writes evidence/appmap/laravel-<time>.json (audited, so evidence_provenance verifies it)."""
    import laravel_map
    i = core.info(eng)
    entry = {"engagement": eng, "uid": i["uid"], "action": "appmap", "framework": "laravel", "path": path,
             **({"task": task} if task else {})}
    try:
        p = _source_path(eng, i, path)
    except ValueError as e:
        core._audit({**entry, "refused": str(e)})
        return f"REFUSED: {e}"
    if not (os.path.isfile(os.path.join(p, "artisan")) or os.path.isfile(os.path.join(p, "bootstrap", "app.php"))):
        return f"REFUSED: {path} doesn't look like a Laravel application (no artisan or bootstrap/app.php)"
    m = laravel_map.analyze(p)  # reads nothing whose real path leaves p
    m["source_path"] = p
    if routes_file:
        work = os.path.realpath(os.path.join(core.WORK, eng))  # resolved: a link could lead into /control
        rf = os.path.realpath(routes_file if routes_file.startswith("/") else os.path.join(core.WORK, eng, routes_file))
        if not rf.startswith(work + "/") or not os.path.isfile(rf):
            return f"REFUSED: the route export must be a file in /work/{eng}"
        try:
            export = json.load(open(rf))
        except ValueError:
            return "REFUSED: the route export isn't JSON (php artisan route:list --json)"
        m["route_comparison"] = {**laravel_map.compare_routes(m["routes"], export),
                                 "export": os.path.relpath(rf, work)}
    if build_url:
        build, how, ev = _deployed_build(eng, build_url, max_tier, task)
        if build:
            m["build"].update(deployed=build, deployed_from=f"{build_url} ({how})", deployed_evidence=ev,
                              match=build == m["build"]["source_digest"])
        else:
            m["build"].update(deployed=None, deployed_error=how, match=None)
    else:
        m["build"]["deployed_error"] = "no build URL given (a version endpoint or header of the deployment)"
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
    rel = os.path.join("evidence", "appmap", f"laravel-{ts}-{os.urandom(2).hex()}.json")
    try:
        full = os.path.join(work_dir(eng, "evidence", "appmap"), os.path.basename(rel))  # chowned below
    except Refused as e:
        return f"REFUSED: {e}"
    with open(full, "w") as f:
        json.dump(m, f, indent=1)
    if os.geteuid() == 0:  # the engagement's user owns its files, like the sandbox's own output
        os.chown(full, i["uid"], i["uid"], follow_symlinks=False)
    core._audit({**entry, "command": f"appmap laravel {p}", "tier": "passive", "network": "none",
                 "leads": len(m["leads"]), "source_digest": m["build"]["source_digest"],
                 "build_match": m["build"].get("match"), "outputs": {rel: core.sha256_file(full)}})
    return core.scrub(eng, laravel_map.summary(m) + f"\n\n[map saved as verified evidence: /work/{eng}/{rel}]")
