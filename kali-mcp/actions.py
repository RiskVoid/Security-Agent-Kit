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


def http_action(method, url, headers, body):
    """What an approval of a request is bound to (the body by its digest)."""
    return {"kind": "http", "method": method, "url": url,
            "headers": {k.lower(): v for k, v in sorted(headers.items())},
            "body": hashlib.sha256(body).hexdigest()}


def _evidence_path(eng, method, host):
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
    rel = os.path.join("evidence", "http", f"{ts}-{method.lower()}-{re.sub(r'[^a-z0-9.-]', '_', host)[:60]}-"
                       f"{os.urandom(3).hex()}.txt")
    os.makedirs(os.path.join(core.WORK, eng, os.path.dirname(rel)), exist_ok=True)
    return rel


def http_request(eng, method, url, headers=None, body="", approval_id=None, max_tier=None, task=None,
                 timeout_s=30, body_base64=False):
    i = core.info(eng)
    rules = i["rules"]
    method = (method or "GET").upper()
    entry = {"engagement": eng, "action": "http", "method": method, "url": url, **({"task": task} if task else {})}

    def refuse(msg, **extra):
        core._audit({**entry, "refused": msg, **extra})
        return f"REFUSED: {msg}"

    if method not in METHODS:
        return refuse(f"method must be one of {', '.join(METHODS)}")
    if i["halted"]:
        return refuse("engagement is halted (./rvkit resume <engagement> on the host)")
    late = rvpolicy.time_refusal(rules)
    if late:
        return refuse(late + " (RULES.md)")
    tier = "active" if method in SAFE_METHODS else "intrusive"
    entry["tier"] = tier
    if tier not in rules["tiers"]:
        return refuse(f"{method} is tier '{tier}', RULES.md allows only {rules['tiers']}")
    if core._tier_over(tier, max_tier):
        return refuse(f"{method} is tier '{tier}' and this task may only use '{max_tier}'")
    try:
        hdrs = _clean_headers(headers)
        data = base64.b64decode(body) if body_base64 else (body or "").encode()
    except (ValueError, TypeError) as e:
        return refuse(str(e))
    if len(data) > MAX_BODY_IN:
        return refuse(f"request body over {MAX_BODY_IN} bytes")
    pol = core.policy_of(eng)
    why = rvpolicy.check_url(pol, url)
    if why:
        return refuse(why)
    if tier == "intrusive":
        action = http_action(method, url, hdrs, data)
        if not approval_id:
            shown = f"HTTP {method} {url}" + (f" ({len(data)} byte body)" if data else "")
            a = core.request_approval(eng, action, tier, shown, task)
            return (f"APPROVAL REQUIRED ({method} can change state). Approval id: {a['id']}. Ask the user to "
                    f"review and run on the host:  ./rvkit approve {eng} {a['id']}   Then call http_request again "
                    f"with the same method, URL, headers and body and approval_id='{a['id']}'.")
        err = core.consume_approval(eng, approval_id, action, rules)
        if err:
            return refuse(err, approval=approval_id)
        entry["approval"] = approval_id

    blocked, hops, notes = _blocked(), [], []
    cur, cur_method, cur_data = url, method, data
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
            conn.request(cur_method, path, body=cur_data or None, headers=hdrs)
            r = conn.getresponse()
            raw = r.read(MAX_BODY_OUT + 1)
            hop_rec = {"url": cur, "method": cur_method, "ip": ip, "status": r.status, "reason": r.reason,
                       "headers": r.getheaders(), "body": raw[:MAX_BODY_OUT], "truncated": len(raw) > MAX_BODY_OUT,
                       "seconds": round(time.time() - t0, 2)}
            if u.scheme == "https" and conn.sock:
                der = conn.sock.getpeercert(binary_form=True)
                hop_rec["tls"] = {"version": conn.sock.version(), "cert_sha256": hashlib.sha256(der).hexdigest()
                                  if der else None, "verified": False}
        except (OSError, http.client.HTTPException) as e:
            hops.append({"url": cur, "method": cur_method, "ip": ip, "error": f"{type(e).__name__}: {e}"})
            break
        finally:
            conn.close()
        hops.append(hop_rec)
        loc = dict((k.lower(), v) for k, v in hop_rec["headers"]).get("location")
        if hop_rec["status"] not in (301, 302, 303, 307, 308) or not loc:
            break
        nxt = urllib.parse.urljoin(cur, loc)
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

    rel = _evidence_path(eng, method, urllib.parse.urlsplit(url).hostname or "host")
    full = os.path.join(core.WORK, eng, rel)
    with open(full, "wb") as f:
        f.write(f"# rvkit http_request {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')} "
                f"tier={tier}\n".encode())
        f.write(f"> {method} {url}\n".encode())
        for k, v in hdrs.items():
            f.write(f"> {k}: {v}\n".encode())
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
    last = hops[-1] if hops else None
    out = [f"{method} {url}"]
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
    return "\n".join(out)


# ---------------------------------------------------------------- source analysis, no network
SOURCE_TOOLS = ("semgrep", "gitleaks", "trufflehog", "bandit")
EXT_RULES = {".php": "php", ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript",
             ".tsx": "typescript", ".java": "java", ".go": "go", ".rb": "ruby", ".cs": "csharp", ".kt": "kotlin",
             ".scala": "scala", ".c": "c", ".rs": "rust", ".swift": "swift", ".yaml": "yaml", ".yml": "yaml",
             ".tf": "terraform", ".sol": "solidity", ".html": "html", ".json": "json"}


def _source_path(eng, i, path):
    p = os.path.normpath(path or "")
    allowed = list(i["scope"]["paths"]) + [os.path.join(core.WORK, eng)]
    if not any(p == a or p.startswith(a.rstrip("/") + "/") for a in allowed):
        raise ValueError(f"{path} is not in scope: use a /src path from SCOPE.md or a path under /work/{eng}")
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
    os.makedirs(os.path.join(core.WORK, eng, "evidence", "source"), exist_ok=True)
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
    res = core._execute(eng, i, entry, cmd, "passive", timeout_s, False, None)
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
