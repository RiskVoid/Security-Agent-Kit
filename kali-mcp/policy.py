"""Effective engagement policy: SCOPE.md and RULES.md parsed into what the kit enforces, what it refuses to accept,
and what it can't enforce (stated, never implied). Pure functions, no I/O: core.py stores revisions and applies
the result to the firewall, DNS, the request adapter and the run checks.

SCOPE.md, one entry per line ("#" starts a comment):
  app.example.com            that host only, every port
  *.example.com              its subdomains (not example.com itself: list it too if it is in scope)
  app.example.com:443,8443   that host, those ports only (also 10.0.0.0/24:22,80)
  10.0.0.0/24, 10.0.0.5      addresses
  https://app.example.com    the host on the URL's port (443 here)
  https://app.example.com/api/   only URLs under /api/ on that host and port. The sandbox's raw commands can't
                             enforce a path, so such a host is reachable only through the http_request tool
  !admin.example.com         exclusion of that host and its subdomains (also !10.0.0.9, !10.0.0.0/28,
                             !*.corp.example.com, !https://app.example.com/admin)
  /src/repo                  source code mounted read-only

RULES.md, "key: value" per line; an unknown key is an error rather than silently ignored:
  Allowed tiers, Max rate, Network, Strict tiers, Worker model   (as before)
  Timezone: Europe/Berlin    used by Window, Dates and Days (default UTC)
  Window: 08:00-18:00        Dates: 2026-11-10 to 2026-11-20      Days: mon-fri
  Max requests: 5000         requests through http_request, whole engagement
  Max commands: 300          commands through run, whole engagement
  Max parallel: 2            network commands at once; each gets Max rate / Max parallel
  Redirects: in-scope | none Execution: standard | controlled    Approval expiry: 24h
  Stop condition: ...        instruction for the agent and you; not detected by the kit
  Note: ...                  free text, kept with the policy
"""
import datetime
import ipaddress
import posixpath
import re
import urllib.parse

try:
    import zoneinfo
except ImportError:  # pragma: no cover (Python < 3.9)
    zoneinfo = None

TIERS = ("passive", "active", "intrusive")
ALWAYS_BLOCKED = ["127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4"]
NAME_RX = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}")
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
DEFAULT_RULES = {"tiers": ["passive", "active"], "max_rate": 100, "network": "online", "window": None,
                 "strict": False, "worker": "auto", "timezone": "UTC", "dates": None, "days": None,
                 "max_requests": None, "max_commands": None, "max_parallel": 2, "redirects": "in-scope",
                 "execution": "standard", "approval_hours": 24, "stop_conditions": [], "notes": []}


def entries(text):
    for line in (text or "").splitlines():
        s = re.sub(r"^[-*+]\s+", "", line.strip()).split("#")[0].strip()  # a bullet, never "*." of a wildcard
        if s:
            yield s


# ---------------------------------------------------------------- scope
def _ports(spec):
    """'443' / '80,443' / '8000-8100' -> sorted list of ints or ranges as 'a-b' strings; ValueError when invalid."""
    out = []
    for p in spec.split(","):
        p = p.strip()
        m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", p)
        if not m:
            raise ValueError(f"bad port {p!r}")
        a, b = int(m.group(1)), int(m.group(2) or m.group(1))
        if not (1 <= a <= b <= 65535):
            raise ValueError(f"bad port {p!r}")
        out.append(a if a == b else f"{a}-{b}")
    return out


def port_in(port, ports):
    if ports is None:
        return True
    for p in ports:
        if isinstance(p, int) and p == port:
            return True
        if isinstance(p, str):
            a, b = map(int, p.split("-"))
            if a <= port <= b:
                return True
    return False


def _norm_path(path):
    """Decoded, normalised URL path, or None when it hides structure (encoded slash or backslash, NUL)."""
    raw = path or "/"
    if re.search(r"%2f|%5c|%00|\\", raw, re.I):
        return None
    p = posixpath.normpath(urllib.parse.unquote(raw))
    p = "/" + p.lstrip("/") if p != "." else "/"
    return p + ("/" if raw.endswith("/") and p != "/" else "")


def under(path, prefix):
    """Path under a URL prefix: '/api/' covers '/api' and '/api/x', not '/apix'."""
    base = prefix.rstrip("/")
    return not base or path == base or path.startswith(base + "/")


def _split_url(s):
    u = urllib.parse.urlsplit(s)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("only http and https URLs")
    if u.username or u.password:
        raise ValueError("credentials don't belong in a URL scope entry")
    try:
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError:
        raise ValueError("bad port")
    prefix = _norm_path(u.path)
    if prefix is None:
        raise ValueError("encoded slashes or backslashes in the path")
    if u.query or u.fragment:
        raise ValueError("a URL scope entry can't have a query or fragment")
    return u.scheme, u.hostname.lower().rstrip("."), port, prefix


def _host_or_net(s):
    """'name' / '*.name' / 'ip' / 'cidr', optionally ':ports' -> ('host', name, wildcard, ports) or
    ('net', cidr, None, ports). ValueError with a reason."""
    s = s.lower()
    ports = None
    m = re.fullmatch(r"(.+?):([\d,\s-]+)", s)
    if m and ":" not in m.group(1):
        s, ports = m.group(1), _ports(m.group(2))
    if ":" in s or s.startswith("["):
        raise ValueError("IPv6 is not supported: the sandbox has no IPv6 route and DNS drops AAAA records")
    try:
        net = ipaddress.ip_network(s, strict=False)
        return "net", str(net), None, ports
    except ValueError:
        pass
    wildcard = s.startswith("*.")
    name = s[2:] if wildcard else s
    name = name.rstrip(".")
    if "*" in name or not NAME_RX.fullmatch(name):
        raise ValueError("not a host name, address, CIDR, URL or /src path")
    return "host", name, wildcard, ports


def parse_scope(text, blocked=ALWAYS_BLOCKED):
    pol = {"hosts": [], "nets": [], "urls": [], "paths": [],
           "exclude": {"hosts": [], "nets": [], "urls": []}, "errors": [], "warnings": []}
    seen = set()
    for raw in entries(text):
        s, neg = (raw[1:].strip(), True) if raw.startswith("!") else (raw, False)
        key = (neg, s.lower())
        if key in seen:
            pol["warnings"].append(f"listed twice: {raw}")
            continue
        seen.add(key)
        try:
            if s.startswith("/"):
                if neg:
                    raise ValueError("source paths can't be excluded; list only the ones in scope")
                p = posixpath.normpath(s)
                if not (p == "/src" or p.startswith("/src/")):
                    raise ValueError("source paths must be under /src")
                pol["paths"].append(p)
                continue
            if re.match(r"^[a-z][a-z0-9+.-]*://", s, re.I):
                scheme, host, port, prefix = _split_url(s)
                kind, name, _, _ = _host_or_net(host)
                if kind == "net" and not name.endswith("/32"):
                    raise ValueError("a URL needs one host, not a range")
                entry = {"scheme": scheme, "host": host, "port": port, "prefix": prefix}
                if neg:
                    pol["exclude"]["urls"].append(entry)
                elif prefix == "/":  # the whole host on that port: same as host:port
                    target = {"cidr": name, "ports": [port]} if kind == "net" else \
                        {"name": host, "wildcard": False, "ports": [port]}
                    pol["nets" if kind == "net" else "hosts"].append(target)
                else:
                    pol["urls"].append(entry)
                continue
            kind, name, wildcard, ports = _host_or_net(s)
            if neg:
                if ports:
                    raise ValueError("exclusions apply to every port; leave the port off")
                if kind == "net":
                    pol["exclude"]["nets"].append(name)
                else:
                    pol["exclude"]["hosts"].append({"name": name, "wildcard": wildcard})
            elif kind == "net":
                if any(ipaddress.ip_network(name).overlaps(ipaddress.ip_network(b)) for b in blocked):
                    raise ValueError("loopback, link-local, multicast and the kit's own networks are never reachable")
                pol["nets"].append({"cidr": name, "ports": ports})
            else:
                pol["hosts"].append({"name": name, "wildcard": wildcard, "ports": ports})
        except ValueError as e:
            pol["errors"].append(f"{raw}: {e}")
    for w in [h for h in pol["hosts"] if h["wildcard"]]:
        e = next((h for h in pol["hosts"] if not h["wildcard"] and h["name"] == w["name"]), None)
        if e and e["ports"] != w["ports"]:
            pol["errors"].append(f"{w['name']} and *.{w['name']} need the same ports: the firewall learns their "
                                 f"addresses from the same DNS rule, so it can't keep their ports apart")
    for u in pol["urls"]:
        if any(ipaddress.ip_network(u["host"] + "/32").overlaps(ipaddress.ip_network(b)) for b in blocked
               if _is_ip(u["host"])):
            pol["errors"].append(f"{u['scheme']}://{u['host']}: never reachable")
    return pol


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def name_matches(name, entry):
    n = name.lower().rstrip(".")
    return n.endswith("." + entry["name"]) if entry["wildcard"] else n == entry["name"]


def url_hosts(pol):
    """Hosts with URL-level rules: only the request adapter can enforce those, so raw commands don't reach them."""
    return sorted({u["host"] for u in pol["urls"] + pol["exclude"]["urls"]})


def excluded_name(pol, name):
    """!admin.example.com excludes it and its subdomains (DNS can't exclude a name alone); !*.x.com the
    subdomains only."""
    n = name.lower().rstrip(".")
    return any(name_matches(n, e) or not e["wildcard"] and n.endswith("." + e["name"]) for e in pol["exclude"]["hosts"])


def excluded_ip(pol, ip):
    a = ipaddress.ip_address(ip)
    return any(a in ipaddress.ip_network(n) for n in pol["exclude"]["nets"])


def raw_host(pol, name):
    """The scope entry that lets raw commands reach this host name, or None."""
    n = name.lower().rstrip(".")
    if excluded_name(pol, n) or n in url_hosts(pol):
        return None
    return next((h for h in pol["hosts"] if name_matches(n, h)), None)


def raw_net(pol, ip):
    """The scope entry that lets raw commands reach this address (ip or CIDR), or None."""
    try:
        net = ipaddress.ip_network(ip, strict=False)
    except ValueError:
        return None
    if net.version != 4 or any(net.overlaps(ipaddress.ip_network(n)) for n in pol["exclude"]["nets"]):
        return None
    if any(net.overlaps(ipaddress.ip_network(h + "/32")) for h in url_hosts(pol) if _is_ip(h)):
        return None
    return next((e for e in pol["nets"] if net.subnet_of(ipaddress.ip_network(e["cidr"]))), None)


def check_url(pol, url):
    """None when the request adapter may send a request to this URL, else the reason. Checks scheme, host, port,
    path and exclusions; the caller still resolves the name and checks the address (check_address)."""
    try:
        u = urllib.parse.urlsplit(url)
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError:
        return "not a valid URL"
    if u.scheme not in ("http", "https") or not u.hostname:
        return "only http and https URLs"
    if u.username or u.password:
        return "put credentials in headers, not in the URL"
    host = u.hostname.lower().rstrip(".")
    path = _norm_path(u.path)
    if path is None:
        return "encoded slashes, backslashes or NUL in the path are refused (they can hide where a request goes)"
    if _is_ip(host) and excluded_ip(pol, host) or not _is_ip(host) and excluded_name(pol, host):
        return f"{host} is excluded from scope"
    for x in pol["exclude"]["urls"]:
        if x["host"] == host and x["port"] == port and under(path, x["prefix"]):
            return f"{x['scheme']}://{host}{x['prefix']} is excluded from scope"
    for e in pol["urls"]:
        if e["host"] == host and e["port"] == port and e["scheme"] == u.scheme and under(path, e["prefix"]):
            return None
    if host in url_hosts(pol) and not any(e["host"] == host for e in pol["urls"]):
        pass  # only exclusions on this host: fall through to the host/net entries
    elif host in url_hosts(pol):
        allowed = ", ".join(f"{e['scheme']}://{e['host']}:{e['port']}{e['prefix']}" for e in pol["urls"] if e["host"] == host)
        return f"only {allowed} is in scope on {host}"
    if _is_ip(host):
        e = next((n for n in pol["nets"] if ipaddress.ip_address(host) in ipaddress.ip_network(n["cidr"])), None)
    else:
        e = next((h for h in pol["hosts"] if name_matches(host, h)), None)
    if not e:
        return f"{host} is not in scope"
    if not port_in(port, e["ports"]):
        return f"port {port} of {host} is not in scope (allowed: {e['ports']})"
    return None


def check_address(pol, host, ip, blocked):
    """After resolving a host name for the request adapter: the address must not be a kit, host or loopback
    address, and must not be excluded. Name-based entries accept whatever address DNS returns."""
    a = ipaddress.ip_address(ip)
    if a.version != 4:
        return "IPv6 is not supported"
    if any(a in ipaddress.ip_network(b) for b in blocked):
        return f"{host} resolves to {ip}, which is never reachable"
    if excluded_ip(pol, ip):
        return f"{host} resolves to {ip}, which is excluded from scope"
    return None


# ---------------------------------------------------------------- rules
def _tz(name):
    if name.upper() == "UTC":
        return datetime.timezone.utc
    if zoneinfo is None:
        raise ValueError("time zones other than UTC need Python 3.9+")
    try:
        return zoneinfo.ZoneInfo(name)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        raise ValueError(f"unknown time zone {name!r} (use a name like Europe/Berlin)")


def _days(v):
    out = set()
    for part in re.split(r"[,\s]+", v.strip()):
        if not part:
            continue
        m = re.fullmatch(r"([a-z]{3})[a-z]*(?:-([a-z]{3})[a-z]*)?", part)
        if not m or m.group(1) not in DAYS or (m.group(2) and m.group(2) not in DAYS):
            raise ValueError(f"bad day {part!r} (use mon, tue, ... or mon-fri)")
        a = DAYS.index(m.group(1))
        b = DAYS.index(m.group(2)) if m.group(2) else a
        i = a
        while True:
            out.add(DAYS[i])
            if i == b:
                break
            i = (i + 1) % 7
    return [d for d in DAYS if d in out]


def _int(v, lo, hi, what):
    m = re.fullmatch(r"(\d+)\s*(?:/s|per second|requests?|commands?)?", v.strip())
    if not m or not lo <= int(m.group(1)) <= hi:
        raise ValueError(f"{what} must be a number from {lo} to {hi}")
    return int(m.group(1))


def parse_rules(text):
    r = {k: (list(v) if isinstance(v, list) else v) for k, v in DEFAULT_RULES.items()}
    errors, window_tz, tz_set = [], None, False
    for s in entries(text):
        k, sep, v0 = s.partition(":")
        k, v = k.strip().lower(), v0.strip().lower()
        try:
            if not sep:
                raise ValueError("not a rule (use 'Key: value'; free text goes after 'Note:')")
            if k.startswith("allowed tier"):
                tiers = [t for t in re.split(r"[,\s]+", v) if t]
                bad = [t for t in tiers if t not in TIERS]
                if bad or not tiers:
                    raise ValueError(f"tiers are passive, active and intrusive (got {', '.join(bad) or 'none'})")
                r["tiers"] = [t for t in TIERS if t in tiers]
            elif k.startswith("max rate"):
                r["max_rate"] = _int(v, 1, 100000, "Max rate")
            elif k == "network":
                if v not in ("online", "offline"):
                    raise ValueError("Network is online or offline")
                r["network"] = v
            elif k.startswith("strict"):
                if v not in ("on", "off", "yes", "no", "true", "false"):
                    raise ValueError("Strict tiers is on or off")
                r["strict"] = v in ("on", "yes", "true")
            elif k.startswith("worker"):
                if v not in ("private", "auto"):
                    raise ValueError("Worker model is private or auto")
                r["worker"] = v
            elif k.startswith("window"):
                m = re.fullmatch(r"(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})\s*(\S+)?", v0.strip())
                if not m or int(m.group(1)) > 23 or int(m.group(3)) > 24 or int(m.group(2)) > 59 or int(m.group(4)) > 59:
                    raise ValueError("Window is HH:MM-HH:MM, optionally followed by a time zone")
                r["window"] = [int(x) for x in m.groups()[:4]]
                window_tz = m.group(5) or ("UTC" if "utc" in k else None)
            elif k in ("timezone", "time zone"):
                _tz(v0.strip())
                r["timezone"], tz_set = ("UTC" if v == "utc" else v0.strip()), True
            elif k == "dates":
                m = re.fullmatch(r"(\d{4}-\d{2}-\d{2})\s*(?:to|-|until|–)\s*(\d{4}-\d{2}-\d{2})", v)
                if not m:
                    raise ValueError("Dates is YYYY-MM-DD to YYYY-MM-DD")
                a, b = (datetime.date.fromisoformat(x) for x in m.groups())
                if b < a:
                    raise ValueError("the end date is before the start date")
                r["dates"] = [a.isoformat(), b.isoformat()]
            elif k == "days":
                r["days"] = _days(v)
            elif k.startswith("max request"):
                r["max_requests"] = _int(v, 1, 10_000_000, "Max requests")
            elif k.startswith("max command"):
                r["max_commands"] = _int(v, 1, 1_000_000, "Max commands")
            elif k.startswith("max parallel"):
                r["max_parallel"] = _int(v, 1, 16, "Max parallel")
            elif k == "redirects":
                if v not in ("in-scope", "none"):
                    raise ValueError("Redirects is in-scope or none")
                r["redirects"] = v
            elif k == "execution":
                if v not in ("standard", "controlled"):
                    raise ValueError("Execution is standard or controlled")
                r["execution"] = v
            elif k.startswith("approval expir"):
                m = re.fullmatch(r"(\d{1,3})\s*h(?:ours?)?", v)
                if not m or not 1 <= int(m.group(1)) <= 168:
                    raise ValueError("Approval expiry is 1h to 168h")
                r["approval_hours"] = int(m.group(1))
            elif k.startswith("stop"):
                if not v:
                    raise ValueError("say what the condition is")
                r["stop_conditions"].append(v0.strip()[:300])
            elif k == "note":
                r["notes"].append(v0.strip()[:300])
            else:
                raise ValueError("unknown rule")
        except ValueError as e:
            errors.append(f"{s}: {e}")
    if window_tz:  # "Window: 08:00-18:00 Europe/Berlin" or the older "Window (UTC): ..."
        try:
            _tz(window_tz)
            if tz_set and window_tz.upper() != r["timezone"].upper():
                errors.append(f"Window says {window_tz} but Timezone is {r['timezone']}")
            else:
                r["timezone"] = "UTC" if window_tz.upper() == "UTC" else window_tz
        except ValueError as e:
            errors.append(f"Window: {e}")
    return r, errors


def time_refusal(rules, now=None):
    """None when testing is allowed at this moment, else a readable reason."""
    if not (rules.get("window") or rules.get("dates") or rules.get("days")):
        return None
    try:
        tz = _tz(rules.get("timezone") or "UTC")
    except ValueError:
        return "the time zone in RULES.md is not valid"
    now = (now or datetime.datetime.now(datetime.timezone.utc)).astimezone(tz)
    zone = rules.get("timezone") or "UTC"
    if rules.get("dates"):
        a, b = rules["dates"]
        if now.date().isoformat() < a:
            return f"testing starts on {a} ({zone})"
        if now.date().isoformat() > b:
            return f"testing ended on {b} ({zone})"
    if rules.get("days") and DAYS[now.weekday()] not in rules["days"]:
        return f"testing is allowed on {', '.join(rules['days'])} only ({zone})"
    if rules.get("window"):
        h1, m1, h2, m2 = rules["window"]
        cur, a, b = now.hour * 60 + now.minute, h1 * 60 + m1, h2 * 60 + m2
        if not (a <= cur < b if a <= b else (cur >= a or cur < b)):
            return f"outside the testing window {h1:02d}:{m1:02d}-{h2:02d}:{m2:02d} ({zone})"
    return None


# ---------------------------------------------------------------- effective policy
def limits(pol, rules):
    """What the kit does not enforce, in words: shown before activation and kept with every revision."""
    out = []
    for h in url_hosts(pol):
        paths = [u["prefix"] for u in pol["urls"] if u["host"] == h]
        ex = [u["prefix"] for u in pol["exclude"]["urls"] if u["host"] == h]
        what = (f"only {', '.join(paths)}" if paths else "") + (" and " if paths and ex else "") + \
            (f"not {', '.join(ex)}" if ex else "")
        out.append(f"{h}: path limits ({what}) are enforced by the http_request tool only. Commands through run "
                   f"can't reach {h} at all.")
    if pol["exclude"]["hosts"] and pol["hosts"]:
        names = ", ".join(("*." if e["wildcard"] else "") + e["name"] for e in pol["exclude"]["hosts"])
        out.append(f"Excluded names ({names}) don't resolve in the sandbox and are refused by the request tool. "
                   f"If one shares an IP address with an in-scope host, a tool that sets the Host header itself "
                   f"can still reach it there: exclude the address too if that matters.")
    if pol["hosts"]:
        out.append("Host names are allowed by name: their addresses are whatever DNS returns during the test.")
    if rules["stop_conditions"]:
        out.append("Stop conditions are instructions to the agent and to you; the kit doesn't detect them.")
    if rules["max_requests"] is None:
        out.append("No request budget (Max requests): the http_request tool is limited only by Max rate.")
    if rules["execution"] == "standard" and (pol["hosts"] or pol["nets"]):
        out.append("Execution: standard. Scripts and unknown programs run through run at their classified tier; "
                   "use Execution: controlled to require an approval for every network command that isn't a "
                   "known tool.")
    out.append("IPv6 is never reachable from the sandbox (AAAA records are filtered).")
    return out


def effective(scope_text, rules_text, blocked=ALWAYS_BLOCKED):
    pol = parse_scope(scope_text, blocked)
    rules, rerr = parse_rules(rules_text)
    pol["errors"] += rerr
    if not (pol["hosts"] or pol["nets"] or pol["urls"] or pol["paths"]):
        pol["warnings"].append("nothing is in scope yet")
    pol["rules"] = rules
    pol["limits"] = limits(pol, rules)
    return pol


def legacy_scope(pol):
    """The {nets, domains, paths} shape older readers use: every target, for display and for keeping the web
    research tools away from engagement targets (broader is safer there)."""
    nets = [n["cidr"] for n in pol["nets"]] + [u["host"] + "/32" for u in pol["urls"] if _is_ip(u["host"])]
    domains = [("*." if h["wildcard"] else "") + h["name"] for h in pol["hosts"]] + \
        [u["host"] for u in pol["urls"] if not _is_ip(u["host"])]
    return {"nets": sorted(set(nets)), "domains": sorted(set(domains)), "paths": pol["paths"]}


def describe(pol):
    """One line per entry, for people: what each scope entry allows."""
    out = []
    for h in pol["hosts"]:
        out.append(("*." if h["wildcard"] else "") + h["name"] + (f" ports {','.join(map(str, h['ports']))}" if h["ports"] else ""))
    for n in pol["nets"]:
        out.append(n["cidr"] + (f" ports {','.join(map(str, n['ports']))}" if n["ports"] else ""))
    for u in pol["urls"]:
        out.append(f"{u['scheme']}://{u['host']}:{u['port']}{u['prefix']} (request tool only)")
    out += pol["paths"]
    return out
