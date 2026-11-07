"""Scope-aware web fetching, shared by the worker (fetch_url) and the planner's web MCP (fetch).

Research fetches must never reach an engagement target (targets are tested only through the kali tool, which is
scope-checked and audit-logged) or anything non-public (the kit's own services, the lab, cloud metadata). Each
check resolves the host name and tests every address it resolves to, and runs again on every redirect.
Residual risk: the name is resolved again when connecting (DNS rebinding); the kali firewall is the hard boundary.
"""
import html, ipaddress, re, socket, urllib.error, urllib.parse, urllib.request

UA = "Mozilla/5.0 (rvkit research)"


def in_scope_name(host, domains):
    return any(host == d or host.endswith("." + d) for d in domains)


def refusal(url, nets, domains):
    """Why this URL must not be fetched, or None. nets/domains: the scope(s) to keep away from."""
    u = urllib.parse.urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        return "only http(s) URLs"
    host = u.hostname.lower()
    if in_scope_name(host, domains):
        return "REFUSED: this host is an engagement target. Use the kali tool (scope-checked and audit-logged)."
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(host, u.port or (443 if u.scheme == "https" else 80),
                                                       proto=socket.IPPROTO_TCP)}
    except OSError as e:
        return f"cannot resolve {host}: {e}"
    for a in addrs:
        ip = ipaddress.ip_address(a.split("%")[0])
        if any(ip in ipaddress.ip_network(n) for n in nets):
            return (f"REFUSED: {host} resolves to {ip}, which is in an engagement scope. "
                    "Use the kali tool (scope-checked and audit-logged).")
        if not ip.is_global:
            return f"REFUSED: {host} resolves to non-public address {ip}; this tool is for public research only."
    return None


class _CheckedRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, nets, domains):
        self.nets, self.domains = nets, domains

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        why = refusal(newurl, self.nets, self.domains)
        if why:
            raise urllib.error.URLError(f"redirect to {newurl} blocked: {why}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def html_to_text(raw):
    text = re.sub(r"(?is)<(script|style|noscript|svg)[^>]*>.*?</\1>", " ", raw)
    text = re.sub(r"(?i)<(br|/p|/div|/li|/h[1-6]|/tr)[^>]*>", "\n", text)
    text = html.unescape(re.sub(r"(?s)<[^>]+>", " ", text))
    text = re.sub(r"[ \t]+", " ", text)
    return re.sub(r"\n\s*\n+", "\n\n", re.sub(r" *\n *", "\n", text)).strip()


def fetch(url, nets, domains, max_bytes=2_000_000, timeout=30):
    """Fetch a public URL as text (HTML stripped), or return a REFUSED / error string."""
    why = refusal(url, nets, domains)
    if why:
        return why
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _CheckedRedirect(nets, domains))
    with opener.open(req, timeout=timeout) as r:
        ctype = r.headers.get("Content-Type", "")
        raw = r.read(max_bytes).decode("utf-8", "replace")
    return html_to_text(raw) if "html" in ctype or raw.lstrip()[:1] == "<" else raw
