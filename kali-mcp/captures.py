"""Request captures: import, sanitize, replay and compare (RW-009).

The researcher imports a HAR file (browser developer tools, ZAP, mitmproxy) or a Burp Suite XML export on the host
(./rvkit capture, the console). kali-mcp keeps two copies:

  raw original     the file as imported, encrypted with the vault key in the control volume. Only the host can read
                   it (./rvkit capture <eng> raw <id>); it never reaches a model.
  sanitized copy   what the agent works with: cookies, authorization and token headers, secret-looking query, form
                   and JSON fields, JWTs and key-like values are replaced by [redacted]. Requests outside the scope
                   are kept but marked and can't be replayed. Authoritative copy in the control volume, a mirror in
                   /work/<eng>/captures/<id>.json for reading.

replay sends a captured request again through the execution broker (actions.send): the URL is checked against the
current policy, a request that can change state needs an approval bound to it, and the session comes from a named
identity rather than from the capture. The response is compared with the captured one (status, size, similarity,
JSON fields, fixture markers), and the comparison is saved as evidence.
"""
import base64, datetime, difflib, json, os, re, urllib.parse, uuid
import xml.etree.ElementTree as ET

import core
import policy as rvpolicy

SECRET_HEADER = {"cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token", "x-csrf-token",
                 "x-xsrf-token", "set-cookie", "x-amz-security-token", "x-goog-api-key", "api-key"}
SECRET_NAME = re.compile(r"pass|pwd|secret|token|api[_-]?key|apikey|auth|session|sessid|sid$|csrf|xsrf|signature|"
                         r"^sig$|^code$|otp|jwt|bearer|credential|private|^key$", re.I)
SECRET_VALUE = [re.compile(p) for p in (
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*",            # JWT
    r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{12,}",
    r"AKIA[0-9A-Z]{16}", r"gh[pousr]_[A-Za-z0-9]{30,}", r"xox[abpr]-[A-Za-z0-9-]{10,}", r"sk-[A-Za-z0-9]{20,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")]
RED = "[redacted]"
EXCERPT = 4000
ID_RX = re.compile(r"^[a-z0-9-]{4,40}$")


def _ctl(eng):
    d = os.path.join(core.ctl_dir(eng), "captures")
    os.makedirs(d, exist_ok=True)
    return d


def _mirror(eng):
    d = os.path.join(core.WORK, eng, "captures")
    os.makedirs(d, exist_ok=True)
    return d


# ---------------------------------------------------------------- sanitizing
def _values(text, counts):
    for rx in SECRET_VALUE:
        text, n = rx.subn(RED, text)
        counts["value"] = counts.get("value", 0) + n
    return text


def _json(node, counts):
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if SECRET_NAME.search(str(k)) and isinstance(v, (str, int, float)) and v not in ("", None):
                out[k] = RED
                counts["field"] = counts.get("field", 0) + 1
            else:
                out[k] = _json(v, counts)
        return out
    if isinstance(node, list):
        return [_json(v, counts) for v in node]
    if isinstance(node, str):
        return _values(node, counts)
    return node


def sanitize_text(text, mime, counts):
    """A request or response body with secret fields and values replaced."""
    if text is None:
        return None
    mime = (mime or "").lower()
    if "json" in mime or text[:1] in "{[":
        try:
            return json.dumps(_json(json.loads(text), counts), ensure_ascii=False)
        except ValueError:
            pass
    if "x-www-form-urlencoded" in mime or (re.fullmatch(r"[^\s=&]+=[^\s&]*(&[^\s=&]+=[^\s&]*)*", text or "")
                                            and "=" in text):
        pairs = urllib.parse.parse_qsl(text, keep_blank_values=True)
        out = []
        for k, v in pairs:
            if SECRET_NAME.search(k) and v:
                v = RED
                counts["field"] = counts.get("field", 0) + 1
            out.append((k, _values(v, counts)))
        return urllib.parse.urlencode(out, safe="[]")
    return _values(text, counts)


def sanitize_url(url, counts):
    u = urllib.parse.urlsplit(url)
    if not u.query:
        return url
    q = []
    for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True):
        if SECRET_NAME.search(k) and v:
            v = RED
            counts["query"] = counts.get("query", 0) + 1
        q.append((k, _values(v, counts)))
    return urllib.parse.urlunsplit(u._replace(query=urllib.parse.urlencode(q, safe="[]")))


def sanitize_headers(headers, counts):
    out = []
    for k, v in headers:
        lk = k.lower()
        if lk in (":authority", ":method", ":path", ":scheme"):
            continue
        if lk in ("cookie",):
            v = "; ".join(f"{c.split('=', 1)[0].strip()}={RED}" for c in v.split(";") if c.strip())
            counts["header"] = counts.get("header", 0) + 1
        elif lk == "set-cookie":
            v = re.sub(r"^(\s*[^=;\s]+)=[^;]*", r"\1=" + RED, v)
            counts["header"] = counts.get("header", 0) + 1
        elif lk in SECRET_HEADER or SECRET_NAME.search(lk.replace("content-", "")) and lk not in ("accept",):
            v = RED
            counts["header"] = counts.get("header", 0) + 1
        else:
            v = _values(v, counts)
        out.append([k, v])
    return out


# ---------------------------------------------------------------- parsing
def _har_entries(data):
    har = json.loads(data)
    for e in har.get("log", {}).get("entries", []):
        rq, rs = e.get("request", {}), e.get("response", {})
        post = rq.get("postData") or {}
        body = post.get("text")
        if body is None and post.get("params"):
            body = urllib.parse.urlencode([(p.get("name", ""), p.get("value", "")) for p in post["params"]])
        content = rs.get("content") or {}
        rbody = content.get("text")
        if rbody and content.get("encoding") == "base64":
            try:
                rbody = base64.b64decode(rbody).decode("utf-8", "replace")
            except ValueError:
                rbody = None
        yield {"method": rq.get("method", "GET").upper(), "url": rq.get("url", ""),
               "headers": [(h.get("name", ""), h.get("value", "")) for h in rq.get("headers", [])],
               "body": body, "mime": post.get("mimeType", ""), "started": e.get("startedDateTime"),
               "status": rs.get("status"), "response_headers": [(h.get("name", ""), h.get("value", ""))
                                                                for h in rs.get("headers", [])],
               "response_body": rbody, "response_mime": content.get("mimeType", ""),
               "response_size": content.get("size")}


def _http_message(raw):
    head, _, body = raw.partition("\r\n\r\n") if "\r\n\r\n" in raw else raw.partition("\n\n")
    lines = head.splitlines()
    return lines[0] if lines else "", [tuple(x.split(":", 1)) for x in lines[1:] if ":" in x], body


def _burp_entries(data):
    root = ET.fromstring(data)  # Burp's "Save items" XML; defusing isn't needed: no DTDs are resolved by ElementTree
    for item in root.iter("item"):
        def txt(tag):
            el = item.find(tag)
            if el is None or el.text is None:
                return ""
            return base64.b64decode(el.text).decode("utf-8", "replace") if el.get("base64") == "true" else el.text
        first, hdrs, body = _http_message(txt("request"))
        resp = txt("response")
        rfirst, rhdrs, rbody = _http_message(resp) if resp else ("", [], None)
        status = re.search(r"\s(\d{3})\b", rfirst)
        yield {"method": (item.findtext("method") or first.split(" ")[0] or "GET").upper(),
               "url": item.findtext("url") or "", "headers": [(k.strip(), v.strip()) for k, v in hdrs],
               "body": body or None, "mime": dict((k.strip().lower(), v.strip()) for k, v in hdrs).get("content-type", ""),
               "started": item.findtext("time"), "status": int(status.group(1)) if status else None,
               "response_headers": [(k.strip(), v.strip()) for k, v in rhdrs], "response_body": rbody,
               "response_mime": item.findtext("mimetype") or "", "response_size": len(rbody or "")}


def parse(data):
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
    s = text.lstrip()
    if s.startswith("{"):
        return "har", list(_har_entries(text))
    if s.startswith("<"):
        return "burp", list(_burp_entries(text))
    raise ValueError("not a HAR (JSON) file or a Burp Suite XML export")


# ---------------------------------------------------------------- import
def import_capture(eng, data, name=""):
    """Store the raw capture (encrypted) and its sanitized copy. Returns the sanitized summary."""
    core.require(eng)
    if len(data) > 50 * 1024 * 1024:
        raise ValueError("captures over 50 MB are refused")
    kind, raw_entries = parse(data)
    if not raw_entries:
        raise ValueError("the capture has no requests")
    pol = core.policy_of(eng)
    cid = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:6]
    counts, entries = {}, []
    for n, e in enumerate(raw_entries[:2000], 1):
        why = rvpolicy.check_url(pol, e["url"]) if e["url"] else "no URL"
        resp_body = e["response_body"]
        entries.append({
            "n": n, "method": e["method"], "url": sanitize_url(e["url"], counts),
            "in_scope": why is None, **({"scope_note": why} if why else {}), "started": e["started"],
            "request": {"headers": sanitize_headers(e["headers"], counts),
                        "body": sanitize_text(e["body"], e["mime"], counts), "mime": e["mime"]},
            "response": {"status": e["status"], "headers": sanitize_headers(e["response_headers"], counts),
                         "mime": e["response_mime"], "size": e["response_size"],
                         "body_excerpt": (sanitize_text(resp_body[:EXCERPT * 4], e["response_mime"], counts) or "")[:EXCERPT]
                         if resp_body else None}})
    doc = {"id": cid, "name": (name or "")[:100], "source": kind, "imported_at": core._now_iso(),
           "imported_by": core.ACTOR, "entries": entries, "redactions": counts,
           "out_of_scope": sum(1 for x in entries if not x["in_scope"]), "truncated": len(raw_entries) > 2000}
    raw = core._fernet().encrypt(data if isinstance(data, bytes) else data.encode())
    with open(os.path.join(_ctl(eng), f"{cid}.raw"), "wb") as f:
        f.write(raw)
    os.chmod(os.path.join(_ctl(eng), f"{cid}.raw"), 0o600)
    core._write_json(os.path.join(_ctl(eng), f"{cid}.json"), doc)
    core._write_json(os.path.join(_mirror(eng), f"{cid}.json"), doc)
    core._audit({"engagement": eng, "event": "capture-imported", "capture": cid, "source": kind,
                 "entries": len(entries), "redactions": counts, "out_of_scope": doc["out_of_scope"]})
    return summary(doc)


def summary(doc):
    return {"id": doc["id"], "name": doc["name"], "source": doc["source"], "imported_at": doc["imported_at"],
            "entries": len(doc["entries"]), "out_of_scope": doc["out_of_scope"], "redactions": doc["redactions"]}


def load(eng, cid):
    if not ID_RX.match(cid or ""):
        raise ValueError("bad capture id")
    try:
        return json.load(open(os.path.join(_ctl(eng), f"{cid}.json")))
    except OSError:
        raise ValueError(f"no capture {cid} in {eng}")


def raw(eng, cid):
    """The original capture (host only)."""
    load(eng, cid)
    data = core._fernet().decrypt(open(os.path.join(_ctl(eng), f"{cid}.raw"), "rb").read())
    core._audit({"engagement": eng, "event": "capture-raw-read", "capture": cid})
    return data


def listing(eng):
    core.require(eng)
    out = []
    for fn in sorted(os.listdir(_ctl(eng)), reverse=True):
        if fn.endswith(".json"):
            try:
                out.append(summary(json.load(open(os.path.join(_ctl(eng), fn)))))
            except (OSError, ValueError, KeyError):
                continue
    return out


def entry(eng, cid, n):
    doc = load(eng, cid)
    for e in doc["entries"]:
        if e["n"] == int(n):
            return e
    raise ValueError(f"capture {cid} has no request {n}")


def delete(eng, cid):
    load(eng, cid)
    for d, ext in ((_ctl(eng), ".json"), (_ctl(eng), ".raw"), (_mirror(eng), ".json")):
        try:
            os.remove(os.path.join(d, cid + ext))
        except OSError:
            pass
    core._audit({"engagement": eng, "event": "capture-deleted", "capture": cid})


# ---------------------------------------------------------------- compare and replay
def _keys(text):
    try:
        node = json.loads(text)
    except (ValueError, TypeError):
        return None
    keys = set()

    def walk(n, pre=""):
        if isinstance(n, dict):
            for k, v in n.items():
                keys.add(pre + str(k))
                walk(v, pre + str(k) + ".")
        elif isinstance(n, list) and n:
            walk(n[0], pre + "[].")
    walk(node)
    return keys


def compare(a_status, a_body, b_status, b_body, markers=()):
    """How response b differs from response a: status, size, similarity, JSON fields and which markers each holds."""
    a_body = a_body or ""
    b_body = b_body or ""
    if isinstance(a_body, bytes):
        a_body = a_body.decode("utf-8", "replace")
    if isinstance(b_body, bytes):
        b_body = b_body.decode("utf-8", "replace")
    sm = difflib.SequenceMatcher(None, a_body[:EXCERPT * 5], b_body[:EXCERPT * 5], autojunk=False)
    ka, kb = _keys(a_body), _keys(b_body)
    out = {"status": [a_status, b_status], "size": [len(a_body), len(b_body)],
           "similarity": round(sm.ratio(), 3), "same_status": a_status == b_status}
    if ka is not None and kb is not None:
        out["json_fields_added"] = sorted(kb - ka)[:50]
        out["json_fields_removed"] = sorted(ka - kb)[:50]
    if markers:
        out["markers"] = {m: [m in a_body, m in b_body] for m in markers}
    diff = list(difflib.unified_diff(a_body[:EXCERPT].splitlines(), b_body[:EXCERPT].splitlines(), "captured",
                                     "replayed", lineterm="", n=1))
    out["diff"] = "\n".join(diff[:120])
    return out


def build(e, changes=None):
    """The request to send from a sanitized entry plus the changes. Redacted headers are dropped (the identity
    supplies the session); a body or URL that still contains [redacted] is refused."""
    changes = changes or {}
    method = (changes.get("method") or e["method"]).upper()
    url = changes.get("url") or e["url"]
    u = urllib.parse.urlsplit(url)
    if RED in urllib.parse.unquote(u.query):  # redacted query values (tokens, keys) are dropped like headers
        q = [(k, v) for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True) if v != RED]
        url = urllib.parse.urlunsplit(u._replace(query=urllib.parse.urlencode(q)))
    if changes.get("query"):
        u = urllib.parse.urlsplit(url)
        q = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
        q.update({str(k): str(v) for k, v in changes["query"].items()})
        url = urllib.parse.urlunsplit(u._replace(query=urllib.parse.urlencode(q)))
    drop = {h.lower() for h in changes.get("remove_headers") or []}
    hop = {"host", "content-length", "connection", "accept-encoding", "transfer-encoding", "te", "upgrade",
           "keep-alive", "proxy-connection", "trailer"}
    headers = {k: v for k, v in e["request"]["headers"] if RED not in v and k.lower() not in drop and
               k.lower() not in hop and not k.startswith(":")}
    headers.update({str(k): str(v) for k, v in (changes.get("headers") or {}).items()})
    body = changes["body"] if "body" in changes else (e["request"].get("body") or "")
    for part, what in ((url, "URL"), (body, "body")):
        if RED in (part or ""):
            raise ValueError(f"the captured {what} has redacted values: give the {what.lower()} in changes "
                             "(use {{cred:NAME}} for a stored credential) or replay it as an identity")
    return method, url, headers, (body or "").encode()


def replay(eng, cid, n, identity=None, changes=None, approval_id=None, max_tier=None, task=None, markers=()):
    import actions
    e = entry(eng, cid, n)
    if not e["in_scope"] and not (changes or {}).get("url"):
        raise ValueError(f"request {n} is outside the scope ({e.get('scope_note')}); it can't be replayed")
    method, url, headers, data = build(e, changes)
    r = actions.send(eng, method, url, headers, data, approval_id, max_tier, task, identity=identity,
                     evidence_kind="replay")
    if "refused" in r or "approval" in r:
        return {"text": r["text"], **{k: r[k] for k in ("refused", "approval") if k in r}}
    cmp = compare(e["response"]["status"], e["response"].get("body_excerpt") or "", r["status"],
                  core.scrub(eng, r["body"]).decode("utf-8", "replace") if isinstance(r["body"], bytes) else r["body"],
                  markers)
    rec = {"capture": cid, "entry": n, "identity": identity, "changes": changes or {}, "method": method,
           "url": url, "replay_evidence": r["evidence"], "comparison": cmp, "at": core._now_iso()}
    rel = os.path.join("evidence", "replay", os.path.basename(r["evidence"])[:-4] + "-compare.json")
    core._write_json(os.path.join(core.WORK, eng, rel), rec)
    core._audit({"engagement": eng, "event": "capture-replayed", "capture": cid, "entry": n, "identity": identity,
                 "status": r["status"], "outputs": {rel: core.sha256_file(os.path.join(core.WORK, eng, rel))}})
    lines = [f"replayed {cid} #{n}: {method} {url}" + (f" as {identity}" if identity else ""),
             f"  status {cmp['status'][0]} -> {cmp['status'][1]}, size {cmp['size'][0]} -> {cmp['size'][1]}, "
             f"similarity {cmp['similarity']}"]
    if cmp.get("json_fields_added") or cmp.get("json_fields_removed"):
        lines.append(f"  JSON fields added {cmp.get('json_fields_added')}, removed {cmp.get('json_fields_removed')}")
    for m, (a, b) in (cmp.get("markers") or {}).items():
        lines.append(f"  marker {m!r}: captured {'yes' if a else 'no'}, replayed {'yes' if b else 'no'}")
    lines += [f"  {x}" for x in r["notes"]]
    lines.append(f"[comparison saved as evidence: /work/{eng}/{rel}; response: /work/{eng}/{r['evidence']}]")
    return {"text": core.scrub(eng, "\n".join(lines)), "comparison": cmp, "evidence": [r["evidence"], rel],
            "status": r["status"]}
