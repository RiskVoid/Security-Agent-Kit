"""The planner's conversation as the console's Agent section shows it. Host only, read-only.

Reads the events of a conversation bound to an engagement from the local OpenHands API and turns them into the
items the page renders: the operator's and the planner's messages, and one step per tool call with what kind of
call it was, its tier, its result, whether the kit refused it or asked for an approval, the evidence files it
recorded and the finding it created. Secrets are redacted the same way as in evidence previews and the report.
Nothing here writes to OpenHands or to the engagement.

  python3 scripts/agent_view.py <eng> <conversation id>     the view as JSON
"""
import hashlib, json, os, re, sys, threading, time, urllib.parse

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(KIT, "harness"))
import conversations  # noqa: E402
from redact import redact  # noqa: E402  (stdlib only; shared with the worker and the report)

Fail = conversations.Fail
CID_RX = re.compile(r"^[0-9a-fA-F-]{8,64}$")
MAX_EVENTS = 6000        # a conversation longer than this shows its first MAX_EVENTS events and says so
OUT_CHARS, ARG_CHARS, TEXT_CHARS, WHY_CHARS = 8000, 4000, 40000, 800
# tools of OpenHands itself: they run in the planner's container, not in the Kali sandbox
LOCAL = {"terminal": "shell", "file_editor": "file"}
KINDS = {"kali_http_request": "http", "kali_browse": "browser"}
SERVERS = {"kali": "kali", "findings": "record", "worker": "worker", "web": "web", "intel": "intel"}

_lock = threading.Lock()
_events = {}   # conversation id -> {"events": [...], "ids": set, "last": timestamp, "at": time, "cut": bool}
_bound = {}    # engagement -> (time, {conversation ids})


def _text(content):
    return "\n".join(c.get("text", "") for c in content or [] if isinstance(c, dict) and c.get("type") == "text")


def _cut(s, n):
    s = s or ""
    return (s, False) if len(s) <= n else (s[:n], True)


def _args(e):
    raw = (e.get("tool_call") or {}).get("arguments") or ""
    try:
        a = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        a = None
    if not isinstance(a, dict):
        a = {k: v for k, v in (e.get("action") or {}).items() if k != "kind"} if not raw else {"arguments": raw}
    return a


def _kind(tool):
    if tool in LOCAL:
        return LOCAL[tool]
    return KINDS.get(tool) or SERVERS.get(tool.split("_", 1)[0], "tool")


def _title(tool, a):
    if tool in ("kali_run", "terminal") and a.get("command"):
        return str(a["command"])
    if tool == "kali_http_request" and a.get("url"):
        return f"{a.get('method') or 'GET'} {a['url']}" + (f" as {a['identity']}" if a.get("identity") else "")
    if tool == "file_editor":
        return f"{a.get('command') or 'view'} {a.get('path') or ''}".strip()
    short = (tool.split("_", 1)[1] if tool.split("_", 1)[0] in SERVERS and "_" in tool else tool).replace("_", " ")
    for key in ("title", "url", "path", "query", "item", "id", "name"):   # what the call is about, when it says so
        if isinstance(a.get(key), str) and a[key]:
            extra = f"  {a['state']}" if key == "item" and isinstance(a.get("state"), str) else ""
            return f"{short}  {a[key][:240]}{extra}"
    bits = [f"{k}={str(v)[:80]}" for k, v in a.items()
            if k not in ("engagement", "max_tier", "task", "timeout_s") and isinstance(v, (str, int, float, bool)) and v != ""]
    return (short + ("  " + "  ".join(bits) if bits else ""))[:300]


def _finding(out):
    i = out.find("{")
    if i < 0:
        return None
    try:
        d, _ = json.JSONDecoder().raw_decode(out[i:])
    except ValueError:
        return None
    if not isinstance(d, dict) or not re.fullmatch(r"F-\d{3,}", str(d.get("id") or "")):
        return None
    return {k: str(d.get(k) or "") for k in ("id", "title", "severity", "cwe", "status")}


def _step(e, obs):
    tool = e.get("tool_name") or (e.get("action") or {}).get("kind") or "tool"
    a = _args(e)
    step = {"t": "step", "id": e.get("id"), "ts": e.get("timestamp"), "tool": tool, "kind": _kind(tool),
            "local": tool in LOCAL, "title": redact(_title(tool, a)), "state": "running"}
    if isinstance(a.get("task"), str) and a["task"].strip():   # the planner's own label for the call
        step["task"] = redact(a["task"].strip()[:200])
    why, _ = _cut(e.get("reasoning_content") or "", WHY_CHARS)
    if why.strip():
        step["why"] = redact(why.strip())
    args, _ = _cut(json.dumps(a, indent=1, ensure_ascii=False, default=str), ARG_CHARS)
    step["args"] = redact(args)
    if obs is None:
        return step
    o = obs.get("observation") or {}
    out = _text(o.get("content"))
    out = re.sub(r"^\[Tool '[^']*' executed\.\]\n?", "", out)
    head = out[:400]
    step["state"] = "ok"
    if out.startswith("REFUSED:"):
        step["state"], step["reason"] = "refused", redact(out[8:].strip().split("\n", 1)[0][:400])
    elif "APPROVAL REQUIRED" in head:
        step["state"] = "approval"
        m = re.search(r"Approval id: ([a-f0-9]{6,32})", out)
        if m:
            step["approval"] = m.group(1)
    elif o.get("is_error"):
        step["state"] = "bad"
    m = re.search(r"\btier=(passive|active|intrusive)\b", head) or re.search(r"tier '(passive|active|intrusive)'", head)
    if m:
        step["tier"] = m.group(1)
    code = o.get("exit_code")
    m = re.search(r"\bexit=(-?\d+)\b", head)
    if m:
        code = int(m.group(1))
    if step["state"] == "ok":
        m = re.search(r" -> (\d{3})\b", head) if step["kind"] == "http" else None
        if m:
            step["res"] = m.group(1)
            if m.group(1)[0] == "5":
                step["state"] = "bad"
        elif isinstance(code, int):
            step["res"] = f"exit {code}"
            if code:
                step["state"] = "bad"
    ev = []
    for p in re.findall(r"/work/[A-Za-z0-9._-]+/(evidence/[A-Za-z0-9._/-]+)", out):
        if p not in ev:
            ev.append(p)
    if ev:
        step["evidence"] = ev[:6]
    if tool == "findings_record_finding" and step["state"] == "ok":
        f = _finding(out)
        if f:
            step["finding"] = f
    body, cut = _cut(out, OUT_CHARS)
    step["out"], step["cut"] = redact(body), cut
    return step


def normalize(events):
    """OpenHands events (oldest first) -> {"items", "status", "steps"}. Pure: the unit test feeds it fixtures."""
    obs = {e.get("action_id"): e for e in events if e.get("kind") == "ObservationEvent"}
    items, status, steps = [], None, 0
    for e in events:
        k = e.get("kind") or ""
        if k == "MessageEvent":
            text, cut = _cut(_text((e.get("llm_message") or {}).get("content")), TEXT_CHARS)
            if text.strip():
                items.append({"t": "user" if e.get("source") == "user" else "agent", "id": e.get("id"),
                              "ts": e.get("timestamp"), "text": redact(text), "cut": cut})
        elif k == "ActionEvent":
            steps += 1
            thought, cut = _cut(_text(e.get("thought")), TEXT_CHARS)
            if thought.strip():
                items.append({"t": "agent", "id": f"{e.get('id')}-t", "ts": e.get("timestamp"),
                              "text": redact(thought), "cut": cut})
            if e.get("tool_name") == "finish":   # the planner's closing message
                msg = str(_args(e).get("message") or "")
                if msg.strip():
                    items.append({"t": "agent", "id": e.get("id"), "ts": e.get("timestamp"),
                                  "text": redact(msg[:TEXT_CHARS]), "cut": len(msg) > TEXT_CHARS})
                continue
            items.append(_step(e, obs.get(e.get("id"))))
        elif k == "ConversationStateUpdateEvent":
            if e.get("key") == "execution_status":
                status = e.get("value")
        elif "Error" in k or k == "PauseEvent":
            text = e.get("error") or e.get("detail") or e.get("message") or ("Paused" if k == "PauseEvent" else k)
            items.append({"t": "note", "id": e.get("id"), "ts": e.get("timestamp"), "bad": "Error" in k,
                          "text": redact(str(text)[:2000])})
    return {"items": items, "status": status, "steps": steps}


def _page(cid, query):
    return conversations.api("GET", f"/api/conversations/{cid}/events/search?limit=100&sort_order=TIMESTAMP{query}",
                             timeout=20)


def events(cid):
    """Every event of a conversation, oldest first. The first call reads it all; later calls only what is new."""
    with _lock:
        c = _events.get(cid) or {"events": [], "ids": set(), "last": None, "cut": False}
        query = f"&timestamp__gte={urllib.parse.quote(c['last'])}" if c["last"] else ""
        page = None
        while not c["cut"]:
            r = _page(cid, query + (f"&page_id={urllib.parse.quote(str(page))}" if page else ""))
            for e in r.get("items") or []:
                if e.get("id") not in c["ids"]:
                    c["ids"].add(e.get("id"))
                    c["events"].append(e)
                    c["last"] = e.get("timestamp") or c["last"]
            page = r.get("next_page_id")
            if len(c["events"]) >= MAX_EVENTS:
                c["cut"] = True
            if not page:
                break
        c["at"] = time.time()
        _events[cid] = c
        for old in sorted(_events, key=lambda k: _events[k]["at"])[:-8]:   # keep the eight most recent
            del _events[old]
        return list(c["events"]), c["cut"]


def is_bound(eng, cid, actor):
    """Only a conversation bound to the engagement is shown under it (the binding is in kali-mcp's control volume)."""
    with _lock:
        at, ids = _bound.get(eng, (0, set()))
    if time.time() - at > 10 or cid not in ids:
        ids = {c["id"] for c in conversations.bound(eng, actor)}
        with _lock:
            _bound[eng] = (time.time(), ids)
    return cid in ids


def view(eng, cid, actor="cli:host", rev=""):
    if not CID_RX.match(cid or ""):
        raise Fail("invalid conversation id")
    if not is_bound(eng, cid, actor):
        raise Fail(f"this conversation is not bound to {eng}")
    info = conversations.api("GET", f"/api/conversations/{cid}", timeout=10)
    evs, cut = events(cid)
    n = normalize(evs)
    out = {"id": cid, "title": info.get("title") or "", "status": info.get("execution_status") or n["status"],
           "steps": n["steps"], "max_steps": info.get("max_iterations"), "created": info.get("created_at"),
           "updated": info.get("updated_at"), "url": conversations.url(cid), "truncated": cut, "items": n["items"]}
    out["rev"] = hashlib.sha256(json.dumps(out, sort_keys=True, default=str).encode()).hexdigest()[:16]
    if rev and rev == out["rev"]:
        return {"id": cid, "rev": rev, "unchanged": True}
    return out


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__); sys.exit(1)
    try:
        print(json.dumps(view(sys.argv[1], sys.argv[2]), indent=1))
    except Fail as e:
        print(f"error: {e}", file=sys.stderr); sys.exit(1)
