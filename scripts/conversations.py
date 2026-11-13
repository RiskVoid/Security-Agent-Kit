"""OpenHands conversations bound to engagements (RW-007). Host only: the console and ./rvkit use it.

A bound conversation's model calls follow its engagement at the model gateway (Client data rule, halt), whatever
model or agent profile it is switched to later. The binding lives in kali-mcp's control volume (rvctl bind); this
module creates the conversation through the local OpenHands API and pauses bound conversations on halt.

  python3 scripts/conversations.py new <eng> [--message <text>] [--actor console:<name>]
  python3 scripts/conversations.py list <eng>         bound conversations with their OpenHands status (JSON)
  python3 scripts/conversations.py pause <eng>        pause every bound conversation (after a halt)

The console's Agent section also sends a message to one bound conversation, pauses it and resumes it (send,
pause_one, resume): a halted engagement takes no message and doesn't resume.
"""
import json, os, re, subprocess, sys, urllib.error, urllib.request

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(KIT, "litellm"))
import rv_routes  # noqa: E402


def env():
    out = {}
    try:
        for line in open(os.path.join(KIT, ".env")):
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.rstrip("\n").split("=", 1)
                out[k] = v
    except OSError:
        pass
    return out


E = env()
BASE = os.environ.get("OPENHANDS_URL", f"http://127.0.0.1:{E.get('GATEWAY_PORT') or 8000}")


class Fail(Exception):
    pass


def api(method, path, body=None, timeout=30):
    req = urllib.request.Request(BASE + path, method=method,
                                 headers={"Content-Type": "application/json",
                                          "X-Session-API-Key": E.get("OPENHANDS_API_KEY", "")},
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return json.loads(raw, strict=False) if raw else {}
    except urllib.error.HTTPError as e:
        raise Fail(f"OpenHands API {method} {path}: HTTP {e.code} {e.read()[:200].decode(errors='replace')}")
    except (urllib.error.URLError, OSError) as e:
        raise Fail(f"OpenHands is not reachable at {BASE} ({e}); start the stack with ./rvkit up")


def ctl(actor, *args):
    r = subprocess.run(["docker", "compose", "exec", "-T", "kali-mcp", "python3", "/opt/kali-mcp/rvctl.py",
                        "--actor", actor, *args], cwd=KIT, capture_output=True, text=True, timeout=120)
    if r.returncode:
        raise Fail(re.sub(r"^error:\s*", "", (r.stderr or r.stdout).strip().splitlines()[-1]))
    return r.stdout


def profile_for(rules):
    """riskvoid-planner, unless the engagement's Client data rule doesn't allow the planner's destination."""
    allowed = rules.get("client_data")
    planner = rv_routes.group_route("planner", E)[0]
    return "riskvoid-planner" if not allowed or planner in allowed else "riskvoid-local"


def url(cid):
    return f"http://localhost:{E.get('GATEWAY_PORT') or 8000}/canvas/conversations/{cid}"


def new(eng, actor="cli:host", message=""):
    info = json.loads(ctl(actor, "show", eng))
    if info.get("halted"):
        raise Fail(f"{eng} is halted: resume it first")
    name = profile_for(info["rules"])
    profiles = {p["name"]: p["id"] for p in api("GET", "/api/agent-profiles").get("profiles", [])}
    if name not in profiles:
        raise Fail(f"agent profile {name} is missing: run ./rvkit openhands")
    body = {"agent_profile_id": profiles[name], "tags": {"engagement": eng}, "autotitle": False,
            "workspace": {"working_dir": "/home/openhands/workspace/project", "kind": "LocalWorkspace"}}
    conv = api("POST", "/api/conversations", body)
    cid = conv["id"]
    title = f"Engagement {eng}"
    try:
        # bind before the first message, so the first model call already follows the engagement
        ctl(actor, "bind", eng, cid, title)
    except Fail:
        api("DELETE", f"/api/conversations/{cid}")
        raise
    try:
        api("PATCH", f"/api/conversations/{cid}", {"title": title})
    except Fail:
        pass
    if message.strip():
        api("POST", f"/api/conversations/{cid}/events",
            {"role": "user", "content": [{"type": "text", "text": f"Engagement `{eng}`: {message.strip()}"}],
             "run": True})
    return {"id": cid, "engagement": eng, "agent": name, "url": url(cid), "title": title}


def bound(eng, actor="cli:host"):
    return json.loads(ctl(actor, "conversations", eng, "--json"))


def listing(eng, actor="cli:host"):
    rows = []
    for c in bound(eng, actor):
        row = {**c, "url": url(c["id"])}
        try:
            d = api("GET", f"/api/conversations/{c['id']}", timeout=5)
            row.update(status=d.get("execution_status"), title=d.get("title") or c.get("title"),
                       updated=d.get("updated_at"))
        except Fail:
            row["status"] = "missing"
        rows.append(row)
    return rows


def pause(eng, actor="cli:host"):
    """Pause the engagement's bound conversations (the model gateway already refuses their calls once halted)."""
    out = []
    for c in bound(eng, actor):
        try:
            api("POST", f"/api/conversations/{c['id']}/pause", timeout=10)
            out.append({"id": c["id"], "paused": True})
        except Fail as e:
            out.append({"id": c["id"], "paused": False, "error": str(e)})
    return out


def _not_halted(eng, actor):
    if json.loads(ctl(actor, "show", eng)).get("halted"):
        raise Fail(f"{eng} is halted: resume it first")


def send(eng, cid, text, actor="cli:host"):
    """A message from the operator to a bound conversation; the planner starts on it if it isn't running."""
    _not_halted(eng, actor)
    try:
        api("POST", f"/api/conversations/{cid}/events",
            {"role": "user", "content": [{"type": "text", "text": text}], "run": True})
    except Fail as e:
        if "HTTP 429" not in str(e):
            raise
        api("POST", f"/api/conversations/{cid}/run")   # OpenHands saved the message; only the start was refused


def pause_one(cid):
    api("POST", f"/api/conversations/{cid}/pause", timeout=10)


def resume(eng, cid, actor="cli:host"):
    _not_halted(eng, actor)
    api("POST", f"/api/conversations/{cid}/run", timeout=10)


def main(a):
    actor = "cli:host"
    if "--actor" in a:
        i = a.index("--actor"); actor = a[i + 1]; del a[i:i + 2]
    msg = ""
    if "--message" in a:
        i = a.index("--message"); msg = a[i + 1]; del a[i:i + 2]
    if len(a) < 2:
        print(__doc__); return 1
    cmd, eng = a[0], a[1]
    if cmd == "new":
        c = new(eng, actor, msg)
        print(json.dumps(c)); return 0
    if cmd == "list":
        print(json.dumps(listing(eng, actor))); return 0
    if cmd == "pause":
        print(json.dumps(pause(eng, actor))); return 0
    print(__doc__); return 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Fail as e:
        print(f"error: {e}", file=sys.stderr); sys.exit(1)
