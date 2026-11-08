"""Console contract and security test: what the console accepts, refuses and records, against the running stack with
no GPU and no model provider. Uses a throwaway engagement (rv-console-test) that is deleted afterwards.

  sign-in and host checks; cross-site, wrong content type, missing console header, wrong method
  input validation (engagement create, findings, scope apply, audit, stream) gives 400, not a server error
  conflicts: a finding, the cover details, the executive summary and the scope changed since they were loaded give 409
  attribution: changes made through the console are in the audit log with actor and revisions before and after
  live updates: the event stream sends the overview, and the live view of an engagement
  inert content: the HTML report view is sandboxed, downloads are attachments, only report files are served
  isolation: the agent's container can't reach the console; other containers get 401 without the session token

Needs the stack up (./rvkit up). Run: python3 evals/console_contract_test.py
"""
import http.client, json, os, re, subprocess, sys, time

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT, ENG = 18101, "rv-console-test"
H = f"127.0.0.1:{PORT}"
results = []


def check(name, ok, detail=""):
    results.append(bool(ok))
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else f"\n      {str(detail)[:300]}"))


def req(method, path, body=None, headers=None, cookie=True, host=H):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=120)
    h = {"Host": host, **({"Cookie": f"rvc={TOKEN}"} if cookie else {}), **(headers or {})}
    data = None
    if body is not None:
        data = body if isinstance(body, (bytes, str)) else json.dumps(body)
        h.setdefault("Content-Type", "application/json")
        h.setdefault("X-RV-Console", "1")
    c.request(method, path, body=data, headers=h)
    r = c.getresponse()
    raw = r.read()
    try:
        js = json.loads(raw)
    except ValueError:
        js = None
    return r.status, js, raw, dict(r.getheaders())


def post(path, body, **kw):
    return req("POST", path, body, **kw)


def sh(*args, stdin=None):
    return subprocess.run(args, cwd=KIT, capture_output=True, text=True, input=stdin, timeout=300)


def cleanup():
    sh("docker", "compose", "exec", "-T", "kali-mcp", "python3", "/opt/kali-mcp/rvctl.py", "delete", ENG, "--force")
    sh("docker", "compose", "exec", "-T", "kali-mcp", "sh", "-c", f"rm -rf /work/_deleted-{ENG}-*")


def main():
    global TOKEN
    cleanup()
    r = sh("./rvkit", "engagement", ENG, "--tiers", "passive", "198.51.100.20")
    if r.returncode:
        print("FAIL  could not create the test engagement\n" + r.stdout[-500:] + r.stderr[-500:]); return 1
    finding = '{"engagement":"%s","actor":"agent:planner","fields":{"title":"<img src=x onerror=alert(1)>","severity":"high","asset":"a","description":"<script>alert(1)</script>"}}' % ENG
    sh("docker", "compose", "exec", "-T", "findings-mcp", "python3", "ops.py", "finding.record", stdin=finding)
    env = {**os.environ, "CONSOLE_PORT": str(PORT)}
    srv = subprocess.Popen([sys.executable, "scripts/console.py"], cwd=KIT, env=env, stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE)
    try:
        TOKEN = open(os.path.join(KIT, ".rvkit", "console.token")).read().strip()
        for _ in range(40):
            try:
                req("GET", "/", cookie=False); break
            except OSError:
                time.sleep(0.25)
        run_checks()
    finally:
        srv.terminate(); srv.wait(5)
        cleanup()
    print(f"\npassed {sum(results)}, failed {len(results) - sum(results)}")
    return 0 if all(results) else 1


def run_checks():
    started = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 1))  # earlier runs' history stays in the log
    print("== sign-in and request checks")
    check("page needs the session", req("GET", "/", cookie=False)[0] == 401)
    check("API needs the session", req("GET", "/api/overview", cookie=False)[0] == 401)
    check("wrong sign-in token refused", req("GET", "/login?t=nope", cookie=False)[0] == 403)
    check("foreign Host header refused", req("GET", "/api/overview", host="attacker.example")[0] == 403)
    s = req("GET", "/login?t=" + TOKEN, cookie=False)
    check("sign-in sets an HttpOnly SameSite=Strict cookie", "HttpOnly; SameSite=Strict" in s[3].get("Set-Cookie", ""))
    check("cross-site POST refused (Origin)",
          post(f"/api/eng/{ENG}/halt", {}, headers={"Origin": "https://evil.example"})[0] == 403)
    check("cross-site request refused (Sec-Fetch-Site)",
          post(f"/api/eng/{ENG}/halt", {}, headers={"Sec-Fetch-Site": "cross-site"})[0] == 403
          and req("GET", "/api/overview", headers={"Sec-Fetch-Site": "cross-site"})[0] == 403)
    check("POST without the console header refused", post(f"/api/eng/{ENG}/halt", {}, headers={"X-RV-Console": "0"})[0] == 401)
    check("POST that isn't JSON refused", post(f"/api/eng/{ENG}/halt", "x=1", headers={"Content-Type": "text/plain"})[0] == 415)
    check("JSON that isn't an object refused", post(f"/api/eng/{ENG}/halt", "[1]")[0] == 400)
    check("other methods refused", req("DELETE", f"/api/eng/{ENG}")[0] == 405)
    check("engagement still running after the refused halts", json.loads(json.dumps(
        req("GET", f"/api/eng/{ENG}")[1]["info"]["halted"])) is False)

    print("== validation")
    bad = [("bad name", {"name": "../x", "targets": "198.51.100.1"}),
           ("option as target", {"name": "rv-x1", "targets": "--help"}),
           ("target with spaces", {"name": "rv-x1", "targets": "198.51.100.1; rm -rf /"}),
           ("rate not a number", {"name": "rv-x1", "targets": "198.51.100.1", "rate": "lots"}),
           ("unknown tier", {"name": "rv-x1", "targets": "198.51.100.1", "tiers": ["root"]}),
           ("wrong type", {"name": "rv-x1", "targets": ["198.51.100.1"]})]
    for label, body in bad:
        st, js, *_ = post("/api/engagements", body)
        check(f"create refuses {label} (400)", st == 400 and js and js.get("error"), (st, js))
    st, js, *_ = post("/api/engagements", {"name": ENG, "targets": "198.51.100.21"})
    check("create refuses an existing engagement (409)", st == 409, (st, js))
    check("finding id checked", post(f"/api/eng/{ENG}/finding", {"id": "1 OR 1=1", "status": "confirmed"})[0] == 400)
    check("finding revision must be a number", post(f"/api/eng/{ENG}/finding", {"id": "F-001", "status": "confirmed", "revision": "1"})[0] == 400)
    check("finding: unknown status refused", post(f"/api/eng/{ENG}/finding", {"id": "F-001", "status": "pwned"})[0] == 400)
    check("scope revision must be what the page loaded", post(f"/api/eng/{ENG}/apply", {"scope": "- 198.51.100.20\n", "revision": "x"})[0] == 400)
    check("audit size must be a number", req("GET", f"/api/eng/{ENG}/audit?n=abc")[0] == 400)
    check("bad engagement in a path refused", req("GET", "/api/eng/..%2Fetc")[0] == 400)

    print("== conflicts and attribution")
    d = req("GET", f"/api/eng/{ENG}")[1]
    f = d["findings"][0]
    st, js, *_ = post(f"/api/eng/{ENG}/finding", {"id": f["id"], "status": "confirmed", "revision": f["revision"]})
    check("finding saved with its revision", st == 200 and js["finding"]["revision"] == f["revision"] + 1, (st, js))
    st, js, *_ = post(f"/api/eng/{ENG}/finding", {"id": f["id"], "status": "fixed", "revision": f["revision"]})
    check("stale finding revision gives 409", st == 409, (st, js))
    st, js, *_ = post(f"/api/eng/{ENG}/meta", {"client": "Acme", "digest": d["meta_digest"]})
    check("cover details saved", st == 200 and js["meta"]["client"] == "Acme", (st, js))
    check("stale cover details give 409", post(f"/api/eng/{ENG}/meta", {"client": "B", "digest": d["meta_digest"]})[0] == 409)
    st, js, *_ = post(f"/api/eng/{ENG}/summary", {"text": "Summary.", "digest": d["summary_digest"]})
    check("summary saved", st == 200)
    check("stale summary gives 409", post(f"/api/eng/{ENG}/summary", {"text": "X", "digest": d["summary_digest"]})[0] == 409)
    rev = d["info"]["revision"]
    st, js, *_ = post(f"/api/eng/{ENG}/apply", {"scope": "- 198.51.100.22\n", "rules": "- Allowed tiers: passive\n", "revision": rev})
    check("scope applied with its revision", st == 200, (st, js))
    st, js, *_ = post(f"/api/eng/{ENG}/apply", {"scope": "- 198.51.100.23\n", "rules": "- Allowed tiers: passive\n", "revision": rev})
    check("stale scope revision gives 409", st == 409, (st, js))
    check("the refused scope was not applied", "198.51.100.23/32" not in json.dumps(req("GET", f"/api/eng/{ENG}")[1]["info"]["scope"]))
    entries = req("GET", f"/api/eng/{ENG}/audit?n=50")[1]["entries"]
    mine = [e for e in entries if str(e.get("actor", "")).startswith("console:") and e.get("ts", "") >= started]
    events = {e.get("event") for e in mine}
    check("console changes are in the audit log with the console as actor",
          {"finding-updated", "meta-updated", "summary-updated", "scope-sync"} <= events, events)
    fe = next((e for e in mine if e.get("event") == "finding-updated"), {})
    check("audit entries carry revisions before and after", fe.get("before") == f["revision"] and fe.get("after") == f["revision"] + 1, fe)
    check("refused changes leave no audit entry",
          sum(1 for e in mine if e.get("event") == "finding-updated") == 1, [e.get("event") for e in mine])

    print("== live updates")
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
    c.request("GET", f"/api/stream?eng={ENG}", headers={"Host": H, "Cookie": f"rvc={TOKEN}"})
    r = c.getresponse()
    got, t0 = "", time.time()
    while time.time() - t0 < 20 and not ("event: overview" in got and "event: live" in got):
        got += r.fp.readline().decode()
    c.close()
    check("stream is server-sent events", r.getheader("Content-Type", "").startswith("text/event-stream"))
    check("stream sends the overview and the live view", "event: overview" in got and "event: live" in got, got[:300])
    check("stream refuses a bad engagement name", req("GET", "/api/stream?eng=../x")[0] == 400)

    print("== inert content")
    st, _, raw, hd = req("GET", "/")
    csp = hd.get("Content-Security-Policy", "")
    check("page CSP allows only its own scripts", "default-src 'self'" in csp and "script-src" not in csp.replace("default-src", ""), csp)
    check("agent-written text comes back as data, unchanged",
          req("GET", f"/api/eng/{ENG}")[1]["findings"][0]["title"] == "<img src=x onerror=alert(1)>")
    os.makedirs(os.path.join(eng_dir(), "report"), exist_ok=True)
    with open(os.path.join(eng_dir(), "report", "rv-test.html"), "w") as fh:
        fh.write("<script>alert(1)</script>")
    st, _, _, hd = req("GET", f"/report/{ENG}/rv-test.html")
    check("HTML report view is sandboxed, no scripts", st == 200 and "sandbox" in hd.get("Content-Security-Policy", "")
          and "script" not in hd.get("Content-Security-Policy", ""), hd.get("Content-Security-Policy"))
    st, _, _, hd = req("GET", f"/files/{ENG}/rv-test.html")
    check("downloads are attachments", "attachment" in hd.get("Content-Disposition", "") and hd.get("X-Content-Type-Options") == "nosniff")
    check("only report files are served", req("GET", f"/files/{ENG}/findings.db")[0] == 404
          and req("GET", f"/files/{ENG}/..%2FSCOPE.md")[0] == 404)

    print("== isolation from the containers")
    probe = ("import urllib.request\ntry:\n r=urllib.request.build_opener(urllib.request.ProxyHandler({})).open("
             f"urllib.request.Request('http://host.docker.internal:{PORT}/api/overview',headers={{'Host':'{H}'}}),timeout=4)"
             "\n print('status',r.status)\nexcept urllib.error.HTTPError as e: print('status',e.code)\n"
             "except Exception as e: print('unreachable',type(e).__name__)")
    r = sh("docker", "compose", "exec", "-T", "agent-canvas", "sh", "-c",
           f"curl -s -m 4 --noproxy '*' -o /dev/null -w '%{{http_code}}' -H 'Host: {H}' http://host.docker.internal:{PORT}/api/overview; echo; "
           f"curl -s -m 4 -o /dev/null -w '%{{http_code}}' -H 'Host: {H}' http://host.docker.internal:{PORT}/api/overview")
    lines = (r.stdout.strip().splitlines() + ["", ""])[:2]
    check("agent container: no route to the console, proxy refuses it", lines[0] in ("000", "") and lines[1] in ("403", "000"), r.stdout)
    r = sh("docker", "compose", "exec", "-T", "findings-mcp", "python3", "-c", probe)
    out = r.stdout.strip()
    check("other containers: no session token, so 401 (or unreachable)", out in ("status 401",) or out.startswith("unreachable"), out)
    r = sh("docker", "compose", "exec", "-T", "findings-mcp", "sh", "-c", "grep -rl 'rvc=\\|console.token' /work /opt 2>/dev/null | head -1")
    check("the session token isn't in any container's files", not r.stdout.strip(), r.stdout)


def eng_dir():
    env = dict(l.split("=", 1) for l in open(os.path.join(KIT, ".env")).read().splitlines() if "=" in l and not l.startswith("#"))
    return os.path.join(os.path.expanduser(env.get("ENGAGEMENTS_DIR") or "~/riskvoid/engagements"), ENG)


if __name__ == "__main__":
    sys.exit(main())
