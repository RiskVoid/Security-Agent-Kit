"""Browser runner for the browse tool (RW-010). kali-mcp starts it inside the engagement's sandbox, as the
engagement's own user, so the firewall and DNS policy apply underneath. On top of that it enforces the URL policy
(scope, exclusions, URL path limits) on every request the page makes: navigations, redirects, sub-resources,
requests made by scripts and WebSockets. Downloads and service workers are refused. A read-only run (navigation
and reading only) aborts every request that can change state, whatever a script tries.

  python browser_runner.py <job.json>        session material (cookies, headers, fill values) in RV_BROWSER_SESSION

Output in the job's evidence folder: requests.jsonl (every request, allowed or blocked, with the reason),
page.html (DOM with input values masked), screenshot.png (password fields and the job's mask selectors masked),
summary.json. Secret values are replaced by their references before anything is written.
"""
import json, os, sys, time, urllib.parse

sys.path.insert(0, "/opt/kali-mcp")
import policy as rvpolicy  # noqa: E402

SAFE = ("GET", "HEAD", "OPTIONS")
ASSET_TYPES = ("stylesheet", "font", "image", "media", "script")


def main(job_path):
    job = json.load(open(job_path))
    sess = json.loads(os.environ.pop("RV_BROWSER_SESSION", "{}") or "{}")
    secrets = sorted(sess.get("scrub", {}).items(), key=lambda kv: -len(kv[0]))
    fills = sess.get("fills", {})
    out = job["out"]
    os.makedirs(out, exist_ok=True)
    pol, support = job["policy"], [s.lower() for s in job.get("support") or []]
    ident_hosts = set(job.get("identity_hosts") or [])
    session_headers = sess.get("headers") or {}
    writes = bool(job.get("writes"))
    max_requests = int(job.get("max_requests") or 300)
    records, counts = [], {"sent": 0, "blocked": 0}

    def scrub(s):
        s = str(s)
        for v, ref in secrets:
            s = s.replace(v, ref)
        return s

    def decide(url, method, rtype):
        if url.startswith(("data:", "blob:", "about:")):
            return None, "inline"
        why = rvpolicy.check_url(pol, url)
        if why is None:
            if method not in SAFE and not writes:
                return f"{method} can change state and this run is read-only (navigation and reading only)", None
            return None, "scope"
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        if support and method == "GET" and rtype in ASSET_TYPES and \
                any(host == s or host.endswith("." + s) for s in support):
            return None, "support"
        return why, None

    def record(url, method, rtype, allowed, reason, status=None, identity=False):
        records.append({"t": round(time.time(), 3), "url": scrub(url)[:2000], "method": method, "type": rtype,
                        "allowed": allowed, "reason": reason, "status": status, "identity": identity})

    from playwright.sync_api import sync_playwright
    result = {"steps": [], "blocked": [], "downloads_refused": 0, "console_errors": []}
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=job.get("chromium", "/usr/bin/chromium"), headless=True,
                                    args=["--disable-dev-shm-usage", "--no-first-run", "--disable-background-networking",
                                          "--disable-component-update", "--disable-sync", "--metrics-recording-only",
                                          "--disable-default-apps", "--no-default-browser-check"])
        ctx = browser.new_context(ignore_https_errors=True, accept_downloads=False, service_workers="block",
                                  viewport={"width": 1280, "height": 800}, user_agent="rvkit-browser")
        if sess.get("cookies"):
            ctx.add_cookies([{"name": k, "value": v, "domain": h, "path": "/"}
                             for h in ident_hosts for k, v in sess["cookies"].items()])

        def on_route(route, request):
            url, method, rtype = request.url, request.method, request.resource_type
            why, kind = decide(url, method, rtype)
            if why is None and kind != "inline" and counts["sent"] >= max_requests:
                why = f"request limit of this run reached ({max_requests})"
            if why:
                counts["blocked"] += 1
                record(url, method, rtype, False, why)
                result["blocked"].append({"url": scrub(url)[:300], "reason": why})
                return route.abort("blockedbyclient")
            host = (urllib.parse.urlsplit(url).hostname or "").lower()
            add = session_headers if host in ident_hosts and kind == "scope" else {}
            if kind != "inline":
                counts["sent"] += 1
                record(url, method, rtype, True, kind, identity=bool(add))
            return route.continue_(headers={**request.headers, **add} if add else None)

        ctx.route("**/*", on_route)
        if hasattr(ctx, "route_web_socket"):
            def on_ws(ws):
                http_url = ws.url.replace("ws://", "http://", 1).replace("wss://", "https://", 1)
                why = rvpolicy.check_url(pol, http_url)
                if why:
                    counts["blocked"] += 1
                    record(ws.url, "WEBSOCKET", "websocket", False, why)
                    result["blocked"].append({"url": scrub(ws.url)[:300], "reason": why})
                    ws.close()
                else:
                    record(ws.url, "WEBSOCKET", "websocket", True, "scope")
                    ws.connect_to_server()
            ctx.route_web_socket("**/*", on_ws)
        page = ctx.new_page()
        statuses = {}
        page.on("response", lambda r: statuses.__setitem__(r.url, r.status))
        page.on("download", lambda d: (result.__setitem__("downloads_refused", result["downloads_refused"] + 1),
                                       d.cancel()))
        page.on("console", lambda m: m.type == "error" and len(result["console_errors"]) < 20 and
                result["console_errors"].append(scrub(m.text)[:300]))
        page.set_default_timeout(int(job.get("step_timeout_ms") or 15000))

        steps = [{"goto": job["url"]}] + list(job.get("steps") or [])
        for st in steps:
            rec = {"step": {k: (v if k != "value" else "[value]") for k, v in st.items()}}
            try:
                if "goto" in st:
                    try:
                        resp = page.goto(st["goto"], wait_until="domcontentloaded")
                        rec["status"] = resp.status if resp else None
                    except Exception as e:
                        # A URL that answers with a file: the download itself is refused (on_download cancels it),
                        # but the response status is the result an authorization check needs (200 or 403), so
                        # record it and go on with the next step instead of ending the run.
                        if "Download is starting" not in str(e):
                            raise
                        rec["status"], rec["download_refused"] = statuses.get(st["goto"]), True
                elif "click" in st:
                    page.click(st["click"])
                    page.wait_for_load_state("domcontentloaded")
                elif "fill" in st:
                    v = str(st.get("value", ""))
                    for ref, real in fills.items():
                        v = v.replace(ref, real)
                    page.fill(st["fill"], v)
                elif "press" in st:
                    page.press(st["press"], st.get("key", "Enter"))
                    page.wait_for_load_state("domcontentloaded")
                elif "wait_for" in st:
                    page.wait_for_selector(st["wait_for"])
                elif "wait" in st:
                    page.wait_for_timeout(min(int(st["wait"]), 10000))
                elif "text" in st:
                    rec["text"] = scrub(page.inner_text(st["text"]))[:4000]
                rec["url"] = scrub(page.url)
                rec["ok"] = True
            except Exception as e:  # a failed step is reported, not hidden
                rec["ok"], rec["error"] = False, scrub(f"{type(e).__name__}: {e}")[:500]
                result["steps"].append(rec)
                break
            result["steps"].append(rec)
        try:
            page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass
        masks = [page.locator("input[type=password]")] + [page.locator(s) for s in job.get("mask") or []]
        try:
            page.screenshot(path=os.path.join(out, "screenshot.png"), full_page=True, mask=masks,
                            mask_color="#000000")
        except Exception as e:
            result["screenshot_error"] = str(e)[:200]
        try:
            page.evaluate("""() => { for (const el of document.querySelectorAll('input,textarea')) {
                if (el.value) el.setAttribute('value', '[masked]'); } }""")
            html = page.content()
        except Exception:
            html = ""
        result.update(final_url=scrub(page.url), title=scrub(page.title() if html else ""))
        ctx.close()
        browser.close()
    for r in records:
        if r["allowed"] and r["status"] is None:
            r["status"] = statuses.get(r["url"])
    with open(os.path.join(out, "requests.jsonl"), "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    with open(os.path.join(out, "page.html"), "w") as f:
        f.write(scrub(html))
    result.update(sent=counts["sent"], blocked_count=counts["blocked"])
    with open(os.path.join(out, "summary.json"), "w") as f:
        json.dump(result, f, indent=1)
    print(json.dumps({k: result[k] for k in ("final_url", "title", "sent", "blocked_count", "downloads_refused")}))
    print(json.dumps({"steps": result["steps"]}, indent=1)[:6000])
    if result["blocked"]:
        print("blocked:\n" + "\n".join(f"  {b['url']}: {b['reason']}" for b in result["blocked"][:30]))
    return 0 if all(s.get("ok") for s in result["steps"]) else 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
