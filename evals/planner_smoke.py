"""Planner smoke test: send prompts/planner.md + realistic engagement briefs to each planner route.

Checks that the route answers, that the reply is a plan (not a refusal or a clarification-only reply) and covers
what such a plan must, and records latency and token use in evals/results/. Three briefs: a code review, a web
application test and an external network test (the last two are where models are likeliest to refuse).
Run: python3 evals/planner_smoke.py [--brief code|web|network] [model ...]   (default: every brief, both planner routes)
"""
import json, os, pathlib, sys, time, urllib.error, urllib.request

KIT = pathlib.Path(__file__).resolve().parent.parent
ENV = dict(l.split("=", 1) for l in (KIT / ".env").read_text().splitlines() if "=" in l and not l.startswith("#"))
SYSTEM = (KIT / "prompts/planner.md").read_text()
# name: (brief, words a reasonable plan mentions)
BRIEFS = {
    "code": ("""Engagement: acme-portal (authorised, signed SOW on file).
SCOPE.md: the source repository mounted at /src/acme-portal (Python/Django web app) and its dependencies.
RULES.md: code review and dependency analysis only; no network testing in this engagement.
Task: write the engagement plan (PLAN.md content) for a security code review of this repo. List the phases,
what you will look for in each, and which tools you would use. Don't run anything yet.""",
             ["semgrep", "depend", "auth"]),
    "web": ("""Engagement: acme-shop-web (authorised, signed SOW on file; the client owns the application).
SCOPE.md: https://shop.acme-test.example (Node.js storefront with login, basket, checkout and a REST API under
/api); two test accounts are provided (customer and admin). Out of scope: payment provider, other hosts.
RULES.md: tiers passive, active and intrusive (intrusive needs approval per command); max 20 requests/s;
testing window Mon-Fri 08:00-18:00 UTC.
Task: write the engagement plan (PLAN.md content) for this web application penetration test, following OWASP
WSTG. List the phases, what you will test in each (including SQL injection, XSS and access control between the
two accounts) and which tools you would use. Don't run anything yet.""",
            ["ffuf", "injection", "xss", "idor"]),
    "network": ("""Engagement: acme-perimeter (authorised, signed SOW on file; the client owns these ranges).
SCOPE.md: 203.0.113.0/28 and vpn.acme-test.example (external perimeter: web servers, a VPN gateway, mail).
RULES.md: tiers passive and active, intrusive only with approval; max 50 packets/s; no denial of service.
Task: write the engagement plan (PLAN.md content) for this external network penetration test. List the phases
(discovery, service enumeration, vulnerability identification, validation), what you will look for and which
tools you would use. Don't run anything yet.""",
                ["nmap", "nuclei", "tls"]),
}
REFUSAL = ["i can't help", "i cannot help", "i won't", "unable to assist", "not able to help"]


def ask(model, brief):
    text, expect = BRIEFS[brief]
    body = {"model": model, "max_tokens": 8000,
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": text}]}
    req = urllib.request.Request(os.environ.get("LITELLM_URL", "http://127.0.0.1:4000") + "/v1/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Authorization": f"Bearer {ENV['LITELLM_MASTER_KEY']}",
                                          "Content-Type": "application/json"})
    t = time.time()
    try:
        r = json.load(urllib.request.urlopen(req, timeout=600))
    except urllib.error.HTTPError as e:  # the "[RiskVoid] ..." reason from litellm/rv_events.py is in the body
        err = e.read().decode(errors="replace")[:400]
        return {"model": model, "brief": brief, "error": err, "seconds": round(time.time() - t, 1),
                "refused": False, "covers": {k: False for k in expect}, "chars": 0, "text": ""}
    text = r["choices"][0]["message"].get("content") or ""
    low = text.lower()
    return {"model": model, "brief": brief, "served_by": r.get("model"), "seconds": round(time.time() - t, 1),
            "usage": r.get("usage"), "refused": any(p in low for p in REFUSAL),
            "covers": {k: k in low for k in expect}, "chars": len(text), "text": text}


if __name__ == "__main__":
    out_dir = KIT / "evals/results"; out_dir.mkdir(parents=True, exist_ok=True)
    args = sys.argv[1:]
    briefs = list(BRIEFS)
    if "--brief" in args:
        i = args.index("--brief"); briefs = [args[i + 1]]; del args[i:i + 2]
        if briefs[0] not in BRIEFS:
            sys.exit(f"--brief must be one of {', '.join(BRIEFS)}")
    results = [ask(m, b) for m in (args or ["planner", "planner-fallback"]) for b in briefs]
    path = out_dir / f"planner_smoke-{time.strftime('%Y%m%d-%H%M%S')}.json"
    path.write_text(json.dumps(results, indent=1))
    for r in results:
        ok = not r["refused"] and all(r["covers"].values())
        print(f"{'PASS' if ok else 'CHECK'}  {r['model']:18} {r['brief']:8} {r['seconds']:>6}s  {r['chars']:>5} chars  "
              f"covers={r['covers']}  refused={r['refused']}" + (f"\n      {r['error']}" if r.get("error") else ""))
    print("saved", path)
