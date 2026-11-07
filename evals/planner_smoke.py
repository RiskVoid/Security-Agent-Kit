"""Planner smoke test: send prompts/planner.md + a realistic engagement brief to each planner route.

Checks that the route answers, that the reply is a plan (not a refusal or a clarification-only reply),
and records latency and token use in evals/results/. Run: python3 evals/planner_smoke.py [model ...]
"""
import json, os, pathlib, sys, time, urllib.request

KIT = pathlib.Path(__file__).resolve().parent.parent
ENV = dict(l.split("=", 1) for l in (KIT / ".env").read_text().splitlines() if "=" in l and not l.startswith("#"))
SYSTEM = (KIT / "prompts/planner.md").read_text()
BRIEF = """Engagement: acme-portal (authorised, signed SOW on file).
SCOPE.md: the source repository mounted at /src/acme-portal (Python/Django web app) and its dependencies.
RULES.md: code review and dependency analysis only; no network testing in this engagement.
Task: write the engagement plan (PLAN.md content) for a security code review of this repo. List the phases,
what you will look for in each, and which tools you would use. Don't run anything yet."""

EXPECT = ["semgrep", "depend", "auth"]  # a reasonable plan mentions static analysis, dependencies, authn/z
REFUSAL = ["i can't help", "i cannot help", "i won't", "unable to assist", "not able to help"]


def ask(model):
    body = {"model": model, "max_tokens": 8000,
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": BRIEF}]}
    req = urllib.request.Request(os.environ.get("LITELLM_URL", "http://127.0.0.1:4000") + "/v1/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Authorization": f"Bearer {ENV['LITELLM_MASTER_KEY']}",
                                          "Content-Type": "application/json"})
    t = time.time()
    r = json.load(urllib.request.urlopen(req, timeout=600))
    text = r["choices"][0]["message"].get("content") or ""
    low = text.lower()
    return {"model": model, "served_by": r.get("model"), "seconds": round(time.time() - t, 1),
            "usage": r.get("usage"), "refused": any(p in low for p in REFUSAL),
            "covers": {k: k in low for k in EXPECT}, "chars": len(text), "text": text}


if __name__ == "__main__":
    out_dir = KIT / "evals/results"; out_dir.mkdir(parents=True, exist_ok=True)
    results = [ask(m) for m in (sys.argv[1:] or ["planner", "planner-fallback"])]
    path = out_dir / f"planner_smoke-{time.strftime('%Y%m%d-%H%M%S')}.json"
    path.write_text(json.dumps(results, indent=1))
    for r in results:
        ok = not r["refused"] and all(r["covers"].values())
        print(f"{'PASS' if ok else 'CHECK'}  {r['model']:18} {r['seconds']:>6}s  {r['chars']:>5} chars  "
              f"covers={r['covers']}  refused={r['refused']}")
    print("saved", path)
