"""Configure OpenHands (agent-canvas) for the kit through its local API. Idempotent; ./rvkit openhands runs it,
and ./rvkit setup / up run it automatically.

Creates or updates:
  LLM profiles    colab-qwen  (openai/colab-qwen via LiteLLM: the hands-on model — the abliterated Qwen served
                           from Colab by default, or any endpoint via ./rvkit worker; falls back to an OpenRouter
                           model while the endpoint is down)
                  private-llm (same worker endpoint, never falls back: no egress, fails closed)
                  planner (openai/planner via LiteLLM: OpenRouter, with fallback)
  MCP servers     search, fetch, kali, worker, findings, intel
  Agent profiles  riskvoid-planner  planner LLM, prompts/planner.md, all six MCP servers (default)
                  riskvoid-local    private-llm only, no OpenRouter: prompts/planner.md + prompts/local.md
Keys are read from .env and sent only to the local OpenHands API; nothing is printed.
"""
import json, os, sys, urllib.error, urllib.request

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.environ.get("OPENHANDS_URL", "http://127.0.0.1:8000")

MCP = {
    "search":   {"url": "http://mcp-gateway:8081/sse", "transport": "sse",
                 "description": "Web search (SearXNG)"},
    "fetch":    {"url": "http://mcp-gateway:8082/sse", "transport": "sse",
                 "description": "Fetch a web page as text"},
    "kali":     {"url": "http://kali-mcp:8090/mcp", "transport": "http", "timeout": 120, "sse_read_timeout": 1800,
                 "description": "Kali tools in a per-engagement sandbox (scope, tiers, approvals, audit)"},
    "worker":   {"url": "http://worker-mcp:8091/mcp", "transport": "http", "timeout": 120, "sse_read_timeout": 600,
                 "description": "Delegate hands-on tool work to the local worker model"},
    "findings": {"url": "http://findings-mcp:8092/mcp", "transport": "http", "timeout": 120, "sse_read_timeout": 600,
                 "description": "Findings, methodology playbooks, branded report"},
    "intel":    {"url": "http://intel-mcp:8093/mcp", "transport": "http", "timeout": 120, "sse_read_timeout": 600,
                 "description": "Vulnerability intel: OSV, NVD, EPSS, CISA KEV"},
}


def env():
    out = {}
    for line in open(os.path.join(KIT, ".env")):
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.rstrip("\n").split("=", 1)
            out[k] = v
    return out


E = env()
HDR = {"Content-Type": "application/json", "X-Session-API-Key": E.get("OPENHANDS_API_KEY", "")}


def api(method, path, body=None, ok404=False, raise_http=False):
    req = urllib.request.Request(BASE + path, method=method, headers=HDR,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        if ok404 and e.code == 404:
            return None
        if raise_http:
            raise
        raise SystemExit(f"OpenHands API {method} {path}: HTTP {e.code} {e.read()[:300].decode(errors='replace')}")


def llm(model, max_out):
    # max_output_tokens: OpenHands otherwise asks for 64k per call, and OpenRouter reserves credit for the
    # whole amount (requests fail on small balances); 16k is plenty for planning turns
    return {"model": model, "api_key": E["LITELLM_MASTER_KEY"], "base_url": "http://litellm:4000/v1",
            "timeout": 600, "num_retries": 5, "drop_params": True, "native_tool_calling": True,
            "stream": False, "caching_prompt": True, "max_output_tokens": max_out}


def load_profile(name):
    """Current agent profile, or None. A profile this OpenHands version can't load (saved by a different version)
    is deleted so it can be recreated."""
    try:
        return api("GET", f"/api/agent-profiles/{name}", ok404=True, raise_http=True)
    except urllib.error.HTTPError as e:
        if e.code != 400:
            raise SystemExit(f"OpenHands API GET /api/agent-profiles/{name}: HTTP {e.code}")
        api("DELETE", f"/api/agent-profiles/{name}", ok404=True)
        print(f"  {name}: stored profile was from another OpenHands version, recreated")
        return None


def agent_profile(name, llm_ref, mcp_refs, persona):
    cur = load_profile(name)
    base = (cur or {}).get("profile") or {"schema_version": 4, "agent_kind": "openhands", "agent": "CodeActAgent",
                                          "name": name}
    base.update(llm_profile_ref=llm_ref, mcp_server_refs=mcp_refs, persona=persona, system_message_suffix=None)
    res = api("POST", f"/api/agent-profiles/{name}", base)
    return (res.get("profile") or res).get("id") or api("GET", f"/api/agent-profiles/{name}")["profile"]["id"]


def main():
    quiet = "--quiet" in sys.argv
    say = (lambda *a: None) if quiet else print
    # 1. LLM profiles
    for name, model, max_out in (("colab-qwen", "openai/colab-qwen", 8192),
                                 ("private-llm", "openai/private-llm", 8192),
                                 ("planner", "openai/planner", 16384)):
        api("POST", f"/api/profiles/{name}", {"llm": llm(model, max_out), "include_secrets": True})
    say("  LLM profiles: colab-qwen, private-llm, planner")
    # 2. MCP servers (create or update)
    have = set((api("GET", "/api/settings").get("agent_settings", {}).get("mcp_config") or {}).keys())
    for key, cfg in MCP.items():
        api("PATCH" if key in have else "POST", f"/api/settings/mcp/{key}", {**cfg, "enabled": True})
    say("  MCP servers: " + ", ".join(MCP))
    # 3. agent profiles
    planner_md = open(os.path.join(KIT, "prompts", "planner.md")).read()
    local_md = open(os.path.join(KIT, "prompts", "local.md")).read()
    pid = agent_profile("riskvoid-planner", "planner", list(MCP), planner_md)
    agent_profile("riskvoid-local", "private-llm", [k for k in MCP if k != "worker"],
                  planner_md + "\n\n" + local_md)
    # Migrate older installs. The loop above (re)creates colab-qwen / private-llm with the right model, so move the
    # stock "default" agent off any superseded LLM profile name and drop leftover profiles from earlier names:
    #   worker/worker-private (endpoint-neutral build), colab-qwen-private (before the private-llm rename),
    #   colab-qwen38-27b (the original Colab alias).
    d = load_profile("default")
    if d and d.get("profile", {}).get("llm_profile_ref") in ("worker", "colab-qwen38-27b"):
        api("POST", "/api/agent-profiles/default", {**d["profile"], "llm_profile_ref": "colab-qwen"})
    have_llm = {p["name"] for p in api("GET", "/api/profiles").get("profiles", [])}
    for stale in ("worker", "worker-private", "colab-qwen-private"):
        if stale in have_llm:
            api("DELETE", f"/api/profiles/{stale}")
    say("  Agent profiles: riskvoid-planner (default), riskvoid-local")
    # 4. defaults for new conversations
    api("POST", f"/api/agent-profiles/{pid}/activate")
    api("POST", "/api/profiles/planner/activate")
    # 5. check every MCP server answers
    bad = []
    for key, cfg in MCP.items():
        r = api("POST", "/api/mcp/test", {"server": {**cfg, "enabled": True}})
        if not r.get("ok"):
            bad.append(f"{key}: {r.get('error', json.dumps(r))[:160]}")
    if bad:
        print("  MCP check failed:\n   " + "\n   ".join(bad))
        sys.exit(1)
    say("  MCP check: all servers answer")


if __name__ == "__main__":
    main()
