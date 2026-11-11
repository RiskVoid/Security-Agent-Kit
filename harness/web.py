"""Web research MCP server for the planner (streamable HTTP on :8094/mcp): web search and page fetch.

Replaces the generic search/fetch MCP servers. The OpenHands agent has no direct internet access, so this is its
way to read public pages. fetch refuses any engagement target (union of every registered engagement's scope, from
kali-mcp) and any non-public address (kit services, lab, cloud metadata), on the first request and on every
redirect. Targets are tested only through the kali tool, which is scope-checked and audit-logged.
"""
import asyncio, json, os, threading, time, urllib.parse, urllib.request
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.fastmcp import FastMCP
import webfetch

SEARXNG = os.environ.get("SEARXNG_URL", "http://searxng:8080")
KALI_MCP = os.environ.get("KALI_MCP_URL", "http://kali-mcp:8090/mcp")
# Stateless: no per-client session, so a conversation that was open when this server restarted keeps working
# (with sessions, every later tool call failed with "Session terminated" until OpenHands itself was restarted).
mcp = FastMCP("web", host="0.0.0.0", port=8094, stateless_http=True)
_scope = {"at": 0.0, "nets": [], "domains": []}


def _scopes():
    """All engagements' scope, cached for 30 s. Fails closed: if kali-mcp can't be asked, fetch refuses."""
    if time.time() - _scope["at"] < 30:
        return _scope["nets"], _scope["domains"]

    async def go():
        async with streamablehttp_client(KALI_MCP, timeout=20, sse_read_timeout=60) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
                res = await s.call_tool("all_scopes", {})
                return json.loads("".join(c.text for c in res.content if getattr(c, "text", None)))

    box = {}
    t = threading.Thread(target=lambda: box.update(v=asyncio.run(go())), daemon=True)
    t.start(); t.join(30)
    if "v" not in box:
        raise RuntimeError("could not read engagement scopes from kali-mcp")
    _scope.update(at=time.time(), nets=box["v"]["nets"], domains=box["v"]["domains"])
    return _scope["nets"], _scope["domains"]


@mcp.tool()
def web_search(query: str, max_results: int = 8) -> str:
    """Search the web (private SearXNG instance). Returns title, URL and snippet per result."""
    url = f"{SEARXNG}/search?" + urllib.parse.urlencode({"q": query, "format": "json"})
    data = json.load(urllib.request.urlopen(url, timeout=30))
    rows = data.get("results", [])[:max(1, min(max_results, 20))]
    return "\n\n".join(f"{r.get('title')}\n{r.get('url')}\n{(r.get('content') or '')[:300]}" for r in rows) \
        or "no results"


@mcp.tool()
def fetch(url: str, start: int = 0, max_chars: int = 20000) -> str:
    """Read a public web page as text (advisories, CVE pages, vendor docs). Not for engagement targets: those are
    refused here; test them with the kali tool. Long pages: call again with start= the offset to continue."""
    try:
        nets, domains = _scopes()
    except Exception as e:  # fail closed
        return f"REFUSED: {e}"
    try:
        text = webfetch.fetch(url, nets, domains)
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"
    start, max_chars = max(0, int(start or 0)), max(500, min(int(max_chars or 20000), 100000))
    part = text[start:start + max_chars]
    more = len(text) - (start + len(part))
    return part + (f"\n\n[… {more} more characters: call fetch again with start={start + len(part)}]" if more > 0 else "")


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
