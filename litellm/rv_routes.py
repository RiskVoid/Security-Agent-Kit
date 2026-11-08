"""Where a model call sends its data, and whether an engagement allows it (RW-006).

Every model route is classified into a destination: local (a model server on this machine or the local network),
colab (the Colab notebook), api (another self-hosted endpoint), or a hosted provider (openrouter, anthropic,
openai). An engagement's RULES.md can limit where its client data goes ("Client data: local, colab"). The LiteLLM
hook in rv_events.py calls decide() before every model call and refuses the call, or turns off its fallbacks,
when the call would carry an engagement's data to a destination that engagement doesn't allow.

Which engagements a call carries data of:
  - the conversation it belongs to (x-litellm-session-id, sent by OpenHands), when the conversation is bound to an
    engagement (console "New conversation" or ./rvkit conversation);
  - the x-rv-engagement header (worker-mcp sends it for every task);
  - every engagement the agent acted on or was asked about: kit tool calls carry an "engagement" argument, and
    commands name paths under /work/<engagement>/ or an engagement's in-scope /src paths (tool-call arguments and
    user messages; tool results are not scanned).
Each source can only add engagements, so content (a web page, a tool result) can make a call stricter, never
looser. The routing table (bindings, rules, halt state) is written by kali-mcp into a volume this container
mounts read-only; agents can't write it.

Pure Python with no LiteLLM import: the console and the unit tests use it too.
"""
import ipaddress, json, os, re, urllib.parse

ROUTES_FILE = os.environ.get("RV_ROUTES_FILE", "/rv-routes/routes.json")
WORKER_GROUPS = ("colab-qwen", "private-llm")
LABELS = {"local": "a model server on this machine or network", "colab": "the Colab notebook",
          "api": "a self-hosted API endpoint", "openrouter": "OpenRouter", "anthropic": "Anthropic",
          "openai": "OpenAI"}
NAME = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
_cache = {"mtime": None, "data": None}


def _host_kind(base, env):
    """Destination of an OpenAI-compatible endpoint URL."""
    norm = (base or "").rstrip("/")
    colab = (env.get("COLAB_API_BASE") or "").rstrip("/")
    if colab and norm == colab:
        return "colab"
    host = (urllib.parse.urlparse(norm).hostname or "").lower()
    if not host or host.endswith(".invalid"):
        return "local"  # not connected: nothing is sent anywhere
    if host == "openrouter.ai" or host.endswith(".openrouter.ai"):
        return "openrouter"
    if host in ("api.anthropic.com",):
        return "anthropic"
    if host in ("api.openai.com",):
        return "openai"
    if "colab" in host:
        return "colab"
    if host in ("localhost", "host.docker.internal", "host.containers.internal", "gateway.docker.internal") \
            or "." not in host or host.endswith((".local", ".lan", ".internal", ".home.arpa", ".localhost")):
        return "local"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return "local"
    except ValueError:
        pass
    return "api"


def model_destination(model_id, api_base, env):
    """Destination of one LiteLLM deployment (model id + api_base)."""
    m = (model_id or "").lower()
    if m.startswith("openrouter/"):
        return "openrouter"
    if m.startswith("anthropic/"):
        return "anthropic"
    if api_base:
        return _host_kind(api_base, env)
    if m.startswith("openai/"):
        return "openai"
    return m.split("/", 1)[0] or "unknown"


def group_route(group, env):
    """(primary destination, [fallback destinations], description) of a model group in litellm/config.yaml."""
    worker = model_destination(env.get("WORKER_MODEL_ID"), env.get("WORKER_API_BASE"), env)
    fb_worker = model_destination(env.get("WORKER_FALLBACK_MODEL") or "openrouter/x", None, env)
    planner = model_destination(env.get("PLANNER_MODEL") or "openrouter/x", None, env)
    planner_fb = model_destination(env.get("PLANNER_FALLBACK_MODEL") or "openrouter/x", None, env)
    fallback_on = (env.get("WORKER_FALLBACK") or "off") == "on"
    table = {
        "colab-qwen": (worker, [fb_worker] if fallback_on else []),
        "private-llm": (worker, []),
        "colab-qwen-fallback": (fb_worker, []),
        "planner": (planner, [planner_fb]),
        "planner-fallback": (planner_fb, []),
    }
    return table.get(group, ("unknown", []))


def models(env):
    """What the console shows: each route's model, endpoint and destination."""
    def one(group, model_var, base=None):
        dest, fbs = group_route(group, env)
        host = urllib.parse.urlparse(base).hostname if base else None
        return {"group": group, "model": env.get(model_var, ""), "destination": dest, "label": LABELS.get(dest, dest),
                "host": host, "fallbacks": fbs}
    return {"worker": one("colab-qwen", "WORKER_MODEL_ID", env.get("WORKER_API_BASE")),
            "worker_fallback": {"on": (env.get("WORKER_FALLBACK") or "off") == "on",
                                "model": env.get("WORKER_FALLBACK_MODEL", ""),
                                "destination": group_route("colab-qwen-fallback", env)[0]},
            "planner": one("planner", "PLANNER_MODEL"),
            "planner_fallback": one("planner-fallback", "PLANNER_FALLBACK_MODEL")}


def load_routes(path=ROUTES_FILE):
    try:
        mtime = os.stat(path).st_mtime_ns
    except OSError:
        return {"engagements": {}, "conversations": {}, "missing": True}
    if mtime != _cache["mtime"]:
        try:
            with open(path) as f:
                _cache["data"] = json.load(f)
            _cache["mtime"] = mtime
        except (OSError, ValueError):
            return _cache["data"] or {"engagements": {}, "conversations": {}, "missing": True}
    return _cache["data"]


def _text(request):
    """What the agent did and was asked: tool-call arguments (assistant turns) and user messages. Tool results
    are left out on purpose: a listing of all engagements must not tie a call to every one of them, and the call
    that fetched an engagement's data names that engagement in its arguments."""
    parts = []
    for m in request.get("messages") or []:
        if not isinstance(m, dict):
            continue
        for tc in m.get("tool_calls") or []:
            parts.append(str((tc.get("function") or {}).get("arguments") or ""))
        if m.get("role") == "user":
            c = m.get("content")
            parts.append(c if isinstance(c, str) else json.dumps(c, default=str))
    inp = request.get("input")  # Responses API
    for it in inp if isinstance(inp, list) else []:
        if isinstance(it, dict) and it.get("type") == "function_call":
            parts.append(str(it.get("arguments") or ""))
        elif isinstance(it, dict) and it.get("role") == "user":
            parts.append(json.dumps(it.get("content"), default=str))
    if isinstance(inp, str):
        parts.append(inp)
    return "\n".join(parts)


def engagements_named(text, routes):
    """Engagements a request's content refers to (only names that exist in the routing table)."""
    known = routes.get("engagements") or {}
    found = set()
    for m in re.finditer(r"/work/(" + NAME + r")", text):
        if m.group(1) in known:
            found.add(m.group(1))
    # "engagement": "x" in tool-call arguments (JSON inside a JSON string: quotes may be escaped)
    for m in re.finditer(r'engagement\\*"\s*:\s*\\*"(' + NAME + r')\\*"', text):
        if m.group(1) in known:
            found.add(m.group(1))
    for m in re.finditer(r"[Ee]ngagement[\s:`*'\"]+(" + NAME + r")", text):
        if m.group(1) in known:
            found.add(m.group(1))
    for eng, e in known.items():
        for p in e.get("paths") or []:
            p = p.rstrip("/")
            if p and re.search(re.escape(p) + r"(?:/|\b|$)", text):
                found.add(eng)
    return found


def header(headers, name):
    for k, v in (headers or {}).items():
        if isinstance(k, str) and k.lower() == name:
            return v
    return None


def decide(group, request, headers, routes, env, session=None):
    """{"allow": bool, "fallbacks": bool, "reason": str, "engagements": [...], "bound": eng or None}."""
    known = routes.get("engagements") or {}
    session = session or header(headers, "x-litellm-session-id")
    bound = (routes.get("conversations") or {}).get(str(session).replace("-", "").lower()) if session else None
    named_hdr = header(headers, "x-rv-engagement")
    engs = engagements_named(_text(request), routes)
    direct = {e for e in (bound, named_hdr) if e}
    engs |= {e for e in direct if e in known}
    out = {"allow": True, "fallbacks": True, "reason": "", "engagements": sorted(engs), "bound": bound}
    if bound and bound not in known:
        out.update(allow=False, reason=f"this conversation belongs to engagement {bound}, which no longer exists "
                                       "(deleted). Start a new conversation from the console.")
        return out
    for e in sorted(direct & set(known)):
        if known[e].get("halted"):
            out.update(allow=False, reason=f"engagement {e} is halted: its conversations and worker tasks can't call "
                                           f"a model until it is resumed (./rvkit resume {e} or the console).")
            return out
    primary, fbs = group_route(group, env)
    for e in sorted(engs):
        allowed = known[e].get("client_data")
        if not allowed:
            continue
        if primary not in allowed:
            out.update(allow=False, reason=(
                f"engagement {e} allows its client data only to {', '.join(allowed)} (RULES.md: Client data). "
                f"This call would go to {primary} ({LABELS.get(primary, primary)}) through the '{group}' model. "
                + ("Use the riskvoid-local agent, or point the worker at an allowed endpoint (./rvkit worker)."
                   if group.startswith("planner") else "Point the worker at an allowed endpoint (./rvkit worker).")))
            return out
        if any(f not in allowed for f in fbs):
            out["fallbacks"] = False
    return out
