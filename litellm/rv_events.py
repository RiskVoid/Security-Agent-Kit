"""RiskVoid model events: a LiteLLM proxy callback that makes model problems visible and keeps the planner fallback
working when OpenHands streams.

What it does:
  1. Streaming fallback. OpenHands always streams. When a model refuses (finish_reason content_filter) or answers
     with nothing, the HTTP 200 has already started, so LiteLLM's content-policy fallback never runs. This hook holds
     back the stream until the first real content or tool call; if none comes, it streams the fallback group's answer
     instead (the same mapping as content_policy_fallbacks in the config).
  2. A reason in the chat. When no model produced an answer, the reply becomes a short "[RiskVoid] ..." message that
     says why and what to do, instead of an empty reply that OpenHands answers with "did not include a function call".
     Errors (no credits, budget reached, bad key, worker down, ...) get the same plain-language explanation.
  0. Data destinations and halt (rv_routes.py). Before every call: refuse it when it would carry an engagement's
     client data to a destination that engagement's RULES.md doesn't allow, or when its conversation or worker task
     belongs to a halted engagement; turn off fallbacks that would go to a destination that isn't allowed.
  3. An event log. Every problem is appended to /rv-events/model-events.jsonl (.rvkit/events/ on the host). The console,
     ./rvkit status, ./rvkit doctor and ./rvkit watch read it (scripts/model_events.py).

Loaded by LiteLLM from litellm_settings.callbacks (rv_events.handler). classify() needs no LiteLLM, for the unit tests.
"""
import asyncio, json, os, re, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rv_routes  # noqa: E402  (data destinations and halt for model calls, RW-006/RW-007)

try:
    from litellm.integrations.custom_logger import CustomLogger
except ImportError:  # unit tests import classify() without LiteLLM installed
    class CustomLogger:  # noqa: D101
        pass

EVENTS = os.environ.get("RV_EVENTS_FILE", "/rv-events/model-events.jsonl")
MAX_BYTES = 512_000                       # the log is trimmed to its newer half beyond this
WORKER = {"colab-qwen", "private-llm", "colab-qwen-fallback"}
MODEL_VAR = {"planner": "PLANNER_MODEL", "planner-fallback": "PLANNER_FALLBACK_MODEL", "colab-qwen": "WORKER_MODEL_ID",
             "private-llm": "WORKER_MODEL_ID", "colab-qwen-fallback": "WORKER_FALLBACK_MODEL"}
# request fields passed on to the fallback model (everything else is proxy bookkeeping)
PASS = ("messages", "tools", "tool_choice", "temperature", "top_p", "max_tokens", "max_completion_tokens", "stop",
        "parallel_tool_calls", "reasoning_effort", "response_format", "seed", "stream_options")
PREFIX = "[RiskVoid] "
POLICY_TAG = "[RiskVoid] refused by policy: "
GENERIC = {"provider returned error", "invalid input", "internal server error", "bad request", "error"}


def model_name(group):
    """'planner (openrouter/openai/gpt-6.1-sol)' style label for messages."""
    m = os.environ.get(MODEL_VAR.get(group, ""), "")
    return f"{group} ({m})" if m else str(group)


def classify(group, exc=None, status=None, text=""):
    """Map a failure to (kind, message). The message says what happened and what to do, in plain words."""
    name = type(exc).__name__ if exc is not None else ""
    status = status or getattr(exc, "status_code", None)
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None
    raw = f"{text or exc or ''}"
    if POLICY_TAG in raw:  # our own refusal (pre-call hook): pass its reason on as it is
        return "policy", raw[raw.index(POLICY_TAG) + len(POLICY_TAG):].split(" | Original error")[0].strip()
    low = f"{name} {raw}".lower()
    who = model_name(group)
    worker = group in WORKER
    # A provider's safety refusal can come as HTTP 403 (OpenRouter's cyber-policy filter), so recognise its markers
    # before the status codes: otherwise it reads as a rejected API key and the fallback never runs.
    if re.search(r"error_type'?\"?\s*:\s*'?\"?refusal|cyber_policy|flagged for possible", low):
        return "refusal", f"{who} refused this request (its provider's safety filter)."
    if "budget" in low and ("exceed" in low or "crossed" in low or "over" in low):
        return "budget", ("The daily model budget is used up (OPENROUTER_DAILY_BUDGET). Raise it with ./rvkit budget <usd>, "
                          "or wait for the next UTC day.")
    if status == 402 or re.search(r"credit|insufficient (funds|balance)|payment required|balance", low):
        return "credits", (f"{who}: the OpenRouter balance is too low for this call. Top up at "
                           "https://openrouter.ai/settings/credits, then continue the conversation.")
    if status in (401, 403) or "authenticationerror" in low or "invalid api key" in low or "unauthorized" in low:
        if worker:
            return "auth", (f"{who}: the worker endpoint rejected the API key. Run the ./rvkit connect line the Colab "
                            "notebook printed (it carries the key), or ./rvkit worker to point at another endpoint.")
        return "auth", (f"{who}: the API key was rejected. Check the key in .env (./rvkit planner show says which), "
                        "then run ./rvkit up.")
    if "contextwindowexceeded" in low or "context length" in low or "context window" in low or "too many tokens" in low:
        return "context", (f"{who}: the conversation no longer fits the model's context window. Start a new "
                           "conversation for the next step (the engagement's notes and findings are kept).")
    if status == 429 or "ratelimit" in low or "rate limit" in low:
        return "rate_limit", (f"{who} is rate-limited by its provider. Wait a minute and continue the conversation.")
    if "timeout" in low or "timed out" in low:
        if worker:
            return "worker_down", (f"{who} did not answer in time. If Colab disconnected (idle timeout), start it again "
                                   "with /rv-start; otherwise the task may be too big for one call.")
        return "timeout", f"{who} did not answer in time. Continue the conversation to retry."
    if worker and (status in (404, 502, 503, 504, 520, 521, 522, 523, 524, 530) or "connect" in low
                   or "apiconnectionerror" in low or "name or service not known" in low or "nodename" in low):
        return "worker_down", (f"{who} is not reachable: Colab probably stopped or its tunnel address changed. "
                               "Start it with /rv-start (or ./rvkit worker for another endpoint), then continue.")
    if "contentpolicy" in low or "content_filter" in low or "refus" in low or "safety" in low:
        return "refusal", f"{who} refused this request (its provider's safety filter)."
    raw = str(text or exc or name or "unknown error")
    # provider errors nest JSON in strings: prefer the most detailed "message", drop escapes and the litellm prefix
    msgs = re.findall(r'\\*"message\\*"\s*:\s*\\*"((?:[^"\\]|\\.)+?)\\*"', raw)
    msgs = [m for m in msgs if m.strip().lower().rstrip(".") not in GENERIC] or msgs
    prose = [m for m in msgs if "{" not in m and "[" not in m]
    short = (max(prose or msgs, key=len) if msgs else raw).replace("\\n", " ").replace('\\"', '"').replace("\\", "")
    short = re.sub(r"\s+", " ", re.sub(r"^litellm\.\w+:\s*", "", short)).strip()[:200]
    return "error", f"{who} failed ({status or name or 'error'}): {short}"


ENG_ARG = re.compile(r'\\?"engagement\\?"\s*:\s*\\?"([A-Za-z0-9][A-Za-z0-9._-]{0,63})\\?"')
ENG_TEXT = re.compile(r"\b[Ee]ngagement[:\s]+`?([A-Za-z0-9][A-Za-z0-9._-]{0,63})`?")


def engagement_of(request):
    """The engagement a model call belongs to, best effort: the newest tool call that names one (every kit tool takes
    an `engagement` argument), else the brief ("Engagement `lab-juice`: ..."). None when nothing names one."""
    msgs = (request or {}).get("messages") or []
    for m in reversed(msgs):
        for tc in (m.get("tool_calls") or []) if isinstance(m, dict) else []:
            hit = ENG_ARG.search(str((tc.get("function") or {}).get("arguments") or ""))
            if hit:
                return hit.group(1)
    for m in msgs:
        if isinstance(m, dict) and m.get("role") == "user":
            c = m.get("content")
            text = c if isinstance(c, str) else " ".join(str(x.get("text", "")) for x in c or [] if isinstance(x, dict))
            hit = ENG_TEXT.search(text)
            if hit:
                return hit.group(1)
    return None


def record(kind, group, message, **extra):
    """Append one event to the log; never raises (a logging problem must not break a model call)."""
    ev = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kind": kind, "model": group,
          "model_id": os.environ.get(MODEL_VAR.get(group, ""), ""), "message": message, **extra}
    try:
        os.makedirs(os.path.dirname(EVENTS), exist_ok=True)
        if os.path.exists(EVENTS) and os.path.getsize(EVENTS) > MAX_BYTES:
            with open(EVENTS) as f:
                keep = f.readlines()[-500:]
            with open(EVENTS + ".tmp", "w") as f:
                f.writelines(keep)
            os.replace(EVENTS + ".tmp", EVENTS)
        with open(EVENTS, "a") as f:
            f.write(json.dumps(ev) + "\n")
    except OSError:
        pass
    return ev


def fallback_for(group):
    """The content-policy fallback group configured for `group`, or None."""
    try:
        from litellm.proxy.proxy_server import llm_router
        for rule in llm_router.content_policy_fallbacks or []:
            if group in rule and rule[group]:
                return rule[group][0]
    except Exception:  # noqa: BLE001
        pass
    return None


def _choices(chunk):
    return getattr(chunk, "choices", None) or []


def has_payload(chunk):
    """True when a stream chunk carries answer text or a tool call (reasoning alone is held back)."""
    for c in _choices(chunk):
        d = getattr(c, "delta", None)
        if d is not None and (getattr(d, "content", None) or getattr(d, "tool_calls", None)):
            return True
    return False


def finish_of(chunk):
    for c in _choices(chunk):
        if getattr(c, "finish_reason", None):
            return c.finish_reason
    return None


def notice_chunks(group, text):
    """Two stream chunks: the explanation as assistant text, then a normal stop."""
    from litellm.types.utils import Delta, ModelResponseStream, StreamingChoices
    return [ModelResponseStream(model=group, choices=[StreamingChoices(index=0, delta=Delta(role="assistant", content=text))]),
            ModelResponseStream(model=group, choices=[StreamingChoices(index=0, delta=Delta(), finish_reason="stop")])]


def empty_message(response):
    """True for a non-streamed reply with no text and no tool call."""
    for c in _choices(response):
        m = getattr(c, "message", None)
        if m is not None and (getattr(m, "content", None) or getattr(m, "tool_calls", None)):
            return False
    return bool(_choices(response))


def no_answer_text(group, kind, fallback=None, fb_error=None):
    who = model_name(group)
    if kind == "refusal":
        if fallback:
            tail = f"; the fallback {model_name(fallback)} " + (f"failed too ({fb_error})" if fb_error else "refused as well")
        else:
            tail = " and no fallback is configured"
        return (PREFIX + f"No answer: {who} refused this request (provider safety filter){tail}. Rephrase it with the "
                "engagement context, or switch the planner model: ./rvkit planner <model> [fallback].")
    return (PREFIX + f"No answer: {who} returned an empty reply" +
            (f", and the fallback {model_name(fallback)} " + (f"failed ({fb_error})" if fb_error else "returned nothing either")
             if fallback else "") + ". Continue the conversation to retry; if it keeps happening, check ./rvkit status.")


def request_headers(data):
    """Request headers as LiteLLM passes them to hooks (the location differs between versions)."""
    for src in ((data.get("proxy_server_request") or {}).get("headers"), (data.get("metadata") or {}).get("headers"),
                (data.get("litellm_metadata") or {}).get("headers")):
        if isinstance(src, dict) and src:
            return src
    return {}


def session_of(data, headers):
    for v in (rv_routes.header(headers, "x-litellm-session-id"), data.get("litellm_session_id"),
              (data.get("metadata") or {}).get("session_id"), (data.get("litellm_metadata") or {}).get("session_id")):
        if v:
            return str(v)
    return None


def env_now():
    return dict(os.environ)


class RvEvents(CustomLogger):
    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        group = data.get("model")
        if group is None:
            return data
        headers = request_headers(data)
        d = rv_routes.decide(group, data, headers, rv_routes.load_routes(), env_now(), session_of(data, headers))
        if not d["allow"]:
            record("policy", group, d["reason"], engagement=(d["engagements"] or [d["bound"]])[0],
                   engagements=d["engagements"])
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail=POLICY_TAG + d["reason"])
        if not d["fallbacks"]:
            data["disable_fallbacks"] = True
        return data

    async def async_post_call_streaming_iterator_hook(self, user_api_key_dict, response, request_data):
        group, eng = request_data.get("model"), engagement_of(request_data)
        held, sent, finish = [], False, None
        try:
            async for chunk in response:
                if sent:
                    yield chunk
                    continue
                finish = finish_of(chunk) or finish
                if has_payload(chunk):
                    for h in held:
                        yield h
                    held, sent = [], True
                    yield chunk
                else:
                    held.append(chunk)
        except Exception as e:  # noqa: BLE001
            # Some providers refuse with an error inside the stream instead of finish_reason content_filter (for
            # example OpenRouter's "flagged for possible cybersecurity risk", provider_code cyber_policy). Before the
            # first answer chunk that is still a refusal we can answer from the fallback; other errors pass through.
            if sent or classify(group, e)[0] != "refusal":
                raise
            finish = "content_filter"
        if sent:
            return
        kind = "refusal" if finish == "content_filter" else "empty"
        fb, fb_error = (None if request_data.get("disable_fallbacks") else fallback_for(group)), None
        if fb:
            record(kind, group, engagement=eng, message=f"{model_name(group)} " + ("refused this request" if kind == "refusal" else
                   "returned an empty reply") + f"; answering with the fallback {model_name(fb)}.", fallback=fb)
            try:
                from litellm.proxy.proxy_server import llm_router
                params = {k: request_data[k] for k in PASS if k in request_data}
                for attempt in range(3):  # shared OpenRouter pools rate-limit in short bursts: wait 4 s, then 8 s
                    try:
                        stream = await llm_router.acompletion(model=fb, stream=True, **params)
                        break
                    except Exception as e:  # noqa: BLE001
                        if attempt == 2 or classify(fb, e)[0] != "rate_limit":
                            raise
                        await asyncio.sleep(4 * (attempt + 1))
                fb_held, got, fb_finish = [], False, None
                async for c in stream:
                    if got:
                        yield c
                        continue
                    fb_finish = finish_of(c) or fb_finish
                    if has_payload(c):
                        for h in fb_held:
                            yield h
                        got = True
                        yield c
                    else:
                        fb_held.append(c)
                if got:
                    return
                if fb_finish != "content_filter":
                    fb_error = "empty reply"
            except Exception as e:  # noqa: BLE001
                fb_error, raw = classify(fb, e)[1], f"{type(e).__name__}: {e}"[:400]
            else:
                raw = None
        else:
            raw = None
        text = no_answer_text(group, kind, fb, fb_error)
        record("no_answer", group, text[len(PREFIX):], engagement=eng, reason=kind, fallback=fb, **({"error": raw} if raw else {}))
        for c in notice_chunks(group, text):
            yield c

    async def async_post_call_success_hook(self, data, user_api_key_dict, response):
        group, eng = data.get("model"), engagement_of(data)
        hp = getattr(response, "_hidden_params", None) or {}
        served = hp.get("model_group") or (hp.get("additional_headers") or {}).get("x-litellm-model-group")
        if served and group and served != group:
            record("fallback", group, engagement=eng, message=f"{model_name(group)} failed or refused; the answer came from {model_name(served)}.",
                   fallback=served)
        if not empty_message(response):
            return None
        refused = any(getattr(c, "finish_reason", None) == "content_filter" for c in _choices(response))
        text = no_answer_text(group, "refusal" if refused else "empty", served if served != group else None)
        record("no_answer", group, text[len(PREFIX):], engagement=eng, reason="refusal" if refused else "empty")
        c = _choices(response)[0]
        c.message.content, c.finish_reason = text, "stop"
        return response

    async def async_post_call_failure_hook(self, request_data, original_exception, user_api_key_dict, traceback_str=None):
        group = request_data.get("model")
        kind, text = classify(group, original_exception)
        eng, status = engagement_of(request_data), getattr(original_exception, "status_code", None)
        if kind == "context":
            # OpenHands recognises this error by its text ("exceeds the available context size", ...) and then
            # summarises older turns and carries on: pass it through unchanged and log it as recovered.
            used = re.search(r"\((\d+) tokens\) exceeds the available context size \((\d+) tokens\)", str(original_exception))
            size = f" ({int(used.group(1)) // 1000}K tokens, the window is {int(used.group(2)) // 1024}K)" if used else ""
            record("context", group, f"{model_name(group)}: the conversation outgrew the context window{size}; OpenHands "
                   "summarised older turns and continued.", engagement=eng, status=status)
            return None
        record(kind, group, text, engagement=eng, status=status) if kind != "policy" else None
        try:
            from fastapi import HTTPException
            # keep the provider's text after the explanation: OpenHands classifies errors by it (rate limit, quota, ...)
            if kind == "policy":
                return HTTPException(status_code=403, detail=PREFIX + text)
            orig = re.sub(r"\s+", " ", str(original_exception))[:1500]
            return HTTPException(status_code=int(status or 500), detail=f"{PREFIX}{text} | Original error: {orig}")
        except Exception:  # noqa: BLE001
            return None


handler = RvEvents()
