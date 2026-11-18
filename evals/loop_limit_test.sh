#!/usr/bin/env bash
# The gateway's loop limit (litellm/rv_repeats.py) end to end, with no model spend: inside the LiteLLM container a
# second LiteLLM proxy runs with the kit's callback (the same rv_events.py, rv_routes.py and rv_repeats.py the
# gateway runs) and one model, the scripted stub (evals/mock_llm.py). A scripted planner sends one tool call again
# and again; the test plays OpenHands (it sends the conversation back with a tool result each time) and checks each
# stage: the note in place of the repeats, the withheld tool, the turn the gateway ends itself without calling the
# model (streamed, as OpenHands asks), the model heard again after a user message, then the same for a cycle of two
# calls. The events go to a temporary log, not the kit's. Nothing is restarted and the running gateway is not touched.
# Needs the stack up (the litellm container). Run: bash evals/loop_limit_test.sh
cd "$(dirname "$0")/.." || exit 1
pass=0; fail=0
check() { if echo "$2" | grep -qE "$3"; then pass=$((pass+1)); echo "PASS  $1"; else fail=$((fail+1)); echo "FAIL  $1"; echo "$2" | head -5 | sed 's/^/      /'; fi; }

out="$( { sed "/^if __name__ == \"__main__\":/,\$d" evals/mock_llm.py; cat <<'EOF'
import json as _j, os as _o, shutil as _sh, subprocess as _sp, sys as _s, tempfile as _t, time as _ti, urllib.request as _u
STUB, PROXY = 18097, 18096
D = _t.mkdtemp(prefix="rv-loop-")
for f in ("rv_events.py", "rv_routes.py", "rv_repeats.py"):      # the code the gateway runs (mounted in /app)
    _sh.copy(_o.path.join("/app", f), D)
open(_o.path.join(D, "config.yaml"), "w").write(
    "model_list:\n  - model_name: planner\n    litellm_params: {model: openai/stub, api_base: http://127.0.0.1:%d/v1, "
    "api_key: x}\nlitellm_settings:\n  drop_params: true\n  callbacks: [\"rv_events.handler\"]\n" % STUB)
EVENTS = _o.path.join(D, "events.jsonl")
env = {k: v for k, v in _o.environ.items() if k not in ("DATABASE_URL", "LITELLM_MASTER_KEY", "STORE_MODEL_IN_DB")}
# LiteLLM refuses to start with no master key; this one exists only for this throwaway proxy
KEY = "sk-loop-limit-test"
env.update(RV_EVENTS_FILE=EVENTS, RV_ROUTES_FILE=_o.path.join(D, "no-routes.json"), REPEAT_COLLAPSE="1",
           LITELLM_MASTER_KEY=KEY)
cli = [_sh.which("litellm")] if _sh.which("litellm") else [_s.executable, "-m", "litellm.proxy.proxy_cli"]
log = open(_o.path.join(D, "proxy.log"), "w")
proxy = _sp.Popen(cli + ["--config", _o.path.join(D, "config.yaml"), "--port", str(PROXY)], env=env, cwd=D,
                  stdout=log, stderr=_sp.STDOUT)
serve(STUB)
res = {}


def post(body):
    req = _u.Request(f"http://127.0.0.1:{PROXY}/v1/chat/completions", data=_j.dumps(body).encode(),
                     headers={"Content-Type": "application/json", "Authorization": "Bearer " + KEY})
    return _u.urlopen(req, timeout=120)


def ask(msgs, tools, stream=False):
    """(assistant message, whether the stub was called, the request the stub got)."""
    before = len(REQUESTS)
    r = post({"model": "planner", "messages": msgs, "tools": tools, "stream": stream})
    if not stream:
        m = _j.loads(r.read())["choices"][0]["message"]
    else:
        m, calls = {"role": "assistant", "content": ""}, {}
        for line in r.read().decode().splitlines():
            if not line.startswith("data: ") or line[6:].strip() == "[DONE]":
                continue
            for ch in _j.loads(line[6:]).get("choices") or []:
                d = ch.get("delta") or {}
                m["content"] += d.get("content") or ""
                for tc in d.get("tool_calls") or []:
                    c = calls.setdefault(tc.get("index", 0), {"id": "", "type": "function",
                                                              "function": {"name": "", "arguments": ""}})
                    c["id"] = tc.get("id") or c["id"]
                    c["function"]["name"] += (tc.get("function") or {}).get("name") or ""
                    c["function"]["arguments"] += (tc.get("function") or {}).get("arguments") or ""
        if calls:
            m["tool_calls"] = [calls[k] for k in sorted(calls)]
    m = {k: v for k, v in m.items() if k in ("role", "content", "tool_calls") and v is not None}
    return m, len(REQUESTS) > before, (REQUESTS[-1] if len(REQUESTS) > before else None)


def names(req):
    return sorted(t["function"]["name"] for t in (req or {}).get("tools") or [])


def notes(req):
    return [m["content"] for m in (req or {}).get("messages") or [] if str(m.get("content") or "").startswith("[harness]")]


RESULTS = {"findings_update_finding": "REFUSED: needs a reproduction first", "findings_validate_finding": "candidate: not confirmed"}
TOOLS = [{"type": "function", "function": {"name": n, "parameters": {"type": "object", "properties": {}}}}
         for n in ("findings_update_finding", "findings_validate_finding", "kali_run")]


def play(eng, upto, stream_at=()):
    """Plays OpenHands for `upto` requests: each tool call gets its scripted result. [(n, message, stub called, request)]."""
    msgs = [{"role": "system", "content": "You are the planner."}, {"role": "user", "content": f"Engagement `{eng}`: review it."}]
    seen = []
    for n in range(1, upto + 1):
        m, called, req = ask(msgs, TOOLS, stream=n in stream_at)
        seen.append((n, m, called, req))
        msgs.append(m)
        for c in m.get("tool_calls") or []:
            msgs.append({"role": "tool", "tool_call_id": c["id"], "content": RESULTS.get(c["function"]["name"], "ok")})
    return msgs, seen


try:
    for _ in range(90):
        try:
            _u.urlopen(f"http://127.0.0.1:{PROXY}/health/liveliness", timeout=2)
            break
        except Exception:
            _ti.sleep(1)
    # one call, again and again. Request n carries n-1 copies of the call: the note at 3, withheld from 4, ended at 6
    E1 = "loop-test-one"
    call = {"name": "findings_update_finding", "arguments": {"engagement": E1, "finding_id": "F-001", "method": "source-review"}}
    globals()["SCENARIO"] = [{"tool_call": call}]
    msgs, seen = play(E1, 7, stream_at=(7,))
    by = {n: (m, called, req) for n, m, called, req in seen}
    res["first_three_as_sent"] = all(by[n][1] and not notes(by[n][2]) and "findings_update_finding" in names(by[n][2]) for n in (1, 2, 3))
    res["note"] = (notes(by[4][2]) or [""])[0][:200]
    res["note_keeps_tool"] = "findings_update_finding" in names(by[4][2])
    res["note_hides_copies"] = sum(1 for x in by[4][2]["messages"] if x.get("tool_calls")) == 0
    res["withheld_tools"] = names(by[5][2])
    res["withheld_note"] = "not available for your next step" in (notes(by[5][2]) or [""])[0]
    res["cut_called_model"] = by[7][1]
    res["cut_text"] = (by[7][0].get("content") or "")[:160]
    res["cut_no_call"] = not by[7][0].get("tool_calls")
    # the user (or the benchmark runner) answers: the model is asked again, the tool still withheld; the same call is cut
    msgs.append({"role": "user", "content": "go on"})
    m, called, req = ask(msgs, TOOLS)
    res["after_user_called"], res["after_user_tools"] = called, names(req)
    msgs.append(m)
    for c in m.get("tool_calls") or []:
        msgs.append({"role": "tool", "tool_call_id": c["id"], "content": RESULTS[c["function"]["name"]]})
    m, called, req = ask(msgs, TOOLS)
    res["second_cut"] = (not called) and (m.get("content") or "").startswith("[RiskVoid] Loop stopped")
    # two calls in turn: counted in rounds (a round is both calls). The note at 3 rounds, withheld at 4, ended at 6
    E2 = "loop-test-cycle"
    a = {"name": "findings_update_finding", "arguments": {"engagement": E2, "finding_id": "F-002", "method": "runtime-test"}}
    b = {"name": "findings_validate_finding", "arguments": {"engagement": E2, "finding_id": "F-002"}}
    CYCLED[0] = 0
    globals()["SCENARIO"] = [{"cycle": [{"tool_call": a}, {"tool_call": b}]}]
    msgs, seen = play(E2, 13)
    by = {n: (m, called, req) for n, m, called, req in seen}
    res["cycle_before_note"] = not notes(by[6][2])
    res["cycle_note"] = (notes(by[7][2]) or [""])[0][:200]
    res["cycle_withheld_tools"] = names(by[9][2])
    res["cycle_cut"] = (not by[13][1]) and (by[13][0].get("content") or "").startswith("[RiskVoid] Loop stopped")
    res["cycle_cut_text"] = (by[13][0].get("content") or "")[:160]
    # the log: one event per planner reply that went on with the loop, with its stage
    ev = [_j.loads(l) for l in open(EVENTS)] if _o.path.exists(EVENTS) else []
    for eng in (E1, E2):
        st = [e.get("stage") for e in ev if e.get("engagement") == eng and e.get("kind") in ("repeat", "loop")]
        res["stages_" + eng] = {s: st.count(s) for s in ("note", "withhold", "cut")}
    res["cycle_period"] = sorted({e.get("period") for e in ev if e.get("engagement") == E2 and e.get("kind") in ("repeat", "loop")})
except Exception as e:
    res["error"] = f"{type(e).__name__}: {e}"
    try:
        res["proxy_log"] = open(_o.path.join(D, "proxy.log")).read()[-1500:]
    except OSError:
        pass
finally:
    proxy.terminate()
    try:
        proxy.wait(10)
    except Exception:
        proxy.kill()
    _sh.rmtree(D, ignore_errors=True)
print("RESULT " + _j.dumps(res))
EOF
} | docker compose exec -T litellm sh -c 'cd /tmp && python3 -' 2>&1)"
res="$(echo "$out" | sed -n 's/^RESULT //p')"; [ -n "$res" ] || res="$out"
check "the first three calls go to the model as sent"         "$res" '"first_three_as_sent": true'
check "at three in a row the copies become one note"          "$res" '"note": "\[harness\] After this you made the same tool call 3 times in a row'
check "the note leaves no copy to repeat"                     "$res" '"note_hides_copies": true'
check "with the note the tool is still offered"               "$res" '"note_keeps_tool": true'
check "at four the tool is withheld"                          "$res" '"withheld_tools": \["findings_validate_finding", "kali_run"\]'
check "the note says the tool is not available"              "$res" '"withheld_note": true'
check "at six the gateway answers without calling the model" "$res" '"cut_called_model": false'
check "its streamed answer is the Loop stopped text"          "$res" '"cut_text": "\[RiskVoid\] Loop stopped: the planner sent the same tool call 6 times in a row'
check "and ends the turn (no tool call in it)"                "$res" '"cut_no_call": true'
check "after a user message the model is asked again"         "$res" '"after_user_called": true'
check "with the tool still withheld"                          "$res" '"after_user_tools": \["findings_validate_finding", "kali_run"\]'
check "the same call once more is ended at once"              "$res" '"second_cut": true'
check "a cycle of two: no note before three rounds"           "$res" '"cycle_before_note": true'
check "a cycle of two: the note at three rounds"              "$res" '"cycle_note": "\[harness\] After this you made the same 2 tool calls in turn, 3 times over'
check "a cycle of two: both tools withheld at four rounds"    "$res" '"cycle_withheld_tools": \["kali_run"\]'
check "a cycle of two: the turn ended at six rounds"          "$res" '"cycle_cut": true'
check "the log has each stage (one call)"                     "$res" '"stages_loop-test-one": \{"note": 1, "withhold": 2, "cut": 2\}'
check "the log has each stage (cycle)"                        "$res" '"stages_loop-test-cycle": \{"note": 2, "withhold": 4, "cut": 1\}'
check "the cycle's events say period 2"                       "$res" '"cycle_period": \[2\]'
echo; echo "passed $pass, failed $fail"; [ "$fail" -eq 0 ]
