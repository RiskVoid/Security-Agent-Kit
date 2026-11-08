#!/usr/bin/env bash
# The deterministic model stub (evals/mock_llm.py scenario mode) against the real client stack, without a GPU or a
# provider account: inside the LiteLLM container, LiteLLM calls the stub (plain and streaming, as OpenHands does), and
# the stub's HTTP errors are classified by litellm/rv_events.py the way the same provider errors would be.
# Needs the stack up. Run: bash evals/model_stub_test.sh
cd "$(dirname "$0")/.." || exit 1
pass=0; fail=0
check() { if echo "$2" | grep -qE "$3"; then pass=$((pass+1)); echo "PASS  $1"; else fail=$((fail+1)); echo "FAIL  $1"; echo "$2" | head -5 | sed 's/^/      /'; fi; }

out="$( { sed "/^if __name__ == \"__main__\":/,\$d" evals/mock_llm.py; cat <<'EOF'
import asyncio, json as _j, sys as _s
_s.path.insert(0, "/app")
import litellm, rv_events
serve(18098)
B = "http://127.0.0.1:18098/v1"
res = {}
msgs = [{"role": "user", "content": "hi"}]
globals()["SCENARIO"] = [{"content": "first answer"}, {"tool_call": {"name": "think", "arguments": {"x": 1}}}]
r = litellm.completion(model="openai/stub", api_base=B, api_key="x", messages=msgs)
res["plain"] = r.choices[0].message.content
r = litellm.completion(model="openai/stub", api_base=B, api_key="x", messages=msgs + [{"role": "assistant", "content": "first answer"}])
res["turn2_tool"] = r.choices[0].message.tool_calls[0].function.name
parts = [c.choices[0].delta.content or "" for c in litellm.completion(model="openai/stub", api_base=B, api_key="x", messages=msgs, stream=True)]
res["stream"] = "".join(parts)
res["same_again"] = litellm.completion(model="openai/stub", api_base=B, api_key="x", messages=msgs).choices[0].message.content
for code, text in ((429, "Rate limit exceeded: free-models-per-min"), (402, "Insufficient credits. Add more using https://openrouter.ai/settings/credits")):
    globals()["SCENARIO"] = [{"status": code, "error": text}]
    try:
        litellm.completion(model="openai/stub", api_base=B, api_key="x", messages=msgs, num_retries=0)
        res[str(code)] = "no error"
    except Exception as e:
        res[str(code)] = rv_events.classify("planner", e, getattr(e, "status_code", None), str(e))[0]
print("RESULT " + _j.dumps(res))
EOF
} | docker compose exec -T litellm sh -c 'cd /tmp && python3 -' 2>&1)"
res="$(echo "$out" | sed -n 's/^RESULT //p')"; [ -n "$res" ] || res="$out"
check "LiteLLM gets the scripted answer"            "$res" '"plain": "first answer"'
check "the answer follows the conversation's turn"  "$res" '"turn2_tool": "think"'
check "streaming answers work (OpenHands streams)"  "$res" '"stream": "first answer"'
check "same conversation, same answer"              "$res" '"same_again": "first answer"'
check "a 429 is classified as a rate limit"         "$res" '"429": "rate_limit"'
check "a 402 is classified as no credits"           "$res" '"402": "credits"'
echo; echo "passed $pass, failed $fail"; [ "$fail" -eq 0 ]
