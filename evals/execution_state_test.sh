#!/usr/bin/env bash
# Trusted execution state (RW-006, RW-007), end to end against the running stack with a scripted model (no GPU,
# no provider account). A throwaway engagement is created and deleted afterwards.
#   Model gateway: a call carrying an engagement's data to a destination its "Client data" rule doesn't allow is
#     refused (by header, by tool-call argument, by /work path, by bound conversation); a halted engagement's
#     conversations and worker calls are refused.
#   Credentials: stored on the host, used by reference; values never appear in output, evidence or the audit log.
#   Worker tasks: an approval pauses the task and the approved action runs exactly once after the decision; a
#     denied one is reported to the model; cancel and halt stop a running task and its command; after a restart a
#     task with an action in flight is interrupted (needs_review) and resume never repeats it; dependencies.
# Run: bash evals/execution_state_test.sh
cd "$(dirname "$0")/.." || exit 1
ENG=rv-state-test
pass=0; fail=0
check() { if echo "$2" | grep -qE "$3"; then pass=$((pass+1)); echo "PASS  $1"; else fail=$((fail+1)); echo "FAIL  $1"; echo "$2" | head -5 | sed 's/^/      /'; fi; }
ctl() { docker compose exec -T kali-mcp python3 /opt/kali-mcp/rvctl.py --actor cli:state-test "$@" </dev/null; }
DIR="$(grep -E '^ENGAGEMENTS_DIR=' .env | cut -d= -f2- | sed "s|^~|$HOME|")"
OUT="$(mktemp)"
cleanup() {
  ctl halt $ENG >/dev/null 2>&1; ctl delete $ENG --force >/dev/null 2>&1
  docker compose exec -T kali-mcp sh -c "rm -rf /work/_deleted-$ENG-* /work/.control/tasks/state-*" </dev/null
  rm -f "${OUT:?}"
}
trap cleanup EXIT

./rvkit engagement $ENG --replace --tiers passive,active,intrusive example.com /src/rv-demo-app >/dev/null 2>&1 \
  || { echo "FAIL  could not create $ENG"; exit 1; }
printf '%s\n' "- Allowed tiers: passive, active, intrusive" "- Max rate: 10" "- Network: online" "- Client data: local" \
  > "$DIR/$ENG/RULES.md"
ctl sync $ENG --yes >/dev/null || { echo "FAIL  could not apply RULES.md"; exit 1; }

# ---------------------------------------------------------------- model gateway (RW-006)
KEY="$(grep -E '^LITELLM_MASTER_KEY=' .env | cut -d= -f2-)"
llm() { curl -s -m 60 "http://127.0.0.1:$(grep -E '^LITELLM_PORT=' .env | cut -d= -f2- | grep . || echo 4000)/v1/chat/completions" \
          -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' "$@"; }
routes="$(ctl routes | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)))')"
check "routing table has the Client data rule"   "$routes" "\"$ENG\": \{[^}]*\"client_data\": \[[^]]*\"local\""
check "planner refused (x-rv-engagement)"        "$(llm -H "x-rv-engagement: $ENG" -d '{"model":"planner","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}')" \
      "refused by policy|allows its client data only to local"
body="$(python3 -c 'import json, sys; print(json.dumps({"model": "planner", "max_tokens": 5, "messages": [
  {"role": "user", "content": "hi"}, {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "type": "function",
  "function": {"name": "run", "arguments": json.dumps({"engagement": sys.argv[1], "command": "ls"})}}]},
  {"role": "tool", "tool_call_id": "c1", "content": "x"}]}))' "$ENG")"
check "planner refused (tool-call argument)"     "$(llm -d "$body")" "allows its client data only to local"
check "planner refused (/work path in a request)" "$(llm -d '{"model":"planner","max_tokens":5,"messages":[{"role":"user","content":"summarise /work/'$ENG'/notes.md"}]}')" \
      "allows its client data only to local"
CID=00000000-0000-4000-8000-$(printf '%012x' $RANDOM$RANDOM)
ctl bind $ENG "$CID" "state test" >/dev/null
check "conversation bound"                       "$(ctl conversations $ENG)" "$CID"
# The session header alone must tie the call to the engagement. Use the planner: it is off-machine by default, while
# the worker counts as local when it is not connected (CI's .env.example points it at a .invalid host).
check "bound conversation refused, any route"   "$(llm -H "x-litellm-session-id: $CID" -d '{"model":"planner","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}')" \
      "allows its client data only to local"
ctl halt $ENG >/dev/null
check "halted: bound conversation refused"      "$(llm -H "x-litellm-session-id: ${CID//-/}" -d '{"model":"private-llm","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}')" \
      "is halted"
check "halted: worker calls refused"            "$(llm -H "x-rv-engagement: $ENG" -d '{"model":"private-llm","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}')" \
      "is halted"
ctl resume $ENG >/dev/null
ctl unbind $ENG "$CID" >/dev/null
check "refusals are in the model log"           "$(tail -20 .rvkit/events/model-events.jsonl)" "\"kind\": \"policy\".*$ENG"

# ---------------------------------------------------------------- credential references (RW-006)
printf 'Rv-Secret-%s' "$RANDOM$RANDOM" > "$OUT"; SECRET="$(cat "$OUT")"
docker compose exec -T kali-mcp python3 /opt/kali-mcp/rvctl.py --actor cli:state-test cred $ENG set api_token < "$OUT" >/dev/null
check "credential listed by name"               "$(ctl cred $ENG list)" "API_TOKEN .*RV_CRED_API_TOKEN"
kali() { docker compose exec -T worker-mcp python3 -c "
import json, sys; sys.path.insert(0, '/opt/harness'); import worker
print(worker._arun(worker._kali(sys.argv[1], json.loads(sys.argv[2]), 120)))" "$1" "$2" 2>/dev/null </dev/null; }
r="$(kali run '{"engagement": "'$ENG'", "command": "echo n=${#RV_CRED_API_TOKEN} v=$RV_CRED_API_TOKEN"}')"
check "command gets the value"                  "$r" "n=${#SECRET} "
check "command output shows the reference"      "$r" "v=\{\{cred:API_TOKEN\}\}"
r="$(kali http_request '{"engagement": "'$ENG'", "method": "GET", "url": "https://example.com/", "headers": {"Authorization": "Bearer {{cred:API_TOKEN}}"}}')"
check "request with a credential reference"     "$r" "GET https://example.com/ .. 200"
check "unknown reference refused"               "$(kali http_request '{"engagement": "'$ENG'", "method": "GET", "url": "https://example.com/", "headers": {"X": "{{cred:NOPE}}"}}')" \
      "REFUSED: no credential NOPE"
check "value in no evidence file"               "$(grep -rl -- "$SECRET" "$DIR/$ENG" 2>/dev/null | wc -l | tr -d ' ')" "^0$"
check "value not in the audit log"              "$(docker compose exec -T kali-mcp grep -c -- "$SECRET" /control/audit.log </dev/null)" "^0$"
check "evidence keeps the reference"            "$(cat "$DIR/$ENG"/evidence/http/*.txt 2>/dev/null)" "Bearer \{\{cred:API_TOKEN\}\}"

# ---------------------------------------------------------------- durable worker tasks (RW-007)
# The driver runs in the worker container with the scripted model; it prints NEED lines for decisions only the
# host can make (approve, deny, halt) and RESULT lines with what it saw.
{ sed "/^if __name__ == \"__main__\":/,\$d" evals/mock_llm.py; cat <<EOF
import json as _j, os as _o, sys as _s, threading as _t, time as _tm, uuid as _u
_s.path.insert(0, "/opt/harness")
_s.modules["mock_llm"] = _s.modules[__name__]
import worker
serve(18098)
worker.LITELLM = "http://127.0.0.1:18098/v1"
ENG = "$ENG"
info = worker.engagement_info(ENG)
fin = {"tool_call": {"name": "finish", "arguments": {"summary": "done", "confidence": "high"}}}
def say(*a):
    print(*a, flush=True)
def new(tier="passive", **kw):
    t = worker._defaults({"id": "state-" + _u.uuid4().hex[:8], "goal": "test", "engagement": ENG, "tier": tier, "info": info,
                          "max_steps": 5, "timeout_min": 10, "status": "queued", "started": _tm.time(), **kw})
    worker.TASKS[t["id"]] = t
    return t
def until(t, pred, s=90):
    end = _tm.time() + s
    while _tm.time() < end and not pred(t):
        _tm.sleep(0.5)
    return pred(t)
def tool_msgs():
    return [m["content"] for m in REQUESTS[-1]["messages"] if m.get("role") == "tool"]

# 1. approval: pauses, approved action runs exactly once afterwards
SCENARIO = [{"tool_call": {"name": "kali_run", "arguments": {"command": "sqlmap --version"}}}, fin]
REQUESTS.clear()
t = new("intrusive"); _t.Thread(target=worker.run_task, args=(t,), daemon=True).start()
until(t, lambda t: t["status"] == "awaiting_approval")
aid = (t.get("approval") or {}).get("id")
say("NEED approve", aid)
until(t, lambda t: t["status"] not in ("awaiting_approval", "queued", "running"), 120)
again = worker.kali_run(t, "sqlmap --version", approval_id=aid)
say("RESULT approve " + _j.dumps({"status": t["status"], "paused_with": aid, "step": t["steps"][0].get("state"),
    "used_approval": t["steps"][0].get("approval"), "model_saw": tool_msgs()[:1], "again": again[:200],
    "approval": worker.approval_status(t, aid)["status"] if aid else None}))

# 2. denied: the model is told, nothing runs
REQUESTS.clear()
t = new("intrusive"); _t.Thread(target=worker.run_task, args=(t,), daemon=True).start()
until(t, lambda t: t["status"] == "awaiting_approval")
say("NEED deny", (t.get("approval") or {}).get("id"))
until(t, lambda t: t["status"] not in ("awaiting_approval", "queued", "running"), 120)
say("RESULT deny " + _j.dumps({"status": t["status"], "model_saw": tool_msgs()[:1], "step": t["steps"][0].get("state")}))

# 3. cancel from the console (request file) while a command runs
SCENARIO = [{"tool_call": {"name": "kali_run", "arguments": {"command": "sleep 120"}}}, fin]
_t.Thread(target=worker.control_watch, daemon=True).start()
t = new(); t0 = _tm.time(); _t.Thread(target=worker.run_task, args=(t,), daemon=True).start()
until(t, lambda t: t["steps"] and t["steps"][0].get("state") == "started")
_tm.sleep(2)
_o.makedirs(worker.CONTROL, exist_ok=True)
_j.dump({"action": "cancel", "by": "test:state"}, open(_o.path.join(worker.CONTROL, t["id"] + ".json"), "w"))
until(t, lambda t: t["status"] not in ("queued", "running"), 60)
say("RESULT cancel " + _j.dumps({"status": t["status"], "seconds": round(_tm.time() - t0), "error": t.get("error")}))

# 4. halt while a command runs
t = new(); t0 = _tm.time(); _t.Thread(target=worker.run_task, args=(t,), daemon=True).start()
until(t, lambda t: t["steps"] and t["steps"][0].get("state") == "started")
_tm.sleep(2)
say("NEED halt")
until(t, lambda t: t["status"] not in ("queued", "running"), 90)
say("RESULT halt " + _j.dumps({"status": t["status"], "seconds": round(_tm.time() - t0), "error": t.get("error")}))
say("NEED resume")
until(info, lambda i: not worker.engagement_info(ENG).get("halted"), 30)

# 5. restart with a state-changing action in flight: interrupted, needs_review; resume never repeats it
t = new("intrusive", status="running")
call = {"id": "call_x1", "type": "function", "function": {"name": "http_request",
        "arguments": _j.dumps({"method": "POST", "url": "https://example.com/form", "body": "a=1"})}}
msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "test"}, {"role": "assistant", "content": None, "tool_calls": [call]}]
t["pending_calls"] = [call]; t["step"] = 1
t["steps"] = [{"id": t["id"] + "-a1", "call": "call_x1", "tool": "http_request", "args": {"method": "POST", "url": "https://example.com/form"},
               "effect": "write", "state": "started"}]
t["lease"] = {"owner": "gone", "renewed": _tm.time() - 9999}
worker.save(t, msgs)
loaded = _j.load(open(_o.path.join(worker.task_dir(t), "task.json")))
worker.recover(loaded)
SCENARIO = [fin]
REQUESTS.clear()
worker.TASKS[loaded["id"]] = loaded
worker.resume(loaded["id"], "test:state")
until(loaded, lambda t: t["status"] not in ("queued", "running"), 60)
say("RESULT recover " + _j.dumps({"recovery": loaded.get("recovery", {}).get("decision"), "status": loaded["status"],
    "model_saw": tool_msgs()[:1], "step": loaded["steps"][0].get("state"),
    "http_posts": sum(1 for s in loaded["steps"] if s["tool"] == "http_request")}))

# 6. dependencies
SCENARIO = [fin]
a = _j.loads(worker.delegate_task("first", ENG, "passive", wait_s=0))["task_id"]
b = _j.loads(worker.delegate_task("second", ENG, "passive", wait_s=0, depends_on=[a]))["task_id"]
bad = new(status="error"); worker.save(bad)
c = _j.loads(worker.delegate_task("third", ENG, "passive", wait_s=0, depends_on=[bad["id"]]))["task_id"]
until(worker.TASKS[b], lambda t: t["status"] in ("done", "error", "blocked"), 60)
until(worker.TASKS[c], lambda t: t["status"] in ("done", "error", "blocked"), 30)
say("RESULT deps " + _j.dumps({"a": worker.TASKS[a]["status"], "b": worker.TASKS[b]["status"],
    "b_after_a": (worker.TASKS[b].get("finished") or 0) >= (worker.TASKS[a].get("finished") or 1), "c": worker.TASKS[c]["status"],
    "unknown": worker.delegate_task("x", ENG, "passive", wait_s=0, depends_on=["nope"])}))
say("DRIVER DONE")
EOF
} > "$OUT.py"
docker compose exec -T worker-mcp sh -c 'cd /opt/harness && python3 -' < "$OUT.py" > "$OUT" 2>&1 &
drv=$!
seen=""
for _ in $(seq 1 600); do
  while IFS= read -r line; do
    case "$seen" in *"|$line|"*) continue ;; esac
    seen="$seen|$line|"
    case "$line" in
      "NEED approve "*) ctl approve $ENG "${line#NEED approve }" >/dev/null ;;
      "NEED deny "*)    ctl deny $ENG "${line#NEED deny }" >/dev/null ;;
      "NEED halt")      ctl halt $ENG >/dev/null ;;
      "NEED resume")    ctl resume $ENG >/dev/null ;;
    esac
  done < <(grep '^NEED' "$OUT")
  grep -q "DRIVER DONE" "$OUT" && break
  kill -0 $drv 2>/dev/null || break
  sleep 1
done
wait $drv 2>/dev/null
rm -f "${OUT:?}.py"
res() { sed -n "s/^RESULT $1 //p" "$OUT"; }
r="$(res approve)"
check "approval pauses the task"                "$r" '"paused_with": "[a-f0-9]{8}"'
check "approved action ran after the decision"  "$r" '"status": "done".*"step": "done"'
check "the model got the result, not a request" "$r" '"model_saw": \["exit=[0-9]+ tier=intrusive'
check "approval consumed"                       "$r" '"approval": "used"'
check "approval works exactly once"             "$r" '"again": "REFUSED: approval [a-f0-9]{8} is used'
r="$(res deny)"
check "denied action not run, model told"       "$r" '"status": "done".*NOT RUN: The user denied.*"step": "not_run"'
r="$(res cancel)"
check "cancel stops the task and its command"   "$r" '"status": "cancelled", "seconds": ([0-9]|[1-3][0-9]),'
r="$(res halt)"
check "halt stops the task and its command"     "$r" '"status": "halted", "seconds": ([0-9]|[1-5][0-9]),'
r="$(res recover)"
check "restart: action in flight -> needs_review" "$r" '"recovery": "needs_review"'
check "resume does not repeat it"               "$r" '"status": "done".*RESULT UNKNOWN.*don.t repeat it.*"step": "uncertain", "http_posts": 1'
r="$(res deps)"
check "dependency runs after its prerequisite"  "$r" '"a": "done", "b": "done", "b_after_a": true'
check "failed prerequisite blocks a task"       "$r" '"c": "blocked"'
check "unknown dependency refused"              "$r" 'REFUSED: depends_on: no task nope'
[ "$fail" -eq 0 ] || { echo "--- driver output"; tail -30 "$OUT"; }

# ---------------------------------------------------------------- tool servers survive a restart
# A client that was connected before a tool server restarted must keep working afterwards, as an open OpenHands
# conversation does. intel-mcp is the one to restart: it holds no engagement state.
docker compose exec -T worker-mcp python3 - > "$OUT" 2>&1 <<'PY' &
import asyncio, time, urllib.error, urllib.request
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
URL = "http://intel-mcp:8093/mcp"
def up():
    try:
        urllib.request.urlopen(URL, timeout=2)
    except urllib.error.HTTPError:
        return True
    except Exception:
        return False
    return True
async def main():
    async with streamablehttp_client(URL, timeout=20) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            print("BEFORE", len((await s.list_tools()).tools), flush=True)
            t, down = time.time(), False
            while time.time() - t < 120 and not (down and up()):   # wait for the restart: down, then up again
                down = down or not up()
                await asyncio.sleep(0.5)
            print("RESTARTED", down, flush=True)
            print("AFTER", len((await asyncio.wait_for(s.list_tools(), 30)).tools), flush=True)
asyncio.run(main())
PY
client=$!
for _ in $(seq 30); do grep -q '^BEFORE' "$OUT" && break; sleep 1; done
docker compose restart intel-mcp >/dev/null 2>&1
wait $client
r="$(cat "$OUT")"
check "tool server restarted under an open client" "$r" '^RESTARTED True'
check "the same client still works after the restart" "$r" '^AFTER [1-9]'

echo; echo "execution state test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
