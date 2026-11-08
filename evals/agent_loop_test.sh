#!/usr/bin/env bash
# The worker's agent loop end to end, with a scripted model instead of a real one (no GPU, no API key):
# the worker sends its tools to the model, runs the kali command the model asks for in the sandbox, the model
# cites the verified output file, the candidate lands in the findings database, the task is saved and finishes.
# Runs inside the worker container (evals/mock_llm.py serves the model on the container's loopback), on a
# throwaway engagement that is deleted afterwards. Needs the stack up and /src/rv-demo-app (evals/ci_prepare.sh).
# Run: bash evals/agent_loop_test.sh
cd "$(dirname "$0")/.." || exit 1
ENG=rv-loop-test
pass=0; fail=0
check() { if echo "$2" | grep -qE "$3"; then pass=$((pass+1)); echo "PASS  $1"; else fail=$((fail+1)); echo "FAIL  $1"; echo "$2" | head -5 | sed 's/^/      /'; fi; }
cleanup() { RVKIT_YES=1 ./rvkit eng delete $ENG --force >/dev/null 2>&1; }
trap cleanup EXIT

./rvkit engagement $ENG --replace --tiers passive /src/rv-demo-app >/dev/null 2>&1 || { echo "FAIL  could not create $ENG"; exit 1; }

out="$( { sed "/^if __name__ == \"__main__\":/,\$d" evals/mock_llm.py; cat <<EOF
import json as _j, os as _o, sys as _s
_s.path.insert(0, "/opt/harness")
_s.modules["mock_llm"] = _s.modules[__name__]
import worker
serve(18099)
worker.LITELLM = "http://127.0.0.1:18099/v1"
info = worker.engagement_info("$ENG")
task = {"id": "loop-test-" + __import__("uuid").uuid4().hex[:6], "goal": "List the source folder and record what you find.",
        "engagement": "$ENG", "tier": "passive", "info": info, "max_steps": 5, "timeout_min": 5, "status": "queued",
        "started": __import__("time").time(), "steps": [], "evidence": [], "candidates": []}
worker.run_task(task)
saved = _j.load(open(_o.path.join(worker.task_dir(task), "task.json")))
print("RESULT " + _j.dumps({"status": task["status"], "error": task.get("error"), "steps": [s["tool"] for s in task["steps"]],
      "candidates": task["candidates"], "summary": (task.get("result") or {}).get("summary", ""),
      "saved_status": saved.get("status"), "sent_tools": sorted(t["function"]["name"] for t in REQUESTS[0]["tools"]),
      "requests": len(REQUESTS), "model": REQUESTS[0]["model"]}))
EOF
} | docker compose exec -T worker-mcp sh -c 'cd /opt/harness && python3 -' 2>&1)"
res="$(echo "$out" | sed -n 's/^RESULT //p')"
[ -n "$res" ] || res="$out"
get() { echo "$res" | python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get('$1')))" 2>/dev/null; }

check "task finished"                         "$(get status)" '"done"'
check "no error"                              "$(get error)" '^null$'
check "worker sent its tools to the model"    "$(get sent_tools)" 'kali_run.*record_candidate|finish.*kali_run'
check "model asked for the worker model"      "$(get model)" '"colab-qwen"|"private-llm"'
check "kali command, then candidate"          "$(get steps)" '\["kali_run", "record_candidate"\]'
check "three model turns"                     "$(get requests)" '^3$'
check "task saved to disk"                    "$(get saved_status)" '"done"'
fid="$(get candidates | tr -d '[]" ')"
check "candidate recorded"                    "$fid" '^F-[0-9]+$'
row="$(docker compose exec -T findings-mcp python3 -c "
import json, findings_db as db; f = db.get('$ENG', '$fid'); print(json.dumps({'status': f['status'], 'src': f['source'], 'ev': f['evidence']}))" 2>&1)"
check "candidate in the findings database"    "$row" '"status": "candidate".*"src": "worker:loop-test-'
ev="$(echo "$row" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ev"][0])' 2>/dev/null)"
check "evidence cites the saved kali output"  "$ev" "/work/$ENG/evidence/runs/.*-ls-.*\.txt"
prov="$(docker compose exec -T worker-mcp python3 -c "
import sys; sys.path.insert(0, '/opt/harness'); import worker
print(worker._arun(worker._kali('evidence_provenance', {'engagement': '$ENG', 'paths': ['$ev']}, 60)))" 2>&1)"
check "cited evidence verifies"               "$prov" '"status": "verified"'

echo; echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
