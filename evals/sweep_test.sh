#!/usr/bin/env bash
# The harness-run checks (epic #76, #67 to #71) against VAmPI, with no model. A throwaway engagement is
# created and deleted afterwards. The sweep reads the recon map's evidence and checks what the error analysis
# showed the model doesn't reliably think of; each check has a case that must hit and clean controls that must
# not (a book field that validates but stays fast, a parameter whose answers don't change):
#   injection        the SQL injection on GET /users/v1/{username} (missed in 3 of 5 recent runs: the model never
#                    probed the path parameter) hits, error-based, in the read phase
#   mass-assignment  POST /users/v1/register with admin=true reads back admin (GET /me), against a control
#                    account without the field
#   redos            PUT /users/v1/{username}/email's validation regex answers 0.00s, 0.00s, 0.03s, 0.38s for
#                    inputs of growing length, and the ladder stops there, never at the sizes that stop the target
#   jwt              the login token's HMAC key is a common secret; a token forged with it is accepted by /me
# The write checks are proposed as one authorization matrix and run only after it is approved (as the operator
# would), so nothing writes without one decision. The hits import as observations through the sweep parser.
# Run: ./rvkit lab up && bash evals/sweep_test.sh
cd "$(dirname "$0")/.." || exit 1
ENG=rv-sweep-test
V=http://10.250.0.13:5000
pass=0; fail=0
check() { if echo "$2" | grep -qE "$3"; then pass=$((pass+1)); echo "PASS  $1"; else fail=$((fail+1)); echo "FAIL  $1"; echo "$2" | head -8 | sed 's/^/      /'; fi; }
ctl() { docker compose exec -T kali-mcp python3 /opt/kali-mcp/rvctl.py --actor cli:sweep-test "$@"; }
py() { docker compose exec -T kali-mcp python3 -c "import sys; sys.path.insert(0, '/opt/kali-mcp'); import core; core.ACTOR = 'agent:sweep-test'; import sweep; $1" </dev/null; }
fpy() { docker compose exec -T findings-mcp python3 -c "import sys; sys.path.insert(0, '/opt/harness'); import observations as ob, json; $1" </dev/null; }
flat() { docker compose exec -T kali-mcp sh -c "tr -d '\n ' < '$1'" </dev/null; }   # the evidence json is indented
cleanup() {
  ctl halt $ENG >/dev/null 2>&1 </dev/null; ctl delete $ENG --force >/dev/null 2>&1 </dev/null
  docker compose exec -T kali-mcp sh -c "rm -rf /work/_deleted-$ENG-*" </dev/null
  docker compose --profile lab restart lab-vampi >/dev/null 2>&1   # the sweep registers throwaway accounts
}
trap cleanup EXIT

docker compose --profile lab ps lab-vampi --format '{{.State}}' | grep -q running \
  || { echo "FAIL  the VAmPI lab isn't running (./rvkit lab up)"; exit 1; }
./rvkit engagement $ENG --replace --tiers passive,active,intrusive $V >/dev/null 2>&1 \
  || { echo "FAIL  could not create $ENG"; exit 1; }

# ---------------------------------------------------------------- the map, then the read phase
py "print(__import__('recon').build('$ENG', '$V', 1, 30, True, None, None))" >/dev/null \
  || { echo "FAIL  recon_map didn't build a map"; exit 1; }
out="$(py "print(sweep.probe_map('$ENG'))")"
check "read phase: the path-parameter SQL injection hits" "$out" 'HIT injection on GET /users/v1/{}'
check "read phase: the write checks only propose a matrix" "$out" 'matrix sweep-[0-9]+'
check "read phase: the jwt check skips honestly (no token yet)" "$out" 'SKIP jwt.*no JWT was seen'
ev="$(echo "$out" | grep -oE '/work/'$ENG'/evidence/sweep/sweep-[0-9T]+\.json' | head -1)"
check "the sweep's evidence file exists and is audited" \
      "$(docker compose exec -T kali-mcp sh -c "test -f '$ev' && grep -h '\"action\": \"sweep\"' /control/audit.log | tail -1" </dev/null)" \
      '"requests": [0-9]+, "hits": 1'
check "the injection hit cites its exact requests" "$(flat "$ev")" '"param":"0".*"result":"hit"'
check "the benign book parameter stayed clean (probed, no hit)" "$(flat "$ev")" \
      '"check":"injection".*"result":"clean".*"why":"theerrorandbooleanprobes'

# ---------------------------------------------------------------- the write phase, after one approval
name="$(echo "$out" | grep -oE 'matrix sweep-[0-9]+' | head -1 | cut -d' ' -f2)"
ctl authz $ENG approve "$name" >/dev/null 2>&1 </dev/null
check "the sweep matrix is approved" "$(ctl authz $ENG list 2>/dev/null | tr -d '\n ')" '"state":"approved"'
out2="$(py "print(sweep.probe_map('$ENG', matrix='$name'))")"
check "mass-assignment: admin=true registers an admin (read back via /me)" "$out2" \
      'HIT mass-assignment on POST /users/v1/register.*admin is true there and false in the control'
check "redos: the email regex slows with input length, and the ladder stops" "$out2" \
      'HIT redos on PUT /users/v1/{}/email.*0\.[0-9]+s.*past three times'
check "the redos ladder never sent the sizes that stop the target" \
      "$(docker compose exec -T kali-mcp sh -c "grep -hoE 'a{29}' /work/$ENG/evidence/sweep/*.txt 2>/dev/null | wc -l | tr -d ' '" </dev/null)" \
      '^0$'
check "jwt: the common secret is cracked and the forged token is accepted" "$out2" \
      'HIT jwt on GET /me.*accepted where the original is accepted'
check "one jwt row per weak key, not one per token" "$(echo "$out2" | grep -c 'HIT jwt')" '^1$'
ev2="$(echo "$out2" | grep -oE '/work/'$ENG'/evidence/sweep/sweep-[0-9T]+\.json' | head -1)"
check "the throwaway accounts are listed in the evidence" "$(flat "$ev2")" '"created":\["sweep-'
check "the write requests ran under the approved matrix" \
      "$(docker compose exec -T kali-mcp sh -c "grep -h 'sweep-matrix' /control/audit.log | tail -1" </dev/null)" \
      '"kind": "sweep-matrix"'
if flat "$ev2" | grep -q '/books/v1'; then
  fail=$((fail+1)); echo "FAIL  the write phase touched the app's own object creation (books)"
else
  pass=$((pass+1)); echo "PASS  the write phase touched only its own throwaway accounts (never the books)"
fi

# ---------------------------------------------------------------- the hits import as observations
check "the sweep evidence parses as observations (both files, all four checks)" \
      "$(fpy "
rs = [ob.parse(p, json.dumps(json.load(open(p)))) for p in ('$ev', '$ev2')]
ids = sorted(o['rule_id'] for r in rs for o in r['observations'])
print(rs[0]['parser'], len(ids), '-'.join(ids))")" \
      '^sweep 4 injection-jwt-mass-assignment-redos$'
check "the observations carry the evidence files and no secret" \
      "$(fpy "r = ob.parse('$ev2', json.dumps(json.load(open('$ev2')))); t = json.dumps(r['observations']); print('evidence' in t, 'secret_in_evidence' in t)")" \
      '^True False$'
check "skips and throwaway accounts are kept as limitations" \
      "$(fpy "r = ob.parse('$ev2', json.dumps(json.load(open('$ev2')))); print('; '.join(l['note'][:50] for l in r['limitations']))")" \
      'the sweep created sweep-'

echo "---"; echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
