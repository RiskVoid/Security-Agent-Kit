#!/usr/bin/env bash
# The brokered race action (W4, epic #76) against the Laravel lab, with no model. Two throwaway
# engagements are created and deleted afterwards: one on the vulnerable build (10.250.0.16), one on the
# fixed build (10.250.0.17, the locked controller: the clean control).
#
#   the approval    one approval covers the exact request x N: its text names N and the rate exemption
#                  (a race is simultaneous by definition, so Max rate doesn't apply; N is capped at 25)
#   the binding     the approval binds N: a race with a different N is refused
#   the finding     the vulnerable build's one-shot promo (max_uses 1) redeems N times: several shots
#                  succeed, and the read-back (GET /api/promo/<code>) shows uses beyond max_uses - the
#                  oracle decides, not an opinion about N similar answers
#   the control    the fixed build's locked controller redeems at most once: at most one shot succeeds
#                  and the read-back shows uses at max
# Also refused, as they must be: a race on a read (nothing to race), N out of range, and a race whose
# approval doesn't match.
# Run: ./rvkit lab up && bash evals/race_test.sh
cd "$(dirname "$0")/.." || exit 1
ENG=rv-race-test
CTL=rv-race-ctl
V=http://10.250.0.16:8000
F=http://10.250.0.17:8000
pass=0; fail=0
check() { if echo "$2" | grep -qE "$3"; then pass=$((pass+1)); echo "PASS  $1"; else fail=$((fail+1)); echo "FAIL  $1"; echo "$2" | head -6 | sed 's/^/      /'; fi; }
ctl() { docker compose exec -T kali-mcp python3 /opt/kali-mcp/rvctl.py --actor cli:race-test "$@"; }
py() { docker compose exec -T kali-mcp /opt/venv/bin/python3 -c "import sys, json; sys.path.insert(0, '/opt/kali-mcp'); import core; core.ACTOR = 'agent:race-test'; import actions; $1" </dev/null; }
cleanup() {
  for e in $ENG $CTL; do
    ctl halt "$e" >/dev/null 2>&1 </dev/null; ctl delete "$e" --force >/dev/null 2>&1 </dev/null
    docker compose exec -T kali-mcp sh -c "rm -rf /work/_deleted-$e-*" </dev/null
  done
  docker compose --profile lab restart lab-laravel lab-laravel-fixed >/dev/null 2>&1   # a fresh promo (the DB resets on restart)
}
trap cleanup EXIT

docker compose --profile lab ps lab-laravel --format '{{.State}}' | grep -q running \
  || { echo "FAIL  the Laravel lab isn't running (./rvkit lab up)"; exit 1; }
for e in "$ENG" "$CTL"; do
  ./rvkit engagement "$e" --replace --tiers passive,active,intrusive \
    "$([ "$e" = "$ENG" ] && echo "$V" || echo "$F")" >/dev/null 2>&1 \
    || { echo "FAIL  could not create $e"; exit 1; }
  printf 'rvlab-alice-7f3a9c41d2' | ctl cred "$e" set ALICE_TOKEN >/dev/null 2>&1
  printf '{"kind":"bearer","secret":"ALICE_TOKEN","role":"customer","tenant":"acme","check":{"url":"%s/api/me","marker":"alice"},"tiers":["active","intrusive"],"effects":["read","write"]}' \
    "$([ "$e" = "$ENG" ] && echo "$V" || echo "$F")" | ctl identity "$e" set alice >/dev/null 2>&1
done
# the fresh promo: restarting the lab containers reseeded it (uses_count 0)
docker compose --profile lab restart lab-laravel lab-laravel-fixed >/dev/null 2>&1
sleep 6

# ---------------------------------------------------------------- what is refused outright
r="$(py "print(actions.race('$ENG', 'GET', '$V/api/promo/redeem')['text'])")"
check "a race on a read is refused (nothing to race)" "$r" 'REFUSED: race needs a state-changing method'
r="$(py "print(actions.race('$ENG', 'POST', '$V/api/promo/redeem', n=1)['text'])")"
check "N below the range is refused" "$r" 'REFUSED: a race sends 2 to 25'
r="$(py "print(actions.race('$ENG', 'POST', '$V/api/promo/redeem', n=30)['text'])")"
check "N above the cap is refused" "$r" 'REFUSED: a race sends 2 to 25'

# ---------------------------------------------------------------- one approval names N and the exemption
r="$(py "print(actions.race('$ENG', 'POST', '$V/api/promo/redeem', headers={'Content-Type': 'application/json'}, n=10, body='{\"code\":\"RVLAUNCH10\"}', identity='alice')['text'])")"
check "the race asks for an approval that names N" "$r" 'RACE 10x POST'
check "the approval names the rate exemption" "$r" 'exempt from Max rate'
check "the approval names the cap" "$r" 'capped at 25'
aid="$(echo "$r" | grep -oE 'Approval id: [a-f0-9]{8}' | head -1 | cut -d' ' -f3)"
check "an approval id came back" "$aid" '^[a-f0-9]{8}$'

# ---------------------------------------------------------------- the binding: the approval covers request x N
ctl approve "$ENG" "$aid" >/dev/null 2>&1 </dev/null
r="$(py "print(actions.race('$ENG', 'POST', '$V/api/promo/redeem', headers={'Content-Type': 'application/json'}, n=5, body='{\"code\":\"RVLAUNCH10\"}', identity='alice', approval_id='$aid')['text'])")"
check "the approval doesn't cover a different N" "$r" 'REFUSED:'

# ---------------------------------------------------------------- the race, and the oracle that decides
r="$(py "
import json
out = actions.race('$ENG', 'POST', '$V/api/promo/redeem', headers={'Content-Type': 'application/json'}, n=10, body='{\"code\":\"RVLAUNCH10\"}', identity='alice', approval_id='$aid')
print(json.dumps({'text': out['text'], 'succeeded': out.get('succeeded'), 'evidence': out.get('evidence')}))")"
succ="$(echo "$r" | python3 -c 'import json,sys; print(json.load(sys.stdin)["succeeded"])')"
ev="$(echo "$r" | python3 -c 'import json,sys; print(json.load(sys.stdin)["evidence"])')"
check "the vulnerable promo redeems more than once (2 or more of the burst succeed)" "$succ" '^[2-9][0-9]*$|^1[0-9]$'
check "the burst is saved as evidence with every response" "$(docker compose exec -T kali-mcp sh -c "test -f '/work/$ENG/$ev' && grep -c '\"status\"' '/work/$ENG/$ev'" </dev/null)" '^10$'
check "the race is audited under the approval" \
      "$(docker compose exec -T kali-mcp sh -c "grep -h '\"action\": \"race\", \"method\": \"POST\", \"url\": \"http://10.250.0.16:8000/api/promo/redeem\", \"race\": 10' /control/audit.log | tail -1" </dev/null)" \
      '"race": 10'
readback="$(py "
import json
r = actions.send('$ENG', 'GET', '$V/api/promo/RVLAUNCH10', {}, b'', identity='alice')
print(json.dumps({'status': r.get('status'), 'body': (r.get('body') or b'').decode()[:120]}))")"
check "the read-back shows uses beyond max_uses (the oracle decides)" "$readback" 'uses[^0-9]{1,4}[2-9]'

# ---------------------------------------------------------------- the clean control: the locked controller
r="$(py "print(actions.race('$CTL', 'POST', '$F/api/promo/redeem', headers={'Content-Type': 'application/json'}, n=10, body='{\"code\":\"RVLAUNCH10\"}', identity='alice')['text'])")"
fid="$(echo "$r" | grep -oE 'Approval id: [a-f0-9]{8}' | head -1 | cut -d' ' -f3)"
ctl approve "$CTL" "$fid" >/dev/null 2>&1 </dev/null
r="$(py "
import json
out = actions.race('$CTL', 'POST', '$F/api/promo/redeem', headers={'Content-Type': 'application/json'}, n=10, body='{\"code\":\"RVLAUNCH10\"}', identity='alice', approval_id='$fid')
print(out.get('succeeded'))")"
check "the fixed build redeems at most once (the lock holds)" "$r" '^[01]$'
readback="$(py "
import json
r = actions.send('$CTL', 'GET', '$F/api/promo/RVLAUNCH10', {}, b'', identity='alice')
print((r.get('body') or b'').decode()[:120])")"
check "the fixed read-back stays at max_uses" "$readback" 'uses[^0-9]{1,4}1'

echo "---"; echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
