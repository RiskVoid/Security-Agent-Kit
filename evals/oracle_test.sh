#!/usr/bin/env bash
# Verification oracles (epic #52, issues #42 and #44) against the hostile lab (Parcel Tracker: ./rvkit lab up), with
# no model. A throwaway engagement is created and deleted afterwards. Each oracle has a lab case that passes and a
# clean case that doesn't, and every pass has a clean negative control:
#   marker               /search reflects ?q= unescaped (pass); /api/docs ignores it (fail)
#   identity_difference  bob reads alice's parcel at /api/parcels/1 (pass); /api/me/parcels/1 checks the owner (fail)
#   read_back            a note bob adds to alice's parcel shows on her parcel (pass, needs an approval: it writes);
#                        a GET that stores nothing (fail)
# The read_back pass case writes, so it needs the user's approval: the test prints the approval id and the command,
# and runs it on the next run with RV_ORACLE_APPROVAL=<id> RV_ORACLE_MARKER=<marker> (same engagement kept).
# Run: ./rvkit lab up && bash evals/oracle_test.sh
cd "$(dirname "$0")/.." || exit 1
ENG=rv-oracle-test
L=http://10.250.0.18:8000
pass=0; fail=0
check() { if echo "$2" | grep -qE "$3"; then pass=$((pass+1)); echo "PASS  $1"; else fail=$((fail+1)); echo "FAIL  $1"; echo "$2" | head -6 | sed 's/^/      /'; fi; }
ctl() { docker compose exec -T kali-mcp python3 /opt/kali-mcp/rvctl.py --actor cli:oracle-test "$@"; }
py() { docker compose exec -T kali-mcp /opt/venv/bin/python3 -c "import sys, json; sys.path.insert(0, '/opt/kali-mcp'); import core; core.ACTOR = 'agent:oracle-test'; import oracles; $1"; }
cleanup() {
  [ -n "$RV_ORACLE_KEEP" ] && return
  ctl halt $ENG >/dev/null 2>&1 </dev/null; ctl delete $ENG --force >/dev/null 2>&1 </dev/null
  docker compose exec -T kali-mcp sh -c "rm -rf /work/_deleted-$ENG-*" </dev/null
  docker compose --profile lab restart lab-hostile >/dev/null 2>&1   # the test may have written to the lab
}
trap cleanup EXIT

docker compose --profile lab ps lab-hostile --format '{{.State}}' | grep -q running \
  || { echo "FAIL  the hostile lab isn't running (./rvkit lab up)"; exit 1; }
if [ -z "$RV_ORACLE_APPROVAL" ]; then
  ./rvkit engagement $ENG --replace --tiers passive,active,intrusive $L >/dev/null 2>&1 \
    || { echo "FAIL  could not create $ENG"; exit 1; }
  # the lab's own test keys (evals/targets/rv-hostile-lab/app.py)
  printf 'key-alice-7731' | ctl cred $ENG set ALICE_KEY >/dev/null
  printf 'key-bob-2290' | ctl cred $ENG set BOB_KEY >/dev/null
  ident() { # ident <name> <secret> <fixture marker>
    printf '{"kind":"header","header":"X-Api-Key","secret":"%s","role":"customer","tenant":"%s","check":{"url":"%s/api/me","marker":"%s"},"fixtures":[{"kind":"parcel","id":%s,"marker":"%s"}],"tiers":["active","intrusive"],"effects":["read","write"]}' \
      "$2" "$1" "$L" "$1" "$4" "$3" | ctl identity $ENG set "$1" >/dev/null; }
  ident alice ALICE_KEY rvfix-alice-parcel-1001 1
  ident bob BOB_KEY rvfix-bob-parcel-1002 2
  check "identity alice: valid" "$(ctl identity $ENG check alice </dev/null)" '"state": "valid"'
  check "identity bob: valid"   "$(ctl identity $ENG check bob </dev/null)" '"state": "valid"'
fi
v() { py "r = oracles.verify('$ENG', $1); print(r['result']); print(r.get('reason') or ''); print(r.get('marker') or ''); print(r.get('record') or r.get('text'))" </dev/null; }

if [ -z "$RV_ORACLE_APPROVAL" ]; then
  # ---------------------------------------------------------------- marker
  r="$(v "'marker', {'url': '$L/search?q=%3Cb%3E{{marker}}%3C/b%3E'}, expect='<b>{{marker}}</b>'")"
  check "marker: reflected XSS passes, control clean" "$r" '^pass'
  rec="$(echo "$r" | tail -1)"
  check "marker: verification record saved" "$(docker compose exec -T kali-mcp cat "$rec" </dev/null)" '"control_clean": true'
  check "marker: audited" "$(docker compose exec -T kali-mcp sh -c "grep -h '\"action\": \"verify\", \"oracle\": \"marker\"' /control/audit.log | tail -1" </dev/null)" '"oracle": "marker"'
  check "marker: clean case fails" "$(v "'marker', {'url': '$L/api/docs?q={{marker}}'}")" '^fail'

  # ---------------------------------------------------------------- identity difference
  check "identity_difference: bob reads alice's parcel (IDOR) passes" \
        "$(v "'identity_difference', {'url': '$L/api/parcels/1'}, identities=['bob', 'alice'], marker='rvfix-alice-parcel-1001'")" '^pass'
  check "identity_difference: the ownership-checked route fails" \
        "$(v "'identity_difference', {'url': '$L/api/me/parcels/1'}, identities=['bob', 'alice'], marker='rvfix-alice-parcel-1001'")" '^fail'

  # ---------------------------------------------------------------- read-back
  # (arguments with "{..., ...}" go through a variable: bash 3.2 brace-expands them inside "$(...)")
  A="'read_back', {'url': '$L/search?q={{marker}}', 'identity': 'bob'}, check={'url': '$L/api/parcels/1', 'identity': 'alice'}"
  check "read_back: a GET that stores nothing fails" "$(v "$A")" '^fail'
  A="'read_back', {'method': 'POST', 'url': '$L/api/parcels/1/notes', 'body': '{{marker}}', 'identity': 'bob'}, check={'url': '$L/api/parcels/1', 'identity': 'alice'}"
  r="$(v "$A")"
  check "read_back: the write asks for an approval" "$r" '^approval'
  id="$(echo "$r" | grep -oE "Approval id: [a-f0-9]{8}" | head -1 | cut -d' ' -f3)"; mk="$(echo "$r" | sed -n 3p)"
  echo "      The read_back pass case writes to the lab and needs your approval. To run it:"
  echo "        ./rvkit approve $ENG $id"
  echo "        RV_ORACLE_APPROVAL=$id RV_ORACLE_MARKER=$mk bash evals/oracle_test.sh"
  echo "      (the engagement is kept until then; RV_ORACLE_KEEP is set for this run)"
  RV_ORACLE_KEEP=1
else
  A="'read_back', {'method': 'POST', 'url': '$L/api/parcels/1/notes', 'body': '{{marker}}', 'identity': 'bob'}, check={'url': '$L/api/parcels/1', 'identity': 'alice'}, marker='$RV_ORACLE_MARKER', approval_id='$RV_ORACLE_APPROVAL'"
  check "read_back: bob's note on alice's parcel reads back (IDOR write)" "$(v "$A")" '^pass'
fi

echo "---"; echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
