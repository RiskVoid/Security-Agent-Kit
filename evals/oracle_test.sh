#!/usr/bin/env bash
# Verification oracles (epic #52, issues #42, #43 and #44) against the hostile lab (Parcel Tracker: ./rvkit lab up), with
# no model. A throwaway engagement is created and deleted afterwards. Each oracle has a lab case that passes and a
# clean case that doesn't, and every pass has a clean negative control:
#   marker               /search reflects ?q= unescaped (pass); /api/docs ignores it (fail)
#   identity_difference  bob reads alice's parcel at /api/parcels/1 (pass); /api/me/parcels/1 checks the owner (fail)
#   read_back            a note bob adds to alice's parcel shows on her parcel (pass, needs an approval: it writes);
#                        a GET that stores nothing (fail)
#   browser_xss          /search runs a reflected <script> in the sandboxed browser (pass); /api/docs doesn't (fail)
#   timing               /api/eta with detail=full is slow on purpose (pass); two equally fast requests (fail)
#   response_diff        the decoy /debug/status shows a fake shell output an ordinary page doesn't (pass); the
#                        home page doesn't show it (fail); a text both answers contain (inconclusive)
#   persistence          a note stored on alice's parcel runs its script when her parcel page is opened in the
#                        browser (pass; the note is a write, so it needs an approval, like read_back)
#   oob_callback         /api/fetch does a server-side fetch of the kit's own catcher (pass; the engagement allows
#                        the whole lab subnet, and the catcher must still be unreachable from agent commands);
#                        /search, which never fetches (fail). Needs RULES.md 'Out-of-band callbacks: on', which
#                        this test turns on. With the DVGA lab up, its importPaste SSRF is verified the same way;
#                        that probe is a POST mutation, so it needs an approval (printed; run again with
#                        RV_OOB_APPROVAL=<id> RV_OOB_MARKER=<token>).
# The read_back and persistence pass cases write, so they need the user's approval: the test prints the approval
# ids and commands, and runs them on the next run with RV_ORACLE_APPROVAL=<id> RV_ORACLE_MARKER=<marker> and
# RV_PERSIST_APPROVAL=<id> RV_PERSIST_MARKER=<token> (same engagement kept).
# The disprove-only validator (#45) is off here (no model). RV_ORACLE_VALIDATOR=1 turns it on: the oracle-confirmed
# finding then goes to the validator model (one small OpenRouter call) and must stand.
# Run: ./rvkit lab up && bash evals/oracle_test.sh
cd "$(dirname "$0")/.." || exit 1
ENG=rv-oracle-test
ENG2=rv-oob-dvga-test
L=http://10.250.0.18:8000
pass=0; fail=0
check() { if echo "$2" | grep -qE "$3"; then pass=$((pass+1)); echo "PASS  $1"; else fail=$((fail+1)); echo "FAIL  $1"; echo "$2" | head -6 | sed 's/^/      /'; fi; }
ctl() { docker compose exec -T kali-mcp python3 /opt/kali-mcp/rvctl.py --actor cli:oracle-test "$@"; }
py() { docker compose exec -T kali-mcp /opt/venv/bin/python3 -c "import sys, json; sys.path.insert(0, '/opt/kali-mcp'); import core; core.ACTOR = 'agent:oracle-test'; import oracles; $1"; }
cleanup() {
  [ -n "$RV_ORACLE_KEEP" ] && return
  for e in "$ENG" "$ENG2"; do
    ctl halt "$e" >/dev/null 2>&1 </dev/null; ctl delete "$e" --force >/dev/null 2>&1 </dev/null
    docker compose exec -T kali-mcp sh -c "rm -rf /work/_deleted-$e-*" </dev/null
  done
  docker compose --profile lab restart lab-hostile lab-dvga >/dev/null 2>&1   # the tests may have written to the labs
}
trap cleanup EXIT

v() { py "r = oracles.verify('$ENG', $1); print(r['result']); print(r.get('reason') or ''); print(r.get('marker') or ''); print(r.get('record') or r.get('text'))" </dev/null; }
v2() { py "r = oracles.verify('$ENG2', $1); print(r['result']); print(r.get('reason') or ''); print(r.get('marker') or ''); print(r.get('record') or r.get('text'))" </dev/null; }
oob_on() { # oob_on <eng>: the catcher is a host decision; the test enables it like an operator would
  # the rvkit template documents the rule as a comment; only an active line counts
  docker compose exec -T kali-mcp sh -c "grep -q '^- Out-of-band callbacks:' /work/$1/RULES.md 2>/dev/null || printf 'Out-of-band callbacks: on\n' >> /work/$1/RULES.md"
  ctl sync "$1" --yes >/dev/null; }

docker compose --profile lab ps lab-hostile --format '{{.State}}' | grep -q running \
  || { echo "FAIL  the hostile lab isn't running (./rvkit lab up)"; exit 1; }
if [ -z "$RV_ORACLE_APPROVAL" ]; then
  # the whole lab subnet is in scope, so the oob reachability check can prove the catcher is unreachable from
  # agent commands even though its address is authorised for the engagement
  ./rvkit engagement $ENG --replace --tiers passive,active,intrusive 10.250.0.0/24 >/dev/null 2>&1 \
    || { echo "FAIL  could not create $ENG"; exit 1; }
  # out-of-band callbacks are off by default: the catcher is a host decision (RULES.md), like an identity
  oob_on $ENG
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

if [ -z "$RV_ORACLE_APPROVAL" ]; then
  # ---------------------------------------------------------------- marker
  r="$(v "'marker', {'url': '$L/search?q=%3Cb%3E{{marker}}%3C/b%3E'}, expect='<b>{{marker}}</b>'")"
  check "marker: reflected XSS passes, control clean" "$r" '^pass'
  rec="$(echo "$r" | tail -1)"
  check "marker: verification record saved" "$(docker compose exec -T kali-mcp cat "$rec" </dev/null)" '"control_clean": true'
  check "marker: audited" "$(docker compose exec -T kali-mcp sh -c "grep -h '\"action\": \"verify\", \"oracle\": \"marker\"' /control/audit.log | tail -1" </dev/null)" '"oracle": "marker"'
  r2="$(v "'marker', {'url': '$L/api/docs?q={{marker}}'}")"
  check "marker: clean case fails" "$r2" '^fail'
  rec2="$(echo "$r2" | tail -1)"

  # ---------------------------------------------------------------- the finding side (#44)
  fpy() { docker compose exec -T -e VALIDATOR="${RV_ORACLE_VALIDATOR:-0}" findings-mcp python3 -c "import findings; $1" </dev/null; }
  check "a finding can't be confirmed by oracle with the clean case's record" \
        "$(fpy "print(findings.record_finding('$ENG', 'XSS in /api/docs', 'medium', '$L/api/docs', 'Reflected input.', evidence=['$rec2'], status='confirmed', method='oracle', reproduction='Run the oracle record.'))")" \
        'REFUSED: no cited verification passed'
  check "a finding confirmed by oracle with the passing record" \
        "$(fpy "print(findings.record_finding('$ENG', 'HTML injection in /search', 'medium', '$L/search?q=', 'The q parameter is reflected into the page without escaping: HTML tags in it are kept as markup.', evidence=['$rec'], status='confirmed', method='oracle', reproduction='Open /search with an HTML tag in q.'))")" \
        '"verified_method": "oracle"'
  if [ "${RV_ORACLE_VALIDATOR:-0}" = 1 ]; then
    check "the validator lets the oracle-confirmed finding stand" \
          "$(fpy "import validator; print(validator.latest('$ENG'))")" "'verdict': 'stands'"
    # a false confirmation: the clean route's response cited as proof of an injection it doesn't show
    clean="$(fpy "import json; print(json.load(open('$rec2'))['steps'][0]['evidence'])")"
    check "the validator disproves a false confirmation on the clean route; it goes back to candidate" \
          "$(fpy "import json; r = json.loads(findings.record_finding('$ENG', 'SQL injection in /api/docs', 'high', '$L/api/docs', 'The q parameter of /api/docs is injectable: the response shows a database error.', evidence=['$clean'], status='confirmed', method='tool-output', reproduction='Open /api/docs with a quote in q.')); print(r['status'], r['validation']['verdict'])")" \
          '^candidate disproved'
  fi
  printf 'Test report for the verification oracles.\n' | docker compose exec -T findings-mcp sh -c "mkdir -p /work/$ENG/report && cat > /work/$ENG/report/executive-summary.md"
  fpy "import ops; ops.call('report.build', {'engagement': '$ENG', 'actor': 'test:oracle'})" >/dev/null 2>&1
  html="$(docker compose exec -T findings-mcp sh -c "cat /work/$ENG/report/*.html" </dev/null)"
  check "the report shows the oracle and its negative control" "$(echo "$html" | python3 -c 'import sys; t = sys.stdin.read().replace("\n", ""); i = t.find("Verification</div>"); print(t[i:i + 1500] if i >= 0 else "")')" \
        'marker.*pass.*control: status 200'

  # ---------------------------------------------------------------- runtime oracles (#43)
  A="'browser_xss', {'url': \"$L/search?q=<script>rvMarker('{{marker}}')</script>\"}"
  check "browser_xss: the reflected script runs in the browser, control clean" "$(v "$A")" '^pass'
  A="'browser_xss', {'url': \"$L/api/docs?q=<script>rvMarker('{{marker}}')</script>\"}"
  check "browser_xss: a page that doesn't run it fails" "$(v "$A")" '^fail'
  A="'timing', {'url': '$L/api/eta?parcel=1&detail=full'}, control={'url': '$L/api/eta?parcel=1'}, samples=4"
  check "timing: the slow route is slower than its control beyond the noise" "$(v "$A")" '^pass'
  A="'timing', {'url': '$L/api/eta?parcel=1&detail=short'}, control={'url': '$L/api/eta?parcel=1'}, samples=4"
  check "timing: two equally fast requests fail" "$(v "$A")" '^fail'

  # ---------------------------------------------------------------- out-of-band callback (#58)
  A="'oob_callback', {'url': '$L/api/fetch?url=http://10.250.0.2:8080/{{marker}}'}"
  r="$(v "$A")"
  check "oob_callback: the SSRF fetches the catcher, token arrives" "$r" '^pass'
  rec="$(echo "$r" | tail -1)"
  check "oob_callback: the callback is in the verification record" "$(docker compose exec -T kali-mcp cat "$rec" </dev/null)" '"role": "callback"'
  check "oob_callback: the callback is audited" \
        "$(docker compose exec -T kali-mcp sh -c "grep -h '\"action\": \"oob-callback\"' /control/audit.log | tail -1" </dev/null)" "\"token\": \"$ENG\."
  A="'oob_callback', {'url': '$L/search?q={{marker}}'}"
  check "oob_callback: a route that never fetches fails" "$(v "$A")" '^fail'
  # the catcher's address is in scope for this engagement (the lab subnet): an agent command still cannot reach
  # it, so a callback token can only have come from the target itself
  R="$(py "import core; print(core.run('curl -s --max-time 4 -o /dev/null -w %{http_code} http://10.250.0.2:8080/forge-attempt', '$ENG'))" </dev/null)"
  check "oob: the catcher is unreachable from agent commands" "$R" 'exit=28|^REFUSED'

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

# ---------------------------------------------------------------- persistence: a stored script (#W7)
# A note stored on alice's parcel (a write: its own approval) runs when her parcel page is opened in the browser.
# The before-control shows the page runs nothing of the marker first; the write and the browser run are evidenced.
if [ -z "$RV_PERSIST_APPROVAL" ]; then
  A="'persistence', {'method': 'POST', 'url': '$L/api/parcels/1/notes', 'body': \"<script>rvMarker('{{marker}}')</script>\", 'identity': 'bob'}, check={'url': '$L/parcels/1'}"
  r="$(v "$A")"
  check "persistence: the stored note asks for an approval before it is written" "$r" '^approval'
  pid2="$(echo "$r" | grep -oE 'Approval id: [a-f0-9]{8}' | head -1 | cut -d' ' -f3)"; pmark="$(echo "$r" | sed -n 3p)"
  echo "      The persistence pass case writes a note to the lab and needs your approval. To run it:"
  echo "        ./rvkit approve $ENG $pid2"
  echo "        RV_ORACLE_APPROVAL=$id RV_ORACLE_MARKER=$mk RV_PERSIST_APPROVAL=$pid2 RV_PERSIST_MARKER=$pmark bash evals/oracle_test.sh"
  RV_ORACLE_KEEP=1
else
  A="'persistence', {'method': 'POST', 'url': '$L/api/parcels/1/notes', 'body': \"<script>rvMarker('{{marker}}')</script>\", 'identity': 'bob'}, check={'url': '$L/parcels/1'}, marker='$RV_PERSIST_MARKER', approval_id='$RV_PERSIST_APPROVAL'"
  r="$(v "$A")"
  check "persistence: the stored script runs when the parcel page is opened" "$r" '^pass'
  recp="$(echo "$r" | tail -1)"
  check "persistence: the control (the page before the write) is in the record" \
        "$(docker compose exec -T kali-mcp cat "$recp" </dev/null)" '"control: the page before the write"'
fi

# ---------------------------------------------------------------- response difference (#W7)
if [ -z "$RV_ORACLE_APPROVAL" ]; then
  A="'response_diff', {'url': '$L/debug/status'}, control={'url': '$L/api/docs'}, expect='uid=0(root)'"
  check "response_diff: the decoy's shell output is only in the probe's answer" "$(v "$A")" '^pass'
  A="'response_diff', {'url': '$L/'}, control={'url': '$L/api/docs'}, expect='uid=0(root)'"
  check "response_diff: a page without the text fails" "$(v "$A")" '^fail'
  A="'response_diff', {'url': '$L/api/docs'}, control={'url': '$L/api/docs'}, expect='openapi'"
  check "response_diff: a text both answers contain is inconclusive" "$(v "$A")" '^inconclusive'
fi

# ---------------------------------------------------------------- out-of-band on DVGA: the importPaste SSRF (#58)
# A separate throwaway engagement, so the DVGA target is in scope. The fail case is a GET query that never
# fetches anything. The pass case is a POST mutation, so it is intrusive and needs an approval, exactly like
# read_back above: the first run prints it, the next run (RV_OOB_APPROVAL, RV_OOB_MARKER) sends it.
if docker compose --profile lab ps lab-dvga --format '{{.State}}' | grep -q running; then
  if [ -z "$RV_OOB_APPROVAL" ]; then
    ./rvkit engagement $ENG2 --replace --tiers passive,active,intrusive http://10.250.0.14:5013 >/dev/null 2>&1 \
      || { echo "FAIL  could not create $ENG2"; fail=$((fail+1)); }
    if docker compose exec -T kali-mcp sh -c "test -d /work/$ENG2" </dev/null; then
      oob_on $ENG2
      A="'oob_callback', {'url': 'http://10.250.0.14:5013/graphql?query=%7BsystemHealth%7D'}"
      check "oob_callback: a DVGA query that never fetches fails" "$(v2 "$A")" '^fail'
      A="'oob_callback', {'method': 'POST', 'url': 'http://10.250.0.14:5013/graphql', 'headers': {'Content-Type': 'application/json'}, 'body': json.dumps({'query': 'mutation{importPaste(host:\"10.250.0.2\",path:\"/{{marker}}\",port:8080,scheme:\"http\"){result}}'})}"
      r="$(v2 "$A")"
      check "oob_callback: DVGA's importPaste probe asks for an approval" "$r" '^approval'
      id2="$(echo "$r" | grep -oE "Approval id: [a-f0-9]{8}" | head -1 | cut -d' ' -f3)"; mk2="$(echo "$r" | sed -n 3p)"
      echo "      The DVGA importPaste probe is a POST mutation (intrusive) and needs your approval. To run it:"
      echo "        ./rvkit approve $ENG2 $id2"
      echo "        RV_ORACLE_APPROVAL=$id RV_ORACLE_MARKER=$mk RV_OOB_APPROVAL=$id2 RV_OOB_MARKER=$mk2 bash evals/oracle_test.sh"
      echo "      (both engagements are kept until then)"
      RV_ORACLE_KEEP=1
    fi
  else
    A="'oob_callback', {'method': 'POST', 'url': 'http://10.250.0.14:5013/graphql', 'headers': {'Content-Type': 'application/json'}, 'body': json.dumps({'query': 'mutation{importPaste(host:\"10.250.0.2\",path:\"/{{marker}}\",port:8080,scheme:\"http\"){result}}'})}, marker='$RV_OOB_MARKER', approval_id='$RV_OOB_APPROVAL'"
    r="$(v2 "$A")"
    check "oob_callback: DVGA's importPaste SSRF calls back, control clean" "$r" '^pass'
    rec2="$(echo "$r" | tail -1)"
    check "oob_callback: the DVGA callback is evidence with an audit entry" "$(docker compose exec -T kali-mcp cat "$rec2" </dev/null)" '"role": "callback"'
  fi
else
  echo "SKIP  oob on DVGA: lab-dvga isn't running (./rvkit lab up starts it)"
fi

echo "---"; echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
