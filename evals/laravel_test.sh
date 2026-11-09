#!/usr/bin/env bash
# The Laravel reference engagement (RW-012 to RW-014) against Ledgerly, with no model:
#   Application map: routes with effective middleware, controllers, models, policies and scopes from the source,
#     without running it; leads for the seeded flaws, controls for the protected routes, none on the fixed build.
#   Build identity: the deployment's build matches its source, a different build is reported as not matching.
#   Source and runtime evidence establish the seeded cross-tenant read and its corrected behaviour.
#   PHP profile: parse check and a runtime route export in an isolated container with no network; the client
#     source is not modified by anything; outputs are audited evidence.
#   Semgrep's PHP rules parse the code (and what they don't find is recorded, not assumed clean).
#   External effects stay in the lab: mail goes to the lab's log.
# Needs: ./rvkit lab up, bash evals/ci_prepare.sh (copies the lab source to <projects>/rv-laravel-lab[-fixed]).
# Run: bash evals/laravel_test.sh
cd "$(dirname "$0")/.." || exit 1
ENG=rv-laravel-test
V=http://10.250.0.16:8000; F=http://10.250.0.17:8000
pass=0; fail=0
check() { if echo "$2" | grep -qE "$3"; then pass=$((pass+1)); echo "PASS  $1"; else fail=$((fail+1)); echo "FAIL  $1"; echo "$2" | head -5 | sed 's/^/      /'; fi; }
ctl() { docker compose exec -T kali-mcp python3 /opt/kali-mcp/rvctl.py --actor cli:laravel-test "$@"; }
py() { docker compose exec -T kali-mcp /opt/venv/bin/python3 -c "import sys, json; sys.path.insert(0, '/opt/kali-mcp'); import core; core.ACTOR = 'agent:laravel-test'; $1"; }
envget() { grep -E "^$1=" .env | head -1 | cut -d= -f2-; }
P="$(envget PROJECTS_DIR)"; P="${P/#\~/$HOME}"
E="$(envget ENGAGEMENTS_DIR)"; E="${E/#\~/$HOME}"
APP="$P/rv-laravel-lab"
cleanup() {
  ctl halt $ENG >/dev/null 2>&1 </dev/null; ctl delete $ENG --force >/dev/null 2>&1 </dev/null
  docker compose exec -T kali-mcp sh -c "rm -rf /work/_deleted-$ENG-*" </dev/null
  docker compose --profile lab restart lab-laravel >/dev/null 2>&1   # the test sent mail and wrote: reset it
}
trap cleanup EXIT

docker compose --profile lab ps lab-laravel lab-laravel-fixed --format '{{.State}}' | grep -qc running \
  || { echo "FAIL  the Laravel lab isn't running (./rvkit lab up)"; exit 1; }
[ -d "$APP" ] && [ -d "$P/rv-laravel-lab-fixed" ] || { echo "FAIL  run bash evals/ci_prepare.sh first"; exit 1; }
# the client's checkout includes vendor/ (the route export needs it); take the lab image's
[ -f "$APP/vendor/autoload.php" ] || docker run --rm --entrypoint tar riskvoid-lab-laravel:local -C /app -cf - vendor \
  | tar -C "$APP" -xf -
tree_hash() { (cd "$1" && find . -type f | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256 | cut -c1-64); }
BEFORE="$(tree_hash "$APP")"
./rvkit engagement $ENG --replace --tiers passive,active,intrusive /src/rv-laravel-lab /src/rv-laravel-lab-fixed $V $F \
  >/dev/null 2>&1 || { echo "FAIL  could not create $ENG"; exit 1; }

# ---------------------------------------------------------------- application map and build identity (RW-012)
r="$(ctl appmap $ENG /src/rv-laravel-lab --build-url $V/version </dev/null)"
check "map: framework and routes from the source"     "$r" 'Laravel 12\.[0-9.]+ .*routes from bootstrap/app.php'
check "map: build of the deployment matches"          "$r" 'MATCHES the source'
check "map: lead for the cross-tenant API read"       "$r" 'GET /api/invoices/\{invoice\} may return any Invoice'
check "map: lead for the protected-field assignment"  "$r" 'PATCH /api/profile assigns all request input to User .*is_platform_admin'
check "map: lead for the raw SQL"                     "$r" 'a query built from a variable .*SearchController@index'
check "map: lead for the unescaped notes"             "$r" 'invoice.blade.php'
check "map: tenant scope recognised as a control"     "$r" 'tenant-scope: GET /api/payments/\{payment\}: Payment has the global scope'
check "map: route can middleware recognised"          "$r" 'route-authorization: GET /exports/\{export\}/download: can:download,export'
check "map: no lead for the protected payment route"  "$(echo "$r" | grep -c 'payments/{payment} may return')" '^0$'
check "map: the Joern PHP gap is stated"              "$r" 'php2cpg\) needs a PHP binary'
MAP="$(echo "$r" | grep -o 'evidence/appmap/[^ ]*\.json' | head -1)"
check "map: saved as verified evidence"               "$(py "print(core.provenance('$ENG', ['$MAP'])[0]['status'])" </dev/null)" '^verified$'
r="$(ctl appmap $ENG /src/rv-laravel-lab-fixed --build-url $F/version </dev/null)"
check "fixed source: no leads, matches its deployment" "$r" 'Leads \(0\)'
check "fixed source: build matches"                   "$r" 'MATCHES the source'
check "wrong deployment: build mismatch reported"     "$(ctl appmap $ENG /src/rv-laravel-lab --build-url $F/version </dev/null)" 'DOES NOT MATCH the source'
check "map refuses a path outside the scope"          "$(ctl appmap $ENG /src/rv-demo-app 2>&1 </dev/null)" 'not in scope'

# ---------------------------------------------------------------- runtime evidence for the lead, and the fix
printf 'rvlab-carol-c04d17e9b3' | ctl cred $ENG set CAROL_TOKEN >/dev/null
printf 'rvlab-alice-7f3a9c41d2' | ctl cred $ENG set ALICE_TOKEN >/dev/null
ident() { printf '{"kind":"bearer","role":"%s","tenant":"%s","secret":"%s","hosts":["10.250.0.16","10.250.0.17"],"check":{"url":"%s/api/me","marker":"%s","accept":"application/json"},"tiers":["active","intrusive"],"effects":%s}' \
  "$2" "$3" "$4" "$V" "$5" "$6" | ctl identity $ENG set "$1" >/dev/null; }
ident carol-api admin globex CAROL_TOKEN carol@globex.test '["read"]'
ident alice-api admin acme ALICE_TOKEN alice@acme.test '["read","write"]'
check "identity valid"                                "$(ctl identity $ENG check carol-api </dev/null)" '"state": "valid"'
r="$(py "import actions; r = actions.send('$ENG', 'GET', '$V/api/invoices/1', {'Accept': 'application/json'}, b'', identity='carol-api'); print(r['status'], r['body'].decode()[:300])" </dev/null)"
check "runtime: Globex admin reads Acme invoice 1 (seeded flaw)" "$r" '^200 .*ACME-CONFIDENTIAL-1001'
r="$(py "import actions; r = actions.send('$ENG', 'GET', '$F/api/invoices/1', {'Accept': 'application/json'}, b'', identity='carol-api'); print(r['status'], r['body'].decode()[:300])" </dev/null)"
check "runtime: the fixed build refuses it"           "$r" '^(403|404) '
check "runtime: no marker from the fixed build"       "$(echo "$r" | grep -c ACME-CONFIDENTIAL)" '^0$'

# external effects stay in the lab: sending an invoice writes the mail to the lab's log
r="$(py "
h = {'Accept': 'application/json'}
import actions
a = actions.send('$ENG', 'POST', '$V/api/invoices/1/send', h, b'', identity='alice-api')['approval']
core.ACTOR = 'cli:laravel-test'; core.decide('$ENG', a, True); core.ACTOR = 'agent:laravel-test'
print(actions.send('$ENG', 'POST', '$V/api/invoices/1/send', h, b'', a, identity='alice-api')['status'])" </dev/null)"
check "approved state change sends the invoice"       "$r" '^200$'
sleep 1
check "the mail went to the lab's log, nowhere else"  "$(docker compose --profile lab exec -T lab-laravel grep -c 'billing@acme.test' storage/logs/laravel.log </dev/null)" '^[1-9]'

# ---------------------------------------------------------------- PHP profile (RW-013) and Semgrep
r="$(./rvkit php $ENG lint /src/rv-laravel-lab 2>&1 </dev/null)"
check "php lint: every file parses, nothing executed"  "$r" '[0-9]+ PHP files, 0 unparsable'
r="$(RVKIT_YES=1 ./rvkit php $ENG routes /src/rv-laravel-lab 2>&1 </dev/null)"
check "php routes: the application boots in isolation" "$r" '[0-9]+ routes \(Laravel Framework 12'
ROUTES="$(echo "$r" | grep -o 'evidence/php/routes-[0-9T]*\.json' | head -1)"
check "php outputs are verified evidence"             "$(py "print(core.provenance('$ENG', ['$ROUTES'])[0]['status'])" </dev/null)" '^verified$'
check "the boot was recorded as approved"             "$(ctl audit $ENG 50 </dev/null | grep php-profile)" 'approved_by'
r="$(ctl appmap $ENG /src/rv-laravel-lab --routes "$ROUTES" </dev/null)"
check "static and runtime routes agree"               "$r" 'runtime routes: 2[0-9] matched, [0-2] only at runtime, 0 only in the static map'
check "the PHP profile has no network"                "$(docker compose --profile php run --rm --no-deps --entrypoint php php-runner -r 'echo @file_get_contents("http://10.250.0.16:8000/version") === false ? "blocked" : "reached";' 2>/dev/null </dev/null)" '^blocked$'
check "a profile run outside the scope is refused"    "$(./rvkit php $ENG lint /src/rv-demo-app 2>&1 </dev/null)" 'not in scope'
r="$(py "import actions; print(actions.analyze_source('$ENG', 'semgrep', '/src/rv-laravel-lab', ['php']).splitlines()[0])" </dev/null)"
SG="$(echo "$r" | grep -o 'evidence/source/[^ ]*\.json')"
check "semgrep php rules ran offline"                 "$r" 'semgrep: [0-9]+ result'
check "semgrep parsed every PHP file"                 "$(docker compose exec -T kali-mcp python3 -c "import json; d = json.load(open('/work/$ENG/$SG')); print('errors', len(d['errors']), 'scanned', len(d['paths']['scanned']))" </dev/null)" '^errors 0 scanned [1-9]'

# ---------------------------------------------------------------- the client source is untouched
check "client source unchanged by the map, Semgrep and the PHP profile" "$(tree_hash "$APP")" "^$BEFORE\$"

echo
echo "laravel test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
