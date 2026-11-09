#!/usr/bin/env bash
# Authenticated request and browser work (RW-008 to RW-011) against the Laravel lab (Ledgerly: ./rvkit lab up),
# with no model. A throwaway engagement is created and deleted afterwards.
#   Identities: credentials encrypted in the vault, a form login with CSRF and bearer tokens, the valid-session
#     control (valid, expired after the credential changes, revoked), purpose limits; no secret in plain text in
#     the control files, the audit log, evidence or results.
#   Captures: a HAR is sanitized (cookies, tokens, secret fields), the raw original stays encrypted and host-only,
#     out-of-scope requests can't be replayed, a replay as another tenant's identity shows the cross-tenant read.
#   Browser: runs in the sandbox, signed in; out-of-scope assets and state-changing script requests are blocked
#     in a read-only run; steps outside the scope are refused.
#   Approvals name the identity: an approval for one identity doesn't let another identity send the request.
#   Authorization matrix: proposed by the agent, approved by the researcher (bound to its digest and the policy
#     revision); shows the seeded cross-tenant flaw, passes the protected payment and the fixed build, reports
#     cells of an identity that isn't valid as blocked.
# Run: ./rvkit lab up && bash evals/authn_test.sh
cd "$(dirname "$0")/.." || exit 1
ENG=rv-authn-test
V=http://10.250.0.16:8000; F=http://10.250.0.17:8000
pass=0; fail=0
check() { if echo "$2" | grep -qE "$3"; then pass=$((pass+1)); echo "PASS  $1"; else fail=$((fail+1)); echo "FAIL  $1"; echo "$2" | head -5 | sed 's/^/      /'; fi; }
ctl() { docker compose exec -T kali-mcp python3 /opt/kali-mcp/rvctl.py --actor cli:authn-test "$@"; }
py() { docker compose exec -T kali-mcp /opt/venv/bin/python3 -c "import sys; sys.path.insert(0, '/opt/kali-mcp'); import core; core.ACTOR = 'agent:authn-test'; $1"; }
TMP="$(mktemp -d)"
cleanup() {
  ctl halt $ENG >/dev/null 2>&1 </dev/null; ctl delete $ENG --force >/dev/null 2>&1 </dev/null
  docker compose exec -T kali-mcp sh -c "rm -rf /work/_deleted-$ENG-*" </dev/null
  docker compose --profile lab restart lab-laravel >/dev/null 2>&1   # the test wrote to the lab: reset it
  rm -rf "${TMP:?}"
}
trap cleanup EXIT

docker compose --profile lab ps lab-laravel lab-laravel-fixed --format '{{.State}}' | grep -qc running \
  || { echo "FAIL  the Laravel lab isn't running (./rvkit lab up)"; exit 1; }
./rvkit engagement $ENG --replace --tiers passive,active,intrusive $V $F >/dev/null 2>&1 \
  || { echo "FAIL  could not create $ENG"; exit 1; }

# ---------------------------------------------------------------- identities (RW-008)
printf 'alice-lab-pass' | ctl cred $ENG set ALICE_PASS >/dev/null
printf 'rvlab-alice-7f3a9c41d2' | ctl cred $ENG set ALICE_TOKEN >/dev/null
printf 'rvlab-bob-2b8e41a6f0' | ctl cred $ENG set BOB_TOKEN >/dev/null
printf 'rvlab-carol-c04d17e9b3' | ctl cred $ENG set CAROL_TOKEN >/dev/null
api() { # api <name> <secret> <role> <tenant> <email> <effects>
  printf '{"kind":"bearer","role":"%s","tenant":"%s","secret":"%s","hosts":["10.250.0.16","10.250.0.17"],"check":{"url":"%s/api/me","marker":"%s","accept":"application/json"},"tiers":["active","intrusive"],"effects":%s}' \
    "$3" "$4" "$2" "$V" "$5" "$6" | ctl identity $ENG set "$1" >/dev/null; }
printf '{"kind":"form","role":"admin","tenant":"acme","login_url":"%s/login","username":"alice@acme.test","secret":"ALICE_PASS","check":{"url":"%s/dashboard","marker":"ACME-INV-1001"},"fixtures":[{"kind":"invoice","id":1,"marker":"ACME-CONFIDENTIAL-1001"}],"tiers":["active","intrusive"]}' "$V" "$V" \
  | ctl identity $ENG set alice-web >/dev/null
api alice-api ALICE_TOKEN admin acme alice@acme.test '["read","write"]'
api bob-api BOB_TOKEN member acme bob@acme.test '["read","write"]'
api carol-api CAROL_TOKEN admin globex carol@globex.test '["read"]'
check "form login with CSRF: valid"            "$(ctl identity $ENG check alice-web </dev/null)" '"state": "valid"'
check "bearer identity: valid"                 "$(ctl identity $ENG check carol-api </dev/null)" '"state": "valid"'
check "bad spec refused (login URL out of scope)" "$(echo '{"kind":"form","login_url":"http://10.250.0.15:8000/login","username":"x","secret":"ALICE_PASS","check":{"url":"http://10.250.0.15:8000/"}}' | ctl identity $ENG set evil 2>&1)" 'not in scope'
check "unknown credential refused"             "$(echo '{"kind":"bearer","secret":"NOPE","check":{"url":"'$V'/api/me"}}' | ctl identity $ENG set nope 2>&1)" 'no credential NOPE'
check "purpose limit: read-only identity can't send a write" \
      "$(py "import actions; print(actions.send('$ENG', 'PATCH', '$V/api/settings', {}, b'{}', identity='carol-api')['text'])" </dev/null)" \
      'may be used for read actions only'
check "identity hosts: session not usable elsewhere" \
      "$(py "import actions; print(actions.send('$ENG', 'GET', '$F/api/me', {}, b'', identity='alice-web')['text'])" </dev/null)" \
      'only for 10.250.0.16'
r="$(py "import actions; r = actions.send('$ENG', 'GET', '$V/api/me', {'Accept': 'application/json'}, b'', identity='bob-api'); print(r['text'])" </dev/null)"
check "request as an identity"                 "$r" 'bob@acme.test'
check "the session token is not in the result" "$(echo "$r" | grep -c rvlab-bob)" '^0$'

# ---------------------------------------------------------------- approvals name the identity
r="$(py "
import actions, json
b = json.dumps({'notes': 'ACME-CONFIDENTIAL-1002 <img src=\"http://10.250.0.15:8000/pixel.png\"><script>fetch(\"/api/profile\",{method:\"PATCH\"})</script>'}).encode()
h = {'Content-Type': 'application/json', 'Accept': 'application/json'}
a = actions.send('$ENG', 'PUT', '$V/api/invoices/2', h, b, identity='alice-api')['approval']
core.ACTOR = 'cli:authn-test'; core.decide('$ENG', a, True); core.ACTOR = 'agent:authn-test'
print('other:', actions.send('$ENG', 'PUT', '$V/api/invoices/2', h, b, a, identity='bob-api').get('refused'))
print('same:', actions.send('$ENG', 'PUT', '$V/api/invoices/2', h, b, a, identity='alice-api')['status'])
print('again:', actions.send('$ENG', 'PUT', '$V/api/invoices/2', h, b, a, identity='alice-api').get('refused'))
" </dev/null)"
check "approval for alice doesn't cover bob"    "$r" 'other: approval was for a different action \(identity'
check "approved write as the named identity"   "$r" 'same: 200'
check "the approval is used once"              "$r" 'again: .*(used|already)'

# ---------------------------------------------------------------- browser (RW-010)
r="$(py "import actions; print(actions.browse('$ENG', '$V/invoices/2', [{'text': 'h1'}], identity='alice-web'))" </dev/null)"
check "browser signed in through the sandbox"  "$r" 'ACME-INV-1002'
check "browser: out-of-scope asset blocked"    "$r" 'pixel.png: 10.250.0.15 is not in scope'
check "browser: script write blocked (read-only run)" "$r" 'PATCH can change state and this run is read-only'
check "browser: evidence saved"                "$r" 'screenshot.png'
check "browser: goto outside scope refused"    "$(py "import actions; print(actions.browse('$ENG', '$V/dashboard', [{'goto': 'http://10.250.0.15:8000/'}]))" </dev/null)" \
      'REFUSED: step goto .* not in scope'
check "browser: click needs approval"          "$(py "import actions; print(actions.browse('$ENG', '$V/dashboard', [{'click': 'button'}]))" </dev/null)" \
      'APPROVAL REQUIRED'
check "browser: read-only identity can't click" "$(py "import actions; print(actions.browse('$ENG', '$V/dashboard', [{'click': 'button'}], identity='alice-web'))" </dev/null)" \
      'may be used for read actions only'

# ---------------------------------------------------------------- captures (RW-009)
cat > "$TMP/cap.har" <<EOF
{"log":{"version":"1.2","entries":[
{"startedDateTime":"2026-11-08T10:00:00Z","request":{"method":"GET","url":"$V/api/invoices/1?api_key=abc123def456&page=1","headers":[{"name":"Authorization","value":"Bearer rvlab-bob-2b8e41a6f0"},{"name":"Cookie","value":"laravel_session=sess-9f8e7d6c5b4a; theme=dark"},{"name":"Accept","value":"application/json"}]},"response":{"status":200,"headers":[{"name":"Set-Cookie","value":"laravel_session=abcdefabcdef; path=/"}],"content":{"mimeType":"application/json","size":120,"text":"{\"id\":1,\"notes\":\"ACME-CONFIDENTIAL-1001\",\"access_token\":\"tok-should-go\"}"}}},
{"startedDateTime":"2026-11-08T10:00:01Z","request":{"method":"POST","url":"https://example.com/collect","headers":[],"postData":{"mimeType":"application/x-www-form-urlencoded","text":"user=bob&password=hunter22"}},"response":{"status":204,"headers":[],"content":{"size":0}}}
]}}
EOF
CID="$(ctl capture $ENG import --name test < "$TMP/cap.har" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
check "capture imported"                       "$CID" '^[0-9]{14}-[0-9a-f]{6}$'
check "sanitized copy holds no secret"         "$(docker compose exec -T kali-mcp sh -c "grep -c 'rvlab-bob\|hunter22\|abc123def456\|tok-should-go\|sess-9f8e7d6c5b4a' /work/$ENG/captures/$CID.json" </dev/null)" '^0$'
check "raw original kept, host only"           "$(ctl capture $ENG raw "$CID" </dev/null | grep -c hunter22)" '^1$'
check "raw original encrypted at rest"         "$(docker compose exec -T kali-mcp sh -c "grep -c hunter22 /control/eng/$ENG/captures/$CID.raw" </dev/null)" '^0$'
check "out-of-scope request not replayable"    "$(echo '{"entry":2}' | ctl capture $ENG replay "$CID" 2>&1)" 'outside the scope'
r="$(echo '{"entry":1,"identity":"carol-api","markers":["ACME-CONFIDENTIAL-1001"]}' | ctl capture $ENG replay "$CID")"
check "replay as another tenant: cross-tenant read shown" "$r" "marker 'ACME-CONFIDENTIAL-1001': captured yes, replayed yes"

# ---------------------------------------------------------------- authorization matrix (RW-011)
py "
import authz
ops = [{'id': 'invoice-1', 'method': 'GET', 'url': '$V/api/invoices/1', 'marker': 'ACME-CONFIDENTIAL-1001'},
       {'id': 'payment-1', 'method': 'GET', 'url': '$V/api/payments/1', 'marker': 'ACME-PAY-5001'},
       {'id': 'fixed-invoice-1', 'method': 'GET', 'url': '$F/api/invoices/1', 'marker': 'ACME-CONFIDENTIAL-1001'}]
who = ['bob-api', 'carol-api', 'anonymous']
authz.propose('$ENG', 'tenants', {'operations': ops, 'identities': who,
              'expect': {o['id']: {'bob-api': 'allow', 'carol-api': 'deny', 'anonymous': 'deny'} for o in ops}})
" </dev/null >/dev/null
check "matrix can't run before approval"       "$(ctl authz $ENG run tenants 2>&1 </dev/null)" 'not approved'
check "writes need allow_writes and cleanup"   "$(py "import authz; authz.propose('$ENG', 'w', {'operations': [{'id': 'p', 'method': 'PATCH', 'url': '$V/api/profile'}], 'identities': ['bob-api'], 'expect': {'p': {'bob-api': 'allow'}}})" 2>&1 </dev/null)" \
      'allow_writes'
ctl authz $ENG approve tenants </dev/null >/dev/null
r="$(ctl authz $ENG run tenants </dev/null)"
check "seeded cross-tenant flaw: FAIL"         "$r" 'invoice-1 +carol-api +expected deny  -> allowed +FAIL'
check "protected payment: pass (404)"          "$r" 'payment-1 +carol-api +expected deny  -> denied +pass +HTTP 404'
check "fixed build: pass"                      "$r" 'fixed-invoice-1 +carol-api +expected deny  -> denied +pass'
check "anonymous denied (401)"                 "$r" 'invoice-1 +anonymous .*denied +pass +HTTP 401'
docker compose exec -T kali-mcp sh -c "sed -i 's/\"carol-api\": \"deny\"/\"carol-api\": \"allow\"/' /work/$ENG/authz/tenants.json" </dev/null
check "a matrix changed after approval is refused" "$(ctl authz $ENG run tenants 2>&1 </dev/null)" 'changed since it was approved'
docker compose exec -T kali-mcp sh -c "sed -i 's/\"carol-api\": \"allow\"/\"carol-api\": \"deny\"/' /work/$ENG/authz/tenants.json" </dev/null
printf 'rvlab-carol-wrong-token' | ctl cred $ENG set CAROL_TOKEN >/dev/null
check "valid-session control: expired"         "$(ctl identity $ENG check carol-api </dev/null)" '"state": "expired"'
r="$(ctl authz $ENG run tenants </dev/null)"
check "cells of an invalid identity are blocked, not denied" "$r" 'carol-api +expected deny  -> blocked +blocked'
check "no FAIL claimed without a valid session" "$r" 'FAIL 0'

# ---------------------------------------------------------------- secrets stay in the vault
leaks="$(docker compose exec -T kali-mcp sh -c "grep -rl 'alice-lab-pass\|rvlab-alice-7f3a9c41d2\|rvlab-bob-2b8e41a6f0\|rvlab-carol-c04d17e9b3' /control/eng/$ENG /control/audit.log /work/$ENG 2>/dev/null | grep -v '/captures/.*\.raw$' | wc -l" </dev/null)"
check "no secret in plain text (control files, audit log, evidence)" "$leaks" '^ *0$'
check "vault key is root-only"                 "$(docker compose exec -T kali-mcp stat -c %a /control/vault.key </dev/null)" '^600$'

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
