#!/usr/bin/env bash
# RiskVoid Console: sign-in, host check, CSRF header, read API, path checks. Needs the stack up (./rvkit up).
# Run: bash evals/console_test.sh
cd "$(dirname "$0")/.." || exit 1
pass=0; fail=0
check() { if echo "$2" | grep -qE "$3"; then pass=$((pass+1)); echo "PASS  $1"; else fail=$((fail+1)); echo "FAIL  $1"; echo "$2" | head -3 | sed 's/^/      /'; fi; }
PORT=18100; B="http://127.0.0.1:$PORT"; JAR="$(mktemp)"
CONSOLE_PORT=$PORT python3 scripts/console.py >/dev/null 2>&1 & pid=$!
trap 'kill $pid 2>/dev/null; rm -f "$JAR"' EXIT
for _ in $(seq 1 20); do curl -s -o /dev/null "$B/" && break; sleep 0.3; done
T="$(cat .rvkit/console.token)"
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
check "page needs sign-in"                "$(code "$B/")" '^401$'
check "wrong token refused"               "$(code "$B/login?t=nope")" '^403$'
check "foreign Host header refused"       "$(code -H "Host: attacker.example:$PORT" "$B/")" '^403$'
check "sign-in sets the session cookie"   "$(curl -s -c "$JAR" -D - -o /dev/null "$B/login?t=$T")" 'rvc=.*HttpOnly; SameSite=Strict'
check "page loads when signed in"         "$(curl -s -b "$JAR" "$B/")" 'RiskVoid Console'
check "overview lists engagements"        "$(curl -s -b "$JAR" "$B/api/overview")" '"engagement": "demo-code"'
check "engagement detail"                 "$(curl -s -b "$JAR" "$B/api/eng/demo-code")" '"scope_text"'
check "POST without console header refused" "$(code -b "$JAR" -X POST -d '{}' "$B/api/eng/demo-code/halt")" '^401$'
check "POST without cookie refused"       "$(code -H 'X-RV-Console: 1' -X POST -d '{}' "$B/api/eng/demo-code/halt")" '^401$'
check "bad engagement name refused"       "$(code -b "$JAR" "$B/api/eng/..%2Fetc")" '^400$'
check "only report files are served"      "$(code -b "$JAR" "$B/files/demo-code/findings.db")" '^404$'
check "preview writes nothing"            "$(curl -s -b "$JAR" -H 'X-RV-Console: 1' -H 'Content-Type: application/json' -X POST \
  -d '{"scope": "- /src/rv-demo-app\n- 198.51.100.99\n", "rules": "- Allowed tiers: passive\n"}' "$B/api/eng/demo-code/preview")" '198.51.100.99/32'
check "scope still has no preview entry"  "$(./rvkit show demo-code | grep -c 198.51.100.99)" '^0$'
echo; echo "passed $pass, failed $fail"; [ "$fail" -eq 0 ]
