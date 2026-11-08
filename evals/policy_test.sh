#!/usr/bin/env bash
# Policy revisions (RW-004) and action limits (RW-005) against the running stack, with real DNS and the firewall.
# Creates the throwaway engagement rv-pol-test (online: example.com, iana.org, example.net, 1.1.1.1), runs
# commands through kali-mcp over MCP like the agents do, then deletes it.
# Run: bash evals/policy_test.sh
cd "$(dirname "$0")/.." || exit 1
ENG=rv-pol-test
pass=0; fail=0

mcp() { # mcp <tool> <json-args>
  docker compose exec -T worker-mcp python3 -c '
import asyncio, json, sys
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
async def go():
    async with streamablehttp_client("http://kali-mcp:8090/mcp") as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool(sys.argv[1], json.loads(sys.argv[2]))
            print("\n".join(c.text for c in res.content if getattr(c, "text", None)))
asyncio.run(go())' "$1" "$2" 2>/dev/null
}
j() { python3 -c 'import json,sys; a=sys.argv[1:]; print(json.dumps(dict(zip(a[::2], a[1::2]))))' "$@"; }
run() { mcp run "$(python3 -c 'import json,sys; print(json.dumps({"engagement": sys.argv[1], "command": sys.argv[2], "timeout_s": 60, "approval_id": sys.argv[3]}))' "$ENG" "$1" "${2:-}")"; }
ctl() { docker compose exec -T kali-mcp python3 /opt/kali-mcp/rvctl.py --actor cli:policy-test "$@"; }
check() { # check <name> <expected-regex> <output>
  if echo "$3" | grep -qE -- "$2"; then pass=$((pass+1)); echo "PASS  $1"
  else fail=$((fail+1)); echo "FAIL  $1"; echo "$3" | head -6 | sed 's/^/      /'; fi
}
setscope() { # setscope <scope-text> <rules-text>: apply through rvctl like the console does
  python3 -c 'import json,sys; print(json.dumps({"scope": sys.argv[1], "rules": sys.argv[2]}))' "$1" "$2" \
    | ctl sync "$ENG" --yes --stdin 2>&1
}
resolves() { run "getent hosts $1 >/dev/null && echo RESOLVES || echo NORESOLVE"; }
reach() { run "curl -s -o /dev/null -m 8 -w code=%{http_code} $1 || echo BLOCKED"; }

DIR="$(grep -E '^ENGAGEMENTS_DIR=' .env | cut -d= -f2- | sed "s|^~|$HOME|")"
ctl halt "$ENG" >/dev/null 2>&1; ctl close "$ENG" >/dev/null 2>&1; ctl delete "$ENG" --force >/dev/null 2>&1
rm -rf "$DIR/$ENG" "$DIR"/_deleted-"$ENG"-* 2>/dev/null
mkdir -p "$DIR/$ENG"; : > "$DIR/$ENG/SCOPE.md"

SCOPE='- example.com
- *.iana.org:443
- !data.iana.org
- 1.1.1.1:443
- https://example.net/api/'
RULES='- Allowed tiers: passive, active
- Max rate: 50'

echo "== activation"
check "invalid lines refuse activation"           'not applied, fix these lines' "$(setscope $'- example.com\n- ::1\n- what is this' '')"
check "same name, wildcard with other ports"      'need the same ports'          "$(setscope $'- iana.org\n- *.iana.org:443' '')"
check "unknown rule refuses activation"           'unknown rule'                 "$(setscope '- example.com' '- Speed: fast')"
check "valid policy applies"                      'applied'                      "$(setscope "$SCOPE" "$RULES")"
pol="$(ctl policy "$ENG" --json)"
check "policy revision recorded with actor"       '"actor": "cli:policy-test"'       "$pol"
check "limits name the request-tool-only host"    'example.net: path limits'     "$pol"

echo "== names (exact, wildcard, exclusion, request-tool-only)"
check "exact host resolves"                       'RESOLVES'                     "$(resolves example.com)"
check "subdomain of an exact host doesn't"        'NORESOLVE'                    "$(resolves www.example.com)"
check "wildcard covers a subdomain"               'RESOLVES'                     "$(resolves www.iana.org)"
check "wildcard doesn't cover the apex"           'NORESOLVE'                    "$(resolves iana.org)"
check "excluded name doesn't resolve"             'NORESOLVE'                    "$(resolves data.iana.org)"
check "path-limited host doesn't resolve for run" 'NORESOLVE'                    "$(resolves example.net)"
check "excluded name refused before running"      'targets not in scope'         "$(run 'curl -s https://data.iana.org/')"
check "path-limited host refused for run"         'targets not in scope'         "$(run 'curl -s https://example.net/api/')"

echo "== ports"
check "allowed port reachable"                    'code=[23]'                    "$(reach https://1.1.1.1/)"
check "other port blocked by the firewall"        'code=000|BLOCKED'             "$(reach http://1.1.1.1/)"
check "wildcard host on its port"                 'code=[23]'                    "$(reach https://www.iana.org/)"
check "wildcard host, other port blocked"         'code=000|BLOCKED'             "$(reach http://www.iana.org/)"

echo "== time rules"
check "outside the dates refused"                 'testing ended on 2020-01-02' \
  "$(setscope "$SCOPE" "$RULES"$'\n- Dates: 2020-01-01 to 2020-01-02' >/dev/null; run 'echo hi')"
check "outside the days refused"                  'allowed on .* only' \
  "$(setscope "$SCOPE" "$RULES"$'\n- Days: '"$(python3 -c 'import datetime as d; print(["mon","tue","wed","thu","fri","sat","sun"][(d.datetime.now(d.timezone(d.timedelta(hours=14))).weekday()+2)%7])')"$'\n- Timezone: Pacific/Kiritimati' >/dev/null; run 'echo hi')"
setscope "$SCOPE" "$RULES" >/dev/null
check "back inside: runs"                         'exit=0'                       "$(run 'echo hi')"

if [ -f evals/policy_test_rw005.sh ]; then . evals/policy_test_rw005.sh; fi

ctl halt "$ENG" >/dev/null 2>&1; ctl close "$ENG" >/dev/null 2>&1; ctl delete "$ENG" --force >/dev/null 2>&1
rm -rf "$DIR/$ENG" "$DIR"/_deleted-"$ENG"-* "$DIR"/_archive/"$ENG"* 2>/dev/null
echo; echo "policy test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
