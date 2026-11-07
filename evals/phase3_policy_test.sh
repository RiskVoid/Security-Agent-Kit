#!/usr/bin/env bash
# Phase 3 regression test: scope enforcement, isolation, tiers, rate caps, approvals, halt.
# Needs engagements demo-code (scope /src/rv-demo-app, passive) and net-test (example.com, 1.1.1.1,
# all tiers, max rate 20). Calls kali-mcp over MCP from the worker container, like the agents do.
# Run: bash evals/phase3_policy_test.sh
cd "$(dirname "$0")/.." || exit 1
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
run() { mcp run "$(python3 -c 'import json,sys;print(json.dumps({"engagement":sys.argv[1],"command":sys.argv[2],"timeout_s":120,"approval_id":sys.argv[3] if len(sys.argv)>3 else ""}))' "$@")"; }
ctl() { docker compose exec -T kali-mcp python3 /opt/kali-mcp/rvctl.py "$@"; }
check() { # check <name> <expected-regex> <output>
  if echo "$3" | grep -qE "$2"; then pass=$((pass+1)); echo "PASS  $1"
  else fail=$((fail+1)); echo "FAIL  $1"; echo "$3" | head -5 | sed 's/^/      /'; fi
}

echo "== isolation (demo-code)"
check "only own engagement visible in /work"      '^demo-code$'                 "$(run demo-code 'ls /work')"
check "only in-scope code visible in /src"        '^rv-demo-app$'               "$(run demo-code 'ls /src')"
check "client code is read-only"                  'Read-only file system'       "$(run demo-code 'touch /src/rv-demo-app/x')"
check "SCOPE.md mirror is not writable"          'Read-only file system|Permission denied' "$(run demo-code 'echo "- 8.8.8.8" >> SCOPE.md')"
check "SCOPE.md unchanged"                        'exit=1'                      "$(run demo-code 'grep -q 8.8.8.8 SCOPE.md')"
check "control plane hidden"                      'exit=0'                      "$(run demo-code 'test -z "$(ls -A /control)"')"
check "runs unprivileged"                         'uid=2000[0-9]'               "$(run demo-code 'id')"
check "cannot change firewall"                    'Operation not permitted|denied' "$(run demo-code 'nft flush ruleset')"
check "own pid namespace (no server processes)"   '^0$'                         "$(run demo-code 'ps -eo args --no-headers | grep -cE "[p]ython3 .*server.py|[d]nsmasq"')"
check "git trusts client repos (history scans)"   'safe.directory=\*'           "$(run demo-code 'git config --list | grep safe.directory')"

echo "== tiers and pre-check false positives (demo-code: passive only)"
check "semgrep (passive) runs"                    'exit=0 tier=passive'         "$(run demo-code 'semgrep --config p/python --metrics=off -q /src/rv-demo-app/app.py --json -o semgrep.json; echo rc=$?')"
check "grep for a tool name is passive"           'tier=passive'                "$(run demo-code 'grep -ci sqlmap /src/rv-demo-app/app.py')"
check "python json.load is not a host"            'exit=0 tier=passive'         "$(run demo-code "python3 -c 'import json; print(json.loads(\"[1]\"))'")"
check "file names are not hosts"                  'tier=passive'                "$(run demo-code 'echo hi > semgrep_auto.err; cat semgrep_auto.err')"
check "active tool refused in passive engagement" "REFUSED: .*tier 'active'"    "$(run demo-code 'curl -s http://example.com')"
check "pip-audit reaches pypi/osv (infra)"        'PYSEC-|GHSA-|No known vulnerabilities' "$(run demo-code 'pip-audit -r /src/rv-demo-app/requirements.txt 2>&1 | tail -3')"
check "python can't reach out of scope (firewall)" 'BLOCKED'                    "$(run demo-code "python3 -c 'import urllib.request as u; u.urlopen(\"http://1.0.0.1\", timeout=5)' >/dev/null 2>&1 && echo REACHED || echo BLOCKED")"

echo "== network scope (net-test)"
check "in-scope domain reachable"                 'code=200'                    "$(run net-test 'curl -s -o /dev/null -m 10 -w code=%{http_code} http://example.com/')"
check "in-scope IP reachable"                     'code=30[0-9]'                "$(run net-test 'curl -s -o /dev/null -m 10 -w code=%{http_code} http://1.1.1.1/')"
check "out-of-scope IP refused by pre-check"      'REFUSED: targets not in scope' "$(run net-test 'curl -s -m 5 http://1.0.0.1/')"
check "out-of-scope IP blocked by firewall"       'BLOCKED'                     "$(run net-test "python3 -c 'import urllib.request as u; u.urlopen(\"http://1.0.0.1\", timeout=5)' >/dev/null 2>&1 && echo REACHED || echo BLOCKED")"
check "out-of-scope name does not resolve"        'NORESOLVE'                   "$(run net-test 'getent hosts github.io || echo NORESOLVE')"
check "internal services blocked (litellm)"       'BLOCKED'                     "$(run net-test 'curl -s -m 5 -o /dev/null http://litellm:4000/health && echo REACHED || echo BLOCKED')"
check "loopback services blocked (kali-mcp)"      'BLOCKED'                     "$(run net-test "python3 -c 'import urllib.request as u; u.urlopen(\"http://127.0.0.1:8090/mcp\", timeout=5)' >/dev/null 2>&1 && echo REACHED || echo BLOCKED")"

scope_of() { docker compose exec -T kali-mcp python3 -c 'import sys,json; sys.path.insert(0,"/opt/kali-mcp"); import core
print(json.dumps(core.parse_scope(sys.argv[1])["nets"]))' "$1"; }
check "CIDR scope keeps its prefix"               '"203.0.113.0/28", "10.0.0.0/24"' "$(scope_of $'- 203.0.113.0/28\n- 10.0.0.5/24')"
check "URL scope keeps only the host"             '"10.250.0.10/32"'            "$(scope_of '- http://10.250.0.10:3000/login')"

echo "== rate caps (net-test: max 20/s)"
check "rate flag injected"                        'rate limit applied: ffuf -rate 20'  "$(run net-test 'ffuf -V')"
check "higher explicit rate refused"              'exceeds the engagement max rate' "$(run net-test 'nmap -sS -p 80 1.1.1.1 --max-rate 1000')"

echo "== approvals (net-test)"
out="$(run net-test 'sqlmap --version')"
check "intrusive needs approval"                  'APPROVAL REQUIRED'           "$out"
aid="$(echo "$out" | grep -oE 'Approval id: [a-f0-9]{8}' | awk '{print $3}')"
check "unapproved id refused"                     'is pending'                  "$(run net-test 'sqlmap --version' "$aid")"
ctl approve net-test "$aid" >/dev/null
check "different command refused"                 'different command'           "$(run net-test 'sqlmap --help' "$aid")"
check "approved command runs"                     'exit=0 tier=intrusive'       "$(run net-test 'sqlmap --version' "$aid")"
check "approval is single-use"                    'is used'                     "$(run net-test 'sqlmap --version' "$aid")"

echo "== halt (net-test)"
( run net-test 'sleep 60; echo FINISHED' > /tmp/rv-halt-test.out ) &
sleep 4; ctl halt net-test >/dev/null; wait
check "halt kills running command"                '^exit=-?(9|137|1)\b|exit=-9' "$(cat /tmp/rv-halt-test.out)"
check "halted engagement refuses commands"        'halted'                      "$(run net-test 'echo hi')"
ctl resume net-test >/dev/null
check "resume allows commands again"              'exit=0'                      "$(run net-test 'echo hi')"

echo "== engagement lifecycle (rv-del-test)"
./rvkit engagement rv-del-test 198.51.100.7 >/dev/null 2>&1
check "existing engagement not silently replaced" 'exists'                      "$(./rvkit engagement rv-del-test 198.51.100.8 2>&1)"
check "scope unchanged after refusal"             '198.51.100.7/32'            "$(ctl show rv-del-test)"
./rvkit engagement rv-del-test --replace 198.51.100.8 >/dev/null 2>&1
check "--replace applies the new scope"           '198.51.100.8/32'            "$(ctl show rv-del-test)"
check "delete refuses an open engagement"         'not closed'                  "$(ctl delete rv-del-test 2>&1)"
ctl close rv-del-test >/dev/null 2>&1
check "delete a closed engagement"                'deleted'                     "$(ctl delete rv-del-test 2>&1)"
check "deleted engagement unregistered"           'unknown engagement'          "$(run rv-del-test 'echo hi')"
check "deletion is audited"                       '"event": "deleted"'          "$(ctl audit rv-del-test 5)"
docker compose exec -T kali-mcp sh -c 'rm -rf /work/_deleted-rv-del-test-* /work/_archive/rv-del-test-*' </dev/null

echo "== audit"
check "audit log records refusals and approvals"  'approval-approved'           "$(ctl audit net-test 50)"
echo; echo "passed $pass, failed $fail"; [ "$fail" -eq 0 ]
