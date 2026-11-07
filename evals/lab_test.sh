#!/usr/bin/env bash
# Lab isolation test (needs ./rvkit lab up):
#  - an engagement with a lab target in scope reaches it; only that target
#  - engagements without the lab in scope can't reach it
#  - lab targets have no internet and can't reach the kit's services
#  - DVWA is initialised (login works)
# Run: bash evals/lab_test.sh
cd "$(dirname "$0")/.." || exit 1
pass=0; fail=0
ok()  { pass=$((pass+1)); echo "PASS  $1"; }
bad() { fail=$((fail+1)); echo "FAIL  $1"; [ -n "${2:-}" ] && echo "$2" | head -4 | sed 's/^/      /'; }
check() { if echo "$2" | grep -qE "$3"; then ok "$1"; else bad "$1" "$2"; fi; }

kali() { # kali <engagement> <command>
  docker compose exec -T worker-mcp python3 -c '
import asyncio, sys
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
async def go():
    async with streamablehttp_client("http://kali-mcp:8090/mcp") as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool("run", {"engagement": sys.argv[1], "command": sys.argv[2], "timeout_s": 120})
            print("\n".join(c.text for c in res.content if getattr(c, "text", None)))
asyncio.run(go())' "$1" "$2" </dev/null 2>/dev/null
}
code() { kali "$1" "curl -s -o /dev/null -m 8 -w 'HTTP=%{http_code}' $2"; }

docker compose --profile lab ps lab-juice-shop --format '{{.State}}' | grep -q running || { echo "lab not running: ./rvkit lab up"; exit 1; }
./rvkit engagement lab-juice --replace 10.250.0.10 >/dev/null 2>&1
./rvkit engagement lab-dvwa --replace 10.250.0.11 >/dev/null 2>&1

check "in-scope engagement reaches Juice Shop"       "$(code lab-juice http://10.250.0.10:3000/)" 'HTTP=200'
# python is not a network tool, so the pre-check doesn't look at it: these test the firewall itself
fw() { kali "$1" "python3 -c \"import socket; s=socket.socket(); s.settimeout(4); print('OPEN' if s.connect_ex(('$2', $3)) == 0 else 'CLOSED')\""; }
check "firewall: Juice Shop engagement reaches Juice Shop" "$(fw lab-juice 10.250.0.10 3000)" 'OPEN'
check "firewall: Juice Shop engagement can't reach DVWA"   "$(fw lab-juice 10.250.0.11 80)" 'CLOSED'
check "firewall: Juice Shop engagement can't reach the DB" "$(fw lab-juice 10.250.0.12 3306)" 'CLOSED'
check "firewall: unrelated engagement can't reach the lab" "$(fw demo-code 10.250.0.10 3000)" 'CLOSED'
check "pre-check refuses out-of-scope lab host"            "$(code lab-juice http://10.250.0.11/)" 'REFUSED'
check "pre-check ignores URL paths (login.php)"            "$(code lab-dvwa http://10.250.0.11/login.php)" 'HTTP=200'
check "net-test (other scope) can't reach the lab"   "$(code net-test http://10.250.0.10:3000/)" 'HTTP=000|REFUSED'
check "lab engagement still can't reach LiteLLM"     "$(code lab-juice http://litellm:4000/)" 'HTTP=000'

# a container on the lab network, like a target, must not reach the internet or the kit
LABNET="$(docker network ls --format '{{.Name}}' | grep -E '_rvlab$' | head -1)"
probe() { docker run --rm --network "$LABNET" busybox:1.37.0 sh -c "wget -q -T 4 -O /dev/null $1 && echo REACHED || echo BLOCKED" 2>&1 | tail -1; }
check "lab network has no internet"                  "$(probe https://example.com)" 'BLOCKED'
check "lab network can't reach the kit's services"   "$(probe http://litellm:4000/)" 'BLOCKED'

# API, GraphQL and LLM targets (new in Phase 6b)
./rvkit engagement lab-api --replace 10.250.0.13 10.250.0.14 >/dev/null 2>&1
./rvkit engagement lab-llm --replace 10.250.0.15 >/dev/null 2>&1
check "VAmPI answers (users from /createdb)"         "$(kali lab-api 'curl -s -m 8 http://10.250.0.13:5000/users/v1')" '"username"'
check "DVGA GraphQL answers"                         "$(kali lab-api "curl -s -m 20 http://10.250.0.14:5013/graphql -H 'Content-Type: application/json' -d '{\"query\":\"{ __typename }\"}'")" '__typename'
check "LLM lab chat answers"                         "$(kali lab-llm "curl -s -m 8 http://10.250.0.15:8000/api/chat -H 'Content-Type: application/json' -d '{\"message\":\"hi\"}'")" 'Ava'
check "firewall: API engagement can't reach the LLM lab" "$(fw lab-api 10.250.0.15 8000)" 'CLOSED'
check "rv-llm mcp audit flags no-auth + tool poisoning"  "$(kali lab-llm 'rv-llm mcp http://10.250.0.15:8000/mcp --out mcp.json')" 'hidden-instruction tag'
check "rv-llm probe needs approval (intrusive)"      "$(kali lab-llm 'rv-llm probe --http http://10.250.0.15:8000/api/chat --suite leak')" 'APPROVAL REQUIRED|REFUSED: this command is tier .intrusive'

login="$(kali lab-dvwa 'c=/tmp/c; t=$(curl -s -c $c -b $c http://10.250.0.11/login.php | sed -n "s/.*user_token. value=.\([a-f0-9]*\).*/\1/p" | head -1); curl -s -c $c -b $c -o /dev/null -w "%{redirect_url}" -d "username=admin&password=password&Login=Login&user_token=$t" http://10.250.0.11/login.php')"
check "DVWA initialised (admin login redirects to index)" "$login" 'index.php'

echo; echo "passed $pass, failed $fail"; [ "$fail" -eq 0 ]
