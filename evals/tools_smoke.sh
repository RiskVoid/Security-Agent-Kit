#!/usr/bin/env bash
# Phase 4 tool smoke test.
#  1. every tool in the Kali image starts (version check, as root, no policy involved)
#  2. passive code/supply-chain tools work through the sandbox on the demo-code engagement, like agents call them
# Run: bash evals/tools_smoke.sh
cd "$(dirname "$0")/.." || exit 1
pass=0; fail=0
ok()  { pass=$((pass+1)); echo "PASS  $1"; }
bad() { fail=$((fail+1)); echo "FAIL  $1"; [ -n "${2:-}" ] && echo "$2" | head -4 | sed 's/^/      /'; }

echo "== 1. tools start"
while IFS='|' read -r name cmd; do
  out="$(docker compose exec -T kali-mcp bash -c "$cmd" </dev/null 2>&1 | head -c 2000)"
  # a version number, or a "dev" build string for Kali's builds of gitleaks/trufflehog/trivy
  if echo "$out" | grep -qE '[0-9]+\.[0-9]+|\bdev\b|set by build'; then ok "$name"; else bad "$name" "$out"; fi
done <<'EOF'
nmap|nmap --version
naabu|naabu -version 2>&1
dnsx|dnsx -version 2>&1
subfinder|subfinder -version 2>&1
amass|amass -version 2>&1
katana|katana -version 2>&1
httpx-toolkit|httpx-toolkit -version 2>&1
whatweb|whatweb --version
gowitness|gowitness version 2>&1
nuclei|nuclei -version 2>&1
nuclei templates|ls /opt/nuclei-templates | wc -l | sed 's/$/.0 entries/'
nikto|nikto -Version 2>&1
ffuf|ffuf -V
arjun|arjun --help 2>&1 | head -1; dpkg -s arjun | grep Version
dalfox|dalfox version 2>&1
zaproxy|dpkg -s zaproxy | grep Version
sqlmap|sqlmap --version
testssl|testssl --version 2>&1 | grep -m1 -iE 'version|[0-9]+\.[0-9]+'
sslscan|sslscan --version
semgrep|/opt/venv/bin/semgrep --version
joern|ls /opt/joern-cli/lib | grep -m1 -oE "joern-cli-[0-9.]+[0-9]"
semgrep offline rules|ls /opt/semgrep-rules | wc -l | sed 's/$/.0 dirs/'
bandit|/opt/venv/bin/bandit --version
gitleaks|gitleaks version
feroxbuster|feroxbuster --version
gobuster|dpkg -s gobuster | grep Version
wafw00f|dpkg -s wafw00f | grep Version
wpscan|dpkg -s wpscan | grep Version
crlfuzz|dpkg -s crlfuzz | grep Version
commix|dpkg -s commix | grep Version
schemathesis|schemathesis --version
clairvoyance|/opt/apitools/bin/pip show clairvoyance | grep Version
jwt_tool|jwt_tool eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWxpY2UiLCJpYXQiOjE3MDAwMDAwMDB9.x 2>&1 | grep -m1 -oE 'Version [0-9.]+|v[0-9]+\.[0-9.]+'
graphql-cop|graphql-cop -v 2>&1
graphw00f|graphw00f --version 2>&1 | grep -m1 -oE '[0-9]+\.[0-9.]+'
rv-llm|rv-llm list | wc -l | sed 's/$/.0 probes/'
garak|garak --version 2>&1 | grep -m1 -oE '[0-9]+\.[0-9.]+'
trufflehog|trufflehog --version 2>&1
pip-audit|/opt/venv/bin/pip-audit --version
osv-scanner|osv-scanner --version
trivy|trivy --version
syft|syft version
grype|grype version
EOF

echo "== 2. through the sandbox (demo-code, passive)"
mcp_run() {
  docker compose exec -T worker-mcp python3 -c '
import asyncio, json, sys
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
async def go():
    async with streamablehttp_client("http://kali-mcp:8090/mcp") as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool("run", {"engagement": "demo-code", "command": sys.argv[1], "timeout_s": 900})
            print("\n".join(c.text for c in res.content if getattr(c, "text", None)))
asyncio.run(go())' "$1" </dev/null 2>/dev/null
}
S=/src/rv-demo-app
while IFS= read -r line; do
  name="${line%%::*}"; rest="${line#*::}"; expect="${rest%%::*}"; cmd="${rest#*::}"
  out="$(mcp_run "$cmd")"
  if echo "$out" | grep -qE "$expect"; then ok "$name"; else bad "$name" "$(echo "$out" | tail -4)"; fi
done <<EOF
osv-scanner finds dependency vulns::PYSEC-|GHSA-::osv-scanner scan source -r $S --format table 2>&1 | tail -15
trivy fs finds dependency vulns::CVE-::trivy fs --scanners vuln --quiet $S 2>&1 | tail -15
syft writes an SBOM::"bomFormat"::syft dir:$S -q -o cyclonedx-json=sbom.cdx.json && head -c 300 sbom.cdx.json
grype scans the SBOM::CVE-|GHSA-::grype sbom:sbom.cdx.json -q 2>&1 | tail -15
semgrep offline rules find injection::sqli|injection|subprocess|os-system|yaml::semgrep --config /opt/semgrep-rules/python/flask --metrics=off -q $S 2>&1 | tail -20
trivy secret/config scan runs::exit=0::trivy fs --scanners secret,misconfig --quiet $S 2>&1 | tail -5
joern taint finds the 3 injection flows::3 flows::rv-joern taint $S joern-flows.json 2>&1 | tail -2
EOF
echo "== 3. vulnerability intel"
out="$(docker compose exec -T worker-mcp python3 -c "
import worker, json
r = json.loads(worker.vuln_intel({}, ['CVE-2021-44228', 'PYSEC-2020-96']))
print(json.dumps([(x['id'], x['kev'], x['cvss_score'], bool(x['fixed_in'])) for x in r]))" </dev/null 2>/dev/null | tail -1)"
if echo "$out" | grep -q '"CVE-2021-44228", true, 10.0, true'; then ok "intel prioritize (KEV first, CVSS, fixed versions)"
else bad "intel prioritize" "$out"; fi

echo; echo "passed $pass, failed $fail"; [ "$fail" -eq 0 ]
