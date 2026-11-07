#!/usr/bin/env bash
# Phase 5 exit check: an end-to-end run on a test target produces a branded report whose every finding links to
# hashed evidence. Uses engagement "p5-e2e" (scope: the demo app, passive), reset on every run.
#   1. tools run through the audited kali sandbox; their output files are hashed in the audit log
#   2. findings recorded and confirmed through the findings MCP, citing those files
#   3. generate_report -> final (not draft); every evidence row in the .docx says Pass; PDF + XLSX exist; the HTML
#      report is self-contained and has the same findings
#   4. tampering with an evidence file is detected (report goes back to DRAFT); re-running the tool restores it
#   5. ./rvkit close: manifest verifies, archive checksum verifies, engagement refuses new commands
# Run: bash evals/phase5_e2e.sh
cd "$(dirname "$0")/.." || exit 1
ENG=p5-e2e
E="${ENGAGEMENTS_DIR:-$(grep -E '^ENGAGEMENTS_DIR=' .env 2>/dev/null | head -1 | cut -d= -f2-)}"; E="${E:-~/riskvoid/engagements}"
ENGDIR="${E/#\~/$HOME}/$ENG"
pass=0; fail=0
ok()  { pass=$((pass+1)); echo "PASS  $1"; }
bad() { fail=$((fail+1)); echo "FAIL  $1"; [ -n "${2:-}" ] && echo "$2" | head -6 | sed 's/^/      /'; }
check() { if echo "$2" | grep -qE "$3"; then ok "$1"; else bad "$1" "$2"; fi; }

# call <server-url> <tool> <json-args>
call() {
  docker compose exec -T worker-mcp python3 -c '
import asyncio, sys
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
async def go():
    async with streamablehttp_client(sys.argv[1], sse_read_timeout=900) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool(sys.argv[2], __import__("json").loads(sys.argv[3]))
            print("\n".join(c.text for c in res.content if getattr(c, "text", None)))
asyncio.run(go())' "$@" </dev/null 2>/dev/null
}
KALI=http://kali-mcp:8090/mcp; FIND=http://findings-mcp:8092/mcp
kali() { call $KALI run "{\"engagement\": \"$ENG\", \"command\": $(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"), \"timeout_s\": 900}"; }

echo "== 0. reset $ENG"
if [ -d "$ENGDIR" ]; then
  ./rvkit resume $ENG >/dev/null 2>&1
  docker compose exec -T findings-mcp sh -c "cd /work/$ENG && rm -rf findings.db report evidence *.json *.jsonl *.txt MANIFEST.sha256" </dev/null
fi
./rvkit engagement $ENG --replace /src/rv-demo-app >/dev/null 2>&1
sed -i.bak 's/^- Allowed tiers:.*/- Allowed tiers: passive/' "$ENGDIR/RULES.md" && rm -f "$ENGDIR/RULES.md.bak"
./rvkit scope $ENG --yes >/dev/null 2>&1
check "engagement ready" "$(call $KALI engagement_info "{\"engagement\": \"$ENG\"}")" '"passive"'

echo "== 1. audited tool runs"
S=/src/rv-demo-app
check "bandit output hashed" "$(kali "bandit -q -r $S -f json -o bandit.json")" 'evidence recorded: .*bandit.json'
check "semgrep output hashed" "$(kali "semgrep --config /opt/semgrep-rules/python/flask --metrics=off -q --json -o semgrep.json $S")" 'evidence recorded: .*semgrep.json'
check "joern output hashed" "$(kali "rv-joern taint $S joern-flows.json")" 'evidence recorded: .*joern-flows.json'
check "pip-audit output hashed" "$(kali "pip-audit -r $S/requirements.txt -f json -o pip-audit.json --progress-spinner off")" 'evidence recorded: .*pip-audit.json'

echo "== 2. findings"
# each fixture finding: record_finding, then update_finding to its _status
python3 -c 'import json,sys; [print(json.dumps(f)) for f in json.load(open(sys.argv[1]))]' evals/fixtures/p5_findings.json |
while IFS= read -r f; do
  st=$(echo "$f" | python3 -c 'import json,sys; print(json.load(sys.stdin)["_status"])')
  args=$(echo "$f" | python3 -c 'import json,sys; d=json.load(sys.stdin); d.pop("_status"); d["engagement"]="p5-e2e"; print(json.dumps(d))')
  id=$(call $FIND record_finding "$args" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null)
  [ -n "$id" ] || { echo "      record_finding failed: $(echo "$f" | cut -c1-60)"; continue; }
  call $FIND update_finding "{\"engagement\": \"$ENG\", \"finding_id\": \"$id\", \"status\": \"$st\", \"notes\": \"e2e\"}" >/dev/null
done
check "3 confirmed + 1 false positive" "$(call $FIND list_findings "{\"engagement\": \"$ENG\", \"status\": \"confirmed\"}" | grep -c '"id"')" '^3$'
dup=$(call $FIND record_finding "{\"engagement\": \"$ENG\", \"title\": \"Same SQL injection, found twice\", \"severity\": \"high\", \"asset\": \"app.py\", \"description\": \"dup\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null)
j1="{\"engagement\": \"$ENG\", \"finding_id\": \"$dup\", \"status\": \"duplicate\"}"
j2="{\"engagement\": \"$ENG\", \"finding_id\": \"$dup\", \"status\": \"duplicate\", \"duplicate_of\": \"F-001\"}"
check "duplicate needs duplicate_of" "$(call $FIND update_finding "$j1")" 'needs duplicate_of'
check "duplicate links the kept finding" "$(call $FIND update_finding "$j2")" '"duplicate_of": "F-001"'

echo "== 3. report"
mkdir -p "$ENGDIR/report"
printf 'Client: Test Client Ltd\nPrepared by: RiskVoid\nVersion: 1.0\n' > "$ENGDIR/report/meta.txt"
printf 'RiskVoid reviewed the **demo application** source code.\n\nTwo critical injection flaws allow full compromise:\n\n- SQL injection\n- OS command injection\n\nFix both before the next release.\n' > "$ENGDIR/report/executive-summary.md"
out="$(call $FIND generate_report "{\"engagement\": \"$ENG\"}")"
check "report is final" "$out" '"status": "final"'
check "PDF and register written" "$out" '\.pdf".*|\.xlsx"'
DOCX="$(ls "$ENGDIR"/report/*.docx 2>/dev/null | head -1)"
xml="$(unzip -p "$DOCX" word/document.xml 2>/dev/null)"
for f in F-001 F-002 F-003; do check "$f in report" "$xml" "$f"; done
check "false positive excluded" "$(echo "$xml" | grep -c 'Scanner noise')" '^0$'
check "duplicate excluded" "$(echo "$xml" | grep -c 'found twice')" '^0$'
check "classification on the cover" "$xml" 'Classification.*Confidential'
passes=$(echo "$xml" | grep -o '>Pass<' | wc -l | tr -d ' ')
check "every evidence file verified (Pass rows: $passes)" "$(echo "$xml" | grep -cE '>(Fail|Not audited)<')" '^0$'
[ "$passes" -ge 10 ] && ok "evidence rows in detail + appendix ($passes)" || bad "evidence rows" "$passes"
check "client and summary in report" "$xml" 'Test Client Ltd.*|demo application'
check "cover not draft" "$(echo "$xml" | grep -c 'DRAFT')" '^0$'
HTML="$(ls "$ENGDIR"/report/*.html 2>/dev/null | head -1)"
page="$(cat "$HTML" 2>/dev/null)"
check "HTML report written" "$HTML" '\.html$'
check "HTML: every confirmed finding" "$(for f in F-001 F-002 F-003; do echo "$page" | grep -q "id=\"$f\"" && echo "$f"; done | wc -l | tr -d ' ')" '^3$'
check "HTML: false positive and duplicate excluded" "$(echo "$page" | grep -cE 'Scanner noise|found twice')" '^0$'
check "HTML: no scripts, nothing fetched" "$(echo "$page" | grep -ciE '<script|src="https?:|url\(https?:')" '^0$'
check "HTML: fonts and logo embedded" "$(echo "$page" | grep -o 'data:font/woff2\|data:image/png' | sort -u | wc -l | tr -d ' ')" '^2$'

echo "== 4. tamper detection"
# modify it from a container: on Linux the file belongs to the engagement's sandbox user, not to us
docker compose exec -T findings-mcp sh -c "echo ' ' >> /work/$ENG/bandit.json" </dev/null
out="$(call $FIND generate_report "{\"engagement\": \"$ENG\"}")"
check "tampered evidence -> DRAFT" "$out" '"status": "DRAFT"'
check "issue names the file" "$out" 'bandit.json is MODIFIED'
kali "bandit -q -r $S -f json -o bandit.json" >/dev/null
check "re-run restores integrity" "$(call $FIND generate_report "{\"engagement\": \"$ENG\"}")" '"status": "final"'

echo "== 5. close-out"
out="$(./rvkit close $ENG 2>&1)"
check "close" "$out" 'closed and halted'
ARC="$(echo "$out" | sed -n 's/^archive: //p')"
D="$(dirname "$ENGDIR")"
(cd "$D/_archive" && shasum -a 256 -c "$(basename "$ARC").sha256" >/dev/null 2>&1) && ok "archive checksum" || bad "archive checksum"
T="$(mktemp -d)"; tar -xzf "$D/$ARC" -C "$T"
(cd "$T" && shasum -a 256 -c MANIFEST.sha256 >/dev/null 2>&1) && ok "manifest verifies" || bad "manifest verifies"
check "report and audit in archive" "$(ls "$T" "$T/report")" 'audit.jsonl'
check "docx archived" "$(ls "$T/report")" '\.docx'
rm -rf "$T"
check "closed engagement refuses commands" "$(kali "echo hi")" 'halted'

echo; echo "passed $pass, failed $fail"; [ "$fail" -eq 0 ]
