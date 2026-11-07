#!/usr/bin/env bash
# Prepares a fresh install for the regression tests (CI, or a new machine): copies the test apps into the projects
# folder and creates the engagements the tests expect.
#   demo-code  scope /src/rv-demo-app, passive                         (phase3_policy_test, tools_smoke)
#   net-test   example.com and 1.1.1.1, all tiers, max rate 20          (phase3_policy_test)
# Run after ./rvkit setup: bash evals/ci_prepare.sh
set -euo pipefail
cd "$(dirname "$0")/.."
envget() { grep -E "^$1=" .env | head -1 | cut -d= -f2-; }
P="$(envget PROJECTS_DIR)"; P="${P/#\~/$HOME}"
E="$(envget ENGAGEMENTS_DIR)"; E="${E/#\~/$HOME}"
mkdir -p "$P" "$E"
for t in rv-demo-app rv-node-api rv-smoke; do rm -rf "${P:?}/$t"; cp -R "evals/targets/$t" "$P/$t"; done

engagement() { # engagement <name> <tiers> <rate> <target>...
  local name="$1" tiers="$2" rate="$3"; shift 3
  mkdir -p "$E/$name"
  { echo "# test scope"; for t in "$@"; do echo "- $t"; done; } > "$E/$name/SCOPE.md"
  printf -- '- Allowed tiers: %s\n- Max rate: %s\n- Network: online\n' "$tiers" "$rate" > "$E/$name/RULES.md"
  ./rvkit scope "$name" --yes >/dev/null
  echo "engagement $name ready"
}
engagement demo-code "passive" 100 /src/rv-demo-app
engagement net-test "passive, active, intrusive" 20 example.com 1.1.1.1
