#!/usr/bin/env bash
# Every automated check in one go:
#   1. Python suites (4-testing/): the poc/ gateway, the 3-layer claude-proxy/, the strictness profiles
#   2. the admin mockup's browser checks (pipeline/mockups/tests/tests.js), if Node + Playwright are installed
# Needs: pip install -r 5-implementation/requirements.txt
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m pytest 4-testing -q "$@"

export NODE_PATH="${NODE_PATH:-$(npm root -g 2>/dev/null || true)}"
if command -v node >/dev/null && node -e "require('playwright')" 2>/dev/null; then
  node pipeline/mockups/tests/tests.js
else
  echo "Skipped the mockup's browser checks: they need Node.js and Playwright (see pipeline/mockups/tests/README.md)."
fi
