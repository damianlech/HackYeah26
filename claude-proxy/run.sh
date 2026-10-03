#!/usr/bin/env bash
# Run the 3-layer proxy stack without the scripted demo (for curl, the SDK or Claude Code).
#   ./claude-proxy/run.sh          upstream = mock api.anthropic.com (offline)
#   ./claude-proxy/run.sh --live   upstream = real api.anthropic.com (L3 uses ANTHROPIC_API_KEY)
set -euo pipefail
cd "$(dirname "$0")"
python3 certs.py
if [ "${1:-}" = "--live" ]; then export PROXY_UPSTREAM=live; fi
trap 'kill 0' EXIT
U="python3 -m uvicorn --log-level warning"
[ "${PROXY_UPSTREAM:-mock}" = "live" ] || \
  $U --port 9443 --ssl-keyfile .runtime/certs/mock-api.anthropic.com.key --ssl-certfile .runtime/certs/mock-api.anthropic.com.pem mock_anthropic:app &
$U --port 8602 jev_sim:app &
$U --port 8603 l3_egress:app &
$U --port 8601 l2_audit:app &
python3 l1_intercept.py &
sleep 1.5
cat <<MSG

Proxy is up: https://localhost:8443  (upstream: ${PROXY_UPSTREAM:-mock})
  curl:   curl --cacert claude-proxy/.runtime/certs/interception-ca.pem https://localhost:8443/v1/messages \\
            -H 'x-api-key: sk-proxy-alice' -H 'anthropic-version: 2023-06-01' -H 'content-type: application/json' \\
            -d '{"model":"claude-sonnet-5-5","max_tokens":256,"messages":[{"role":"user","content":"hi"}]}'
  Claude: ANTHROPIC_BASE_URL=https://localhost:8443 NODE_EXTRA_CA_CERTS=\$PWD/claude-proxy/.runtime/certs/interception-ca.pem \\
          ANTHROPIC_API_KEY=sk-proxy-alice claude
  Trace:  tail -f claude-proxy/.runtime/trace.jsonl
Ctrl-C stops everything.
MSG
wait
