#!/usr/bin/env bash
# Start the slice: mock LLM :9000, guard-svc :9100, gateway :8080. Ctrl-C stops all three.
set -euo pipefail
cd "$(dirname "$0")"
trap 'kill 0' EXIT
python3 -m uvicorn mock_llm:app  --port 9000 --log-level warning &
python3 -m uvicorn guard_svc:app --port 9100 --log-level warning &
python3 -m uvicorn gateway:app   --port 8080 --log-level warning &
echo "gateway http://127.0.0.1:8080  |  guard http://127.0.0.1:9100  |  mock LLM http://127.0.0.1:9000"
wait
