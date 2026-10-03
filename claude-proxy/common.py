"""Shared bits for all layers: paths, ports, the central policy (hot-reloaded) and the trace log."""
import json
import os
import time
from pathlib import Path

import yaml

HERE = Path(__file__).parent
RUNTIME = HERE / ".runtime"
CERTS = RUNTIME / "certs"
TRACE_LOG = RUNTIME / "trace.jsonl"     # step-by-step events, all layers, keyed by trace id
AUDIT_LOG = RUNTIME / "audit.jsonl"     # one record per request, written by L2
POLICY_PATH = Path(os.environ.get("PROXY_POLICY", HERE / "policy.yaml"))

L1_PORT, L2_PORT, JEV_PORT, L3_PORT, MOCK_PORT = 8443, 8601, 8602, 8603, 9443
L2_URL = f"http://127.0.0.1:{L2_PORT}"
JEV_URL = f"http://127.0.0.1:{JEV_PORT}"
L3_URL = f"http://127.0.0.1:{L3_PORT}"

# hop-by-hop / transport headers never relayed between layers
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
               "transfer-encoding", "upgrade", "host", "content-length", "content-encoding", "accept-encoding"}

_policy_cache = {"mtime": None, "policy": None, "error": None}


def load_policy():
    """Central policy, reloaded when the file changes. A broken edit keeps the last good version."""
    mtime = POLICY_PATH.stat().st_mtime_ns
    if mtime != _policy_cache["mtime"]:
        _policy_cache["mtime"] = mtime
        try:
            _policy_cache["policy"] = yaml.safe_load(POLICY_PATH.read_text())
            _policy_cache["error"] = None
        except yaml.YAMLError as e:
            _policy_cache["error"] = str(e)
            if _policy_cache["policy"] is None:
                raise
    return _policy_cache["policy"]


def trace(trace_id, layer, event, **data):
    RUNTIME.mkdir(exist_ok=True)
    line = json.dumps({"ts": time.time(), "trace": trace_id, "layer": layer, "event": event, **data})
    with TRACE_LOG.open("a") as f:
        f.write(line + "\n")


def anthropic_error(status, err_type, message, **extra):
    """Error body in the same shape api.anthropic.com uses, so SDKs and Claude Code parse it."""
    return status, {"type": "error", "error": {"type": err_type, "message": message, **extra}}


def mask(key):
    return f"{key[:9]}…{key[-4:]}" if key and len(key) > 14 else (key or "-")
