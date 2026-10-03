"""LAYER 2 - audit & decision (:8601).

Receives the PLAINTEXT request from L1 and decides, from the central policy:
  identify (virtual key) -> model allowlist -> cost estimate + budget reservation
  -> JEV harm score -> allow / flag / block
Allowed requests go to L3. On the way back it settles the real cost from the upstream `usage`.
Every request produces one audit record (.runtime/audit.jsonl).
"""
import json
import time
import uuid

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from common import AUDIT_LOG, HOP_HEADERS, JEV_URL, L3_URL, RUNTIME, anthropic_error, load_policy, mask, trace

app = FastAPI(title="L2 audit")
spent_usd: dict[str, float] = {}  # per virtual key (in-memory for the prototype)


def request_text(req):
    """Everything the model will read: system prompt, messages (text + tool results), tool definitions."""
    parts = []

    def walk(content):
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    walk(block.get("text") or block.get("content") or "")
    walk(req.get("system", ""))
    for m in req.get("messages", []):
        walk(m.get("content", ""))
    for t in req.get("tools", []):
        parts.append(t.get("description", ""))
    return "\n".join(p for p in parts if p)


def usage_from(body: bytes, content_type: str):
    """Token usage from a JSON response or from SSE stream events (message_start + message_delta)."""
    if "text/event-stream" in content_type:
        usage = {}
        for line in body.decode(errors="replace").splitlines():
            if line.startswith("data: "):
                event = json.loads(line[6:])
                usage.update((event.get("message") or {}).get("usage") or {})
                usage.update(event.get("usage") or {})
        return usage
    try:
        return json.loads(body).get("usage") or {}
    except ValueError:
        return {}


def write_audit(record):
    RUNTIME.mkdir(exist_ok=True)
    with AUDIT_LOG.open("a") as f:
        f.write(json.dumps(record) + "\n")


@app.get("/status")
def status():
    policy = load_policy()
    return {"spent_usd": spent_usd, "jev": policy["jev"], "models": policy["models"]}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def audit(path: str, request: Request):
    t0 = time.perf_counter()
    tid = request.headers.get("x-trace-id") or "t-" + uuid.uuid4().hex[:8]
    policy = load_policy()
    body = await request.body()
    key = request.headers.get("x-api-key") or request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    record = {"ts": time.time(), "trace": tid, "path": "/" + path, "l1_tls": request.headers.get("x-l1-tls")}

    def finish(status, payload, decision, reason, extra_headers=None):
        trace(tid, "L2", "decision", decision=decision, reason=reason)
        record.update(decision=decision, reason=reason, status=status, ms=round((time.perf_counter() - t0) * 1000))
        write_audit(record)
        return JSONResponse(payload, status_code=status, headers={"x-proxy-decision": decision, **(extra_headers or {})})

    ident = policy["keys"].get(key)
    if not ident:
        trace(tid, "L2", "identify", ok=False, key=mask(key))
        return finish(*anthropic_error(401, "authentication_error", "Unknown proxy key. Agents get a virtual key from the proxy, not a real Anthropic key."),
                      "block", "unknown virtual key")
    trace(tid, "L2", "identify", ok=True, user=ident["user"], team=ident["team"], key=mask(key))
    record.update(user=ident["user"], team=ident["team"])

    is_messages = request.method == "POST" and path == "v1/messages"
    headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_HEADERS}
    if not is_messages:  # count_tokens, models, etc.: identified and logged, but not scored
        trace(tid, "L2", "passthrough", method=request.method, path="/" + path)
        return await forward(tid, headers, request.method, path, body, ident, key, policy, record, t0, None)

    req = json.loads(body)
    model, max_tokens = req.get("model"), int(req.get("max_tokens") or 0)
    record.update(model=model, max_tokens=max_tokens, stream=bool(req.get("stream")))
    if model not in policy["models"]["allowed"]:
        return finish(*anthropic_error(403, "permission_error", f"Blocked by policy: model '{model}' is not allowed. Allowed: {policy['models']['allowed']}"),
                      "block", f"model {model} not allowed")

    price = policy["pricing_usd_per_mtok"][model]
    text = request_text(req)
    in_est = max(1, len(text) // 4)
    worst = (in_est * price["input"] + max_tokens * price["output"]) / 1e6
    budget, spent = ident["budget_usd"], spent_usd.get(key, 0.0)
    trace(tid, "L2", "estimate", model=model, input_tokens_est=in_est, max_tokens=max_tokens,
          worst_case_usd=worst, spent_usd=spent, budget_usd=budget)
    record.update(worst_case_usd=worst)
    if worst > policy["cost"]["max_request_usd"]:
        return finish(*anthropic_error(403, "permission_error", f"Blocked by policy: worst-case cost ${worst:.4f} exceeds the per-request cap ${policy['cost']['max_request_usd']:.2f}"),
                      "block", f"worst-case ${worst:.4f} > cap ${policy['cost']['max_request_usd']:.2f}")
    if spent + worst > budget:
        return finish(*anthropic_error(403, "permission_error", f"Blocked by policy: budget for {ident['user']} would be exceeded (spent ${spent:.4f} + worst-case ${worst:.4f} > ${budget:.4f})"),
                      "block", f"budget: ${spent:.4f} + ${worst:.4f} > ${budget:.4f}")

    jev_cfg, verdict = policy["jev"], None
    if jev_cfg.get("enabled", True):
        try:
            async with httpx.AsyncClient(timeout=jev_cfg.get("timeout_s", 2)) as c:
                r = await c.post(f"{JEV_URL}/v1/evaluate", json={"text": text})
                r.raise_for_status()
                verdict = r.json()
        except httpx.HTTPError as e:
            trace(tid, "L2", "jev", ok=False, error=type(e).__name__, on_error=jev_cfg["on_error"])
            record.update(jev=None)
            if jev_cfg["on_error"] == "block":
                return finish(*anthropic_error(403, "permission_error", "Blocked by policy: JEV evaluator unavailable and on_error=block (fail closed)"),
                              "block", "JEV unavailable, fail closed")
        if verdict:
            trace(tid, "L2", "jev", ok=True, score=verdict["score_pct"], categories=verdict["categories"],
                  latency_ms=verdict["latency_ms"], model=verdict["model"], block_at=jev_cfg["block_at"], flag_at=jev_cfg["flag_at"])
            record.update(jev=verdict["score_pct"], jev_categories=[c["category"] for c in verdict["categories"]])
            if verdict["score_pct"] >= jev_cfg["block_at"]:
                cats = ", ".join(c["category"] for c in verdict["categories"]) or "-"
                return finish(*anthropic_error(403, "permission_error", f"Blocked by policy: JEV harm score {verdict['score_pct']}% >= block_at {jev_cfg['block_at']}% ({cats})"),
                              "block", f"JEV {verdict['score_pct']}% >= {jev_cfg['block_at']}%", {"x-proxy-jev": str(verdict["score_pct"])})

    flagged = bool(verdict and verdict["score_pct"] >= jev_cfg["flag_at"])
    trace(tid, "L2", "decision", decision="flag" if flagged else "allow",
          reason=f"JEV {verdict['score_pct']}% >= flag_at {jev_cfg['flag_at']}%" if flagged
          else (f"JEV {verdict['score_pct']}% < {jev_cfg['flag_at']}%" if verdict else "JEV skipped"))
    record.update(decision="flag" if flagged else "allow")
    return await forward(tid, headers, "POST", path, body, ident, key, policy, record, t0, verdict, price)


async def forward(tid, headers, method, path, body, ident, key, policy, record, t0, verdict, price=None):
    headers["x-trace-id"] = tid
    try:
        async with httpx.AsyncClient(timeout=180) as c:
            r = await c.request(method, f"{L3_URL}/{path}", headers=headers, content=body)
    except httpx.HTTPError as e:
        status, payload = anthropic_error(502, "api_error", f"L2: egress layer unreachable ({type(e).__name__})")
        return JSONResponse(payload, status_code=status)

    out_headers = {k: v for k, v in r.headers.items() if k.lower() not in HOP_HEADERS and k.lower() not in ("date", "server")}
    if price:
        usage = usage_from(r.content, r.headers.get("content-type", ""))
        cost = (usage.get("input_tokens", 0) * price["input"] + usage.get("output_tokens", 0) * price["output"]) / 1e6
        spent_usd[key] = spent_usd.get(key, 0.0) + cost
        trace(tid, "L2", "settle", status=r.status_code, input_tokens=usage.get("input_tokens", 0),
              output_tokens=usage.get("output_tokens", 0), cost_usd=cost, spent_usd=spent_usd[key], budget_usd=ident["budget_usd"])
        record.update(cost_usd=cost, usage=usage)
        out_headers["x-proxy-cost-usd"] = f"{cost:.6f}"
    if verdict:
        out_headers["x-proxy-jev"] = str(verdict["score_pct"])
    out_headers["x-proxy-decision"] = record.get("decision", "allow")
    record.update(status=r.status_code, upstream=r.headers.get("x-proxy-upstream"), ms=round((time.perf_counter() - t0) * 1000))
    record.setdefault("decision", "allow")
    write_audit(record)
    return Response(r.content, status_code=r.status_code, headers=out_headers)
