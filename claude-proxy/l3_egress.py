"""LAYER 3 - re-encrypt & egress (:8603).

Receives the approved PLAINTEXT request from L2, swaps the agent's virtual key for the real Anthropic
credential (which only this layer holds), opens a NEW TLS connection to the upstream, verifies the
upstream certificate chain, and sends the request. The plaintext never leaves the proxy unencrypted.

Upstream (central policy `upstream.mode`, overridable with env PROXY_UPSTREAM):
  mock -> https://localhost:9443, the local stand-in for api.anthropic.com, verified against the mock public CA
  live -> https://api.anthropic.com, verified against the public web PKI (certifi)
"""
import os
import ssl
import time

import certifi
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from certs import MOCK_CA
from common import HOP_HEADERS, anthropic_error, load_policy, mask, trace

app = FastAPI(title="L3 egress")
MOCK_UPSTREAM_KEY = "sk-ant-mock-UPSTREAM-0000"


def _cn(name):  # ((('commonName', 'x'),), ...) -> 'x'
    return next((v for rdn in name for k, v in rdn if k in ("commonName", "organizationName")), "?")


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def egress(path: str, request: Request):
    tid = request.headers.get("x-trace-id", "-")
    policy = load_policy()
    mode = os.environ.get("PROXY_UPSTREAM") or policy["upstream"]["mode"]
    base = policy["upstream"][f"{mode}_url"]
    ctx = ssl.create_default_context(cafile=str(MOCK_CA) if mode == "mock" else certifi.where())

    headers = {k: v for k, v in request.headers.items()
               if k.lower() not in HOP_HEADERS and not k.lower().startswith("x-l1-") and k.lower() != "x-trace-id"}
    virtual = headers.pop("x-api-key", None) or headers.pop("authorization", "").removeprefix("Bearer ").strip()
    real = MOCK_UPSTREAM_KEY if mode == "mock" else os.environ.get("ANTHROPIC_API_KEY", "")
    if real:
        headers["x-api-key"] = real
    if mode == "mock":
        headers["x-trace-id"] = tid  # lets the local mock join the demo trace; never sent to the real API

    url = f"{base}/{path}" + (f"?{request.url.query}" if request.url.query else "")
    t0 = time.perf_counter()
    try:
        async with httpx.AsyncClient(verify=ctx, timeout=180) as client:
            async with client.stream(request.method, url, headers=headers, content=await request.body()) as r:
                tls = r.extensions["network_stream"].get_extra_info("ssl_object")
                peer = tls.getpeercert()
                trace(tid, "L3", "egress", mode=mode, upstream=base, tls=tls.version(), cipher=tls.cipher()[0],
                      cert_subject=_cn(peer["subject"]), cert_issuer=_cn(peer["issuer"]),
                      key_swap=f"{mask(virtual)} -> {mask(real) if real else '(none: ANTHROPIC_API_KEY not set)'}")
                body = await r.aread()
    except (httpx.HTTPError, ssl.SSLError) as e:
        trace(tid, "L3", "egress_error", upstream=base, error=f"{type(e).__name__}: {e}")
        status, payload = anthropic_error(502, "api_error", f"L3: upstream {base} failed ({type(e).__name__})")
        return JSONResponse(payload, status_code=status)

    trace(tid, "L3", "upstream_response", status=r.status_code, bytes=len(body),
          ms=round((time.perf_counter() - t0) * 1000), request_id=r.headers.get("request-id"))
    out = {k: v for k, v in r.headers.items() if k.lower() not in HOP_HEADERS and k.lower() not in ("date", "server")}
    out["x-proxy-upstream"] = base
    return Response(body, status_code=r.status_code, headers=out)
