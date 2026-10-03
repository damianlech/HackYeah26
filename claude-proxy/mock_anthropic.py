"""Mock api.anthropic.com (:9443, HTTPS with a cert for api.anthropic.com from the mock public CA).

Speaks the Messages API shape (JSON and SSE streaming, with `usage`) so the SDK, L2's cost settlement
and L3's TLS verification all behave as they would against the real API. No model behind it.
"""
import json
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from common import mask, trace

app = FastAPI(title="mock api.anthropic.com")


def answer_for(prompt: str) -> str:
    p = prompt.lower()
    if "python" in p:
        return ("Here's a compact version:\n\n```python\ndef iban_ok(iban: str) -> bool:\n"
                "    s = iban.replace(' ', '').upper()\n    s = s[4:] + s[:4]\n"
                "    return int(''.join(str(int(c, 36)) for c in s)) % 97 == 1\n```\n"
                "It moves the country code and check digits to the end, maps letters to numbers, and checks mod 97.")
    if "ransomware" in p:
        return ("Ransomware usually arrives by phishing or exposed remote access, escalates privileges, spreads "
                "laterally, then encrypts shared drives. For training, focus on phishing recognition, MFA, "
                "patching and offline backups.")
    if "support report" in p:
        return ("Q3 in short: ticket volume was broadly flat, SLA stayed above 90% every week, and card blocks, "
                "login and transfers remained the top three topics.")
    if "release notes" in p:
        return "Release 4.2 adds SSO login, fixes two export bugs and deprecates the v1 reports API."
    return "Done. Here is a short, helpful answer from the (mock) model."


def last_user_text(req):
    for m in reversed(req.get("messages", [])):
        if m.get("role") == "user":
            c = m.get("content")
            return c if isinstance(c, str) else " ".join(b.get("text", "") for b in c if isinstance(b, dict))
    return ""


@app.post("/v1/messages")
async def messages(request: Request):
    req = await request.json()
    trace(request.headers.get("x-trace-id", "-"), "UP", "received", key=mask(request.headers.get("x-api-key")),
          model=req.get("model"))
    if not request.headers.get("x-api-key", "").startswith("sk-ant-"):
        return JSONResponse({"type": "error", "error": {"type": "authentication_error", "message": "invalid x-api-key"}}, 401)

    text = answer_for(last_user_text(req))
    in_tok = max(1, len(json.dumps(req.get("messages", []))) // 4)
    out_tok = max(1, len(text) // 4)
    msg_id = "msg_mock_" + uuid.uuid4().hex[:12]
    headers = {"request-id": "req_mock_" + uuid.uuid4().hex[:12]}

    if not req.get("stream"):
        return JSONResponse({
            "id": msg_id, "type": "message", "role": "assistant", "model": req.get("model"),
            "content": [{"type": "text", "text": text}], "stop_reason": "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": in_tok, "output_tokens": out_tok,
                      "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0},
        }, headers=headers)

    def sse():
        def ev(name, data):
            return f"event: {name}\ndata: {json.dumps({'type': name, **data})}\n\n"
        yield ev("message_start", {"message": {"id": msg_id, "type": "message", "role": "assistant", "model": req.get("model"),
                                               "content": [], "stop_reason": None, "stop_sequence": None,
                                               "usage": {"input_tokens": in_tok, "output_tokens": 1}}})
        yield ev("content_block_start", {"index": 0, "content_block": {"type": "text", "text": ""}})
        for i in range(0, len(text), 24):
            yield ev("content_block_delta", {"index": 0, "delta": {"type": "text_delta", "text": text[i:i + 24]}})
            time.sleep(0.01)
        yield ev("content_block_stop", {"index": 0})
        yield ev("message_delta", {"delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": out_tok}})
        yield ev("message_stop", {})
    return StreamingResponse(sse(), media_type="text/event-stream", headers=headers)
