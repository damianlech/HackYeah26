"""Deterministic OpenAI-compatible SSE mock: 200 content chunks + usage chunk + [DONE]."""
import json, asyncio
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
app = FastAPI()
WORDS = ("The quarterly risk report shows stable exposure across desks . ").split()
@app.post("/v1/chat/completions")
async def chat(req: Request):
    body = await req.json()
    n = int(body.get("max_tokens", 200)); delay = float(body.get("mock_delay", 0))
    secret_at = body.get("mock_secret_at")  # inject a fake AWS key at chunk k (split across 2 chunks)
    async def gen():
        base = {"id": "chatcmpl-mock", "object": "chat.completion.chunk", "created": 0, "model": body.get("model", "mock")}
        for i in range(n):
            txt = WORDS[i % len(WORDS)] + " "
            if secret_at is not None and i == secret_at: txt = "key AKIAABCDEF"
            if secret_at is not None and i == secret_at + 1: txt = "GHIJKLMNOP done "
            yield "data: " + json.dumps({**base, "choices": [{"index": 0, "delta": {"content": txt}, "finish_reason": None}]}) + "\n\n"
            if delay: await asyncio.sleep(delay)
        yield "data: " + json.dumps({**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}) + "\n\n"
        yield "data: " + json.dumps({**base, "choices": [], "usage": {"prompt_tokens": 20, "completion_tokens": n, "total_tokens": 20 + n}}) + "\n\n"
        yield "data: [DONE]\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream")
