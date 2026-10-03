"""Minimal streaming guard gateway (benchmark harness, not production code).
mode=pass  : relay upstream bytes untouched
mode=scan  : parse SSE, run a holdback-window secret scanner on deltas, re-emit; on hit -> redact or block
"""
import json, os, re, time
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
UP = os.environ.get("UPSTREAM", "http://127.0.0.1:9101")
ENGINE = os.environ.get("ENGINE", "re")          # re | hs
ACTION = os.environ.get("ACTION", "block")       # block | redact
PATTERNS = [r"AKIA[0-9A-Z]{16}", r"ghp_[A-Za-z0-9]{36}", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"sk-[A-Za-z0-9]{20,}",
            r"xox[baprs]-[A-Za-z0-9-]{10,48}", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"]
RX = re.compile("|".join(f"(?:{p})" for p in PATTERNS))
HOLD = 64   # holdback chars >= longest pattern we must catch across chunk boundaries
app = FastAPI()
client = httpx.AsyncClient(timeout=None, limits=httpx.Limits(max_connections=1000, max_keepalive_connections=1000))

class Scanner:
    """Release text only once it can no longer be part of a match that starts earlier."""
    def __init__(self): self.buf = ""; self.emitted = 0; self.hit = None
    def feed(self, s):
        self.buf += s
        m = RX.search(self.buf)
        if m:
            self.hit = m.group(0)
            if ACTION == "redact":
                self.buf = self.buf[:m.start()] + "[REDACTED:secret]" + self.buf[m.end():]
            else:
                safe = self.buf[:m.start()]; self.buf = ""; return safe, True
        if len(self.buf) > HOLD:
            out, self.buf = self.buf[:-HOLD], self.buf[-HOLD:]; return out, False
        return "", False
    def flush(self): out, self.buf = self.buf, ""; return out

def chunk(base, text=None, finish=None):
    d = {"content": text} if text else {}
    return "data: " + json.dumps({**base, "choices": [{"index": 0, "delta": d, "finish_reason": finish}]}) + "\n\n"

@app.post("/v1/chat/completions")
async def proxy(req: Request):
    raw = await req.body(); mode = req.headers.get("x-mode", "scan")
    t0 = time.perf_counter()
    upreq = client.build_request("POST", UP + "/v1/chat/completions", content=raw, headers={"content-type": "application/json"})
    up = await client.send(upreq, stream=True)
    pre_ms = (time.perf_counter() - t0) * 1e3
    hdrs = {"server-timing": f"preflight;dur={pre_ms:.2f}"}
    if mode == "pass":
        async def relay():
            async for b in up.aiter_raw(): yield b
            await up.aclose()
        return StreamingResponse(relay(), media_type="text/event-stream", headers=hdrs)
    async def guarded():
        sc = Scanner(); base = None; usage = None; out_chars = 0
        try:
            async for line in up.aiter_lines():
                if not line.startswith("data: "): continue
                data = line[6:]
                if data == "[DONE]": break
                ev = json.loads(data)
                base = base or {k: ev[k] for k in ("id", "object", "created", "model")}
                if ev.get("usage"): usage = ev["usage"]
                for ch in ev.get("choices", []):
                    txt = ch.get("delta", {}).get("content")
                    if txt:
                        safe, blocked = sc.feed(txt)
                        if safe: out_chars += len(safe); yield chunk(base, safe)
                        if blocked:
                            # protocol-correct termination for OpenAI-style clients
                            yield chunk(base, None, "content_filter")
                            yield "data: " + json.dumps({"error": {"message": "Blocked by policy SEC-001 (secret in model output)", "type": "policy_violation", "code": "content_blocked"}}) + "\n\n"
                            return
                    if ch.get("finish_reason"):
                        rest = sc.flush()
                        if rest: out_chars += len(rest); yield chunk(base, rest)
                        yield chunk(base, None, ch["finish_reason"])
            if usage: yield "data: " + json.dumps({**base, "choices": [], "usage": usage}) + "\n\n"
            yield "data: [DONE]\n\n"
        finally:
            await up.aclose()   # settle budget here: usage if seen, else estimate from out_chars
    return StreamingResponse(guarded(), media_type="text/event-stream", headers=hdrs)
