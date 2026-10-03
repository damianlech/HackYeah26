import re
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class Envelope(BaseModel):
    phase: str
    input: dict
    config: dict
    context: dict = {}

def evaluate(env: dict) -> dict:
    cfg = env["config"]
    pat = cfg["pattern"]
    if cfg.get("whole_word"):
        pat = r"\b" + pat + r"\b"
    rx = re.compile(pat, re.I if cfg.get("ignore_case") else 0)
    text = " ".join(m["content"] for m in env["input"]["messages"] if m["role"] == "user")
    m = rx.search(text)
    if not m:
        return {"decision": "allow", "reason": "no match"}
    return {"decision": cfg["decision"], "reason": f"matched {cfg['pattern']}", "findings": [{"start": m.start(), "end": m.end()}]}

@app.post("/evaluate")
def ev(body: Envelope):
    return evaluate(body.model_dump())
