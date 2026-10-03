"""Guard service: a separate process the gateway calls for a semantic risk score.

Stand-in for the real classifier (Prompt Guard / Qwen3Guard). Same contract:
POST /score {"text": "..."} -> {"score": 0.0-1.0, "reasons": [...]}
"""
import unicodedata

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Mandate POC guard-svc")

# phrase -> weight; the score is the sum, capped at 1.0
INDICATORS = {
    "ignore previous instructions": 0.6,
    "ignore all previous": 0.6,
    "disregard your rules": 0.5,
    "system prompt": 0.3,
    "you are now": 0.3,
    "developer mode": 0.4,
    "exfiltrate": 0.5,
    "send it to": 0.2,
    "password": 0.2,
    # PL (matched on text with diacritics folded: "pokaż" -> "pokaz")
    "zignoruj poprzednie instrukcje": 0.6,
    "zignoruj wszystkie poprzednie instrukcje": 0.6,
    "prompt systemowy": 0.3,
    "instrukcje systemowe": 0.3,
}


class ScoreIn(BaseModel):
    text: str


@app.post("/score")
def score(body: ScoreIn):
    low = unicodedata.normalize("NFKD", body.text.lower().replace("ł", "l"))
    low = "".join(c for c in low if not unicodedata.combining(c))
    reasons = [p for p in INDICATORS if p in low]
    return {"score": min(1.0, sum(INDICATORS[p] for p in reasons)), "reasons": reasons}


@app.get("/health")
def health():
    return {"ok": True}
