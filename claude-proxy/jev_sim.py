"""JEV evaluator - SIMULATED (:8602).

Stands in for the real JEV model. Same contract the real one will have:
POST /v1/evaluate {"text": "..."} -> {"score_pct": 0-100, "categories": [...], "model": ..., "latency_ms": ...}

The simulation is deterministic (same text, same score): weighted signal phrases per harm category,
combined as independent probabilities, dampened by "defensive context" phrases, plus a small
hash-based jitter and a simulated inference delay.
"""
import hashlib
import time
import unicodedata

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="JEV evaluator (simulated)")

CATEGORIES = {  # category: (base weight, signal phrases)
    "weapons": (0.93, ["pipe bomb", "build a bomb", "explosive device", "detonator", "untraceable gun"]),
    "self_harm": (0.90, ["kill myself", "hurt myself", "end my life"]),
    "malware": (0.72, ["ransomware", "keylogger", "credential stealer", "reverse shell", "disable antivirus", "evade edr"]),
    "prompt_injection": (0.55, ["ignore previous instructions", "ignore all previous", "disregard your instructions",
                                "you are now", "developer mode", "reveal your system prompt"]),
    "data_exfiltration": (0.45, ["~/.ssh", "id_rsa", ".env file", "exfiltrate", "send it to", "all customer records"]),
}
DEFENSIVE = ["explain", "awareness", "training", "detect", "defend", "protect against", "for our security team"]


class EvalIn(BaseModel):
    text: str


def fold(text):
    text = unicodedata.normalize("NFKD", text.lower())
    return "".join(c for c in text if not unicodedata.combining(c))


@app.post("/v1/evaluate")
def evaluate(body: EvalIn):
    t0 = time.perf_counter()
    text = fold(body.text)
    h = int(hashlib.sha256(text.encode()).hexdigest(), 16)
    time.sleep(0.04 + (h % 90) / 1000)  # simulated inference: 40-130 ms

    found, p_clean = [], 1.0
    defensive = [d for d in DEFENSIVE if d in text]
    for name, (weight, phrases) in CATEGORIES.items():
        hits = [p for p in phrases if p in text]
        if not hits:
            continue
        w = min(0.99, weight + 0.05 * (len(hits) - 1))
        if defensive and name not in ("weapons", "self_harm"):
            w *= 0.6
        p_clean *= 1 - w
        found.append({"category": name, "weight": round(w, 2), "evidence": hits})

    score = (1 - p_clean) * 100 if found else 1 + h % 4  # benign baseline 1-4 %
    score = max(0.0, min(99.0, score + ((h >> 8) % 5) - 2))
    return {"score_pct": round(score, 1), "categories": found, "defensive_context": defensive,
            "model": "jev-sim-0.1", "simulated": True, "latency_ms": round((time.perf_counter() - t0) * 1000)}


@app.get("/health")
def health():
    return {"ok": True, "model": "jev-sim-0.1"}
