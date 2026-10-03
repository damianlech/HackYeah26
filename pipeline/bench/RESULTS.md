# Gate-hop latency micro-benchmark

What it measures: the pure overhead of calling N gates over HTTP from the pipeline, for four ways of calling them.
The gate is a real FastAPI service (`gate.py`): pydantic envelope, one compiled regex over a ~500-character prompt.
No JEV, no upstream model. Those add their own time on top.

**Setup:** 4-vCPU Linux sandbox, Python 3.11, FastAPI 0.142, uvicorn (h11, 1 worker per gate), httpx.
300 requests per cell after 30 warm-up requests. **Re-run it on the demo Mac before quoting numbers on a slide.**

| N gates | new `httpx.AsyncClient` per call | one shared client, serial | shared client, parallel | in-process function |
|---|---|---|---|---|
| 1 | 49.6 ms (p95 66.7) | 1.7 ms (p95 2.3) | 1.9 ms | 0.02 ms |
| 3 | 157.7 ms | 5.1 ms | 4.3 ms ¹ | 0.04 ms |
| 7 | 370.2 ms | 12.6 ms | 12.3 ms ¹ | 0.11 ms |
| 10 | 539.4 ms (p95 589.9) | 17.4 ms (p95 21.2) | 18.6 ms ¹ | 0.16 ms |

¹ All N "gates" were one single-worker process here, so parallel calls queued behind each other. With **separate gate processes**,
which is the real setup (`bench2.py`, 10 uvicorn processes on 4 vCPUs):

| N gates (separate processes) | serial | parallel |
|---|---|---|
| 3 | 5.8 ms (p95 7.4) | 3.9 ms (p95 5.1) |
| 7 | 17.0 ms (p95 20.8) | 8.9 ms (p95 11.9) |
| 10 | 26.3 ms (p95 31.2) | 13.2 ms (p95 17.8) |

**Why the first column is so slow:** `httpx.AsyncClient()` takes **~48 ms to create**, because each new client builds an SSL context
(`ssl.create_default_context()` alone takes ~22 ms) even for plain-HTTP calls. `claude-proxy/l2_audit.py` creates one per JEV call
and one per forward call, so about 100 ms of every request is client set-up.

**Takeaways for the pipeline:**
1. Create **one** `httpx.AsyncClient` at startup (FastAPI lifespan) and reuse it for every gate call. That is a ~30× cheaper hop.
2. One HTTP gate hop costs **~1.5–2.5 ms** on localhost. 10 gates add ~20–30 ms, which is fine, but say so and show it per gate.
3. Read-only gates (deny/flag only, no modify) can run **in parallel** inside a stage, which halves that.
4. Cheap gates (word filter, allowlists) can run **in-process** with the same contract: ~0.02 ms. Keep HTTP for heavy or third-party gates (JEV).
5. JEV (40–130 ms simulated, real LLM evals 100s of ms+) dominates anyway, so put it **last**, after the cheap gates that can deny first.

Re-run on a Mac: see the commands at the top of `bench.py` and `bench2.py`. You need `pip install fastapi uvicorn httpx`.
Start `uvicorn gate:app --port 8799` for `bench.py`, or ports 8800–8809 for `bench2.py`.
