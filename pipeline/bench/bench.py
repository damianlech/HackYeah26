# Usage: uvicorn gate:app --port 8799 &  then  python bench.py
import asyncio, json, statistics, time, sys
import httpx
sys.path.insert(0, ".")
from gate import evaluate

URL = "http://127.0.0.1:8799/evaluate"
PROMPT = ("Please summarise the attached quarterly report for the payments team and list the three biggest risks. " * 5)
ENV = {"phase": "request", "input": {"model": "claude-sonnet-5-5", "max_tokens": 512,
       "messages": [{"role": "user", "content": PROMPT}]},
       "config": {"pattern": "kill", "decision": "deny", "ignore_case": True, "whole_word": True},
       "context": {"identity": {"user": "alice"}, "restart": 0, "trail": []}}

def pct(xs, p):
    xs = sorted(xs); k = (len(xs) - 1) * p; f = int(k); c = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)

async def run(mode, n, iters=300, warm=30):
    shared = httpx.AsyncClient(timeout=5) if mode in ("shared", "parallel") else None
    times = []
    for i in range(iters + warm):
        t0 = time.perf_counter()
        if mode == "new_client":
            for _ in range(n):
                async with httpx.AsyncClient(timeout=5) as c:
                    r = await c.post(URL, json=ENV); r.json()
        elif mode == "shared":
            for _ in range(n):
                r = await shared.post(URL, json=ENV); r.json()
        elif mode == "parallel":
            rs = await asyncio.gather(*[shared.post(URL, json=ENV) for _ in range(n)])
            [r.json() for r in rs]
        elif mode == "inproc":
            for _ in range(n):
                evaluate(json.loads(json.dumps(ENV)))
        dt = (time.perf_counter() - t0) * 1000
        if i >= warm:
            times.append(dt)
    if shared:
        await shared.aclose()
    return pct(times, 0.5), pct(times, 0.95)

async def main():
    rows = []
    for n in (1, 3, 7, 10):
        for mode in ("new_client", "shared", "parallel", "inproc"):
            p50, p95 = await run(mode, n)
            rows.append((n, mode, p50, p95))
            print(f"N={n:2d} {mode:11s} p50={p50:7.2f} ms  p95={p95:7.2f} ms", flush=True)
    json.dump(rows, open("results.json", "w"))

if __name__ == "__main__":
    asyncio.run(main())
