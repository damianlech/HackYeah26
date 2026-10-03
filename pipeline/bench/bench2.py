# Usage: for p in $(seq 8800 8809); do uvicorn gate:app --port $p & done; then python bench2.py
import asyncio, json, time, sys
import httpx
sys.path.insert(0, ".")
from bench import ENV, pct
async def run(mode, n, iters=300, warm=30):
    urls = [f"http://127.0.0.1:{8800+i}/evaluate" for i in range(n)]
    c = httpx.AsyncClient(timeout=5)
    times = []
    for i in range(iters + warm):
        t0 = time.perf_counter()
        if mode == "serial":
            for u in urls:
                r = await c.post(u, json=ENV); r.json()
        else:
            rs = await asyncio.gather(*[c.post(u, json=ENV) for u in urls]); [r.json() for r in rs]
        if i >= warm: times.append((time.perf_counter() - t0) * 1000)
    await c.aclose()
    return pct(times, .5), pct(times, .95)
async def main():
    for n in (3, 7, 10):
        for mode in ("serial", "parallel"):
            p50, p95 = await run(mode, n)
            print(f"N={n:2d} separate gate processes, {mode:8s} p50={p50:6.2f} ms p95={p95:6.2f} ms", flush=True)
asyncio.run(main())
