import asyncio, time, sys, statistics, httpx, json
async def run(url, mode, n, c, max_tokens=200, delay=0.0, secret_at=None):
    lim = httpx.Limits(max_connections=c, max_keepalive_connections=c)
    ttfb, tot, blocked = [], [], 0
    async with httpx.AsyncClient(timeout=60, limits=lim) as cl:
        sem = asyncio.Semaphore(c)
        async def one():
            nonlocal blocked
            async with sem:
                body = {"model": "mock", "stream": True, "max_tokens": max_tokens, "mock_delay": delay, "messages": [{"role": "user", "content": "hi"}]}
                if secret_at is not None: body["mock_secret_at"] = secret_at
                t = time.perf_counter(); first = None; text = ""
                async with cl.stream("POST", url + "/v1/chat/completions", json=body, headers={"x-mode": mode}) as r:
                    async for line in r.aiter_lines():
                        if line.startswith("data: ") and first is None: first = time.perf_counter() - t
                        if '"error"' in line: blocked += 1
                tot.append(time.perf_counter() - t); ttfb.append(first)
        await one()  # warm-up
        ttfb.clear(); tot.clear(); blocked = 0
        t0 = time.perf_counter()
        await asyncio.gather(*[one() for _ in range(n)])
        wall = time.perf_counter() - t0
    q = lambda xs, p: sorted(xs)[int(len(xs) * p) - 1] * 1e3
    return dict(rps=n / wall, ttfb_p50=q(ttfb, .5), ttfb_p99=q(ttfb, .99), total_p50=q(tot, .5), total_p99=q(tot, .99), blocked=blocked)
if __name__ == "__main__":
    url, mode, n, c = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
    extra = json.loads(sys.argv[5]) if len(sys.argv) > 5 else {}
    r = asyncio.run(run(url, mode, n, c, **extra))
    print(json.dumps({"url": url, "mode": mode, "n": n, "c": c, **extra, **{k: round(v, 2) for k, v in r.items()}}))
