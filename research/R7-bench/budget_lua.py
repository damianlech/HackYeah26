"""Reservation-then-settle budget ledger on Redis/Valkey with one Lua script per phase.
Keys: one counter per (scope, period), e.g. {acme}:spend:user:alice:2026-10-03 (micro-USD integers).
The {acme} hash tag keeps all of a tenant's counters in one cluster slot, so the multi-key script is cluster-safe.
"""
import asyncio, time, statistics, uuid, redis.asyncio as redis

RESERVE = """
-- KEYS: counters to check; ARGV[1]=amount, ARGV[2]=ttl_seconds, ARGV[3..]=limits (same order as KEYS)
local amt = tonumber(ARGV[1])
for i, k in ipairs(KEYS) do
  local cur = tonumber(redis.call('GET', k) or '0')
  local lim = tonumber(ARGV[i+2])
  if lim >= 0 and cur + amt > lim then
    return {0, i, cur, lim}          -- denied: which scope breached, its usage and limit
  end
end
for i, k in ipairs(KEYS) do
  redis.call('INCRBY', k, amt)
  if redis.call('TTL', k) < 0 then redis.call('EXPIRE', k, tonumber(ARGV[2])) end
end
return {1, 0, 0, 0}
"""
SETTLE = """
-- ARGV[1] = actual - reserved (may be negative: refund unused reservation)
local d = tonumber(ARGV[1])
for _, k in ipairs(KEYS) do redis.call('INCRBY', k, d) end
return 1
"""

async def main():
    r = redis.Redis(port=6390)
    await r.flushall()
    reserve = r.register_script(RESERVE); settle = r.register_script(SETTLE)
    keys = ["{acme}:spend:org:2026-10", "{acme}:spend:team:quant:2026-10", "{acme}:spend:user:alice:2026-10-03"]
    limits = [10_000_000_000, 1_000_000_000, 50_000_000]   # micro-USD: $10k, $1k, $50
    lat = []
    async def one():
        t = time.perf_counter()
        ok = await reserve(keys=keys, args=[2000, 86400*40, *limits])
        await settle(keys=keys, args=[-500])
        lat.append(time.perf_counter() - t)
        return ok
    for N, C in ((5000, 1), (20000, 16), (20000, 64)):
        await r.flushall(); lat.clear()
        sem = asyncio.Semaphore(C)
        async def guarded():
            async with sem: return await one()
        t0 = time.perf_counter()
        res = await asyncio.gather(*[guarded() for _ in range(N)])
        dt = time.perf_counter() - t0
        lat.sort()
        denied = sum(1 for x in res if x[0] == 0)
        print(f"reserve+settle pairs: {N} @ concurrency {C}: {N/dt:,.0f} pairs/s; per pair p50 {statistics.median(lat)*1e3:.2f} ms p99 {lat[int(N*0.99)]*1e3:.2f} ms; denied={denied}")
    print("user counter after run (micro-USD):", await r.get(keys[2]), "limit", limits[2])
    # Race test: 200 concurrent reservations of $1 against a $50 user cap -> exactly 50 must pass
    await r.flushall()
    sem2 = asyncio.Semaphore(50)
    async def g2():
        async with sem2: return await reserve(keys=keys, args=[1_000_000, 3600, *limits])
    res = await asyncio.gather(*[g2() for _ in range(200)])
    print("race test: allowed", sum(1 for x in res if x[0]==1), "of 200 (expected 50)")
    await r.aclose()
asyncio.run(main())
