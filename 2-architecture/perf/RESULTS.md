# Enforcement latency: raw results

Output of `python3 2-architecture/perf/perf_enforcement.py` on 2026-10-04, Intel Xeon @ 2.10GHz, 4 vCPU, 15 GB RAM. Samples: 2000 per in-process row, 200-1000 per HTTP row.
The JEV judge is simulated (jev_sim.py sleeps 40-130 ms), so rows with JEV measure the architecture around it, not a model. Read the interpretation in [../README.md](../README.md#performance).

Machine: Linux-6.18.44-fc-v64-x86_64-with-glibc2.39, 4 vCPU, Python 3.11.15

A. Deterministic controls, in-process (poc/gateway.py), per call
| Control | short prompt p50 | p95 | long prompt (4 KB) p50 | p95 |
|---|---|---|---|---|
| auth | 0 µs | 0 µs | 0 µs | 0 µs |
| model_allowlist | 1 µs | 2 µs | 1 µs | 2 µs |
| budget | 1 µs | 1 µs | 1 µs | 1 µs |
| clamp_max_tokens | 1 µs | 1 µs | 1 µs | 1 µs |
| signatures | 43 µs | 62 µs | 1.3 ms | 1.4 ms |
| pii | 22 µs | 31 µs | 549 µs | 580 µs |
| system_prompt | 0 µs | 0 µs | 0 µs | 0 µs |
| **whole request pipeline, guard off** | 78 µs | 105 µs | 1.8 ms | 1.9 ms |
| response pipeline (strip exfil link + redact PII) | 35 µs | 50 µs | | |
(10 feed rules loaded)

B. Semantic check as a separate service (poc/guard_svc.py over HTTP)
| Call | p50 | p95 | n | note |
|---|---|---|---|---|
| new HTTP client per call (poc today) | 39.7 ms | 53.7 ms | 200 | client setup dominates |
| one shared HTTP client | 1.6 ms | 2.2 ms | 1000 | the network hop itself |

C. poc/ gateway end to end, client-observed (includes the mock model)
| Path | p50 | p95 | n | note |
|---|---|---|---|---|
| deterministic block (SIG-0012), no model call | 1.8 ms | 2.5 ms | 1000 |  |
| allowed, deterministic controls only | 43.7 ms | 55.7 ms | 1000 | guard disabled |
| allowed, + semantic guard service | 88.1 ms | 110.5 ms | 1000 | guard enabled (default) |

D. claude-proxy/ (Claude traffic), client-observed
| Path | p50 | p95 | n | note |
|---|---|---|---|---|
| L2 deterministic block (model not allowed) | 1.5 ms | 2.3 ms | 1000 | no JEV, no upstream |
| L2 allowed, JEV off | 52.8 ms | 67.7 ms | 333 | L2 + L3 + TLS to mock upstream |
| L2 allowed, JEV on | 222.4 ms | 245.7 ms | 333 | JEV is simulated: 40-130 ms sleep |
| full path L1 -> L2 -> JEV -> L3 -> upstream | 268.0 ms | 300.0 ms | 250 | two TLS sessions |
