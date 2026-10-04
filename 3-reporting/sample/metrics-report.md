# Clearance metrics report
28 requests from poc (15), claude-proxy (13), 2026-10-04 07:18:52 to 07:18:58 UTC.

## For management

| Metric | Value |
|---|---|
| Requests | 28 |
| Let through | 11 (39%) |
| ...of which rewritten on the way (modify) | 6 |
| ...of which flagged for review | 2 |
| Blocked | 17 (61%) |
| Errors (upstream failed) | 0 |
| Spend, Claude traffic (USD) | $0.008276 |
| Tokens charged | 3,757 |
| Time in poc, p50 / p95 | 41 ms / 88 ms |
| Time in claude-proxy, p50 / p95 | 156 ms / 212 ms |

### Per user

| User | Requests | Blocked | Flagged | USD | Tokens |
|---|---|---|---|---|---|
| (unknown key) | 2 | 2 | 0 | $0.000000 | 0 |
| alice | 21 | 13 | 2 | $0.001508 | 587 |
| bob | 3 | 1 | 0 | $0.006768 | 3,096 |
| judge | 2 | 1 | 0 | $0.000000 | 74 |

## For security

### Blocks by gate

| Gate | Blocks | Example reason |
|---|---|---|
| jev | 3 | JEV 78.8% >= 70% |
| guard | 2 | score 0.90 vs threshold 0.7 ['ignore previous instructions', 'system prompt'] |
| model_allowlist | 2 | model 'ollama/qwen3:8b' not allowed for alice (allowed: ['mock/echo']) |
| signatures SIG-0012 | 1 | SIG-0012 s1ngularity AI-CLI recon prompt + IOCs (prompt) |
| signatures SIG-0018 | 1 | SIG-0018 Content-safety topic pack EN+PL (malware creation, weapons, self-harm, investment |
| signatures SIG-0001 | 1 | SIG-0001 Invisible Unicode tag-character smuggling (prompt) |
| auth | 1 | unknown or missing API key |
| guard (unavailable, fail closed) | 1 | guard service unavailable (ConnectError), on_error=closed |
| pii | 1 | 1x EMAIL in request |
| cost_cap | 1 | worst-case $0.6401 > cap $0.50 |
| identity | 1 | unknown virtual key |
| budget | 1 | budget: $0.0068 + $0.0081 > $0.0130 |
| jev (unavailable, fail closed) | 1 | JEV unavailable, fail closed |

### Attack signatures from the external feed

| Rule | Action | Hits |
|---|---|---|
| SIG-0001 | block | 1 |
| SIG-0002 | modify | 1 |
| SIG-0009 | monitor | 2 |
| SIG-0012 | block | 1 |
| SIG-0016 | monitor | 1 |
| SIG-0018 | block | 1 |

### Personal data

| Entity | Redacted | Blocked | Seen (monitor) |
|---|---|---|---|
| CARD | 1 | 0 | 0 |
| EMAIL | 2 | 1 | 0 |
| IBAN | 1 | 0 | 0 |
| PL_PESEL | 2 | 0 | 0 |

### For review (allowed, but flagged)

| Time (UTC) | User | Gate | Detail |
|---|---|---|---|
| 07:18:52 | alice | signatures | SIG-0009 Jailbreak families EN (DAN / Policy Puppetry / Skeleton Key) (prompt) |
| 07:18:56 | alice | jev | score 43.2% ['malware'] |

### Availability and policy

| Metric | Value |
|---|---|
| Requests refused because a checker was down (fail closed) | 2 |
| Requests decided by policy `487d974af7b2` | 13 |
| Requests decided by policy `1094484e801d` | 1 |
| Requests decided by policy `3078409c8163` | 1 |
