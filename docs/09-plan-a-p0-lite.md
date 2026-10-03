# 09 · Plan (a) "P0-lite": what we build if the deadline is 11:00 on 4 October

> **Status:** proposal for the H0 kickoff (2026-10-03, ~18:00 CEST). Owner: L. Applies only to scenario (a) of `design/VISION-SPEC.md` §13.4 (deadline 11:00 Oct 4, freeze H11, submit H15). It runs until Q2 confirms the deadline in writing.
> **Inputs:** VISION-SPEC v1.1 §0, §4, §5.4-5.7, §6, §8, §9, §10, §12, §13 (esp. the §13.4 re-baseline table, §13.2 WPs and loads, §13.3 P1, §13.6 cut lines and the never-cut list); `docs/00-task-analysis.md` (R1-R6, D1-D4, rubric); `docs/04-lane-cards.md`; the POC in `poc/` (`gateway.py`, `guard_svc.py`, `mock_llm.py`, `policy.yaml`, `demo.sh`, `README.md`, `WALKTHROUGH.md`).
> **Precedence:** the spec stays canonical. This file only says which parts of spec P0 we ship, simplify or label "designed" under plan (a). Control IDs are the spec's `C01`-`C36`.
> **Reading order at kickoff:** §1 (5 min), then your lane table in §3.

---

## 1. Verdict

1. **Full P0 does not fit.** Spec P0 is 79.5 h (§13.2). Plan (a) has about 54 h of build time: 6 people × 9 h between the end of kickoff (H0:30) and the freeze (H11), after ~1.5 h of meals, breaks and stand-ups (§13.4). That is **147%** of capacity. The §13.6 never-cut list alone needs about **68 h (126%)** of the §13.2 work packages (see the footnote). D's serial gate chain (D1 → D2a → D3a → D5a → D4) is 9.0 h, a whole person's window with no slack.
2. **So plan (a) needs P0-lite, not just cuts 1-5.** P0-lite keeps every formal requirement (R1-R6) and deliverable (D1-D4), the C24/C33 detectors-off guarantee and the ★ beats. To fit, it also simplifies some never-cut items: no load balancer, streaming in buffer mode only, a thin MCP proxy, one classifier and a console reused from the mockup. The pitch states each simplification (§2.3).
3. **Strategy: evolve the POC (a strangler approach) instead of restarting.** The POC already works as the IC1 walking skeleton. It covers about 5 h of §13.2 work, and the demo runs at every hour from H0.
4. **The POC's gaps against the contracts are known, bounded and fixed first** (§1.2). They are: 403 instead of `content_filter`, `X-Mandate-*` headers, control names outside the spec, Python `re`, no strict schema, `/control/*` on the data port, no hash chain and a check-then-charge budget. The fixes are tasks A0 (H1:45), B1 and C1 (H2:30), A2 (H4:00) and B4 (H6:30). A0 lands before anyone else edits gateway code.
5. **Recommendation:** P0-lite on the POC uses the 54 h like this: **45.25 h of build, 1.75 h of stretch, 5.0 h of tests/demo/submission and 2.0 h of reserve.** The **guarantee gate is at H9 (03:00)**, 1.5 h before the spec's merged IC3/IC4 at H10:30. Freeze is at H11 and submission at H15. If the deadline turns out to be 23:00, we grow the same code additively (§5).

<sub>Footnote: the never-cut list (§13.6) priced with §13.2 WPs: L 12.0 (all but L6) · A 13.0 (all but A7) · B 13.0 (all; B7 without policy history) · C 9.0 (C1, C2, C3, the C10 half of C4, the race half of C6) · D 12.25 (all but vault, filesystem, path/amount validators and C31) · F 9.0 (F1, F2, F3, F5) = **68.25 h**. Update after the never-cut list was widened (lead decision, 2026-10-03): add the C4 topic-pack half (~1.25 h), C5 at cut-line-6 level (~1.5 h), the F6 KPI tiles (~1.0 h) and F7 (1.0 h). Export + Verify were already inside B7. New total **≈ 73 h (estimate)**, still about 135% of the ~54 h available, which is why §2 builds on `poc/`.</sub>

### 1.1 Strangler on the POC vs spec architecture from scratch

| | (i) Evolve the POC (strangler, **recommended**) | (ii) Spec architecture from scratch |
|---|---|---|
| Runs end to end | At H0, and at every checkpoint after it | First at IC1 (spec H5; realistically H5-H6) |
| Work already done | ≈ 5 h of §13.2 work: the mock LLM (part of A1); hot reload + LKG (part of A2); the pipeline engine (part of A4); regex/keyword/url_ioc rules + per-rule vectors + skipped-type listing (part of B3); PESEL/Luhn PII (part of B6); a remote guard with `on_error: closed` (part of C3); the `max_tokens` clamp (part of C2) | 0 h. Those ≈ 5 h are built again |
| Contract conformance on day 1 | No. It needs the realignment in §1.2: A0, B1 and C1 by H2:30, A2 by H4:00, B4 by H6:30 | Yes, by construction |
| Merge risk | High in the first hour: one 444-line `gateway.py`. **Mitigation:** A0 splits it into modules by H1:45, and nobody else edits gateway files before then | Low: one owner per new file |
| Gate timing | D builds the MCP chain against a running gateway from H0:30. Gate at **H9**, with 1.5-2 h of buffer | Gate at H10:30 (spec plan (a)) with zero buffer, because D's chain is 9 h |
| Main risk | POC shortcuts survive into the product (403 blocks, Python `re`, post-hoc budget). **Mitigation:** the first tasks of A, B and C replace them, and tests assert the spec contract, not POC behaviour | Nothing runs until ~H5. Six AI assistants generate code against paper contracts, so integration surprises land at H5-H7 |
| Growth into plan (b) | Additive (§5) | Additive and slightly cleaner, but it starts ~5 h behind |

**Decision:** (i). We tag `poc-v0` at H0:25 and A0 moves the code into the spec layout (§3.9 names) with `git mv`, so history is kept. `poc/README.md` and `poc/WALKTHROUGH.md` stay as the record of `poc-v0`.

### 1.2 What the POC gives vs what the spec contracts require

| Area | POC today (file:line) | Spec contract | P0-lite fix (task) |
|---|---|---|---|
| Data-plane API | `/v1/chat/completions` (non-stream; `stream` forced to `False`, `gateway.py:354`), filtered `/v1/models` | §11.2: adds `/v1/me`, `/v1/runs`, `/mcp/{server}`, `/v1/artifacts/scan`, and streaming | A4, A5, D1, C6 |
| Block semantics | HTTP 403 `policy_violation` (`gateway.py:374`) | §5.7: a content block is 200 + `finish_reason: content_filter`; typed 400/401/413/429/503 | A0 |
| Headers | `X-Mandate-Decision/Policy/Event` (`gateway.py:384`) | `x-aicl-decision`, `x-aicl-event-id`, `x-aicl-policy: v18/3f2a9c1`, `x-aicl-replica`, `x-aicl-run`, `Server-Timing` | A0 |
| Control names | `pii`, `guard`, `signatures`, `budget` (`policy.yaml`) | §6.2 keys (`C07_pii`, `C10_injection`, …); audit `controls[].id` matches `^C[0-9]{2}$` | A0 |
| Policy validation | checks only for required top-level keys (`gateway.py:62`), so a typo key `enabeld:` is silently accepted | pydantic `extra="forbid"`, YAML path in the error, versions + heartbeats (C30) | A2 |
| Pattern engine | Python `re` for feed patterns, plus a `\x{…}` translation hack (`gateway.py:102`) | `google-re2` for every policy or feed pattern (CLAUDE.md rule 2; the ReDoS answer) | B4 |
| Reload | checks mtime on each request (`gateway.py:49`) | watch + 1 s sha poll; applies without traffic; 2/2 replicas | A2 |
| Audit | plain JSON lines, no seq or hash (`gateway.py:337`) | `aicl.audit/v1`, per-replica hash chain, verify (C25) | B1 |
| Budget | in-memory dict, check then charge (`gateway.py:147, 208, 223`), which overshoots under concurrency | Valkey Lua reserve → settle (C03, §7.3) | C1 |
| Guard | keyword sum (`guard_svc.py`); synchronous `httpx.post` (`gateway.py:298`); `on_error` exists only for the guard | `/v1/inspect`, a windowed classifier, a fail mode for every control (C10, C32) | C2, A6 |
| Control plane | `/control/*` on :8080 with no auth. `PATCH` rewrites `policy.yaml` and drops its comments (`gateway.py:420-431`) | C35: a separate service with an admin token. Console toggles are P1 | A0 deletes the routes; L4 builds `control` |
| Feed | read from disk next to the policy (`gateway.py:128`); vectors run and unknown types are listed (good) | a separate signed service with serial and expiry (C19, §8.2) | B5 |
| PII | EMAIL, PESEL checksum, IBAN (no mod-97), CARD Luhn | adds NIP, phone and IBAN mod-97; placeholders `[PL_PESEL] [IBAN] [PAN] [EMAIL]` (§11.6) | B6 |
| Agents, MCP, runs, taint | none | C14-C16, C24, C33, C31 | A4, A7, D1-D5 |
| Tests | `demo.sh` (10 scenarios) + `WALKTHROUGH.md` (16) | hermetic `make test` with YAML cases (§10) | L3 (the POC scenarios become `tests/cases/poc_*.yaml`) |
| Containers and fence | none | compose networks + fence probe (C13) | L2 |

---

## 2. P0-lite scope

### 2.1 Budget (person-hours, before freeze)

| Bucket | Hours | Notes |
|---|---|---|
| Build (committed) | **45.25** | Includes each control's YAML cases (≈ 1.5 h). The rule stays "no case, no merge" |
| Stretch (only if the lane is green at H6) | 1.75 | C bench 0.5 · B signed checkpoints 0.75 · A C27 canary 0.5 |
| Tests / demo / submission | **5.0** | invariants, storyline, README/JUDGES, race test, scripted agent, diagram, placeholder + PDF v0, dry run |
| Reserve | 2.0 | L 0.5 · A 0.25 · C 0.25 · D 0.75 (gate buffer) · F 0.25 · B 0 |
| **Total** | **54.0** | 6 × 9 h; no lane is above 9.0 h (§3) |

Build plus stretch is 47.0 h (≤ 48). Tests/demo/submission is 5.0 h in lanes plus ≈ 1.5 h of cases inside the build estimates, so about 6 h.

### 2.2 Control-by-control scope (spec §4 IDs)

KEPT = as in spec P0. LITE = simplified. STRETCH = only if the lane is green at H6. P1 = as the spec already says. The pitch wording for every LITE or missing item is in §2.3.

| ID | Spec P0 | P0-lite | Owner (task) |
|---|---|---|---|
| C01 | vk + JWT/JWKS; agents as principals | **LITE**: hashed virtual keys for users, services and agents (owner, cost centre, `enabled`). JWT cut | A (A4) |
| C02 | allowlist, default deny, hint, filtered `/v1/models` | **KEPT**: POC allowlist + user ∩ agent + hint "granted to groups: …" | A (A4) |
| C03 | Valkey Lua reserve/settle, 5 scopes, 3 units + tool units, leases | **LITE**: Valkey Lua reserve/settle over `org:`/`pool:`/`seat:`/`agent:` in tokens, µUSD (`sim/*`) and compute-ms (`ollama/*`). No tool units, warn thresholds or leases. Ledger down → 503 for all models (fail closed) | C (C1) |
| C04 | hygiene + GCRA rate + concurrency leases | **LITE**: `max_tokens ≤ 0` → 400, clamp (POC), `n` clamp, Ollama `options` stripped, 413 size cap, fixed-window rpm in Valkey | C (C3) |
| C05 | per-run counters, identical-call hash, wall clock, run USD | **LITE**: max tool calls + identical `sha256(tool‖JCS(args))` ≥ 3 → `run_circuit_open` | C (C4) |
| C06 | ~30 gitleaks-derived patterns + entropy | **LITE**: ~10 RE2 patterns + an entropy gate → `[SECRET:<kind>]` | B (B3) |
| C07 | checksum PII + PL false-positive guards, tool args | **KEPT**: the POC plus IBAN mod-97, NIP, phone, per-entity action, tool args | B (B6) |
| C08 | 6 views, `confusables.txt` | **LITE**: views `stripped`, `tag_decoded`, `nfkc`, `folded` (POC), `decoded` (b64/hex, depth 2). A small homoglyph map instead of the full TR39 table | B (B2) |
| C09 | feed regex + keyword over every view, EN+PL | **KEPT** (RE2 instead of `re`) | B (B4) |
| C10 | windowed classifier + multilingual kNN | **LITE**: protectai-v2 INT8 ONNX over sliding windows (EN), with `GUARD_ENGINE=stub` (the POC scorer) for `make test`. kNN cut | C (C2) |
| C11 | topic pack + knn-harm; guard-LLM is P1 | **LITE**: topic pack only (SIG-0018 via the feed, already working in the POC) | B (B4) |
| C12 | URL extraction in streaming holdback + entropy flag | **LITE**: link stripping on the buffered response (POC SIG-0002). Entropy flag cut | B/A |
| C13 | compose `internal` networks + fence probe | **KEPT, CONDITIONAL**: we claim only what the H1 probe proves (§3.4 ladder) | L (L2, L8) |
| C14 | registry, risk ceiling, jsonschema, path, ssrf, url, sql, email, amount, IBAN, DLP | **LITE**: registry, labels, risk ceiling/floors, `ssrf`, `url_allowlist`, `sql` (sqlglot `LIMIT` → modify), `email`, DLP on args; **one `decide()` for both edges**. Path, amount and IBAN validators cut (no such tools in the demo) | D (D3) + A (A7) |
| C15 | pins, description scan, cross-server refs, floors | **LITE**: JCS pins in Valkey, SIG-0003 scan, quarantine + old/new diff, floors. Cross-server refs cut | D (D5) |
| C16 | result scan + label taint | **KEPT** | D (D4) |
| C17 | feed code-guard pack on tool args | **KEPT** (SIG-0017) | D hook / B rules |
| C18 | pickle walk, torch zip, safetensors, hashes, fail closed | **KEPT lite** (§13.6 cut 6, pickle only, is the fallback) | C (C6) |
| C19 | Ed25519, persisted serial, expiry, vectors, local overrides | **LITE**: signed and served by a separate `feed` process; serial persisted in Valkey; expiry → stale; vectors gate activation. Local unsigned overrides (§8.3) cut | B (B5) |
| C20 | `http_request` hard exclusions + Ollama-admin floor | **KEPT** | B (B4) rules, D (D3) hook |
| C23 | P1 | P1: `ask` = block "approval required (C23 not enabled)" | — |
| C24 | run taint + Rule of Two + provenance, full §5.6 matrix | **KEPT, full**: all three profiles, spoof, derived-trusted, fallback run | D (D4) |
| C25 | per-replica chain + signed checkpoints held outside the writer | **LITE**: per-replica chain + `verify`. Signed checkpoints are STRETCH | B (B1, B7) |
| C26 | kill switch | **KEPT** | A (A4) |
| C27 | canary token | **STRETCH** (the POC `system_prompt` step makes it cheap) | A (A8) |
| C30 | strict schema, RE2, vectors, LKG, versions, heartbeats, `control_weakened` | **KEPT lite**: no `/api/policy/history`. `policy_change` events (with `weakened[]`) appear in Threats | A (A2) |
| C31 | honeypot → kill run + quarantine agent | **KEPT** (0.25 h inside D5) | D (D5) |
| C32 | `fail:` per control | **KEPT** (generalises POC `guard.on_error`) | A (A6) |
| C33 | run tokens + ingress-anchored trusted text | **KEPT** | A (A4) token, D (D4) state |
| C35 | admin plane separated | **KEPT**: a separate process, port and token (plus the `admin` network in compose); the data plane returns 404 on `/api/*`, `/admin/*`, `/control/*` | L (L4) + A (A0) |
| C36 | multimodal deny for agents | **KEPT** | A (A4) |

Shipped: 29 of the spec's 30 P0 controls (C01-C20, C24-C26, C30-C33, C35, C36); C27 is the 30th if the stretch lands. Each has ≥ 1 POS and ≥ 1 NEG case. C07 and C24 meet the spec's ≥ 2 NEG.

### 2.3 Platform items: cut or simplified, with the honest wording

**Rule for every slide and answer:** an item is either **shipped** (it is in `make test`) or **designed** (cite the spec §). There is no third category.

| Spec P0 item | P0-lite | What we say in the pitch |
|---|---|---|
| 2 replicas behind Caddy (§3.2) | **Two gateway processes** (`gw-1`, `gw-2`) sharing Valkey. No load balancer: the agent talks to `gw-1`; the race and reload tests hit both | "Two stateless replicas share budgets, runs, pins and policy versions through Valkey. The race test fires 200 requests across both and admits exactly 50. In the demo the agent talks to one replica directly; the Caddy load balancer is designed, not shipped." |
| … if Valkey Lua is red at H6 (pre-decided fallback) | `LocalLedger` (an in-process `asyncio.Lock`, same interface), **one** replica | "One replica in the demo. Reserve → settle is atomic in-process. The multi-replica Valkey Lua ledger is designed (§7.3)." We never say "Valkey ready" unless the Lua script passes its tests |
| Caddy `lb` | Dropped. In compose, the gateways are the only hosts on the `agents` network | "The only host on the agents' network is the gateway." |
| `control` service with DuckDB, SSE, checkpoints, exports | A **separate FastAPI process** on 127.0.0.1:3000 with an admin bearer token, on the `admin` network in compose. Plain Python over the tailed JSONL (no DuckDB) | "The control plane is a separate service. Agents have no route to it, and the data plane has no admin routes (tested). If it dies, enforcement and audit continue." |
| C13 fence via `internal` networks | Kept **only as far as the H1 probe proves** | Probe green: "From inside the agent container, Valkey, control, guard, the MCP servers, the mock and the internet are unreachable (`make fence`)." Host leak: add "On Docker Desktop the host's Ollama is reachable; that is residual T5 (§14.2)." Compose broken entirely: "Fence designed (§3.4); not demonstrated today." |
| Streaming with trigger-aware holdback (§5.5) | **Buffer mode only** (`stream_mode: buffer`, the spec's strict default and IC2 fallback): scan the whole answer, then emit OpenAI SSE | "Streaming clients work in buffer mode: we scan the full answer, then stream it. The low-latency holdback is designed (§5.5), so time to first token equals generation time today." |
| MCP edge: FastMCP or a thin proxy, sandbox containers | A **thin JSON-RPC proxy** (`initialize` answered locally, `tools/list`, `tools/call`, JSON responses). One `mcp-demo` process on the `sandbox` network serving six servers: web, crm, bankdb, mail, facts, vault | "The MCP edge speaks the JSON-RPC core of Streamable HTTP for six sandboxed servers. SSE sessions and C34 protocol hardening are designed." |
| Semantic tier: classifier + multilingual kNN | **protectai-v2 ONNX classifier** (Apache-2.0, ungated) over sliding windows; the stub engine for tests | "One local injection classifier, in English, scans every prompt and tool result. Polish attacks are caught by the deterministic Polish packs, not by the classifier. We don't claim classifier recall on indirect injection: the guarantee is C24. Multilingual kNN is designed." If ONNX is red at H6: "Today the semantic tier is a keyword stub (header says DEGRADED)", and we drop "AI-based" from the slides |
| JWT/JWKS identity | Cut. Hashed virtual keys only | "Groups live in the policy file today. Mapping the JWT `groups` claim is designed (§2.3) and is our first add-back." |
| Valkey with ACL users | `requirepass` only | (no claim about ACLs) |
| Console: React 19 + shadcn, 4 pages | **`mockups/dashboard.html` reused** (vanilla JS, no build step, works offline) and wired to live endpoints: header, Threats + drawer (Trace/Run/Evidence/Integrity), Playground, Overview-lite (KPIs, spend tiles, posture, controls + self-test table) | "Four live views. The coverage grid, spend burn-down, policy history and Agents & MCP pages are designed." |
| Coverage grid (§9.4) | Cut. Every event carries OWASP/ATLAS tags; the README has the control → framework table | "Every decision is tagged with OWASP 2026 and ATLAS IDs. The computed coverage grid is designed." |
| Posture (§9.3) with 4 sub-scores and a measured column | **Posture lite**: Σ w·E·M·V / Σ w with the critical-gate cap of 70. No health sub-score and no measured column | "Posture is computed from what the replicas loaded and from the last live self-test." |
| Live self-test (§10.4) | **Kept lite**: PASS / GAP / FAIL / ERROR, plus EXPOSED for `attack: true` cases when the control is relaxed; re-runs on every reload | as in the spec |
| `make bench` (P1 #1) | **STRETCH** (C8, 0.5 h) | If shipped: quote only `reports/perf.md`. If not: "We show per-request stage timings (`Server-Timing`); a benchmark is next." |
| Prometheus metrics | Cut | "Stage timings are in every response header and audit event; Prometheus is designed." |
| Signed audit checkpoints | **STRETCH** (B7) | Shipped: as in the spec. Not shipped: "verify finds an edited or deleted line. A full-chain rewrite or tail truncation needs the signed checkpoints, which are designed (§9.2)." |
| Local unsigned feed overrides (§8.3) | Cut | "Judges add rules through the signed publish step (`make feed-publish`)." |
| Policy toggles from the console | Cut (they are P1 anyway). The POC `PATCH` is removed | "Judges edit `policy/policy.yaml`. The console shows the result within 2 s." |
| `tools/seed.py` synthetic history | Cut. `make demo-warmup` replays the storyline, so the Threats page shows real events | "Every row you see is a real decision." |
| Exploit Museum cards | Cut. E1-E10 are YAML cases | "Ten historical attacks are replayed in `make test`." |
| CI on GitHub Actions | Optional: L adds it only if L's reserve is unused | — |

### 2.4 R1-R6 and D1-D4: each one still met

| Req | Minimal P0-lite evidence | Beat | Test |
|---|---|---|---|
| R1 central policy | one `policy/policy.yaml` (seeded from `examples/policy.yaml`): strict schema, profiles `permissive/balanced/strict`, `block_at`/adherence, model allowlists, budgets; reload < 2 s on 2/2 with LKG and the YAML path in the error | 5 | `tests/integration/test_hot_reload.py` |
| R2a deterministic | C01, C02, C06, C07, C08, C09, C12, C14, C17, C20 with rule IDs in the trace | 1, 2 | `tests/cases/c0[1-9]_*.yaml`, `c1[247]_*.yaml`, `c20_*.yaml` |
| R2b semantic | C10 classifier score vs threshold in the Playground | **2 + insert 2b** | `tests/cases/c10_injection.yaml` (stub engine) + one ONNX smoke test |
| R3 budgets | C03 in tokens / µUSD / compute-ms, C04, C05; 429 with zero upstream calls; race across 2 replicas | 1 | `tests/integration/test_budget_race.py`, `c03_budget.yaml` |
| R4 historical attacks | signed feed from a separate process (C19), C09/C17/C20 rules, C18 pickle gate, C15 rug pull | **8-lite ★**, 4 | `tests/integration/test_feed.py`, `tests/cases/museum_e*.yaml` |
| R5 reporting | hash-chained audit + verify; JSONL/CSV export; Threats with decision trace (security); Overview-lite KPIs, spend and posture (management) | 4, 10 | `tests/integration/test_audit_chain.py`, `test_export.py` |
| R6 self-testing | hermetic `make test` (compose, stub guard, mock LLM), POS+NEG for every shipped control incl. budgets and exploits; live self-test with GAP vs FAIL | 10 | the suite + `tests/test_meta.py` |
| D1 diagram | P0-lite architecture diagram (README + slide 3) | 0 | — |
| D2 sample config | `policy/policy.yaml` with three profiles, group budgets and comments (from `examples/policy.yaml`) | 5 | schema test on the file |
| D3 dashboard | header + Threats + Playground + Overview-lite (controls, posture, blocked threats, cost) | 2, 4, 10 | `tests/e2e/test_demo_storyline.py` asserts the API side |
| D4 executable tests | `make test` plus the raw `docker compose … --exit-code-from tests` command (README first screen) | 10 | clean room at H12:30 |

### 2.5 Storyline for plan (a)

This is the spec's ★ beats (§12; 8-lite became a ★ beat in the lead's final review) plus the short insert 2b, so that R2b and R4 are visible on stage. The storyline test asserts all of them.

| Beat | What changes vs §12 |
|---|---|
| 0 ★ | P0-lite architecture slide (gw-1/gw-2, Valkey, guard, feed, control, mcp-demo, mock) |
| 1 ★ | as in the spec; `make fence` shows what the probe proved |
| 2 ★ + **2b** (15 s) | as in the spec, plus one Playground chip with a paraphrased injection: `C10 pi-classifier 0.9x ≥ 0.80` blocked |
| 4 ★ | as in the spec, driven by `tools/demo_agent.py` on the host terminal |
| 5 ★ | as in the spec; the header shows `v{n} · 2/2 replicas · applied 0.x s`, posture ▼ and self-test GAP. There is no coverage-cell colour |
| **8-lite** ★ (30 s) | `make feed-publish` adds SIG-9001: header `feed #N ✓`, the next request is blocked; `aicl scan evil.pt` → blocked |
| 10 ★ | as in the spec. The perf strip appears only if the bench stretch shipped |
| 11 ★ | adoption slide + residual risks + one line: "everything shown is in `make test`; anything marked 'designed' is not shipped" |

---

## 3. Lanes, interfaces and checkpoints for scenario (a)

### 3.0 H0:00-H0:30 kickoff (all six)

- **0:00-0:10, L:** the verdict (§1). Ask the organisers Q2 (the deadline) in writing. Plan (a) runs until the answer arrives.
- **0:10-0:20, everyone:** read your lane table below and confirm the interfaces (§3.1).
- **0:20-0:30:** L tags `poc-v0` and starts the fence probe on both demo Macs (by name and by raw host IP, §3.4). C pulls `valkey/valkey:8` and checks the protectai ONNX asset. F opens the mockup.
- **Rule until H1:45:** nobody edits `src/aicl/gateway/*` except A (A0). Everyone else builds new modules against the stubs in `contracts/interfaces.md`.

### 3.1 Interfaces frozen at H1 (`contracts/interfaces.md`; stubs by H1:30)

| Interface | Owner | Used by |
|---|---|---|
| `Finding{id: "C07", name, mode, verdict, rule_id, score, threshold, detector, view, origin, ms}` and `Ctx` (from the POC `Ctx`) | A | all |
| `scan_text(text, surface, ctx) -> (text', findings, revealed)`: views + C06/C07/C09/C10/C11 | A (signature), B (body) | A (LLM in/out), D (MCP args/results) |
| `destinations.extract(views) -> set[Dest]`, `canonical(d)`, `skeleton(d)` | B | A (`/v1/runs`), D (C24) |
| `runs.mint/resolve`, `RunState.taint/add_dest/mark_private_read`, `runs.describe(run_id)` | D (state), A (HMAC token) | A, D, C5 (`/api/runs`) |
| `tools.decide(tool, args, run, edge) -> Decision{verdict, rule_id, args', reason}` | D | D (MCP), A (LLM-tc) |
| `ledger.reserve(scopes, units)` / `ledger.settle(res, actual)`; `breakers.check(run, tool, args)` | C | A, D |
| `guard.inspect(views, surface) -> {score, detector, windows, ms}` or `GuardError` | C | A, D |
| `audit.emit(event)` (queue), `audit.verify(chain) -> {ok, first_bad_seq, reason}` | B | A, D, L, C5 |
| `feed.current().rules_for(applies_to)` | B | A, D, C |

### 3.2 Target layout (the subset of spec §3.9 we create)

```text
contracts/  errors.md  audit-event.schema.json  case.schema.json  interfaces.md  control-api.md  frameworks-lite.yaml  canonical.py
src/aicl/gateway/{app,policy,pipeline,wire,stream}.py      # from poc/gateway.py (A0)
src/aicl/controls/c0{4,6,7,8}_*.py c09_signatures.py c10_injection.py c12_output_links.py c36_multimodal.py
src/aicl/core/{identity,runs,taint,destinations}.py   src/aicl/tools/{registry,validators,decide}.py   src/aicl/mcp/{edge,pins}.py
src/aicl/budget/{ledger.py,reserve.lua,settle.lua,breakers.py}   src/aicl/audit/{event,chain,verify}.py
src/aicl/feed/{engine,client}.py   src/aicl/artifacts/scan.py   src/aicl/control/{selftest,posture}.py   src/aicl/testkit/{runner,steps}.py
services/{control,feed,guard,mock_llm,mcp_demo}/app.py     # guard and mock_llm are from poc/ (C2, A1)
console/{index.html,api.js}                                 # from mockups/dashboard.html (F1)
policy/policy.yaml  policies/{test.yaml,test-detectors-off.yaml}  feed/rules/00-seed.yaml (from examples/feed/signatures.yaml)
tests/{cases,integration,invariants,fence,e2e}/  tools/{keys,feedctl,demo_agent,aicl_audit,aicl_scan,make_artifacts,bench}.py  tools/fence_probe.sh
deploy/{Dockerfile,compose.yaml,compose.test.yaml}  Makefile
```

### 3.3 Lane tables

Task IDs below belong to plan (a). The spec WP each one replaces is in brackets. "Due" times include breaks. ⇒ marks a hand-off.

#### Lane L: lead / integrator (8.5 h = 6.25 build + 2.25 T; reserve 0.5)

| # | Task | Files | h | Due | Hand-offs |
|---|---|---|---|---|---|
| L1 | Contracts-lite [L1 part]: §5.7 errors, the audit schema (copied from `examples/audit/aicl-audit-v1.schema.json`), the subset of the §10.3 case schema we execute, interfaces (§3.1), the control endpoints we build, a control → framework map, rfc8785 wrapper | `contracts/*` | 0.5 | H1:00 (CF) | ⇒ everyone |
| L2 | One image + compose (gw-1, gw-2, control, feed, guard, mock-llm, mcp-demo, valkey, fence-probe, tests; networks `agents`/`core`/`sandbox` internal, `admin`) + Makefile (`dev`, `test`, `demo-offline`, `demo-warmup`, `reset-demo`, `keys`, `fence`, `demo-check`) + probe script; log the probe result for both Macs [L1 part] | `deploy/*`, `Makefile`, `tools/fence_probe.sh` | 0.75 | H2:00 | ⇒ all (`make dev`), L8 |
| L3 | `test_skeleton.py` first (the H3 gate), then the YAML case runner + `steps` executor + meta-test + `rich` matrix + JUnit. Port the 10 `poc/demo.sh` scenarios to cases [L2, L8 part] | `tests/e2e/test_skeleton.py`, `src/aicl/testkit/*`, `tests/test_cases.py`, `tests/test_meta.py`, `tests/cases/poc_*.yaml` | 1.75 | H3:00 skeleton / H4:00 runner | needs A0, A1, B1 · ⇒ all owners write cases from H4 |
| L4 | `control` skeleton: bearer auth, serves `console/`, audit tailer (glob `audit/gw-*.jsonl`, complete lines only) → `GET /api/stream` (SSE), `/api/header` (§11.3 shape: versions/heartbeats from Valkey, chain heads, feed state, guard health, last self-test), `/api/health` [L3] | `services/control/app.py` | 1.25 | H5:30 | needs B1, A2 · ⇒ F2/F3 live, C5 |
| L5 | Live self-test (`canary: true` cases through gw-1 as `svc-selftest`; PASS/GAP/FAIL/ERROR/EXPOSED; auto-run on `policy_reloaded`, debounced 1 s) + posture lite; `POST /api/selftest/runs`, `GET /api/selftest/runs/latest` [L5, L6 lite] | `src/aicl/control/{selftest,posture}.py` | 1.25 | H6:45 | needs L3, A2 · ⇒ F5 |
| L6 | `POST /api/playground/inspect`: sends through gw-1 as `judge`/`alice`/`ola` (no bypass); `response_override` → `[[mock:reply:…]]`; stages from the event's `controls[].tier`; sent vs forwarded (`evidence.forwarded`, capture L2 for judges) [L7] | `services/control/playground.py` | 0.75 | H7:30 | needs A1, B1 · ⇒ F4 |
| L8 | **T** Invariants: the detectors-off overlay (C09, C10, C11, C16 off) with S4 (`untrusted`) and S5 (`trifecta`) still denied; forged/absent/rotated run token → fallback with taint kept; paraphrased destination never trusted; homoglyph → spoof deny; fence test; C35 404s [L4] | `policies/test-detectors-off.yaml`, `tests/invariants/*`, `tests/fence/test_fence.py` | 0.75 | H8:15 | needs D4 · ⇒ **H9 gate** |
| L9 | **T** Storyline test (★ beats 1, 2, 4, 5, 8-lite, 10 + insert 2b), `make demo-check`; chair the H10:15 dry run [L8] | `tests/e2e/test_demo_storyline.py` | 0.75 | H9:00 | ⇒ dry run |
| L7 | **T** README first screen (what it is, diagram, `make test`, the raw compose command, `make demo-offline`, the "designed vs shipped" box) + `docs/JUDGES.md` (keys, URLs, the §10.8 pokes P0-lite supports) + the 100-word description for the placeholder | `README.md`, `docs/JUDGES.md` | 0.75 | H10:00 | ⇒ F6, submission |

#### Lane A: gateway core (8.25 h build; stretch 0.5; reserve 0.25)

| # | Task | Files (POC origin) | h | Due | Hand-offs |
|---|---|---|---|---|---|
| A0 | Split the POC into modules (one per control, keys renamed to §6.2, findings `id: "Cnn"`); wire contract §5.7 (typed 400/401/413/429/503; content block = 200 + `content_filter` + "Blocked by AICL (Cnn.rule). Ref …"); `x-aicl-*` headers + pre-flight `Server-Timing`; **delete `/control/*`** from the data plane | `src/aicl/gateway/{app,pipeline,wire}.py`, `src/aicl/controls/*` (from `poc/gateway.py`) | 1.25 | H1:45 | ⇒ everyone may touch gateway modules |
| A1 | Mock LLM: keep echo and "leak"; add `[[mock:reply\|tool_call\|usage\|error:…]]`, `GET/DELETE /_mock/calls`, priced `sim/*` aliases [A1] | `services/mock_llm/app.py` (from `poc/mock_llm.py`) | 0.5 | H2:15 | ⇒ L3 (`upstream_called`) |
| A2 | Policy engine: pydantic `extra="forbid"` over the shipped subset of §6.2 (YAML path in errors), size/alias limits, RE2 compile, profiles §6.3, 1 s background sha poll + LKG (POC `PolicyStore`), version = Valkey `INCR` per new sha, heartbeat `aicl:replica:{id}`, a `policy_change` event with `weakened[]`; seed `policy/policy.yaml` from `examples/policy.yaml` [A2] | `src/aicl/gateway/policy.py`, `policy/policy.yaml` | 1.75 | H4:00 | ⇒ L4 header, L5, all |
| A3 | `gw-2`: a second process (`AICL_REPLICA=gw-2`, :8081) in compose and `make dev` [A6 lite] | `deploy/compose.yaml` (with L) | 0.25 | H4:15 | ⇒ C7 race |
| A4 | Identity (C01, C02, C26, C36): hashed vks, agents as principals, user ∩ agent, hint, filtered `/v1/models`, `/v1/me`; **`POST /v1/runs`** (user credential only; task → `destinations.extract` → trusted dest) + HMAC run token bound to the agent + sticky fallback run (C33); 403 if the agent is disabled or quarantined; `tools/keys.py` [A3] | `src/aicl/core/identity.py`, `tools/keys.py` | 2.0 | H6:15 | needs B2 extractor (H4:30), C1 · ⇒ D4, L8 |
| A5 | `stream: true` in buffer mode: upstream non-stream, full response pipeline, OpenAI SSE out (role, content chunks, `finish_reason`, usage, `[DONE]`) [A5 lite] | `src/aicl/gateway/stream.py` | 0.75 | H7:00 | — |
| A6 | Pipeline: `fail: open\|closed\|taint\|profile` for every control (C32), `decision.degraded` + reasons, flag → taint the run, per-stage ms in the event [A4] | `src/aicl/gateway/pipeline.py` | 0.75 | H7:45 | ⇒ beat 10 (guard down) |
| A7 | LLM-edge mediation (pair with D): model-emitted `tool_calls` → `tools.decide()`; a denied call is removed and replaced by text naming the rule and ref, `finish_reason: stop`; unvouched `role: tool` content taints the run [A5 part] | `src/aicl/gateway/pipeline.py`, `tests/cases/c14_llm_tc.yaml` | 1.0 | H8:45 | needs D3, D4 |
| A8 | STRETCH C27 canary: the POC `system_prompt` step appends `CNRY-<8hex>`; block if it appears in the output or in tool args [A7] | `src/aicl/controls/c27_canary.py` | 0.5 | H9:30 | only if green at H6 |

#### Lane B: deterministic detection, feed, audit (8.25 h build; stretch 0.75)

| # | Task | Files (POC origin) | h | Due | Hand-offs |
|---|---|---|---|---|---|
| B1 | Audit (C25): `aicl.audit/v1` builder from `Ctx` (required fields, `controls[]`, framework tags, `run` block, capture L0/L1/L2, HMAC `user_ref`); per-replica chain `audit/gw-N-YYYY-MM-DD.jsonl` (seq, `prev_hash` inside the hashed body, sha256 over JCS); a bounded async writer; `verify` CLI + `POST /api/integrity/verify` [B1] | `src/aicl/audit/*`, `tools/aicl_audit.py` (replaces `poc/gateway.py:337`) | 1.75 | H2:30 | ⇒ L3, L4, C5, F |
| B2 | C08 views (extends POC `fold()`): stripped, tag_decoded (hidden text recorded for the Evidence tab), nfkc, folded, decoded; `destinations.py`: extract and canonicalise email, URL host, IBAN and phone from every view, plus `skeleton()` [B4] | `src/aicl/controls/c08_normalize.py`, `src/aicl/core/destinations.py` | 2.0 | **H4:30** | ⇒ D4, A4 |
| B3 | C06 secrets: ~10 RE2 patterns + entropy gate; fixtures generated at runtime [B2] | `src/aicl/controls/c06_secrets.py` | 0.75 | H5:15 | ⇒ beat 2 |
| B4 | Rule engine (from POC `compile_rule`): `google-re2` everywhere (drop the `\x{…}` hack), keyword over every view, url_ioc (POC), **`http_request`** compiled into hard exclusions + the Ollama-admin floor (C20), `hash` and `pickle_globals` handed to C6, unknown types skipped and listed [B3] | `src/aicl/feed/engine.py` | 1.25 | H6:30 | ⇒ D3 (C17/C20 hooks), C6 |
| B5 | Feed (C19): the `feed` service holds the only Ed25519 private key; `feedctl publish` (validate, compile, run vectors, bump the serial, sign JCS); `GET /bundle` + ETag; gateway client (3 s poll, pinned key, `serial > last_serial` persisted in Valkey, expiry → stale, vectors, atomic swap, `feed_update`/reject events) [B5] | `services/feed/app.py`, `tools/feedctl.py`, `src/aicl/feed/client.py`, `feed/rules/00-seed.yaml` (replaces `poc/gateway.py:122`) | 2.0 | H8:30 | ⇒ L4 header, beat 8-lite |
| B6 | C07 (from POC `step_pii`): IBAN mod-97, NIP, PL phone, `[CARD]` → `[PAN]`, per-entity actions, tool args [B6] | `src/aicl/controls/c07_pii.py` | 0.5 | H9:00 | ⇒ beat 2 |
| B7 | STRETCH: signed checkpoints by `control` (Ed25519 key only there; `witness/checkpoints.jsonl` every 60 s); verify also detects a recompute and truncation [B7 part] | `services/control/checkpoints.py` | 0.75 | H10:00 | only if green at H6 |

#### Lane C: budgets, semantic, artifacts, read API (7.5 build + 0.75 T; stretch 0.5; reserve 0.25)

| # | Task | Files (POC origin) | h | Due | Hand-offs |
|---|---|---|---|---|---|
| C1 | Ledger (C03): Lua all-or-nothing reserve over `org:`/`pool:`/`seat:`/`agent:` in tokens, µUSD and compute-ms; settle under `asyncio.shield`; 429 `billing_error` + `x-should-retry: false` + `retry-after`; Valkey down → 503; `LocalLedger` with the same interface as the fallback [C1] | `src/aicl/budget/*` (replaces POC `step_budget*`) | 2.0 | stub H1:30 / H2:30 | ⇒ A4, C7 |
| C2 | Guard (C10): `POST /v1/inspect {views[], surface}`; `GUARD_ENGINE=stub` (the POC scorer) and `onnx` (protectai-v2 INT8, 512-token windows, stride 448, ≤ 8 windows, one batched run, threadpool); gateway client with deadline, `block_at`, band → flag + taint, error → C32; latency on the demo Mac → `reports/perf-h4.md` [C3] | `services/guard/app.py` (from `poc/guard_svc.py`), `src/aicl/controls/c10_injection.py` | 2.0 | H4:30 | ⇒ A6, D4 |
| C3 | C04 hygiene (from POC `step_clamp_max_tokens`) + fixed-window rpm + `/v1/me` payload [C2] | `src/aicl/controls/c04_limits.py` | 0.75 | H5:15 | ⇒ beat 1 |
| C4 | C05 breakers: max tool calls, identical-call hash ≥ 3 → `run_circuit_open` [D3b part] | `src/aicl/budget/breakers.py` | 0.5 | H5:45 | ⇒ D (MCP path) |
| C5 | Control read API (no DuckDB): `/api/threats` (filters + cursor over the tail index), `/api/events/{id}`, `/api/runs/{run_id}` (D's `describe`), `/api/export?format=jsonl\|csv` + an `export` event [B7 part] | `services/control/reports.py` | 1.25 | H7:00 | needs L4, B1 · ⇒ F3 |
| C6 | C18 lite: `pickletools.genops` walk with the SIG-0004 allowlist; parse error → block; torch-zip `data.pkl`; safetensors header; sha256 rules; `/v1/artifacts/scan` + `aicl scan`; artifact fixtures generated, never loaded [C5] | `src/aicl/artifacts/scan.py`, `tools/{aicl_scan,make_artifacts}.py` | 1.0 | H8:00 | needs B4 · ⇒ beat 8-lite |
| C7 | **T** Race test (200 across gw-1/gw-2 → exactly 50) + budget/limits/breaker cases (429 with `upstream_called: false`) [C6 part] | `tests/integration/test_budget_race.py`, `tests/cases/c0[345]_*.yaml` | 0.75 | H8:45 | ⇒ **H9 gate** |
| C8 | STRETCH `make bench`: c = 1/10 via gw-1 vs direct to the mock, overhead p50/p95 → `reports/perf.md` [P1 #1 lite] | `tools/bench.py` | 0.5 | H9:30 | only if green at H6 |

#### Lane D: MCP, tools, taint; **owns the guarantee** (7.75 build + 0.5 T; reserve 0.75 = gate buffer)

| # | Task | Files | h | Due | Hand-offs |
|---|---|---|---|---|---|
| D1 | Thin MCP edge: `POST /mcp/{server}` JSON-RPC (`initialize` local, `tools/list` filtered + namespaced, `tools/call` with the agent's token stripped and the backend token injected, `X-AICL-Run`); blocks are `result.isError: true`; one audit event per call [D1] | `src/aicl/mcp/edge.py` (APIRouter mounted by A0) | 1.0 | H1:30 | — |
| D2 | Demo servers in one process on `sandbox`: `web_fetch` (`ticket-42` with a Unicode-tag-smuggled instruction to email `audit@evil.test`), `crm_get_customer` (→ `jan.nowak@client.example`, `trusted_source`), `bankdb_query` (sqlite, Faker rows), `mail_send_email` (`outbox.jsonl` + `GET /_outbox`), `facts_get_fact` (`POST /_admin/rugpull` → poisoned v2), `vault_admin_get_credentials` (honeypot) [D2a + D2b lite] | `services/mcp_demo/app.py` | 1.5 | H3:00 | ⇒ L3 skeleton |
| D3 | `aicl.tools` (C14): registry/labels/risk from policy `tools:`, `ssrf`, `url_allowlist`, `sql` (sqlglot, forced `LIMIT 100`), `email`, DLP via `scan_text`, C17 and C20 hooks; `decide()` shared by both edges [D3a + D3b part] | `src/aicl/tools/*` | 1.75 | H4:45 | ⇒ A7 |
| D4 | **C24/C33/C16**: run state in Valkey; result scan on every string leaf (views + C09 + C10 + C06/C07, span redacted with a notice; `untrusted_source` always taints); destinations from every view → `untrusted_dest`; `trusted_source` → `derived_dest`; `private` → `private_read`; the full §5.6 matrix for all three profiles; spoof; fallback run; `describe()`; cases S4/S5 NEG + POS twins [D4 + D5a] | `src/aicl/core/{runs,taint}.py`, `tests/cases/s4_exfil.yaml`, `s5_trifecta.yaml` | 2.5 | **H7:30** | needs B2 (H4:30), A4 (H6:15; a test helper mints runs before that) · ⇒ L8, A7 |
| D5 | C15 pins (JCS sha in Valkey; first sight pin; change → quarantine + old/new diff + `mcp_quarantined`; SIG-0003 scan; floors) + C31 honeypot (deny, revoke the run, `agent:{id}:quarantined`) [D5b] | `src/aicl/mcp/pins.py` | 1.0 | H8:30 | ⇒ A4 (403 check) |
| D6 | **T** Scripted `support-bot`: mint as alice → web_fetch → crm → bankdb → mail to evil (denied) → mail to jan (allowed + flag); `--honeypot` and `--rugpull` flags; prints the verdict + event id per step [D6] | `tools/demo_agent.py` | 0.5 | H9:00 | ⇒ beat 4, L9 |

#### Lane F: console (7.25 build + 1.5 T; reserve 0.25)

| # | Task | Files | h | Due | Hand-offs |
|---|---|---|---|---|---|
| F1 | Mockup → console: copy `mockups/dashboard.html`; hide the P1/P2 pages (spend, policy, agents, approvals, audit, my-ai); `api.js` with token login (`sessionStorage`); `?fixtures=1` keeps the mockup's simulation as fixtures mode; in live mode stop the simulation timers and map `aicl.audit/v1` to the mockup's event shape with one adapter. **Go/no-go at H1:30:** if a fixture row can't render through the adapter, build a fresh vanilla page that reuses the mockup's CSS tokens | `console/index.html`, `console/api.js` | 1.0 | H1:30 | served by L4 at `/` |
| F2 | Header ribbon: `/api/header` + SSE (`policy_reloaded/rejected` with the YAML path, `feed_*`, `health_changed`, `selftest_finished`); states normal/amber/red/stale (> 15 s); labels "single admin token (demo)", "LLM: mock", "2/2 replicas" [F2] | `console/*` | 1.25 | H3:00 fixtures / H6:00 live | needs L4 |
| F3 | Threats: live SSE table (prepend, cap 200, client-side filters); drawer tabs **Trace**, **Run** (the beat-4 money shot: where `audit@evil.test` came from), **Evidence** (snippet + revealed hidden text), **Integrity**; **Export CSV** and **Verify chain** buttons [F3] | `console/*` | 2.0 | H5:00 fixtures / H7:30 live | needs C5, B1 |
| F4 | Playground: principal and model pickers, chips (PESEL + IBAN + AWS key, a bad checksum, EN/PL injection, base64 + zero-width PL, Unicode tags, markdown exfil via `response_override`, intern over budget); verdict banner, T0/T1/T2/OUT stages with ms, sent vs forwarded, headers incl. `Server-Timing` [F5] | `console/*` | 1.5 | H6:30 fixtures / H8:00 live | needs L6 |
| F5 | Overview-lite + `GET /api/summary` (F owns both ends): KPI band (requests, blocked, redacted, flagged, spend today in µUSD and tokens, local compute-s; "simulated commercial pricing" label on `sim/*`), posture + critical-gate banner, controls table (enabled, mode, fail, self-test state, hits) + **Run self-test** [F6 + F7 lite] | `console/*`, `services/control/summary.py` | 1.5 | H8:30 | needs L5, C1 |
| F6 | **T** P0-lite architecture diagram; screenshots; **placeholder submission at H8** (title, team, L's description, a 4-slide PDF v0) | `diagrams/src/*`, PDF | 1.0 | H8:00 / H9:00 | ⇒ L7 |
| F7 | **T** H10:15 dry run of the storyline on the console with L and D; fix list | — | 0.5 | H10:45 | — |

**Lane totals:** L 8.5 · A 8.25 (+0.5 stretch) · B 8.25 (+0.75) · C 8.25 (+0.5) · D 8.25 · F 8.75. Every lane is ≤ 9.0 h including its stretch.

### 3.4 Checkpoints (plan (a); H0 = 18:00 CEST, 3 Oct)

| Checkpoint | Time (clock) | Green means | If red (L decides, no debate) |
|---|---|---|---|
| Kickoff | H0-H0:30 (18:00) | plan accepted, Q2 asked, `poc-v0` tagged, fence probe running | — |
| CF | H1:00 (19:00) | contracts-lite committed; interface stubs by H1:30 | ship as-is; gaps go to an RFC |
| A0 / D1 / F1 | H1:30-H1:45 | POC split + wire contract merged; MCP edge answers `initialize`; console go/no-go | A0 merges by H2:15 at the latest; F switches to a fresh vanilla page |
| **H3 skeleton** (IC1) | H3:00 (21:00) | `test_skeleton.py` green: stack up (compose or `make dev`) incl. Valkey; a 200 allow with `x-aicl-*`; PESEL redacted and absent from `/_mock/calls`; 400 `model_not_allowed`; 401; typo key rejected + LKG; `C07_pii.mode: block` flips < 2 s; audit chain verifies; `tools/call web_fetch` via `/mcp/web`; guard stub `/v1/inspect`; console on fixtures | L + A pair until green; no new module merges until then |
| **H6 integration** (IC2) | H6:00 (00:00) | Valkey reserve/settle + 429 with zero upstream calls; gw-2 up and both on the same version; `/v1/runs` + fallback run; S4 tools proxied, one call blocked by a validator, C16 taints `web_fetch`; extractor merged; ONNX guard loaded (or stub + DEGRADED); SSE live with a Threats row; the feed process serves a bundle | **Pre-decided fallbacks, no retry window:** Lua → `LocalLedger` + 1 replica (wording §2.3); ONNX → stub + "semantic tier degraded"; feed signing → sha-pinned unsigned bundle, said openly; fence leak → §3.4 ladder; compose broken → `make dev` + no fence claim. Stretch work starts only on lanes green here |
| Placeholder | H8:00 (02:00) | title, team, description v1, PDF v0 uploaded (F6 + L) | checklist dry run |
| **H9 guarantee gate** | H9:00 (03:00) | detectors-off S4 (`untrusted`) and S5 (`trifecta`) denied; run-token escape, paraphrase and homoglyph cases green; C35 404s; fence test (what the probe proved); race 200 → 50 across gw-1/gw-2; ≥ 85% of cases green; ★ beats 1, 2, 4, 5 green offline | **D + A + L swarm on C24; all stretch frozen; F keeps building.** Still red at H10:30: the pitch falls back to the deterministic backstop ("external mail is denied by the C14 email allowlist"), and C24 is presented as designed (§14.1 R3) |
| Dry run | H10:15 (04:15) | storyline on the console | each item: a ≤ 30 min fix or a flag off |
| **P0-lite complete** (IC4) | H10:30 (04:30) | every shipped control has ≥ 1 POS + ≥ 1 NEG green; storyline test green; header + Threats + Playground + Overview-lite live; tag `ic4` | a red control → flag off in the demo policy and update the wording table |
| **Freeze** `rc1` | H11:00 (05:00) | tag `rc1` | after this: fixes, cases, docs and CSS only |
| **Clean room** (IC5) | H12:30 (06:30) | fresh clone on the hot spare, Wi-Fi off: `make test && make demo-offline && make demo-check` 100% | a ≤ 30 min fix (A/C before they sleep) or a cut |
| Video · PDF v1 · repo public · PDF v2 | H13:00 · H13:30 · H14:00 · H14:15 | 3-4 min storyline + clips (F + A); ≤ 10 slides; `gitleaks` clean + licence table | — |
| **Submit** | H15:00 (09:00) | PDF, public repo, video, tag `v1.0-submission`, a second person watching the screen | — |
| Deadline | H17:00 (11:00) | — | — |

**Sleep (spec §13.4 plan (a)):** nobody sleeps before freeze. Then **B, D 90 min H11:00-H12:30** (05:00-06:30; back for the clean room) · **A, C 90 min H13:30-H15:00** (07:30-09:00; after clean-room fixes and the video) · **F 90 min H15:00-H16:30** · **L 60 min H15:30-H16:30**, after submitting. Never more than two people asleep at once, and L is awake at every checkpoint through submission.

---

## 4. Judging criterion → P0-lite evidence → beat → test

| Criterion (weight, CRITERIA/RULES) | What P0-lite shows | Beat | Test |
|---|---|---|---|
| **Robustness & guardrail quality (30%)** | Deterministic first over 5 views (C08), checksum PII and secrets (C06/C07), signed EN+PL signatures (C09/C17/C20), one classifier (C10); **authority beats detection:** S4/S5 denied with every detector off (C24/C33); fail-to-taint when the guard is down (C32); rug pull and honeypot (C15/C31); pickle gate (C18) | 2, 2b, 4, **5**, 10 | `tests/invariants/test_detectors_off.py`, `test_run_tokens.py`, `tests/cases/s4_exfil.yaml`, `s5_trifecta.yaml`, `c06-c10_*.yaml`, `museum_e*.yaml`, `tests/integration/test_guard_down.py` |
| **Architecture & performance (20%)** | Data plane vs control plane as separate processes (and networks in compose); 2 stateless replicas + Valkey; guard and feed as separate services; **one `tools.decide()` for LLM `tool_calls` and MCP `tools/call`**; RE2 linear-time matching; `Server-Timing` + stage ms; `reports/perf.md` if the C8 stretch ships | 0, 2 (stage ms), 5 (2/2 replicas), 11 | `test_hot_reload.py` (2/2), `test_budget_race.py`, `tests/fence/test_fence.py` (C35), `c14_llm_tc.yaml`, `tools/bench.py` (stretch) |
| **Security reporting (20%)** | `aicl.audit/v1` hash chain + verify names the seq (+ signed checkpoints if B7 ships); Threats with decision trace and **Run provenance**; JSONL/CSV export; Overview-lite KPIs, spend and posture for management; a live header that turns red or amber within 2 s | 4, 10 | `test_audit_chain.py` (edited line → first bad seq), `test_export.py`, `test_completeness.py` (one event per request), `test_api_header.py` |
| **Self-testing suite (15% / 20%)** | Hermetic `make test` (compose, stub guard, mock LLM, no Ollama or HF token); POS + NEG for every shipped control incl. budgets, the race, exploit replays, hot-reload/tamper and the feed; meta-tests; live self-test with GAP vs FAIL and "S4 EXPOSED"; ≈ 120 cases (we quote the real count) | 10 + README | the whole suite, `tests/test_meta.py`, `src/aicl/control/selftest.py` |
| **Implementability & scalability (15% / 10%)** | Drop-in `base_url` + MCP URL (`examples/agent-config/`); one policy file with profiles; agents as principals with a kill switch; `docker compose up`; stateless replicas + Valkey; K8s mapping slide (§3.8); permissive licences; runs offline | 1, 11 | IC5 clean room, the raw compose command on the README's first screen |
| Phase-1 minimum bar (≥ 50%) | Mentors may run the repo without us: the README's first screen + `make test` + the raw command | — | IC5 clean room on a fresh clone |

---

## 5. If the deadline turns out to be 23:00 (plan (b))

**When it switches:** only on written confirmation of Q2. Nothing built for P0-lite is thrown away. Every item below is additive, each lands behind a flag, and the contracts-lite are not reopened without an RFC.
- **Confirmed before H6:** keep the H9 gate. Freeze moves H11 → **H18 (12:00)**, the clean room to H19:30 and submission to **H23 (17:00)**, as in spec §13.4 (b).
- **Sleep under (b):** F 3 h at H11:00-H14:00 (F's early slot is gone), then the spec's slots: B and D H17:30-H20:30, L 90 min H20:30-H22:00, A and C H22:00-H25:00.
- **Confirmed between H6 and H11:** the same, but add-backs start only after IC4 (H10:30).
- **Confirmed after H11:** unfreeze only items 1-5 and freeze again at H18.

**Capacity:** H11 → H18 is 7 h × 6 people, minus F's 3 h of sleep and ~3 h of meals, ≈ 36 h. The add-back order below is by rubric weight × stage visibility ÷ cost:

| # | Add back (spec ref) | Owner | h | Cum. | Criterion it buys |
|---|---|---|---|---|---|
| 1 | Signed audit checkpoints, if not shipped as stretch (§9.2, B7) | B | 0.75 | 0.75 | Reporting; closes the full-recompute hole |
| 2 | `make bench` + perf strip, if not shipped (P1 #1) | C | 1.0 | 1.75 | Architecture & performance |
| 3 | Multilingual kNN + EN/PL exemplars (C10 `knn-pi`, C4) | C | 1.5 | 3.25 | Robustness on Polish |
| 4 | JWT/JWKS + `group_map` + `tools/mint_jwt.py` (C01, A3) | A | 1.0 | 4.25 | Implementability; the team's SSO idea |
| 5 | Caddy `lb` in front of gw-1/gw-2, agents see only `lb`, re-probe (A6, L1) | A + L | 0.75 | 5.0 | Architecture; fence story |
| 6 | Trigger-aware streaming holdback + mid-stream C12/C06/C07 + tool-call delta buffering (§5.5, A5) | A | 3.0 | 8.0 | Architecture & performance (TTFT) |
| 7 | C27 canary, if not shipped (A7) | A | 0.5 | 8.5 | Robustness |
| 8 | Coverage grid: `frameworks.yaml` content, `/api/coverage`, full posture with H and the measured column (L6) + Overview grid (F6) | L + F | 2.5 | 11.0 | Reporting |
| 9 | Policy history + `control_weakened` UI + local unsigned feed overrides (§8.3, B7) | B + F | 1.75 | 12.75 | R1 live-edit story |
| 10 | Remaining C14 validators (path, amount, IBAN), the `filesystem` and `bankdb_transfer` tools, S1-S8 twins (D2b, D3b) | D | 2.0 | 14.75 | Robustness, self-test |
| 11 | C03/C04 remainder: leases, GCRA, warn thresholds, tool units, the local-capped ledger-down mode (C1) | C | 1.5 | 16.25 | Budgets (R3) |
| 12 | Spend panel / burn-down + `tools/seed.py` synthetic history (C6, C8, F6) | C + F | 2.5 | 18.75 | Reporting (management) |
| 13 | C06 → ~30 patterns, full TR39 confusables, C12 query-entropy flag (B2, B4) | B | 1.5 | 20.25 | Robustness |
| 14 | CI on GitHub Actions running `make test` + badge | L | 0.5 | 20.75 | Self-testing |
| 15 | Spec P1 ranks 2-5 (§13.3): guard-LLM lane (2.5), `make eval` + Polish slice (2.0), OCSF export (1.5), C23 approvals (2.5) | per §13.3 | 8.5 | 29.25 | Robustness, reporting |

Items 1-14 (~21 h) bring back spec P0 apart from two things we deliberately keep: the **mockup-based console** (no React rewrite; F's hours go to pages instead) and the **thin MCP proxy** (spec D1 allows it; no FastMCP migration). Item 15 (8.5 h) fits in the remaining ~15 h, with ~6 h left as buffer. If the confirmation arrives late (after H11), take items 1-7 only.
