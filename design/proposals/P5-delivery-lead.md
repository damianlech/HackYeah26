# P5: Delivery Lead proposal. "Governor", the AI control layer that still works when the Wi-Fi doesn't

> **Lens:** delivery. We are six Python developers with about 24 hours of wall clock (18-20 effective hours each), Apple Silicon laptops, unreliable hackathon Wi-Fi, one person on the UI (Claude Design + Claude Code), and AI coding assistants on every keyboard. The question this document answers is: *what is the most ambitious scope that will reliably work end to end at demo time, and when mentors run the repo without us?*
> **Status:** an independent, opinionated proposal for the design panel. It makes one choice at each decision point and does not hedge.
> **Sources:** research notes cited by file name: `research/R1-threat-frameworks.md` … `research/R9-reporting-audit-dashboards.md`, `research/FACT-CHECK.md` (errata, wins over R1-R9), `docs/00-task-analysis.md`, `docs/01-review-of-our-first-idea.md`, `docs/02-threats-and-attack-museum.md`, and the existing `examples/` (feed, audit schema, test cases, agent configs), which we reuse as-is wherever possible.

---

## 0. TL;DR

- **We build one Python 3.12 / FastAPI gateway process, "Governor".** It holds one policy brain and two enforcement points: the agent→LLM boundary (OpenAI-compatible, streaming, tool-call mediation) and the agent→MCP boundary (FastMCP 4 proxy with middleware). Around it sit four small sidecars: `guard` (ONNX semantic classifier), `feed` (the "externally managed" signed signature feed), `mock-upstream` (deterministic LLM and simulated paid API), `valkey` (budgets and run state). A React console is served by Caddy. **No Squid fork, no Keycloak, no Kubernetes live, no A2A protocol.** Those are slides, not code (§15).
- **Contracts are frozen at H1.** That means four of them (policy schema, audit event, detector interface, admin/report API) plus three conventions (case schema, feed bundle, headers). Every lane codes against stubs from minute 61. The **walking skeleton is green at H5**: key → model allowlist → secret redaction → mock upstream → budget settle → hash-chained audit → live row in the console. A one-line policy edit flips the verdict in under 2 s, and `make test` runs green in CI.
- **Determinism is a delivery feature.** A scripted mock upstream and a scripted agent make every test and every demo step reproducible without Ollama and without Wi-Fi. Real models are an upgrade path, not a dependency. `make test` is hermetic and takes under 90 s. `make demo-offline` shows the whole product with no model at all.
- **The demo is a test.** `tests/e2e/test_demo_storyline.py` runs every pitch beat. It runs at each integration checkpoint and 10 minutes before we go on stage. If a beat is red, it leaves the pitch.
- **The ambition sits in breadth of small, deterministic, tested controls** (about 22 P0 controls, each a few hours of work and each with positive and negative cases), not in risky infrastructure. Feature freeze is at **H16**. The clean-room run (fresh clone, spare laptop, Wi-Fi off) is at **H17.5**. **Final submission is at H21**, three hours before the deadline, with a placeholder submission at H11.

---

## 1. Thesis

The judges reward what they can poke: they run our test suite, type ad-hoc prompts, edit config files and signature feeds live, ask for telemetry and read logs (`docs/00-task-analysis.md` §2). In phase 1 the mentors do this **alone, on their own machine**, and a project that does not reach 50% in phase 1 is not eligible for a prize. Most hackathon AI gateways fail in one of three ways. The repo does not start on someone else's laptop. A live edit crashes the process or does nothing. Or the demo depends on a 4B local model making the right tool call on stage.

So the central bet is this. **We win on reliability under poking. The scope is chosen and sequenced so that it is always in a demoable state from H5 onward.** In practice:

1. **One brain, two enforcement points, one process.** Policy, detection pipeline, budgets and audit are a library (`governor.core`) of mostly pure functions. The LLM proxy and the MCP proxy are thin adapters around it. The same `tools` policy is enforced on a model's `tool_calls` and on MCP `tools/call`, so stdio tools that no network proxy can see are still governed (`research/R1-threat-frameworks.md` §11, `research/R6-mcp-agent-security.md` §5). Fewer moving parts means fewer integration failures.
2. **Deterministic first, semantic second, everything behind a policy flag.** Deterministic controls (normalizer, secrets, checksum PII, signatures, tool validators, artifact allowlist, taint) carry the guarantees and the test count. Semantic controls (Prompt Guard 2 classifier, later MiniLM similarity and a Llama Guard escalation) add depth, and their scores and thresholds are visible in every trace. A feature that isn't finished ships **disabled by a flag**, never half-wired.
3. **Contracts before code, stubs before features, skeleton before breadth.** Six people and six AI assistants generating code in parallel will drift unless the shapes are frozen and checked by CI (schema tests on every sample event, policy and case file).
4. **Offline and deterministic by default.** The mock upstream speaks OpenAI and Ollama dialects and takes `[[mock:...]]` directives. The scripted agent replays the MCP attack scenarios. Seeded, clearly labelled synthetic history fills the charts. Models, images, wheels and npm packages are pre-fetched before the event.
5. **Evidence is generated, not written.** The coverage grid, the posture score, the perf table and the test matrix are computed from the live policy, the audit log and the latest test run. If a judge changes the policy, the evidence changes within seconds.

Our pitch line: *"Disable any control, and within two seconds our own self-test tells you which OWASP and ATLAS risks you just uncovered. Everything you see runs on this laptop with Wi-Fi off."*

---

## 2. Architecture

### 2.1 Components

```mermaid
flowchart LR
  subgraph CLIENTS["Clients"]
    PG["Console Playground<br/>(judges type here)"]
    AG["demo-agent<br/>scripted or live (qwen3:8b)"]
    SDK["Any OpenAI SDK or curl<br/>judge virtual key"]
    CC["Claude Code via managed-settings<br/>(P1 dialect, P2 clip)"]
    CI["CI job or data scientist<br/>model artifact scan"]
  end

  subgraph GW["governor-gateway :8080 (FastAPI, Python 3.12, one process)"]
    direction TB
    ING["Data plane routes<br/>/v1/chat/completions, /v1/models, /v1/me<br/>/mcp/{server}, /v1/artifacts/scan<br/>P1: /v1/messages, /hf/*, /v1/agents/{id}/runs"]
    ID["T0 policy: C01 identity, C02 models,<br/>C04 limits, C26 kill switch"]
    PIPE["Decision pipeline<br/>T1 deterministic then T2 semantic<br/>short-circuit, fail modes"]
    STR["Stream guard<br/>trigger-aware holdback,<br/>tool_call delta buffer"]
    TOOLS["governor.tools<br/>tool policy + validators<br/>(shared by LLM and MCP)"]
    MCPX["MCP proxy<br/>FastMCP 4 create_proxy + middleware<br/>pins, description scan, result scan"]
    POL["Policy engine<br/>pydantic v2, watch + 1 s hash poll,<br/>compile-then-swap, last-known-good"]
    FEEDC["Feed client<br/>ed25519 verify, serial, expiry,<br/>embedded test vectors"]
    BUDC["Budget client<br/>reserve / settle"]
    AUD["Audit writer<br/>aicl.audit/v1, sha256 chain,<br/>background queue"]
    API["Admin + report API<br/>DuckDB over JSONL, SSE hub,<br/>/metrics, Server-Timing"]
    ST["Self-test runner<br/>policy-aware, posture + coverage"]
  end

  subgraph SIDE["Sidecars (docker compose)"]
    GUARD["guard :9200<br/>onnxruntime: Prompt Guard 2 22M INT8<br/>P1: MiniLM kNN"]
    FEED["feed :9000<br/>external threat-intel service<br/>signs rules/*.yaml"]
    VK[("valkey :6379<br/>budgets, run state, pins")]
    MOCK["mock-upstream :9100<br/>OpenAI + Ollama dialects,<br/>simulated paid API"]
    UI["console :3000<br/>React 19 + Vite + shadcn,<br/>served by Caddy"]
  end

  subgraph HOST["Mac host (native, Metal)"]
    OLL["Ollama >= 0.14<br/>qwen3:8b, qwen3:4b,<br/>P1 llama-guard3:1b"]
  end

  subgraph MCPS["MCP servers (stdio, spawned by gateway)"]
    FS["filesystem (naive)"]
    ML["mail (outbox.jsonl)"]
    DB["bankdb (sqlite + honeypot)"]
    WEB["web (local pages, ticket-42)"]
    FACTS["facts (MALICIOUS: poison, rug pull)"]
  end

  PG & AG & SDK & CC --> ING
  CI --> ING
  ING --> ID --> PIPE
  PIPE --> GUARD
  PIPE --> STR
  STR --> OLL
  STR --> MOCK
  ING --> MCPX --> TOOLS
  STR --> TOOLS
  MCPX --> FS & ML & DB & WEB & FACTS
  ID --> BUDC --> VK
  POL -.-> PIPE
  FEED -- "signed bundle, poll 3 s" --> FEEDC -.-> PIPE
  PIPE --> AUD --> API --> UI
  ST --> ING
```

**Why this shape (delivery reasons, not only security ones):**
- **One gateway process** means one Dockerfile, one log, one debugger session, and no inter-service auth or retries on the hot path. The only network hop inside a decision is the optional `guard` call, and it has a 150 ms timeout and a policy-defined fail mode.
- **`guard` is a separate container** so the ONNX runtime and model files stay out of the gateway image, the semantic lane owner works independently from H1, and `make test` swaps it for `GUARD_ENGINE=stub` (a deterministic keyword scorer) with no model download.
- **`feed` is a separate container** because the task says signatures come "from some externally managed system". It holds the signing key; the gateway holds only the public key.
- **Ollama runs natively on the Mac** (Docker on macOS has no Metal). Containers reach it at `host.docker.internal:11434`, and the compose file sets `extra_hosts: ["host.docker.internal:host-gateway"]` so the same file also works for Linux mentors (`research/R4-local-models.md`, team facts).
- **Valkey from minute one**, not an in-memory dict. The reserve/settle Lua is already prototyped (`research/R7-bench/budget_lua.py`, 0.30 ms/request, exactly 50 of 200 admitted at a $50 cap). It gives us the "stateless gateway pods" scalability story for free, and Valkey is BSD-3 where Redis 8 is tri-licensed (`research/R3-oss-landscape.md`).

### 2.2 One request, end to end

```mermaid
sequenceDiagram
  autonumber
  participant A as demo-agent
  participant G as governor-gateway
  participant V as valkey
  participant S as guard
  participant O as Ollama (host)
  participant M as MCP server (stdio)
  participant L as audit + SSE
  A->>G: POST /v1/chat/completions stream=true, tools, X-Ctl-Run-Id run_7f3a
  G->>G: T0 C01 vk_bot to support-bot (agents), C02 model ok, C04 clamp max_tokens
  G->>V: EVALSHA reserve(org, group, user, run) est_in=ceil(chars/2)
  V-->>G: ok, lease ttl 600 s
  G->>G: T1 C08 normalize, C06 secrets, C07 PII (PESEL redacted), C09 feed signatures
  alt T1 inconclusive and C10 enabled
    G->>S: POST /v1/inspect texts, detectors=[pi]
    S-->>G: pi score 0.07 (block_at 0.80) allow, 14 ms
  end
  G->>O: forward redacted body with stream_options.include_usage=true
  loop each SSE chunk
    O-->>G: delta text
    G->>G: holdback scan C12 links, C06, C07 (redact in place)
    G-->>A: released text
  end
  O-->>G: tool_call web_fetch(url) + usage
  G->>G: buffer full tool_call, C14 tool policy, C20 http signatures on args
  G-->>A: tool_call chunk, finish_reason tool_calls, [DONE]
  G->>V: EVALSHA settle(actual minus reserved), compute_ms from wall clock
  G-)L: decision event (seq, prev_hash) and SSE topic event
  A->>G: POST /mcp/web tools/call web_fetch, same X-Ctl-Run-Id
  G->>G: C14 validators (SSRF), C05 loop counter, C24 taint check (P1)
  G->>M: tools/call
  M-->>G: result ticket-42.html
  G->>G: C16 result scan (C08 + C09 + C10), injected span redacted, run marked tainted
  G-->>A: sanitized result
  G-)L: mcp decision event
```

The Server-Timing header on every LLM response (`auth;dur=0.2, t1;dur=1.4, t2;dur=14.1, upstream;dur=812`) is how we answer "show me the performance telemetry" in one second (`research/R7-budget-streaming-performance.md` §3.9).

### 2.3 Runtime topology (docker compose)

| Service | Tech | Port | In `make test` | In `make demo-offline` | In `make demo` | Owner |
|---|---|---|---|---|---|---|
| `gateway` | Python 3.12, FastAPI 0.142, httpx, pydantic v2, fastmcp 4.0.10, google-re2, pyahocorasick, sqlglot, duckdb, prometheus-client | 8080 | yes (`policies/test.yaml`) | yes | yes | A |
| `guard` | onnxruntime + tokenizers; Prompt Guard 2 22M INT8, fallback `protectai/deberta-v3-base-prompt-injection-v2` (Apache-2.0, ungated) | 9200 | `GUARD_ENGINE=stub` | stub or real | real | C |
| `feed` | FastAPI + `cryptography` (ed25519), watches `services/feed/rules/` | 9000 | yes (test key) | yes | yes | B |
| `mock-upstream` | FastAPI; OpenAI chat (SSE), Ollama native, `/_mock/calls`; also serves `mock-openai/*` as the simulated paid provider | 9100 | yes | yes (replaces Ollama) | yes (paid-API sim) | A |
| `valkey` | `valkey/valkey:8` | 6379 (internal) | yes | yes | yes | C |
| `console` | React 19, Vite 8, Tailwind 4, shadcn `dashboard-01`, Recharts 3, TanStack Query; Caddy 2 serves `dist/` and proxies `/api`, `/admin` | 3000 | no | yes | yes | F |
| `demo-agent` | Python, `openai` SDK + `mcp` client; `--script S1..S8` or `--live` | none | as test driver | scripted | live + scripted | D |
| Ollama | native on host, `OLLAMA_KEEP_ALIVE=-1`, `OLLAMA_NUM_PARALLEL=2`, `OLLAMA_CONTEXT_LENGTH=8192` | 11434 | no | no | yes | C |

The networks are `core` and `agents`. In P1, `agents` becomes `internal: true` so the agent container can only reach the gateway, and a test proves that a direct `curl https://api.openai.com` from it fails (C13).

### 2.4 Repository layout (created at H0:30 by the lead)

```text
governor/
  contracts/                 # FROZEN at H1 (CODEOWNERS: lead). Schemas, OpenAPI, fixtures, canonical.py
    policy.schema.json  audit-event.schema.json  feed-bundle.schema.json  case.schema.json
    openapi.yaml  sse-topics.md  detector.py  canonical.py  fixtures/api/*.json  examples/events/*.json
  policy/policy.yaml         # the one file judges edit (demo)
  policies/test.yaml         # frozen policy for `make test`
  src/governor/
    core/      policy/ (model.py loader.py)  pipeline/ (engine.py)  identity.py  telemetry.py
    detectors/ normalize.py secrets.py pii.py output_links.py signatures.py semantic_client.py
    proxy/     openai_chat.py streaming.py upstreams.py  (P1: anthropic_messages.py)
    tools/     policy.py validators/{path,ssrf,sql,email,amount}.py codeguard.py
    mcp/       mount.py middleware.py pins.py descscan.py
    budget/    ledger.py lua/{reserve,settle}.lua prices.py limits.py
    audit/     writer.py chain.py verify.py
    feed/      client.py
    artifacts/ pickle_scan.py safetensors.py torchzip.py routes.py  (P1: gguf.py hf_mirror.py)
    api/       admin.py report.py sse.py playground.py exports.py
    selftest/  runner.py expectations.py posture.py coverage.py
  services/  guard/  feed/  mock_upstream/  mcp_servers/{filesystem,mail,bankdb,web,facts}.py  demo_agent/
  ui/        (Vite app; src/mocks/*.json copied from contracts/fixtures)
  tests/     unit/  cases/*.yaml  integration/  e2e/test_walking_skeleton.py  e2e/test_demo_storyline.py  perf/
  deploy/    compose.yaml compose.test.yaml compose.offline.yaml  (P1: k8s/ kustomize)
  tools/     doctor.sh seed.py coverage_matrix.py bench.py make_fixtures.py submission_check.py
  docs/      ARCHITECTURE.md POLICY.md JUDGES.md LICENSES.md
  CLAUDE.md  Makefile  pyproject.toml  uv.lock
```

`CLAUDE.md` is a delivery tool. It tells every AI assistant on the team the following: the contracts are law; use `google-re2`, never Python `re`, for policy- or feed-supplied patterns; mutate JSON bodies in place, never re-serialize through a strict schema (`research/R7-budget-streaming-performance.md` risks); every control PR adds at least one positive and one negative YAML case; never assert on LLM prose; and every new feature goes behind a policy flag.

---

## 3. Contracts frozen in hour 1

These are drafted **before** the event as design documents, from this proposal and the existing `examples/`. At H0:30 they are committed to `contracts/` and reviewed in a 20-minute walk-through, and they are frozen at **H1:00**. Any change after H1 needs a one-paragraph RFC in the team chat, the lead's approval, and a version bump. CI validates every sample against its schema on every push.

### 3.1 Policy schema (`contracts/policy.schema.json`, generated from `src/governor/core/policy/model.py`)

Top-level keys, frozen: `schema`, `profile`, `profiles`, `identities`, `groups`, `models`, `budgets`, `controls`, `tools`, `agents`, `mcp`, `feed`, `audit`, `posture`. Every entry under `controls` has the same base shape, `{enabled: bool, mode: block|redact|mask|strip|modify|ask|monitor|profile, fail: open|closed|profile, …control-specific}`. Control keys are `<R1 id>_<slug>` (e.g. `C07_pii`), so a judge can map a line to the coverage grid instantly. Unknown keys are **rejected** (pydantic `extra="forbid"`), so a typo is a visible rejection and not a silently ignored edit. The excerpt is in §5.

### 3.2 Audit event (`contracts/audit-event.schema.json`, `aicl.audit/v1`)

We adopt `examples/audit/aicl-audit-v1.schema.json` (`research/R9-reporting-audit-dashboards.md` §2.5) unchanged in structure, **with one fix at H1**. The example event uses control ids that collide with the R1 catalog: `C09` for the classifier (R1: C10), `C10` for the feed (R1: C09), `C20` for the budget reserve (R1: C03) and `C03` for the model allowlist (R1: C02). From H1, control ids in events, policy, tests and the UI are **R1 ids only**. Event types: `decision`, `policy_change`, `feed_update`, `budget_alert`, `selftest_run`, `mcp_pin`, `approval` (P1), `export`, `health`. Money is integer micro-USD; refs are keyed HMACs; the chain is sha256 over `contracts/canonical.py` output (sorted keys, compact separators, UTF-8). The writer and the verifier import the same function, which avoids the canonicalization drift R9 warns about.

### 3.3 Detector interface (`contracts/detector.py`, vendored by gateway and guard)

```python
Surface = Literal["llm.request", "llm.response", "llm.tool_call", "mcp.tools_list",
                  "mcp.tool_call", "mcp.tool_result", "artifact", "http_request", "agent.ingress"]
Verdict = Literal["allow", "flag", "modify", "redact", "ask", "block"]   # ACS: allow/deny/modify/ask/defer

@dataclass(frozen=True)
class Item:                      # one inspectable piece of a request/response
    surface: Surface
    text: str                    # after C08 normalization
    raw: str
    path: str                    # "messages[2].content", "tool_calls[0].arguments.url", "tools[3].description"
    meta: Mapping[str, Any]      # model, server, tool, principal, agent, run_id

@dataclass
class Finding:
    control: str                 # R1 id, e.g. "C07"
    rule_id: str                 # "C07.PL_PESEL" or feed "SIG-0003"
    verdict: Verdict
    score: float | None = None
    threshold: float | None = None
    spans: tuple[tuple[int, int, str], ...] = ()     # (start, end, label) for redaction + evidence
    replacement: str | None = None                   # for modify (e.g. SQL with LIMIT)
    frameworks: tuple[str, ...] = ()                 # ("LLM02:2026", "AML.T0057")
    latency_ms: float = 0.0

class Detector(Protocol):
    control: str
    tier: Literal["T0", "T1", "T2"]
    surfaces: frozenset[Surface]
    def compile(self, cfg: "ControlConfig", feed: "FeedRules") -> None: ...   # called on reload; may raise -> reload rejected
    async def inspect(self, item: Item, cfg: "ControlConfig", ctx: "RequestCtx") -> list[Finding]: ...
```

Combination rule: `block > ask > redact/modify > flag > allow`. The first `block` short-circuits the remaining tiers. Redactions are applied right-to-left by span. A detector that raises returns a synthetic finding according to its `fail` mode and sets `decision.degraded=true`. The guard sidecar contract is `POST /v1/inspect {texts:[...], detectors:["pi"], surface}` → `{results:[{detector, model, score, label, latency_ms}]}`.

### 3.4 Data plane, admin and report API (`contracts/openapi.yaml`)

| Group | Endpoints (P0 unless marked) |
|---|---|
| Data plane | `POST /v1/chat/completions` (stream and non-stream) · `GET /v1/models` (filtered per caller) · `GET /v1/me` (allowed models, remaining budget per scope, reset times) · `/mcp/{server}` Streamable HTTP (matches `examples/agent-config/claude-code/managed-mcp.json`) · `POST /v1/artifacts/scan` · P1: `POST /v1/messages`, `GET /hf/{repo}/resolve/{rev}/{file}`, `POST /v1/agents/{id}/runs`, `POST /v1/guard` |
| Admin | `GET /admin/policy` (version, sha256, loaded_at, status, last_error) · `GET /admin/policy/history` · `POST /admin/policy/validate` · `POST /admin/selftest/runs`, `GET /admin/selftest/runs/{id}` · `GET /admin/feed` · `POST /admin/demo/reset` (only with `TEST_MODE`) · P1: `GET/POST /admin/approvals` |
| Report (console read side) | `GET /api/overview` · `GET /api/threats` · `GET /api/events/{id}` · `GET /api/spend` · `GET /api/controls` · `GET /api/integrity`, `POST /api/integrity/verify` · `GET /api/export?format=jsonl\|csv` (P1 `ocsf`) · `POST /api/playground` (admin-only impersonation, so a judge can act as `ola` or `alice`) · `GET /api/stream` (SSE) |

**Block and error contract** (decided at H1, because every test and client depends on it; `research/R8-testing-evaluation.md` §9.3, `research/R7-budget-streaming-performance.md` §2.5):

| Situation | Response |
|---|---|
| Missing or unknown key | `401 {"error":{"code":"unauthenticated"}}` |
| Model not granted | `400 {"error":{"code":"model_not_allowed"}}` (same as the Claude apps gateway) |
| Budget exceeded | `429` + `x-should-retry: false` + `retry-after` + `{"error":{"code":"budget_exceeded","message":"daily token budget reached for ola@ (interns); resets 00:00 UTC"}}` |
| Pre-flight content block | `200`, `finish_reason: "content_filter"`, refusal text with rule id and event id (works with promptfoo and garak and shows a readable message in clients) |
| Mid-stream block | final chunk `finish_reason: "content_filter"` + `[DONE]`. Never a TCP reset, because clients retry those |
| MCP block | JSON-RPC result `isError: true`, text `Blocked by Governor (C14.path_traversal), ref <event_id>` |
| Every response | `x-governor-decision`, `x-governor-event-id`, `x-governor-policy: v14/b7f0c2a9`, `Server-Timing` |

### 3.5 Conventions frozen alongside

- **Headers:** `X-Ctl-Run-Id` and `X-Ctl-Agent-Id` (already used in `examples/agent-config/python/clients.py`). The gateway mints a run id if it is absent and returns it. Taint, loop counts and per-run budgets are keyed by `principal + run_id`, because MCP 2026-07-28 has no sessions (`research/R6-mcp-agent-security.md` §1.5).
- **Test cases:** `contracts/case.schema.json` = the R8 §5 format already used in `examples/tests/c07_pii.yaml`.
- **Feed bundle:** `contracts/feed-bundle.schema.json` = the R2 format already used in `examples/feed/signatures.yaml`, plus a `signature: {alg: ed25519, key_id, sig}` envelope.
- **SSE envelope:** `{"topic":"event|policy|feed|selftest|budget|health","seq":18452,"ts":"…","data":{…}}`, one multiplexed stream with `id=seq` (`research/R9-reporting-audit-dashboards.md` §4.3).
- **Framework ids:** always with the edition suffix, `LLM01:2026` (2025 id in brackets in docs only), `ASI01`, `MCP03` (OWASP MCP Top 10 2025 edition, beta, per `research/FACT-CHECK.md` C3), and ATLAS ids from v2026.09 (`docs/02-threats-and-attack-museum.md` §1).

---

## 4. Controls

Ids are from the R1 catalog (`research/R1-threat-frameworks.md` §9). **P0** = must ship by IC3 (H12). **P1** = ranked stretch, built H12-H16 behind flags (§11.5). **P2** = only if everything else is green. Type: **DET** deterministic, **SEM** semantic (AI-based), **POL** policy/access, **BUD** budget/resource, **TAINT** information-flow, **AUD** audit.

| Control | Type | Surface | Pri | How we implement it | OWASP / ATLAS |
|---|---|---|---|---|---|
| **C01** Identity (virtual key → user, LDAP-style groups, agent id) | POL | all edges | P0 | `Authorization: Bearer vk_*` looked up by sha256 in `identities`. 401 on unknown or revoked keys. Agents get their own keys. Production path: OIDC `groups` claim into the same field | ASI03, MCP07, AML.T0012 |
| **C02** Model allowlist per group, filtered `/v1/models` | POL | LLM | P0 | union of the caller's groups' `models`; 400 `model_not_allowed` | LLM04:2026 (LLM03:2025), ASI03 |
| **C03** Budgets: tokens, micro-USD, local compute-seconds | BUD | LLM, MCP | P0 | Valkey Lua reserve/settle over org, group, user and run scopes (§6) | LLM06:2026 (LLM10:2025), ASI08, AML.T0034 |
| **C04** Rate and size limits, `max_tokens` clamp | BUD | LLM | P0 | Valkey per-minute counter, input char cap, clamp = `modify` verdict | LLM06:2026, AML.T0029 |
| **C05** Run circuit breakers | BUD | LLM, MCP | P0 | per-run counters: max LLM calls, max tool calls, identical-call hash ≥ 3, wall clock | ASI08, LLM06:2026, AML.T0034 |
| **C06** Secrets | DET | LLM in/out, tool args/results | P0 | ~30 gitleaks-derived patterns (MIT) on google-re2 + Shannon-entropy gate; redact or block. Test fixtures generated at runtime (GitHub push protection) | LLM02:2026, MCP01, AML.T0057 |
| **C07** PII with checksums | DET | LLM in/out, tool results | P0 | own recognizers: PESEL (weights 1-3-7-9), IBAN mod-97, PAN Luhn, NIP mod-11, email, PL/intl phone. Per-entity `block / redact / mask / allow`. No Presidio (avoids the `pl`-language trap and the image weight, `research/R8-testing-evaluation.md` key findings) | LLM02:2026, MCP10, AML.T0057 |
| **C08** Normalizer and de-obfuscation | DET | all text | P0 | NFKC; strip zero-width, bidi and variation selectors; **decode** Unicode tag block U+E0000-E007F to visible text and rescan; base64/hex blob decode depth 1 | LLM01:2026, AML.T0068 |
| **C09** Injection/jailbreak signatures from the feed | DET | LLM in, tool results, tool descriptions | P0 | feed `regex` (re2) and `keyword` (pyahocorasick) rules; severity maps to action | LLM01:2026, ASI01, AML.T0051.000, AML.T0054 |
| **C10** Semantic injection classifier | SEM | LLM in, tool results | P0 | `guard`: Llama Prompt Guard 2 22M INT8 ONNX (~13-40 ms, `research/R4-local-models.md` bench). `block_at` and `escalate_at` thresholds and `fail` mode live in the policy. Fallback model protectai v2 (English-only, `research/FACT-CHECK.md` A5) | LLM01:2026, ASI01, AML.T0051 |
| **C10b** Semantic signature similarity | SEM | LLM in, tool results | P1 | all-MiniLM-L6-v2 ONNX kNN against `semantic` exemplars in the feed (SIG-0010) | LLM01:2026, AML.T0054 |
| **C11** Guard-LLM escalation | SEM | LLM in/out | P1 | `llama-guard3:1b` on native Ollama, only for the C10 gray zone, 2.5 s timeout, fail mode from the policy | LLM01:2026, AML.T0054 |
| **C12** Output link and markdown exfil sanitizer | DET | LLM out (stream) | P0 | trigger-aware holdback (k=64 chars, held open while `![`, `](` or `http` is unterminated, max 1 KB). Non-allowlisted image/link URLs are stripped | LLM10:2026, LLM02:2026, AML.T0077 |
| **C13** Egress fence | POL | network | P1 | compose `agents` network `internal: true` + bypass test; kustomize NetworkPolicy default-deny | MCP09, AML.T0096 |
| **C14** Tool mediation + argument validators | POL+DET | LLM `tool_calls`, MCP `tools/call` | P0 | `governor.tools`: allowlist per agent/group, jsonschema args, path (realpath + commonpath), SSRF (`ipaddress` over all resolved IPs), SQL (sqlglot verb/table allowlist + forced `LIMIT` as `modify`), email domain, amount | LLM03:2026 (LLM06:2025), ASI02, ASI03, AML.T0053, AML.T0086, AML.T0101 |
| **C15** MCP tool pinning + description scan | DET | MCP `tools/list` | P0 | sha256 of the canonical tool definition on first sight. A changed hash means quarantine plus a stored diff. Descriptions are scanned with C08 + `tool_description` feed rules (SIG-0003). Risk ceiling by name floor (`delete_`, `drop_` → L5) | MCP03, ASI04, AML.T0110, AML.T0109 |
| **C15b** Cross-server shadowing and collisions | DET | MCP | P1 | `{server}_{tool}` namespacing; a description mentioning another server's tool means quarantine | MCP03, ASI04 |
| **C16** Tool-result injection scan | DET+SEM | MCP results, `role: tool` messages | P0 | the same pipeline (C08 + C09 + C10 + C06/C07) on tool results; the injected span is redacted and wrapped in a datamark notice | LLM01:2026, ASI01, MCP06, AML.T0051.001 |
| **C17** Command/code guard | DET | tool args (shell, python, sql, http body) | P0 | feed regex pack: `curl …\| sh`, reverse-shell idioms, `pickle.loads`, `os.system`, `eval(`, `rm -rf` | ASI05, MCP05, LLM10:2026, AML.T0050 |
| **C18** Model artifact gate | DET | artifacts | P0 (lite) | stdlib `pickletools.genops` walk with a GLOBAL/STACK_GLOBAL **allowlist**; **fail closed** on any parse error; PyTorch zip traversal; safetensors header validation; sha256 + `org/model@revision` pins. P1: GGUF chat-template scan, `/hf/` scanning mirror, picklescan as a second opinion | LLM04:2026, ASI04, AML.T0010.003, AML.T0011.000 |
| **C19** External signed signature feed | DET | all | P0 | ed25519, monotonic serial, expiry, embedded test vectors gate activation (§7) | LLM04:2026, MCP04 |
| **C20** AI-infra endpoint guard | DET+POL | http tool args | P0 | feed `http_request` rules: Ray `POST /api/jobs/`, Langflow `/api/v1/validate/code`, Ollama `/api/pull`, `/api/create` and `DELETE /api/delete`, TorchServe `/models?url=` (SIG-0005..0007) | ASI05, AML.T0132 |
| **C23** Human approval (`ask`) | POL | MCP, LLM tool calls | P1 | retry-token bound to the args hash, TTL 300 s, approval card in the console plus a CLI fallback | ASI09, LLM03:2026, AML.T0101 |
| **C24** Session taint + provenance (Rule of Two) | TAINT | LLM + MCP per run | P1 | run labels in Valkey. Tainted + private read + external sink → block. A sink destination found only in untrusted text → block (CaMeL-lite) | ASI01, LLM01:2026, MCP06, AML.T0086 |
| **C25** Hash-chained audit log | AUD | all | P0 | `aicl.audit/v1` JSONL, sha256 chain, background writer, `governor audit verify` | MCP08 |
| **C26** Agent kill switch | POL | all edges | P0 | `agents.<id>.enabled: false` → 403 on every edge within reload time; P1 honeypot trips it | ASI10 |
| **C27** Hidden-context canary | DET | LLM out | P1 | per-policy canary token injected into system prompts; output containing it → block | LLM08:2026 (LLM07:2025), AML.T0056 |
| **C30** Policy engine meta-control | POL | control plane | P0 | single YAML, pydantic, watch + hash poll, compile-then-swap, last-known-good, `policy_change` event with diff | supports all; SOC 2 CC8.1 evidence |
| **C31** Honeypot decoy tool | DET | MCP | P1 | `bankdb_get_admin_credentials` decoy; any call → block + kill switch + critical alert | ASI10, AML.M0039 |
| **C32** Failure posture per control | POL | control plane | P0 | `fail: open/closed` per control; guard timeout or feed staleness → per policy; `degraded` in audit and header | — |

**Coverage if P0 + the top P1 items ship** (computed live, not claimed; method from `research/R1-threat-frameworks.md` §12): LLM 2026 01/02/03/04/06/08*/10, ASI 01/02/03/04/05/08/09*/10, MCP 01/02/03/04/05/06/07/08/09*/10 (* = P1). ASI07 (A2A) and LLM05/07/09:2026 are shown as out of scope or partial, honestly.

**Definition of done for a control:** detector code, unit tests, ≥ 1 POS and ≥ 2 NEG YAML cases (one of them a false-positive guard such as Polish diacritics or a failing checksum), policy keys documented in `docs/POLICY.md`, framework tags, a decision-trace row in the console, and an entry in the demo storyline if it is demo-worthy. **No case, no merge.**

---

## 5. Policy file shape

One file, `policy/policy.yaml`, heavily commented (~250 lines in the repo). The excerpt below is what judges see first. Three strictness profiles set the defaults, and any control can override them. `mode: profile` and `fail: profile` mean "inherit from the active profile".

```yaml
# policy/policy.yaml: the ONE file. Hot reload < 2 s. An invalid edit is rejected and the last-known-good
# stays active (red banner in the console). Only mcp.servers (process launch specs) needs `make restart`.
schema: governor.policy/v1
profile: balanced                       # strict | balanced | permissive
profiles:
  strict:     {pii_action: block,  semantic_block_at: 0.50, semantic_fail: closed, unknown_tool: deny}
  balanced:   {pii_action: redact, semantic_block_at: 0.80, semantic_fail: open,   unknown_tool: deny}
  permissive: {pii_action: mask,   semantic_block_at: 0.95, semantic_fail: open,   unknown_tool: ask}

identities:                             # MVP stand-in for SSO/LDAP (production: OIDC groups claim)
  vk_alice: {user: alice@bank.example, groups: [quant-analysts]}
  vk_ola:   {user: ola@bank.example,   groups: [interns]}
  vk_bot:   {user: svc-support-bot,    groups: [agents], agent: support-bot}
  vk_judge: {user: judge@hackyeah.pl,  groups: [quant-analysts]}

groups:                                 # names mirror LDAP CNs
  quant-analysts: {models: ["ollama/qwen3:8b", "mock-openai/gpt-4.1"], daily: {usd: 20, tokens: 400000, compute_s: 1800}}
  interns:        {models: ["ollama/qwen3:4b"], daily: {tokens: 2000, compute_s: 120}}
  agents:         {models: ["ollama/qwen3:8b"], daily: {usd: 5}, tools: ["web_*", "bankdb_query", "mail_send_email"]}

models:
  "ollama/qwen3:8b":     {upstream: ollama, local: true,  usd_per_compute_s: 0.0007, max_output: 4096}
  "ollama/qwen3:4b":     {upstream: ollama, local: true,  usd_per_compute_s: 0.0004, max_output: 2048}
  "mock-openai/gpt-4.1": {upstream: mock,   local: false, usd_per_mtok: {in: 2.00, out: 8.00}, max_output: 8192}  # SIMULATED paid API

budgets:
  org: {monthly_usd: 5000}
  run: {max_llm_calls: 30, max_tool_calls: 40, identical_tool_calls: 3, max_wall_s: 600}
  warn_at: [0.75, 0.95]
  on_ledger_down: {external: fail_closed, local: fail_open}
  limits: {rpm_per_user: 60, max_input_chars: 32000, clamp_max_tokens: true}

controls:                               # ids = R1 catalog
  C06_secrets:      {enabled: true, mode: redact}
  C07_pii:          {enabled: true, mode: profile, entities: {PL_PESEL: profile, IBAN: profile, PAN: block, EMAIL: allow}}
  C08_normalize:    {enabled: true, decode_unicode_tags: true, decode_base64_depth: 1}
  C09_signatures:   {enabled: true, min_severity: medium}        # rules arrive via the signed feed
  C10_pi_semantic:  {enabled: true, mode: block, block_at: profile, escalate_at: 0.50, fail: profile, timeout_ms: 150}
  C12_output_links: {enabled: true, mode: strip, allow_hosts: [intranet.bank.example]}
  C15_mcp_pins:     {enabled: true, on_change: quarantine, max_risk: L3}
  C16_tool_results: {enabled: true, mode: redact}
  C17_code_guard:   {enabled: true, mode: block}
  C18_artifacts:    {enabled: true, allow_formats: [safetensors, gguf, pickle], pickle: allowlist, on_parse_error: block}
  C24_taint:        {enabled: true, trifecta: block, tainted_sink: ask, provenance: block}   # P1 flag

tools:                                  # ONE tool policy for LLM tool_calls AND MCP tools/call
  "filesystem_*":   {path: {root: /sandbox, deny: ["**/.ssh/**", "**/.env"]}}
  web_fetch:        {ssrf: {allow_private: false}, labels: [untrusted_source]}
  bankdb_query:     {sql: {allow: [select], tables: [customers, transactions], force_limit: 100}, labels: [private]}
  bankdb_transfer:  {amount: {ask_above: 1000, block_above: 50000}, labels: [destructive]}
  mail_send_email:  {email: {internal_domains: [bank.example]}, labels: [sink_external]}

agents:
  support-bot: {enabled: true, mcp_servers: [web, mail, bankdb, facts]}

feed:    {url: "http://feed:9000/bundle", poll_s: 3, pubkey_file: keys/feed.pub, allow_local_unsigned: false}
audit:   {capture: L1}                  # L0 metadata only; L1 adds a redacted snippet on non-allow verdicts
posture: {weights: {critical: 4, high: 3, medium: 2, low: 1}}
```

**"Adherence %"**: thresholds are the P0 knob. In P1, `make eval` writes `calibration/pi_classifier.json` (threshold → recall/FPR on public datasets, `research/R8-testing-evaluation.md` §11.2). The policy then accepts `adherence: 95` as an alternative to `block_at`, and the console shows both.

**Judge-poke matrix** (rehearsed; every row is also a test in `tests/integration/test_live_edits.py`):

| Judge does | System does | Visible in | Within |
|---|---|---|---|
| `C07_pii.mode: block` | the PESEL prompt is now blocked, not redacted | header `v15`, posture toast, Threats row, self-test `PASS (changed)` | < 2 s |
| `C10_pi_semantic.enabled: false` | the paraphrased injection now passes | coverage cell LLM01 turns amber `GAP`, posture drops | < 2 s |
| `profile: strict` | emails blocked, semantic threshold 0.50, semantic fail-closed | Controls page, posture | < 2 s |
| a catastrophic regex or broken YAML | rejected, last-known-good kept | red banner with the line number, `policy_change{result: rejected}` | < 2 s |
| `groups.interns.daily.tokens: 50` | ola's next request gets 429 with the reset time | Spend page, `/v1/me` | next request |
| `agents.support-bot.enabled: false` | kill switch, 403 on every edge | Threats, header | < 2 s |
| adds a rule to `services/feed/rules/90-judge.yaml` | feed re-signs, serial+1, gateway verifies and applies | header `feed #43 ✓`, `feed_update` event | < 5 s |
| edits a byte of the served bundle | signature invalid → rejected, previous bundle kept | red feed badge | < 5 s |
| edits one line of the audit JSONL | `Verify` fails at that exact seq | integrity badge red | on click |
| `make demo-rugpull` | the facts tool is quarantined with a diff | Threats + MCP card | next `tools/list` |

---

## 6. Budget model

**Units (three, so the "commercial and local" requirement is explicit):** tokens, integer **micro-USD** from a per-model price table (the paid provider is simulated by `mock-upstream` and labelled as simulated everywhere), and **compute-ms** for local models. Per `research/FACT-CHECK.md` A2, Ollama's nanosecond durations appear only on the native `/api/chat`, so P0 measures compute as upstream wall-clock from dispatch to the final chunk. P1 adds native-duration accounting when the gateway calls `/api/chat` and charges `load_duration` to the platform, not the user (`research/R7-budget-streaming-performance.md` §1.10). A local model's compute-ms is also priced (`usd_per_compute_s`) so management sees one money number.

**Scopes (hierarchical AND):** `org` (monthly) → `group` pool (each of the caller's groups; for seats, the most restrictive per-seat cap wins) → `user` → `run` (calls, tool calls, wall clock, money). The team's original idea of SSO/LDAP groups → budgets and allowed models lands exactly here, and `GET /v1/me` is the "user logs in and sees their limit and models" view.

**Algorithm (reserve → settle; never post-hoc only):**
1. Pre-flight estimate: `est_in = ceil(chars/2)` (not chars/4, which underestimates Polish and JSON by 22-48%, `research/R7-bench/tokenizer_divergence_out.txt`). `est_out = min(max_tokens or model.max_output, clamp)`.
2. One `EVALSHA reserve` checks every scope atomically and returns `{ok}` or `{exceeded, scope, used, limit}`. On ok it writes a lease key with TTL = max stream duration. On exceeded: **429** with the contract in §3.4, and **zero upstream calls**.
3. The gateway injects `stream_options.include_usage=true` upstream and settles with the real usage. On a mid-stream block or a client abort it settles `input + ceil(emitted_chars/3)`, never zero. Settlement runs in `finally` under `asyncio.shield`, because Starlette cancels the generator on disconnect (R7 §1.6).
4. Tool calls increment run counters and can carry a per-tool cost. C05's identical-call hash stops loops. Warnings at 75% and 95% become `budget_alert` events, an SSE toast and the `x-governor-budget-remaining` header.

**Fail mode:** `on_ledger_down: {external: fail_closed, local: fail_open}`, shown as a health tile.
**Proof:** `tests/integration/test_budget_race.py` fires 50 concurrent requests at a cap worth 10 and asserts **exactly 10 admitted, 0% overshoot**. The same test against a naive check-then-charge variant overshoots by about 400% (`research/R8-testing-evaluation.md` summary). This is one slide and one test.
**P1:** `on_breach: downgrade` to a cheaper local model, and a two-replica cross-gateway race in the scale profile.

---

## 7. Attack-signature feed (historical exploit mitigation)

**The "externally managed system" is a real separate service.** The `feed` container owns `services/feed/rules/*.yaml` (seeded from `examples/feed/signatures.yaml`, SIG-0001..0015, `research/R2-historical-attacks.md` §2.3-2.6) and an ed25519 private key generated by `make keys`. When a rule file changes it builds the bundle `{feed: {name, serial, created, expires, rules_sha256, rules[]}, signature: {alg: ed25519, key_id, sig}}` over `contracts/canonical.py` output, increments `serial`, and serves `GET /bundle` with an ETag.

**The gateway feed client** polls every 3 s (configurable). It accepts a bundle only if all five checks pass:
1. the signature verifies against the pinned `key_id`;
2. `serial` is greater than the active serial (anti-rollback);
3. the bundle has not expired;
4. every rule compiles (re2 validation, so ReDoS patterns are rejected; `research/R7-budget-streaming-performance.md` §3.5);
5. **every rule's embedded positive and negative test vectors pass**.

It then swaps atomically and writes a `feed_update` event. Any failure keeps the previous bundle and shows a red badge. **Unknown rule types are skipped and listed, never fatal**, so a judge adding a `yara` rule cannot crash anything.

| Rule type | Applies to | Pri | Example rules |
|---|---|---|---|
| `regex` (re2) | prompts, outputs, tool args/results | P0 | SIG-0001 Unicode tags, SIG-0002 markdown exfil, SIG-0012 s1ngularity prompt, C17 code pack |
| `keyword` (Aho-Corasick) | prompts, tool descriptions | P0 | SIG-0003 MCP tool poisoning, SIG-0009 jailbreak families |
| `http_request` | http/web tool calls | P0 | SIG-0005 Ray Jobs, SIG-0006 Langflow, SIG-0007 Ollama pull traversal |
| `pickle_globals` | artifacts | P0 | SIG-0004 (parametrizes the C18 allowlist) |
| `package_ioc`, `url_ioc` | MCP launch specs, tool args (`pip install`, `npx`) | P0 | SIG-0013 postmark-mcp ≥1.0.16 and bad nx versions, SIG-0015 |
| `hash` | artifacts | P0 | known-bad sha256 |
| `semantic` | prompts, tool results | P1 | SIG-0010 paraphrase exemplars (C10b) |
| `tool_sequence` | run state | P1 | SIG-0011 toxic flow (C24) |
| `yara` | artifacts | P2 | SIG-0008 is implemented as `regex` over the GGUF chat template in P1 |

**Judge workflow:** edit `services/feed/rules/90-judge.yaml` → see `feed #43 ✓` in the console header in under 5 s → the next matching request is blocked with `rule_id: SIG-9001`. A local unsigned override exists only behind `feed.allow_local_unsigned: true`, which turns the posture "Health" sub-score amber. The feed doubles as about 30 self-test cases (two vectors per rule).

**The Attack Museum** (`docs/02-threats-and-attack-museum.md` §3) is the demo content. Each of the 16 exhibits is a feed rule, a test case and, in P1, a "Replay" button in the console. Payloads are benign markers (e.g. `touch /tmp/CTRL_TEST`); detectors fire on structure.

---

## 8. Reporting & dashboard

**One event stream, two audiences** (`research/R9-reporting-audit-dashboards.md`). Every decision writes one `aicl.audit/v1` event. The console reads the same JSONL through DuckDB (`read_json_auto`), and Prometheus serves low-cardinality metrics (`governor_stage_seconds{stage}`, `governor_decisions_total{verdict,control}`, `governor_policy_reload_total{result}`; never a user label).

**Console pages (P0 = 5 pages + global header):**

| Page | Audience | Judge moment |
|---|---|---|
| **Global header** (every page) | all | `policy v15 · sha b7f0 · reloaded 3 s ago ✓ · feed #42 ✓ · audit chain ✓ seq 1845 · guard ✓ 14 ms p95` turns red or amber within 2 s of a bad edit |
| **Overview** | management | posture score with 4 sub-scores; KPI tiles (requests, blocked, redacted, spend, compute, overhead p95); OWASP/ASI/MCP/ATLAS coverage grid computed from policy × last self-test |
| **Threats** + decision-trace drawer | security | live table (SSE); the drawer shows every control's verdict, score/threshold, rule id+version, ms, frameworks, redacted evidence and the integrity seq; export buttons (JSONL, CSV) and `Verify chain` live here |
| **Spend & Budgets** | management | burn-down per scope, spend by group × model (local vs simulated paid), top runs, blocked-by-budget, compute-seconds |
| **Controls & Policy** | security/risk | one row per control (enabled, mode, threshold, tests pos/neg, hits 24 h, p95 ms, health); the `Run self-test` button with a live matrix; policy history with diffs and rejected edits |
| **Playground** | judges | prompt box, `act as` identity picker, model picker, `Send` / `Dry-run`; the verdict, redactions and trace inline, with prefilled attack examples |
| P1: **MCP & Approvals** | security | servers, tools (pinned / quarantined), rug-pull diff with Approve re-pin, approval queue cards |

**Posture** = `100 × Σ w·E·M·V·H / Σ w`, exactly as in `research/R9-reporting-audit-dashboards.md` §1.5. It is recomputed on every policy reload, feed update and self-test run. The weights are in `policy.yaml`, so judges can argue with them.

**Exports:** JSONL and CSV in P0 (DuckDB `COPY`, each export writes an `export` audit event). **OCSF 1.9.0** (API Activity 6003 + Detection Finding 2004, `record_integrity` for the chain) is P1. `governor audit verify` is the CLI, and the same function backs `POST /api/integrity/verify`.

**Making one UI person productive (the delivery part):**
- **H0:30, design brief into Claude Design**, written by the lead and the UI owner together. Audience: CISO, SOC analyst, judge. Dark theme default. Verdict colours: block red, redact amber, ask violet, flag blue, allow neutral grey-green. Dense tables, monospace ids, one accent colour. Every chart has an empty state and a "synthetic data" badge for seeded history. The header is the hero. Components: KPI tile, coverage grid (heatmap of framework ids), live table, side drawer with a trace ladder, burn-down line with threshold markers, diff viewer, toast.
- **H1:30, fixtures.** `contracts/fixtures/api/*.json` holds realistic responses for every report endpoint (generated by `tools/make_fixtures.py` from the example events), plus a canned SSE replay. The UI is built against fixtures until the real endpoints land (H5 for threats/stream, H10-H12 for the rest). Switching is one env flag, `VITE_API=fixtures|live`.
- **The UI owner also owns the read-side Python** (`api/report.py`, `api/sse.py`, `api/exports.py`, `api/playground.py`). Shapes and data live with one person, so there is no "the backend didn't give me the field" blocker.
- SSE falls back to 2 s polling if the stream drops, so the UI is never stuck.
- Cut order if behind: Playground and Threats are never cut. Spend merges into Overview tiles. Controls & Policy shrinks to a table + `Run self-test`. MCP & Approvals becomes a CLI.

---

## 9. Self-testing

**Two modes, one case library** (`research/R8-testing-evaluation.md`):

| Command | What | Needs | Time | Output |
|---|---|---|---|---|
| `make test` | L0 unit + L1 YAML cases + suites against gateway + mock-upstream + valkey + feed (test key) + guard stub, frozen `policies/test.yaml` | Docker only (no Ollama, no internet after image build) | < 90 s | console matrix (`rich`), `reports/junit.xml`, `reports/report.html`, `reports/coverage-matrix.json` |
| `make test-live` / console `Run self-test` | the `canary: true` subset against the running stack, **policy-aware** statuses: PASS, PASS (changed), GAP, MONITOR, FAIL, DEGRADED, ERROR | running demo | ~1-3 s | console matrix, `selftest_run` audit event |
| `make test-llm` | e2e S1-S8 with the real Ollama agent; asserts on audit events, never on prose | Ollama | minutes | junit |
| P1 `make bench` | overhead = via gateway − direct to mock at c=1/10/50; per-stage p50/p95 from `/metrics`; TTFT vs holdback k | Docker | ~3 min | `reports/perf.md` (into README + slide) |
| P1 `make test-mutation` | disable each control in turn and expect ≥ 1 case to fail; report the kill rate | Docker | ~5 min | screenshot for the PDF |
| P1 `make eval` | threshold sweeps on cached GitHub-hosted datasets (jailbreak_llms, NotInject, XSTest, CyberSecEval PI, InjecAgent) → TPR/FPR/F1 with Wilson CIs | cached data | ~5 min | `reports/eval/*.json`, calibration file |

For mentors without `make` (e.g. on Windows), the README's first screen also gives the raw command: `docker compose -f deploy/compose.yaml -f deploy/compose.test.yaml up --build --abort-on-container-exit --exit-code-from tests`.

**Suites we will have (target ≥ 150 cases, each tagged with control and framework ids):**
- **Per control:** ≥ 1 POS + ≥ 2 NEG for every P0 control (~70). A **meta-test** fails CI if any enabled control lacks either polarity.
- **Feed vectors:** each rule's embedded pos/neg (~30). **Feed suite:** add a rule (applies < 5 s), tampered bundle rejected, rollback serial rejected, expired bundle flagged, bad regex rejected.
- **Hot reload:** verdict flips < 2 s with the propagation time recorded; invalid YAML or unknown key rejected with last-known-good kept; atomic under load (hash polling as a fallback for flaky bind-mount events on Docker Desktop).
- **Budget:** pre-flight 429 with zero upstream calls, `max_tokens` clamp, warn thresholds, the 50-way race (0% overshoot), loop breaker, ledger-down fail modes.
- **Historical exploits:** fixtures generated at session start (pickle with `posix.system` marker, corrupted pickle → fail-closed, torch zip, safetensors, poisoned tool description, rug pull v1→v2, markdown exfil in mock output, Unicode tag smuggling, Ray/Langflow/Ollama endpoint calls, postmark-mcp IOC).
- **MCP S1-S8** (`research/R6-mcp-agent-security.md` §4.4), each with its allowed twin, driven by raw JSON-RPC and the scripted agent.
- **Audit:** every NEG case yields exactly one event with the rule id; the chain verifies; a tampered line fails at the right seq; no raw PESEL/IBAN in any snippet.
- **`test_walking_skeleton.py` and `test_demo_storyline.py`:** the pitch, executed.

**CI:** GitHub Actions runs `make test-fast` (unit + schema checks, < 3 min) on every PR, and full `make test` on `main`. The green badge goes on the README, and the coverage matrix goes in `GITHUB_STEP_SUMMARY`.

---

## 10. Demo storyline

Seven minutes live, with a three-minute cut (★). Every beat has a scripted fallback and a pre-recorded clip, and every beat is a step in `test_demo_storyline.py`.

| # | Beat | What the judges see | Controls | Fallback |
|---|---|---|---|---|
| 0 ★ | **Why** (30 s) | "SR 26-2 (Fed/OCC/FDIC, Apr 2026) explicitly excludes GenAI and agentic AI. 175,000 Ollama servers sit on the internet with no auth. This is the layer in between." Architecture slide | — | slide |
| 1 ★ | **Identity and models** | `ola` (interns) asks for `mock-openai/gpt-4.1` → 400 `model_not_allowed`. `/v1/me` shows allowed models and the remaining 2,000 tokens: the team's original idea, delivered | C01, C02 | curl script |
| 2 ★ | **Deterministic in 3 ms** | a prompt with PESEL, IBAN and an AWS example key → `[PL_PESEL] [IBAN] [SECRET]`. The trace drawer shows rule ids and `Server-Timing` | C06, C07, C08 | Playground prefill |
| 3 | **Semantic** | a keyword-free paraphrased injection → C10 score 0.97 blocks. Then the same text hidden in Unicode tag characters → C08 decodes it and it is blocked | C08, C09, C10 | stub guard scores via `make demo-offline` |
| 4 ★ | **Judge edits the policy** | `C07_pii.mode: block` → `v15 ✓` in under 2 s, posture toast −x, re-send → blocked. Then a broken regex → rejected, last-known-good kept, red banner | C30, C32 | the edit is also a test |
| 5 ★ | **Agent + MCP** | the scripted support-bot: `facts` poisoned tool quarantined at `tools/list` (S1); `make demo-rugpull` → quarantine + diff (S2); ticket-42 indirect injection redacted (S4); `web_fetch http://169.254.169.254` and Ray `POST /api/jobs/` blocked; P1: the tainted run's external email blocked by provenance | C14, C15, C16, C17, C20, C24 | the scripted agent *is* the default; the live qwen3:8b run is a bonus |
| 6 | **Historical exploits + feed** | upload a malicious-pickle marker → blocked by allowlist; corrupted pickle → fail-closed; edit `90-judge.yaml` → `feed #43 ✓` → new IOC blocked; tampered bundle → rejected | C18, C19 | pre-generated fixtures |
| 7 | **Budget** | a flaky-tool loop is broken at the 4th identical call; the intern hits the daily cap → 429 with reset time; burn-down; race result "50 fired, 10 admitted, 0% overshoot" | C03, C04, C05 | test output screenshot |
| 8 ★ | **Evidence** | Threats → OCSF/CSV export; tamper one audit line → Verify names the seq; `Run self-test` → 150+ cases, then disable C10 → LLM01 turns amber `GAP` | C25, self-test | `make test` terminal recording |
| 9 | **Close** | perf table (overhead p95), K8s path, licenses, "runs offline" | — | slide |

---

## 11. Team split & timeline

### 11.1 Roles (six people, one lane each, one owner per file)

| Who | Lane | Owns |
|---|---|---|
| **L** (delivery lead) | Contracts, harness, integration, submission | `contracts/`, repo/CI/compose/Makefile, case runner, `make test`, live self-test + posture/coverage, demo storyline test, README/JUDGES/PDF/video, checkpoints, cut decisions |
| **A** | Gateway core | app, policy engine + hot reload, pipeline, identity C01/C02/C26, LLM proxy + streaming + C12, tool-call hook, mock-upstream, telemetry |
| **B** | Deterministic guards, feed, audit | C06, C07, C08, signature engine (C09/C17/C20 rule types), feed service + client (C19), audit writer + chain + verify (C25) |
| **C** | Models & money | guard sidecar (C10), artifact gate (C18), budgets C03/C04 + `/v1/me`, Valkey, Ollama/model ops, `make doctor` |
| **D** | Agents & MCP | FastMCP proxy + middleware (C15/C16 wiring), `governor.tools` (C14, validators, C05), demo MCP servers, demo agent (scripted + live), P1 taint/approvals |
| **F** | Console | design brief + Claude Design, SPA, read-side API (report, SSE, exports, playground), seeded history, slide visuals |

### 11.2 Work packages, estimates and dependencies

Estimates are AI-assisted focused hours. Each P0 load is about 11-14 h, which leaves 4-6 h per person for integration, debugging and cases.

| WP | Owner | P0 work package | Est. | Needs (from, by) | Delivers (to, by) |
|---|---|---|---|---|---|
| L1 | L | repo skeleton, `contracts/` commit, compose stubs, Makefile, CI, CLAUDE.md, CODEOWNERS | 1.5 h | drafts from this doc (pre-event) | everyone, **H1** |
| L2 | L | case runner (YAML → pytest), results sink, meta-test, `rich` summary, JUnit/HTML | 3 h | mock-upstream (A, H3) | all owners write cases, H4.5 |
| L3 | L | hermetic `compose.test.yaml`, `make test` green on skeleton cases | 0.5 h | skeleton | IC1, **H5** |
| L4 | L | live self-test runner, policy-aware expectations, posture + coverage calculators, `/admin/selftest` | 3 h | pipeline (A), events (B) | F's Overview, H10 |
| L5 | L | live-edit, feed, budget-race and audit-tamper suites (with owners) | 2 h | B, C | IC3 |
| L6 | L | `test_demo_storyline.py` with the scripted agent, `make demo-offline`, `make reset-demo`, `make doctor` (with C) | 1.5 h | D5a | IC3, **H12** |
| L7 | L | README, JUDGES.md, LICENSES.md, descriptions, PDF content, video, submission | 4 h | everything | **H21** |
| A1 | A | app factory, settings, health; mock-upstream v0 (OpenAI chat + SSE, directives, `/_mock/calls`) | 1.5 h | contracts | L2, H3 |
| A2 | A | policy engine: model, loader, watchfiles + hash poll, compile hooks, swap, LKG, `policy_change` | 2 h | contracts | all detectors, H4.5 |
| A3 | A | identity C01/C02/C26, `/v1/models`, minimal pipeline + non-stream proxy (skeleton) | 1 h | B2, C1 stubs | IC1, H5 |
| A4 | A | full pipeline: tiers, short-circuit, redaction apply, fail modes, Server-Timing, Prometheus | 2 h | — | H7.5 |
| A5 | A | streaming: SSE pass-through, trigger-aware holdback, C12 sanitizer, tool_call buffering, include_usage, protocol-correct termination | 3.5 h | — | IC2 (non-final), H10 |
| A6 | A | guard client (timeout, fail mode) + LLM-boundary tool hook into `governor.tools` | 1 h | C3, D3 | H11 |
| B1 | B | audit event builder, chained JSONL writer (background queue), `verify` CLI | 2.5 h | contracts | skeleton, **H3.5** |
| B2 | B | C06 secrets detector + cases | 1 h | A2 compile hook | skeleton, H4.5 |
| B3 | B | signature engine: regex (re2), keyword (pyahocorasick), http_request, hash, pickle_globals, package/url IOC | 2 h | — | D3, C4, H7 |
| B4 | B | feed service (watch, sign, serial, ETag) + gateway client (verify, serial, expiry, vectors, swap, event) | 2.5 h | B3 | IC2, H9.5 |
| B5 | B | C08 normalizer, C07 checksum PII + Polish false-positive guards | 2.5 h | — | IC3, H12 |
| C1 | C | Valkey Lua reserve/settle, scopes, price table, leases; stub at H2, real at H5 | 3 h | contracts | A3, H5 |
| C2 | C | C04 limits + clamp, `/v1/me`, 429 contract, compute-ms | 1.5 h | C1 | H6.5 |
| C3 | C | guard sidecar: ONNX PG2-22M (+ protectai fallback), `/v1/inspect`, stub engine, health | 2.5 h | pre-exported ONNX | A6, H9 |
| C4 | C | C18: pickle opcode allowlist, torch zip, safetensors, pins, `/v1/artifacts/scan` + CLI, fixture generator | 3 h | B3 (pickle_globals) | IC3, H12 |
| D1 | D | **FastMCP 4 spike**: `create_proxy` for one stdio server at `/mcp/filesystem` + middleware log. **Decision at H2.5**, fallback = thin JSON-RPC proxy (`tools/list`, `tools/call` only) over the `mcp` SDK client | 1.5 h | — | go/no-go **H2.5** |
| D2 | D | demo servers: filesystem, mail, bankdb (+ honeypot table), web (ticket-42 page), facts (v1/v2 via flag file) | 2.5 h | — | H5 |
| D3 | D | `governor.tools`: tool policy, jsonschema args, validators path/SSRF/SQL/email/amount, C17 pack hookup, C05 counters | 3.5 h | B3, C1 | A6, H9 |
| D4a | D | scripted demo agent (S1-S8 sequences, no LLM) | 1 h | D2 | L6, H9 |
| D4b | D | MCP middleware: list filter, C15 scan/pin/quarantine/diff, call → `governor.tools`, C16 result scan, audit | 3 h | A4, B3 | IC3, H12 |
| D5 | D | live agent mode (openai SDK → gateway, qwen3:8b, think off) | 1 h | A5 | H13 |
| F1 | F | design brief → Claude Design; visual system + page mocks | 1.5 h | brief (with L) | H2 |
| F2 | F | SPA scaffold, router, global header, SSE hook with polling fallback, fixtures mode | 2 h | fixtures (L, H1.5) | H4 |
| F3 | F | `/api/stream` SSE hub + `/api/threats` tail; Threats page + trace drawer on **live** data | 2 h | B1 | IC1, **H5** |
| F4 | F | Overview (posture, KPIs, coverage grid) on fixtures | 1.5 h | — | H7 |
| F5 | F | read API on DuckDB (overview, spend, controls, exports, integrity), `/api/playground` | 2.5 h | L4, C2 | H12 |
| F6 | F | Spend, Controls & Policy (+ Run self-test), Playground pages on live data; seeded history (`tools/seed.py`) | 3 h | F5 | IC3/H15 |

**P1 backlog, ranked. We build top-down and cut from the bottom; every item is behind a flag:**

| Rank | Item | Owner | Est. |
|---|---|---|---|
| 1 | `make bench` + perf table + console perf strip (judges ask for telemetry) | A | 1 h |
| 2 | C24 taint + provenance (S4/S5 guarantees) | D | 2.5 h |
| 3 | C23 approvals backend + console card (CLI fallback) | D + F | 2 h |
| 4 | C18 inline `/hf/` scanning mirror (`HF_ENDPOINT`) + GGUF template scan ("model repository" supply chain, end to end) | C | 2 h |
| 5 | Anthropic `/v1/messages` + Claude Code managed-settings smoke | A | 2.5 h |
| 6 | Four edges complete: app→agent ingress `/v1/agents/{id}/runs`; agent→agent via `kyc-agent` exposed as an MCP tool | A + D | 1.5 h |
| 7 | C10b MiniLM kNN + C11 llama-guard3:1b escalation | C | 3 h |
| 8 | OCSF 1.9.0 export | B | 1.5 h |
| 9 | C13 internal agent network + bypass test; kustomize manifests validated by kubeconform in CI | L | 1.5 h |
| 10 | Mutation kill-rate run (screenshot) | L | 1 h |
| 11 | C27 canary + C31 honeypot + C15b shadowing | B + D | 1.5 h |
| 12 | `make eval` + adherence-% calibration | C | 1.5 h |
| 13 | Two-replica scale profile (Caddy LB, cross-replica budget race) | A | 1 h |
| 14 | Console MCP & Approvals page, Signatures page, Attack Museum "Replay" buttons | F | 2 h |

### 11.3 The walking skeleton (green by H5, tag `ic1`)

`tests/e2e/test_walking_skeleton.py` asserts all of these on `make demo-offline`:
1. `gateway`, `mock-upstream`, `valkey` and `console` are healthy (the `feed` stub serves a dev bundle).
2. `POST /v1/chat/completions` as `vk_alice` with `debug key AKIAIOSFODNN7EXAMPLE` → 200, the content contains `[SECRET:aws_access_key]`, and the headers include `x-governor-decision: redact`, an event id and `Server-Timing`.
3. `vk_ola` + `mock-openai/gpt-4.1` → 400 `model_not_allowed`. An unknown key → 401.
4. Valkey shows alice's settled spend, and `/v1/me` reflects it.
5. The event is in `data/audit/gw-1-<date>.jsonl`, validates against `contracts/audit-event.schema.json`, and `governor audit verify` passes.
6. The console Threats page shows the row within 1 s through SSE.
7. Changing `C06_secrets.mode: redact → block` in `policy/policy.yaml` makes the same request return `finish_reason: content_filter` within 2 s, with `x-governor-policy` bumped and a `policy_change` event.
8. `make test` runs ≥ 6 cases (C01, C02, C06 × POS/NEG) green in < 60 s, and CI on `main` is green.

Not in the skeleton: streaming, MCP, semantic, feed signing. Those are IC2.

### 11.4 Timeline, checkpoints and go/no-go

H0 is the official start. Confirm the deadline at the opening: the RULES PDF says "11:00 PM Oct 4", which may be a typo (`docs/00-task-analysis.md` §4). The plan below assumes a 24 h window and submits at **H21** regardless.

```mermaid
gantt
  title Governor build plan (H0 = official start, hours)
  dateFormat HH:mm
  axisFormat H%H
  section Milestones
  Contracts frozen            :milestone, m0, 01:00, 0h
  IC1 walking skeleton        :milestone, m1, 05:00, 0h
  IC2 cross-lane              :milestone, m2, 08:00, 0h
  Placeholder submission      :milestone, m3, 11:00, 0h
  IC3 P0 complete             :milestone, m4, 12:00, 0h
  Feature freeze              :milestone, m5, 16:00, 0h
  Clean-room run offline      :milestone, m6, 17:30, 0h
  Final submission            :milestone, m7, 21:00, 0h
  section L lead
  Repo, contracts, CI         :l1, 00:00, 90m
  Case runner + make test     :l2, after l1, 210m
  Self-test, posture          :l4, 05:00, 2h
  Sleep                       :crit, ls, 07:00, 3h
  Suites + storyline test     :l5, 10:00, 2h
  P1 k8s, mutation, README    :l9, 12:00, 4h
  Hardening, video, PDF       :l7, 16:00, 5h
  section A core
  App, mock, policy engine    :a1, 01:00, 210m
  Skeleton integration        :a3, after a1, 30m
  Pipeline + telemetry        :a4, 05:00, 2h
  Streaming + holdback        :a5, 07:00, 4h
  Tool hook, guard client     :a6, 11:00, 1h
  P1 bench, Anthropic, edges  :a7, 12:00, 4h
  Fixes after clean room      :a8, 16:00, 150m
  Sleep                       :crit, as, 18:30, 3h
  section B guards
  Audit writer + verify       :b1, 01:00, 150m
  Secrets C06                 :b2, after b1, 1h
  Signature engine            :b3, 05:00, 2h
  Feed service + client       :b4, 07:00, 150m
  Normalizer + PII            :b5, 09:30, 150m
  Sleep                       :crit, bs, 12:30, 3h
  P1 OCSF, canary             :b6, 15:30, 30m
  Fixes                       :b7, 16:00, 3h
  section C models and money
  Budget ledger               :c1, 01:00, 4h
  Limits, me, 429             :c2, 05:00, 90m
  Guard sidecar               :c3, 06:30, 150m
  Artifact gate               :c4, 09:00, 3h
  P1 HF mirror               :c5, 12:00, 150m
  Sleep                       :crit, cs, 15:30, 3h
  Fixes                       :c6, 18:30, 150m
  section D agents and MCP
  FastMCP spike, decide       :d1, 01:00, 90m
  Demo MCP servers            :d2, after d1, 150m
  Tools lib + validators      :d3, 05:00, 3h
  Scripted agent              :d4, 08:00, 1h
  MCP middleware              :d5, 09:00, 3h
  Live agent, P1 taint        :d6, 12:00, 4h
  Fixes after clean room      :d7, 16:00, 150m
  Sleep                       :crit, ds, 18:30, 3h
  section F console
  Brief, Claude Design        :f1, 00:30, 90m
  Scaffold on fixtures        :f2, 02:00, 2h
  SSE + Threats live          :f3, 04:00, 1h
  Overview                    :f4, 05:00, 2h
  Sleep                       :crit, fs, 07:00, 3h
  Read API + pages live       :f5, 10:00, 5h
  Polish, P1 MCP page         :f6, 15:00, 1h
  Screenshots, slide visuals  :f7, 16:00, 5h
```

| Checkpoint | Time | Green means | If red → decision (taken by L, no debate) |
|---|---|---|---|
| **CF** | H1:00 | contracts committed, CI green on stubs, each lane has a stub that satisfies its interface | contracts ship as-is; gaps go into a v1.1 RFC |
| **IC1** | H5:00 | walking skeleton test green (§11.3), tag `ic1` | L + A pair on the skeleton until green; Anthropic dialect cut outright; the UI stays on fixtures until IC3 |
| **D1 gate** | H2:30 | FastMCP proxy forwards a stdio `tools/call` with our middleware | switch to the thin JSON-RPC proxy (tools only). Middleware logic is framework-free anyway |
| **IC2** | H8:00 | streaming pass-through via the gateway against the mock (holdback may still be in progress); real Valkey reserve/settle including the 429 path; one MCP `tools/call` on `/mcp/filesystem` blocked by the path validator with an audit event; signature engine compiling ≥ 5 example rules (signed feed lands by H9:30); guard container answering `/v1/inspect` (stub engine at minimum, ONNX model by H9) | streaming unstable → `stream_mode: buffer` (scan the full response, then emit as SSE; slower TTFT, same safety). Guard won't load → `semantic.engine: ollama` fallback (llama-guard3:1b only, escalation-style) or stub with "semantic tier degraded" shown honestly. Feed signing broken → sha256-pinned unsigned bundle, and we say so |
| **Placeholder** | H11:00 | title, team, description v1, draft PDF v0 uploaded (if the platform allows edits; checked at H0) | — |
| **IC3** | H12:00 | every P0 control enabled with ≥ 1 POS + ≥ 2 NEG passing; `make test` < 90 s; storyline steps 1-8 green offline; 5 console pages on live data; tag `ic3` | any P0 control still red → it is disabled in the demo policy, dropped from slides, and its owner fixes it before touching P1. P1 starts only on green lanes |
| **Freeze** | H16:00 | P1 merged behind flags or abandoned; tag `rc1` | unmerged branches are not merged. After this: bug fixes, cases, docs, policy/feed content, CSS only |
| **IC5 clean room** | H17:30 | fresh `git clone` on the spare laptop, Wi-Fi off: `make doctor && make test && make demo-offline && make demo` all pass; storyline test 100% | anything red becomes either a fix (≤ 30 min) or a cut (flag off + slide edit) |
| **Submit** | H21:00 | PDF ≤ 10 slides, repo public, video linked, tag `v1.0-submission` | — |
| **Pitch prep** | H21-H24 | 3 rehearsals, storyline test 10 min before stage | main locked |

### 11.5 Cut lines when we are behind

Cut in this order and never the reverse. Each cut is a flag flip plus a slide edit, not a code change:
1. P1 ranks 14 → 8 (UI extras, two replicas, eval, canary/honeypot, mutation, k8s, OCSF).
2. C10b/C11 (semantic depth). C10 alone carries the semantic requirement.
3. Anthropic dialect and four-edge extras (the agent→LLM and agent→MCP edges remain; app→agent and agent→agent become slides).
4. HF mirror (the scan API + CLI still show artifact governance).
5. Approvals (an `ask` verdict becomes `block` with "approval required" text).
6. Taint (S4/S5 fall back to C16 result redaction + C14 email domain allowlist, which still blocks the external send).

**Never cut:** C01-C10, C12, C14-C20 (P0 parts), C25, C26, C30, C32, hermetic `make test`, the live self-test, the console header + Threats + Playground, the storyline test, the offline mode.

### 11.6 Sleep plan (3 h each, never more than two asleep, never an owner asleep at their own gate)

| Window | Asleep | Covered by |
|---|---|---|
| H7:00-H10:00 | L, F | A deputizes as integrator at IC2. F's pages are on fixtures |
| H12:30-H15:30 | B | B's P1 is small; the feed and detectors are stable by IC3 |
| H15:30-H18:30 | C | C's last merge is at H15:30 (personal freeze) |
| H18:30-H21:30 | A, D | after clean-room fixes; any later issue = flag off, not code |
| H21-H24 | 60-90 min power naps in rotation | L and F rehearse the pitch |

### 11.7 Working agreements

- **Trunk-based.** Branches live < 2 h; PRs need `make test-fast` green. Everyone merges at least every 2 h. Nobody pushes to `main` in the 15 minutes before a checkpoint.
- **Stubs first.** By H1:30 every lane exposes its interface with a fake that returns contract-shaped data, so nobody waits on anyone.
- **Every new feature is a policy flag**, default off until its cases pass.
- **The demo laptop runs a tag, never `main`.** Tags: `ic1`, `ic2`, `ic3`, `rc1`, `v1.0-submission`.
- **AI assistants:** point them at `contracts/` and `CLAUDE.md` first. A contract change suggested by an assistant is an RFC, not an edit.
- **15-minute stand-ups only at checkpoints**, run at a screen with `make demo-check` (storyline test) output, not opinions.

---

## 12. Demo reliability

1. **Offline-first prep before H0** (allowed: downloads, accounts, design docs; no product code). Pre-fetch Ollama `qwen3:8b`, `qwen3:4b` and `llama-guard3:1b`; HF Prompt Guard 2 22M/86M (gated: request access a week ahead), protectai v2 and all-MiniLM-L6-v2, exported once to ONNX INT8; `docker save` tarballs of `python:3.12-slim`, `valkey/valkey:8`, `node:22-alpine` and `caddy:2`; a pip wheelhouse for linux/arm64 + amd64; the npm cache; tiktoken files; eval datasets. All of it goes on two USB sticks and the team drive (`research/R4-local-models.md` recommendations).
2. **Two demo modes, same UI:** `make demo` (native Ollama) and `make demo-offline` (mock upstream + scripted agent + stub guard scores). If the model misbehaves on stage, one command switches modes in 20 s.
3. **The scripted agent is the default** for MCP scenarios. The live qwen3:8b agent is a bonus. Tests assert on audit events, never on prose (`research/R6-mcp-agent-security.md` risks).
4. **The demo is a test.** `test_demo_storyline.py` runs at every checkpoint, after the clean-room run, and 10 minutes before the pitch.
5. **`make doctor`** preflight checks the Docker memory allocation (≥ 8 GB), free ports 8080/3000/9000/9100/9200, Ollama ≥ 0.14 and the models present, disk, and the HF/ONNX files, and prints the fix for each failure. **`make warm`** loads every model with `keep_alive -1` and fires one request each, so nothing cold-starts mid-demo.
6. **`make reset-demo`** flushes Valkey budgets, resets `facts` to v1, restores `policy/policy.yaml` from the tag, rotates the audit chain, and re-seeds labelled synthetic history (`tools/seed.py`) so charts are never empty.
7. **Two identical demo laptops** (primary + hot spare), both rehearsed with Wi-Fi off at IC5. The images are pre-built on both.
8. **Recorded video** (3-4 min) of the full storyline at H18, plus a 20-40 s clip per beat. Slides embed a screenshot of every beat, so the pitch survives a total failure. The video is uploaded unlisted to YouTube with a Google Drive mirror, and an MP4 sits on both laptops.
9. **Judge kit:** `JUDGES.md` with the judge key, 10 copy-paste pokes (the §5 matrix), the files to edit, how to run tests, and what "GAP" means. The console Playground has the same pokes prefilled.
10. **Fail-soft everywhere:** SSE → polling fallback; hot reload via watch + 1 s hash poll; the guard timeout follows the policy fail mode; unknown feed rule types are skipped; a crashing detector degrades instead of killing the request path.

---

## 13. Submission logistics

- **What the platform needs:** title, team name, member list, description, PDF ≤ 10 slides; the repo and demo links go inside the PDF and the description (`docs/00-task-analysis.md` §4).
- **H0:** confirm the deadline wording, whether submissions can be edited, the description length limit and the weights (CRITERIA 15/15 vs RULES 20/10).
- **H10-H11 (L):** description in three lengths (one-liner, 100 words, 300 words), title **"Governor: AI Control Layer"**, and a **placeholder submission at H11** with PDF v0 if edits are allowed. If they are not, a checklist dry-run instead.
- **H16-H20:** PDF v1 at H19 and v2 at H20.5. The 10 slides:
  1. title + one-liner + team;
  2. problem / why now (SR 26-2 gap, incident root causes);
  3. architecture (the §2.1 diagram);
  4. one policy file, profiles, < 2 s hot reload;
  5. guardrails: deterministic first, semantic second (control table + coverage grid);
  6. historical attacks + the signed external feed (Attack Museum);
  7. budgets: three units, reserve/settle, 0% overshoot;
  8. reporting: console screenshot, hash chain, exports;
  9. self-testing: matrix, case counts, mutation kill rate, perf table;
  10. integration (base_url, managed settings, MCP URL), K8s path, licenses, links.

  F does the visuals; L does the content.
- **Repo:** made public at H20 after `gitleaks detect` on the history (fixture secrets are generated at runtime, so push protection never fires). Apache-2.0 LICENSE, NOTICE ("Built with Llama" if Prompt Guard 2 ships), `LICENSES.md` from `pip-licenses` + `license-checker`.
- **The README's first screen:** what it is (3 lines) → architecture diagram → **`make test`** (hermetic, expected output screenshot) → `make demo-offline` → `make demo` → JUDGES.md link → perf table → video link.
- **`make submission-check`:** pypdf page count ≤ 10 and size < 20 MB, README links resolve, tag exists, `make test` green on the tag.
- **H21: final submission** by L, with a second person watching the screen; then a screenshot of the confirmation. Phase-2 roles: L narrates, F drives the console, D runs the agent terminal, A takes architecture/perf questions, B and C take guardrail and budget questions.

---

## 14. Risks

| Risk | Likelihood | Impact | Mitigation | Trigger / owner |
|---|---|---|---|---|
| Streaming proxy (SSE, holdback, tool_call deltas) takes longer than planned | M | H | non-stream in the skeleton; `stream_mode: buffer` fallback; mock-driven stream tests from H5 | IC2 / A |
| FastMCP 4 API differs from the docs (v4 is new; most docs are v2; the `mcp` SDK renamed FastMCP to MCPServer) | M | H | 90-min spike with a hard gate at H2.5; framework-free middleware logic; thin JSON-RPC fallback (`research/FACT-CHECK.md` B2) | H2.5 / D |
| Drift between six people and six AI assistants | H | H | frozen contracts, CODEOWNERS, CI schema tests on fixtures/events/policies, CLAUDE.md, merge every 2 h | CF onward / L |
| One UI person becomes the bottleneck | M | H | fixtures from H1:30, owner also owns the read API, Claude Design brief, page cut order, polling fallback | IC3 / F |
| Gated model download, Wi-Fi, HF blocked | M | M | everything pre-fetched; ungated protectai fallback; stub guard; offline mode | pre-event / C |
| Hot reload flaky on Docker Desktop bind mounts | M | H | watch the directory, not the inode; 1 s sha poll fallback; test asserts propagation time | IC1 / A |
| Judge regex causes ReDoS and freezes the asyncio loop | M | H | google-re2 for every policy/feed pattern; compile validation rejects the edit (`research/R7-budget-streaming-performance.md` §3.5) | B |
| Local LLM tool-calling is flaky on stage | H | M | the scripted agent is the default; the live run is a bonus; assertions on audit | D |
| Mentors' machines (x86, Windows, no make, no Ollama) | M | H | hermetic compose; raw docker command; `host-gateway` extra_hosts; multi-arch base images; `make doctor` | L |
| Semantic classifier is weak on Polish and adaptive attacks | H | M | don't claim it; deterministic + tool mediation + taint carry the guarantees; show the scores and FPR honestly (`docs/02-threats-and-attack-museum.md` §4) | C |
| Fatigue errors late at night | H | M | sleep plan; freeze at H16; tags; the demo laptop runs a tag; "flag off, not code" after H18 | L |
| Deadline ambiguity (PM vs AM) | L | H | confirm at H0; submit at H21 regardless | L |
| License contamination | L | M | no AGPL/GPL in our images (no Grafana, no Squid fork, no Open WebUI); fickling cut; `LICENSES.md` generated | L |

---

## 15. What we deliberately cut

| Cut | Why |
|---|---|
| **Forking Squid** (and stock Squid as the egress fence) | A fork is C++/GPLv2+ work that can't see prompts, tool calls or SSE streams without SslBump (`docs/01-review-of-our-first-idea.md`). Stock Squid as a fence costs 2-3 h for a feature judges barely poke. The Docker internal network (P1) proves the chokepoint more cheaply. The Squid config stays in `examples/agent-config/squid/` as the production fence |
| **Keycloak / LDAP live** | 3-4 h plus RAM, and a login flow that can break mid-demo. Virtual keys with LDAP-named groups give the same policy semantics. OIDC `groups` claim → same field is the production path (`research/R5-proxy-enforcement-identity.md`) |
| **A2A protocol proxy** (C21) | about 4 h for one scenario. Agent→agent is covered as agent-as-MCP-tool (P1), and ASI07 is shown honestly as out of scope |
| **Kubernetes live** | kind on stage is a liability. Manifests are validated by kubeconform (P1); compose shows the stateless design |
| **Presidio** | the `pl`-language trap, image weight, and NER false positives. Our own checksum recognizers are more precise for PESEL/IBAN/PAN |
| **Grafana, Loki** | AGPL, one more container, and the console already shows the perf strip and `/metrics` |
| **Open WebUI** | custom license with branding terms, another container. The Playground covers ad-hoc prompts and any OpenAI SDK works |
| **LiteLLM / Portkey / agentgateway as the core** | enterprise-gated features, restart-on-config, and judges would score the vendor (`research/R3-oss-landscape.md`). Adapters are pitch material |
| **garak / promptfoo red-team runs** | heavy images and cloud defaults. `make eval` on public datasets gives the numbers |
| **Memory-write guard, RAG ACL, slopsquatting check, anomaly baselines, LLM alignment judge** | low demo value per hour; they stay on the roadmap slide |
| **Merkle checkpoints, ECS/CEF/HEC exports, LLM-written exec report** | the hash chain + verify + CSV/JSONL (+ OCSF P1) already satisfies "exportable audit". The rest is polish |
| **Codex `/v1/responses`, Claude Code live on stage** | dialect work for clients judges won't use. A Claude Code clip is P2 |
| **Hyperscan/Vectorscan** | wheel and licence uncertainty; re2 + Aho-Corasick are fast enough (`research/R7-bench/bench_regex_out.txt`) |

---

## 16. Self-assessment against the judging criteria

| Criterion (weight) | Score | Reasons |
|---|---|---|
| **Robustness & quality of guardrails (30%)** | **8/10** | All four edges are addressed. Agent→LLM and agent→MCP are deep. App→agent and agent→agent are thin P1 routes. There are ~22 P0 controls, deterministic first: checksum PII, secret patterns, Unicode-tag decoding, re2 signatures, tool validators applied on **both** the LLM and the MCP boundary, allowlist-first fail-closed artifacts, and a signed feed whose rules must pass their own test vectors. The semantic tier is real (PG2 classifier) and visible (scores and thresholds). **Minus:** semantic quality on Polish is unmeasured, taint/provenance is P1, there is no A2A, and adaptive attacks against the classifier are only bounded by downstream deterministic controls |
| **Architecture & performance efficiency (20%)** | **7/10** | One brain, two thin enforcement adapters, cheap-first cascade with short-circuit, trigger-aware streaming holdback, reserve/settle in Valkey, ReDoS-safe regex, Server-Timing per stage, measured overhead. **Minus:** a Python data plane is "fast enough", not fast; P0 runs a single replica (two-replica scale is P1); the guard hop adds 10-40 ms on CPU |
| **Security reporting (20%)** | **8/10** | Hash-chained `aicl.audit/v1` with verify, decision trace per request with rule ids and OWASP 2026/ASI/MCP/ATLAS tags, live SSE console, posture with sub-scores computed from the policy and tests, budget burn-down, JSONL/CSV export, and an audit event for every policy and feed change. **Minus:** OCSF is P1; no live SIEM integration; exec weekly report cut |
| **Self-testing suite (15-20%)** | **9/10** | Hermetic `make test` in < 90 s on any Docker machine; ≥ 150 tagged cases with a meta-test enforcing POS+NEG per control; live policy-aware self-test (GAP vs FAIL); feed vectors; hot-reload, budget-race, exploit and audit-tamper suites; the demo storyline itself is a test; CI badge. **Minus:** mutation kill-rate and detector P/R/F1 are P1 |
| **Practical implementability & scalability (10-15%)** | **7/10** | Zero-code integration via `base_url` and the existing managed-settings and MCP configs; one policy file with profiles; a one-command offline demo; stateless gateway with state in Valkey; a license-clean stack. **Minus:** SSO/LDAP is simulated with virtual keys; K8s is manifests only; Claude Code and Codex dialects are P1/cut |

**Weighted estimate (CRITERIA weights):** 0.30·8 + 0.20·7 + 0.20·8 + 0.15·9 + 0.15·7 = **7.8 / 10**.
**Delivery confidence:** P0 complete by IC3 (H12) ~70%, by freeze (H16) ~90%. The top four P1 items ship ~65%. The offline demo works on a mentor's laptop with `make test` + `make demo-offline` ~90%. That last number is the one this proposal optimizes for.
