# R3: Open-source landscape and the build vs. build-on decision

> **TL;DR**
> 1. **Don't fork Squid. Don't make LiteLLM or another gateway our core either.** The judged features are policy, guardrails, budgets, exploit signatures, reporting and tests. No OSS gateway ships them in a way judges can edit live. Where gateways do have them, the parts we need are often enterprise-gated (LiteLLM JWT/OIDC, Bifrost guardrails/SSO, Kong 3.10+).
> 2. **Build a thin control layer we own** (Python 3.12 + FastAPI): an OpenAI/Anthropic-compatible LLM proxy, an MCP proxy (FastMCP/MCP SDK), one `policy.yaml` with schema validation and hot reload, a budget ledger, a signature feed, an audit log and metrics. Reuse **libraries** for detection: Presidio, Prompt Guard 2 / Llama Guard / Qwen3Guard via local inference, ModelAudit + picklescan, YARA-X, CEL.
> 3. **Several famous guardrail projects are dead or drifting.** LLM Guard was **archived on 9 Jul 2026**, Rebuff **archived on 16 May 2025**, Vigil has had no commits since **Jan 2024**, and Invariant has been low-activity since Snyk bought it. Snyk Agent Scan (formerly mcp-scan) **needs a Snyk token and sends tool descriptions to Snyk**. Lean on the actively maintained parts.
> 4. **agentgateway** (Linux Foundation, Apache-2.0, Rust, LLM+MCP+A2A, CEL RBAC, hot-reloaded YAML, webhook guardrails) is the best **optional data-plane adapter**. It lets us say "our policy brain plugs into any gateway". It shouldn't be the core.
> 5. Main license and footprint risks: Llama community licenses (gated HF downloads), AGPL (Grafana, Tyk AI Studio, new-api), the Redis 8 tri-license (use Valkey), LGPL (fickling, semgrep: run them as separate processes), ModelAudit telemetry (on by default), and the **LiteLLM PyPI compromise (24 Mar 2026)**. That last one is a reason to pin and hash dependencies, and a nice demo story.

---

## 0. Method, conventions, caveats

- **Verified on 2026-10-03.** License facts come from the repos' actual `LICENSE`/`COPYING` files, fetched from `raw.githubusercontent.com`. Versions and release dates come from the **PyPI JSON API**. Repo status (archived, commit dates, directory listings) comes from GitHub pages. Product facts come from READMEs in the repos. Web search was used for news (acquisitions, incidents) and for vendor docs whose sites were blocked by this session's egress proxy (docs.litellm.ai, agentgateway.dev, huggingface.co, etc.). In those cases the URL cited is the doc page the search returned.
- "OSS" means the open-source edition. "EE" means an enterprise/commercial license is required.
- Hackathon-fit scores (1-5) and hour estimates are **our judgment**, not measured facts.
- Anything I could not verify is marked **UNVERIFIED**. §11 collects all of them.
- Related notes: **R1** (threat frameworks, interception-point table) and **R2** (historical attacks + signature-feed schema). This file doesn't repeat them.

---

## 1. The decision in one picture

```
                 ┌──────────────────────── OUR CODE (the differentiators judges score) ───────────────────────┐
 agents / apps   │                                                                                             │
 (Claude Code,   │   ┌───────────────┐   ┌──────────────────────────────────────────────┐   ┌───────────────┐ │
  Codex, LangGraph├──►│ LLM proxy     │──►│ Guard pipeline (tiered, per-control mode)    │──►│ Upstreams     │ │
  Open WebUI,    │   │ /v1/chat/...  │   │  T0 identity/model/tool allowlist (CEL)      │   │ Ollama (local)│ │
  custom apps)   │   │ /v1/messages  │   │  T1 regex/secrets/PII (Presidio) / signatures │   │ OpenAI-compat │ │
                 │   │ /v1/models    │   │  T2 classifier (Prompt Guard 2, ONNX/torch)   │   │ (no paid keys)│ │
       MCP ─────►│   │ MCP proxy     │   │  T3 LLM judge (Llama Guard / Qwen3Guard)      │   └───────────────┘ │
       A2A ─────►│   │ (FastMCP)     │   │  -> allow / redact / block / audit            │                     │
                 │   └──────┬────────┘   └──────────────────────────────────────────────┘                     │
                 │          │  budget ledger (tokens, $, local compute-s)   signature feed (R2 schema, signed) │
                 │          │  policy.yaml (+JSON-Schema, hot reload, last-known-good, version hash)          │
                 │          └─► audit log (hash-chained JSONL) ─► metrics (Prometheus) ─► dashboard + exports  │
                 │   self-test suite (pytest: +/- case per control, budget, feed, hot-reload mutation tests)   │
                 └─────────────────────────────────────────────────────────────────────────────────────────────┘
   REUSED LIBRARIES: presidio-analyzer/anonymizer (MIT) · transformers/onnxruntime · ollama (MIT) · modelaudit (MIT)
   · picklescan (MIT) · yara-x (BSD-3) · fastmcp (Apache-2.0) · mcp (MIT) · cel (Apache-2.0) · pydantic · watchfiles
   OPTIONAL ADAPTERS (stretch): agentgateway webhook guard · LiteLLM CustomGuardrail · Claude Code hooks · Squid/
   docker-network egress fence (unmodified config, no fork)
```

---

## 2. AI gateways

### 2.1 Master table

| Gateway | License (verified file) | Lang | Budgets / virtual keys | Per-user/team model allowlist | Guardrail hooks | MCP | A2A | SSO/OIDC | Config hot reload | Footprint | Maturity / status | Hackathon fit as **core** (1-5) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **LiteLLM proxy** | MIT, except `enterprise/` (commercial) [litellm-lic][litellm-ee-lic] | Python | Yes, OSS (virtual keys, max_budget, budget_duration; **needs Postgres**) [litellm-pg] | Yes (team/key model access) | `CustomGuardrail` pre/during/post-call hooks; post_call on streams is **audit-only** [litellm-cg] | Yes (MCP gateway in README) [litellm-readme] | Yes (`/a2a`) [litellm-readme] | **EE**: SSO free only up to 5 users; **JWT/OIDC auth is EE** [litellm-ee][litellm-jwt] | `config.yaml` needs restart. Models/keys stored in the DB change live via UI/API [litellm-db] | Postgres required for keys; Redis for multi-instance [litellm-pg] | Very mature, 1.103.2 (1 Oct 2026) [pypi-litellm]. **PyPI compromise 24 Mar 2026 (1.82.7/1.82.8)** [ddog-litellm] | **2.5** |
| **Portkey gateway** | MIT [portkey-lic] | TypeScript (Hono) [portkey-pkg] | OSS 1.x: no (hosted/EE). "Gateway 2.0" pre-release branch merges EE into OSS; press release 24 Mar 2026 says "fully open source" [portkey-readme][portkey-pr] | `modelwhitelist`, `modelRules`, `jwt` default plugins [portkey-manifest] | Plugin framework: 21 plugin dirs (regex, JSON schema, webhook, many SaaS partners) [portkey-plugins] | MCP Gateway (docs say EE auth) [portkey-readme] | not found | EE (1.x) | Configs travel per request (header/JSON). File reload **UNVERIFIED** | Tiny Node service; Redis optional (`ioredis` dep) [portkey-pkg] | Mature in 1.x; 2.0 still "pre-release" in README on 2026-10-03 | **2** |
| **Kong AI Gateway** | Apache-2.0 (OSS core) [kong-lic] | Lua/OpenResty | Advanced token rate limiting (`ai-rate-limiting-advanced`) is **EE** [kong-ai] | via consumers/ACL | OSS ai-* plugins: `ai-proxy`, `ai-prompt-guard` (regex), `ai-prompt-decorator/template`, `ai-request/response-transformer`; semantic guard and sanitizer are EE [kong-plugins][kong-ai] | EE plugins | n/a | EE | DB-less declarative reload **UNVERIFIED** | Postgres or DB-less | **OSS images stop at 3.9.1. From 3.10 there's no free mode** [kong-14628] | **1** |
| **Envoy AI Gateway → "Agent Router"** | Apache-2.0 [envoyai-lic] | Go control plane on Envoy | Token-based rate limits via Envoy global RL; `QuotaPolicy` for cumulative caps; **CEL token-cost expressions** [envoyai-rl] | via JWT claims / CEL | Envoy ext_proc architecture | MCP gateway with CEL/JWT authz (v0.5) [envoyai-v05] | n/a | via Envoy Gateway security policies | K8s CRDs reconciled live (xDS). Standalone `aigw run` exists [envoyai-readme] | **Kubernetes + Envoy Gateway** (Redis for global RL) | Renamed **Agent Router**, now an "Agentic AI Foundation project"; repo moved to `theagentrouter/agent-router` [envoyai-readme] | **2** |
| **agentgateway** | Apache-2.0 [agw-lic] | Rust (+Go controller) [agw-gh] | "budget and spend controls"; v1.5.0 added **API-key-scoped LLM budgets** [agw-readme][agw-rel] | **CEL RBAC** | Guard layers: regex, OpenAI moderation, Bedrock Guardrails, Model Armor, **custom webhook**. Actions: pass/reject/mask/audit [agw-readme][agw-guard] | **Yes**: federation, stdio/SSE/Streamable HTTP, OpenAPI→MCP, OAuth | **Yes** | JWT, API keys, OAuth/OIDC (improved in 1.6) [agw-rel] | **File watched. Most changes hot, except the top-level `config` block** [agw-cfg] | Single binary + YAML; K8s optional (Gateway API) | Linux Foundation project. **v1.6.0 on 2 Oct 2026**, built-in UI [agw-readme][agw-rel] | **3.5** (best adapter) |
| **Apache APISIX (AI plugins)** | Apache-2.0 [apisix-lic] | Lua/OpenResty | `ai-rate-limiting` (tokens per window; local or Redis) [apisix-airl] | consumer-based | `ai-prompt-guard` (allow/deny patterns), `ai-lakera-guard`, `ai-aliyun/aws-content-moderation` (SaaS) [apisix-plugins] | `mcp`, `openapi-to-mcp` dirs [apisix-plugins] | n/a | openid-connect plugin | **Standalone YAML checked every 1 s, hot in-memory update** [apisix-modes] | etcd or standalone file | Mature | **2** |
| **Higress** | Apache-2.0 [higress-lic] | Go + Envoy/Istio, Wasm plugins | `ai-quota`, `ai-token-ratelimit` [higress-ext] | consumer-based | `ai-security-guard` (Aliyun), **`qwen3guard`** plugin, custom Wasm (Go/Rust/JS) [higress-ext] | `mcp-server`, `mcp-router` [higress-ext] | n/a | via Envoy/Istio | xDS hot. Standalone **UNVERIFIED** | K8s-native; standalone Docker possible [higress-gh] | CNCF Sandbox (per README summary) [higress-gh] | **2** |
| **TensorZero** | Apache-2.0 [tz-lic] | Rust | Custom rate limits (`[[rate_limiting.rules]]`), state in **Postgres or Valkey** [tz-rl] | n/a | none focused on guardrails | n/a | n/a | n/a | **UNVERIFIED** | ClickHouse optional (observability) [tz-rl] | Focus is LLMOps/optimization; "Autopilot" is paid [tz-readme] | **1.5** |
| **Helicone** | Platform Apache-2.0 [hel-lic]. `Helicone/ai-gateway` repo: **LICENSE file is GPL-3.0 but README badge says Apache** (discrepancy) [hel-gw-lic][hel-gw-readme] | TS (platform), Rust (ai-gateway) | Rate limits per user/team/global incl. $ [hel-gw-readme] | n/a | n/a | n/a | n/a | n/a | n/a | Supabase + ClickHouse [hel-readme] | **Acquired by Mintlify (Mar 2026), maintenance mode** [hel-acq] | **1** |
| **Bifrost** (Maxim) | Apache-2.0 [bifrost-lic] | Go | **OSS**: virtual keys, hierarchical budgets, rate limits, **MCP tool allowlists per virtual key** [bifrost-gov] | Yes (virtual key) | **EE**: guardrails (Bedrock/Azure/Patronus), custom plugins docs under `/enterprise/` [bifrost-readme][bifrost-gov] | Yes (MCP; federated MCP auth is EE) | n/a | **EE** (OIDC, RBAC, team sync) [bifrost-gov] | Web UI / API dynamic. File reload **UNVERIFIED** | Single Go binary + SQLite/Postgres config store | Claims ~11 µs overhead at 5k RPS (vendor benchmark) [bifrost-readme] | **2.5** |

**Newer or adjacent gateways worth knowing (one line each):**

| Project | License | Note |
|---|---|---|
| **Plano** (Katanemo, formerly archgw) | Apache-2.0 [plano-lic] | Envoy-based "AI-native proxy". Guardrails through **Filter Chains**, agent routing, OTel signals [plano-readme] |
| **Otari** (Mozilla.ai, gateway for `any-llm`) | Apache-2.0 [otari-lic] | Budgets, API keys, usage analytics, multi-tenant [anyllm-readme] |
| **MLflow AI Gateway** | Apache-2.0 [mlflow-lic] | Simple provider routing. Features not checked |
| **LLM Gateway** (theopenco) | Mixed: "portions" under a separate license [llmgw-lic] | Check the enterprise dirs before use |
| **Tyk AI Studio** | **AGPL-3.0** [tyk-lic] | Avoid embedding |
| **new-api** | **AGPL-3.0** [newapi-lic] | Avoid embedding |
| **Microsoft Agent Governance Toolkit (AGT)** | MIT, **Public Preview** [agt-lic][agt-readme] | Not a gateway but the closest *competitor* to our pitch: YAML/OPA/Cedar policies, MCP security gateway, Merkle audit, "OWASP Agentic Top 10: 7 full, 3 partial" badge, Claude Code/Codex/Copilot CLI installers [agt-readme][agt-blog] |

### 2.2 Per-gateway notes that matter for us

**LiteLLM** (the obvious "just configure it" choice)
- *Strengths:* biggest provider coverage. OSS has virtual keys with budgets and model allowlists, spend tracking, an admin UI, MCP and A2A gateways. You can write Python `CustomGuardrail` classes with `async_pre_call_hook` (modify/reject), `async_moderation_hook` (parallel to the LLM call) and `async_post_call_success_hook` [litellm-cg].
- *Problems for our task:*
  1. **The identity piece the team wants (SSO + LDAP groups → budgets/models) is exactly what's gated.** JWT/OIDC auth with `team_ids_jwt_field: "groups"` is EE [litellm-jwt]. Admin-UI SSO is free only up to 5 users [litellm-ee]. Secret detection/redaction and per-key guardrails are EE too [litellm-ee]. The EE license does allow "development and testing purposes" without a subscription [litellm-ee-lic], so a demo is legally fine, but pitching it as the production answer is weak.
  2. **Hot reload:** judges editing `config.yaml` means a restart. Live changes go through the DB/UI instead [litellm-db]. That's a different story from "edit the policy file and watch it take effect".
  3. Streaming post-call guardrails are audit-only [litellm-cg]. Output DLP on streams needs our own buffering anyway.
  4. **Supply chain:** TeamPCP pushed malicious **1.82.7 and 1.82.8** to PyPI on **24 Mar 2026**. A `.pth` payload stole credentials, and the root cause was a compromised Trivy in LiteLLM's CI [ddog-litellm][arthur-litellm]. For a security product that's an awkward core dependency. It's also a great **historical-attack demo** (R2 category e), with hash pinning as the control.
- *Verdict:* use it as a reference design and an optional adapter ("our guard service also works as a LiteLLM CustomGuardrail"), not as the core.

**agentgateway** (the best thing to build *next to*)
- Covers all four interaction types in the task: agent→LLM, agent→MCP, agent→agent (A2A), plus generic HTTP [agw-readme]. Ships as a single binary with YAML config. **Edits are picked up automatically except the top-level `config` section** [agw-cfg]. CEL-based RBAC. Guard layers can **call a custom webhook** and pass/reject/mask/audit [agw-guard].
- Shipping fast: v1.5.0 (27 Aug 2026) added API-key-scoped LLM budgets. **v1.6.0 (2 Oct 2026)**, the day before the hackathon, added cost tracking for public models, OIDC/JWT improvements and per-key local rate limits [agw-rel]. Expect doc/API churn.
- *Use:* a stretch adapter. We ship `adapters/agentgateway/config.yaml` that routes LLM/MCP traffic through agentgateway and points its webhook guard at our `/guard` endpoint. **Our** `policy.yaml` stays the single source of truth, and we can generate agentgateway's RBAC/CEL from it. The webhook request/response schema is **UNVERIFIED** (the docs site is blocked here), so check it before committing.

**Envoy AI Gateway / Agent Router**
- Strong *scalability* story: Envoy, two-tier gateway, K8s CRDs, CEL-weighted token costs, `QuotaPolicy` [envoyai-readme][envoyai-rl]. Needs Kubernetes + Envoy Gateway to shine, though, and our logic would sit behind gRPC ext_proc. Too much plumbing for 24 h. Quote it in the pitch ("our design maps onto Envoy ext_proc / Agent Router in production").

**Portkey OSS 1.x**
- The interesting part is its guardrail **plugin manifest**: `regexMatch`, `jsonSchema`, `modelwhitelist`, `modelRules`, `jwt`, `webhook`, `containsCode`, `validUrls`, etc. [portkey-manifest]. It's good prior art for naming our deterministic checks. Budgets and RBAC aren't in 1.x OSS. The 2.0 status is unclear (README says pre-release, press release says fully open source) [portkey-readme][portkey-pr].

**Kong**: skip. OSS images are frozen at 3.9.1, and advanced AI plugins (semantic guard, sanitizer, advanced token RL) are EE [kong-14628][kong-ai].

**APISIX / Higress**: decent token RL and regex prompt guards, but the semantic guards call SaaS (Lakera, Aliyun, AWS). Lua or Wasm extension cost is high for us. APISIX's 1-second file-poll hot reload is a nice reference for behaviour [apisix-modes]. Higress having a **Qwen3Guard** plugin backs up Qwen3Guard as a local-model choice [higress-ext].

**TensorZero / Helicone**: wrong focus (optimization/observability). Helicone is in maintenance mode [hel-acq].

**Bifrost**: OSS has the budget/virtual-key/MCP-tool-filter model we want to imitate [bifrost-gov]. Guardrails, SSO and RBAC are EE. Go, fast. If the team were Go-first, Bifrost's OSS governance plugin is the best code to *read* for budget hierarchy ideas (Business Unit → Team → Virtual Key → Provider) [bifrost-gov].

### 2.3 The Squid-fork idea, assessed

| Question | Finding | Source |
|---|---|---|
| License | **GPLv2+** (C++). A fork stays GPL, and distributing a modified binary obliges source release | [squid-copying][squid-readme] |
| How content inspection is done in Squid | Not by forking: **ICAP (REQMOD/RESPMOD) or eCAP adapters**, and only on **SslBump-decrypted** traffic. Squid can't send encrypted messages to ICAP/eCAP | [squid-icap] |
| Implication | The AI logic would live in an ICAP server anyway (e.g. `pyicap`, BSD, last release 1.0b1) | [pyicap] |
| TLS interception cost | Needs a CA on every client. Pinned clients break. Much harder to demo than `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL` | general |
| Security record | 2021 audit found **55 flaws**, **35 still unpatched** at public disclosure in Oct 2023 | [squid-register][squid-joshua] |
| What it is good at | Network-level **egress fence**: allowlist only the gateway host, block "shadow AI" domains. No fork needed, just `squid.conf` | R1 §11 |

**Verdict:** keep the *idea* (a forced chokepoint), drop the *fork*. Force agents through the gateway with **managed settings**: Claude Code `managed-settings.json` can set `env` such as `ANTHROPIC_BASE_URL` / `HTTPS_PROXY` with highest precedence, plus an `apiKeyHelper` for per-user gateway tokens [cc-settings][cc-proxy]. Back it with an **egress fence**: Docker internal network/K8s NetworkPolicy, or an unmodified Squid allowlist. For a visible "shadow AI detected" demo, **mitmproxy** (MIT, Python addons, 12.2.3) [pypi-mitmproxy] is a 1-2 h add-on, versus days for Squid C++.

### 2.4 The "they just configured X" risk

Judges score **guardrail robustness (30%)**, **architecture/perf (20%)**, **reporting (20%)** and **tests (15-20%)**. If the core is LiteLLM/Portkey/Bifrost:
- Most visible features (keys, budgets, UI) are the vendor's. Our contribution shrinks to a plugin.
- **Live policy edits** go through *their* config semantics (LiteLLM restart/DB, Bifrost UI). We can't guarantee "edit `policy.yaml` → effect in under 2 s, invalid edit → rejected and last-good kept, visible in dashboard".
- Six capabilities (hybrid guards, compute budgets for local models, exploit-signature feed, artifact scanning, self-tests, audit export) aren't in any gateway, so we'd build them anyway.

→ Owning a thin proxy costs about 4-6 person-hours for the basic OpenAI/Anthropic passthrough with streaming (our estimate). In return, every judged behaviour is ours to explain.

---

## 3. Guardrail libraries and frameworks

### 3.1 Status and fit table

| Library | License | Latest release (PyPI) | Status (2026-10-03) | What it gives us | Offline? | Fit |
|---|---|---|---|---|---|---|
| **Microsoft Presidio** (analyzer + anonymizer) | MIT [presidio-readme] | 2.2.364 (22 Jul 2026), Py 3.10-3.14 [pypi-presidio] | **Active. Moving from Microsoft to the community org `data-privacy-stack`**. Images move from MCR to `ghcr.io/data-privacy-stack/presidio-*` [presidio-transition] | PII detection: regex + checksum + context + NER (spaCy/transformers). Built-ins include CREDIT_CARD, IBAN_CODE, EMAIL, PHONE, IP, crypto, **PL_PESEL** (pattern + context + checksum), many country IDs. Custom/remote recognizers. Anonymizer operators (replace/mask/hash/encrypt) [presidio-entities] | Yes | **MVP: T1 PII/redact** |
| **NVIDIA NeMo Guardrails** | Apache-2.0 [nemo-lic] | 0.24.1 (16 Sep 2026), Py 3.10-3.13 [pypi-nemo] | Active (repo now `NVIDIA-NeMo/Guardrails`) | Colang flows; **5 rail types (input, dialog, retrieval, execution, output)**; jailbreak/injection detection, self-check rails, NVIDIA safety models, guardrails server [nemo-readme] | Yes with local LLM, but self-check rails = extra LLM calls (latency) | Stretch, or "inspiration". Colang is another language for judges |
| **Guardrails AI** | Apache-2.0 [gr-lic] | 0.11.0 (14 Aug 2026) [pypi-guardrails] | Active, but **validators moving to plain PyPI packages; hosted remote inferencing discontinued (cutoff 25 Aug 2026)** [gr-readme] | Validator framework, `guardrails start` OpenAI-compatible guard server [gr-readme] | Partly (depends on validator) | Low: migration churn, Hub token flow |
| **Meta LlamaFirewall** | Code **MIT** (subfolder LICENSE) [lf-lic]. Models under Llama licenses [purplellama-readme] | 1.0.3 (29 May 2025) [pypi-lf] | Quiet since mid-2025 | Orchestrates **PromptGuard 2** (BERT-style injection/jailbreak classifier), **AlignmentCheck** (CoT audit of agent traces), **CodeShield** (Semgrep + regex, 8 languages), regex scanners [lf-readme] | PromptGuard: yes after HF download. **AlignmentCheck defaults to Together API (`TOGETHER_API_KEY`)** [lf-readme] | Reuse **PromptGuard 2 model directly**. Copy the AlignmentCheck *idea* with a local judge |
| **LLM Guard** (Protect AI) | MIT [llmguard-lic] | 0.3.16 (19 May 2025), **Py <3.13** [pypi-llmguard] | **ARCHIVED 9 Jul 2026; models on HF "no longer maintained"** [llmguard-gh][llmguard-readme] | Good scanner catalogue to imitate: Anonymize, BanSubstrings/Topics/Code, Gibberish, InvisibleText, PromptInjection, Regex, Secrets, TokenLimit, Toxicity; output: Deanonymize, MaliciousURLs, NoRefusal, Sensitive, etc. [llmguard-readme] | Yes | **Don't depend on it.** Borrow scanner names/ideas. `InvisibleText` is trivial to re-implement |
| **Vigil** (deadbits) | Apache-2.0 [vigil-lic] | not on PyPI | **Last commit 31 Jan 2024** [vigil-commits] | YARA + vector-similarity + transformer + canary tokens [vigil-gh] | Yes | Design inspiration only (R2 already borrows it) |
| **Rebuff** (Protect AI) | Apache-2.0 [rebuff-lic] | 0.1.1 (Jan 2024) [pypi-rebuff] | **ARCHIVED 16 May 2025** [rebuff-gh] | Heuristics + LLM + vector DB + canary | (needed OpenAI/Pinecone) | Don't use. Canary-token idea is fine |
| **Invariant Guardrails** | Apache-2.0 [invariant-lic] | `invariant-ai` 0.3.5 (28 Jul 2025) [pypi-invariant] | Invariant Labs **acquired by Snyk 24 Jun 2025** [snyk-invariant]. Last commit 12 Jan 2026 (docs move) [invariant-commits] | Python-like **trace rule language** for tool-call flows, e.g. `(call: ToolCall) -> (call2: ToolCall)` exfil patterns; gateway [invariant-gh] | Rules evaluate locally [invariant-gh] | Inspiration for **flow rules** ("read secret then send email") |
| **Snyk Agent Scan** (formerly `mcp-scan`) | Apache-2.0 [agentscan-lic] | `snyk-agent-scan` 0.6.8 (29 Sep 2026). Old `mcp-scan` 0.4.3 (Mar 2026) [pypi-agentscan] | Active, but **needs `SNYK_TOKEN`**. **Sends tool names/descriptions etc. to the Agent Scan API**. CLI output "experimental", v0.5.x slated for deprecation [agentscan-readme] | Detects tool poisoning, shadowing, toxic flows, skill malware [agentscan-readme] | **No** | Don't use in the product (violates the "own setup" constraint). Reuse its risk taxonomy names |
| **OpenAI Guardrails (Python)** | MIT [oaigr-lic] | `openai-guardrails` 0.3.3 (10 Sep 2026) [pypi-oaigr] | **Preview** | Pipeline stages: preflight/input/output. Checks: moderation, URL filter, PII, jailbreak, hallucination, off-topic, custom prompt. Example for **local models** (OpenAI-compatible endpoint) [oaigr-readme] | Yes via local endpoint | Optional reference. JSON config shape is nice prior art |
| **any-guardrail** (Mozilla.ai) | Apache-2.0 [anygr-lic] | 0.7.7 (24 Aug 2026) [pypi-anygr] | Active | **One interface over many guard models** (Prompt Guard, Qwen3Guard, Deepset, Azure Prompt Shields, ...). Uniform `GuardrailOutput` + JSON Schema [anygr-readme][anygr-pg] | Yes for local models | **Good T2/T3 adapter.** Saves writing per-model wrappers |
| **Microsoft AGT** | MIT, Public Preview [agt-readme] | `agent-governance-toolkit` 4.1.0 (11 Jun 2026) [pypi-agt] | Active, preview | YAML/OPA/Cedar policy, tamper-evident audit, MCP security gateway (tool poisoning, drift, typosquatting) [agt-readme] | Yes | Competitive reference. Too broad to adopt in 24 h |

### 3.2 Local guard models (for the semantic tier). Licenses only; sizing and latency belong to the local-models researcher

| Model | Purpose | License | Notes |
|---|---|---|---|
| **Llama Prompt Guard 2 86M / 22M** | Injection + jailbreak classifier | **Llama 4 Community License, gated HF repo** (accept terms + `hf auth login`) [anygr-pg][meta-pg] | 86M multilingual, 22M English-only [anygr-pg]. Latency on laptop CPU: **UNVERIFIED, measure it** |
| `protectai/deberta-v3-base-prompt-injection-v2` | Injection classifier | Apache-2.0 [hf-deberta] | Has ONNX export [hf-deberta]. **Unmaintained** since the LLM Guard archive [llmguard-readme] |
| Llama Guard 3 (1B/8B) / **Llama Guard 4 12B** | Content-safety LLM judge (S1-S14 incl. **S14 Code Interpreter Abuse**) | Llama community licenses [purplellama-readme] | LG4 is 12B and multimodal: too big for laptops [nvidia-lg4]. Ollama tags **UNVERIFIED** |
| **Qwen3Guard-Gen 0.6B/4B/8B** (+ Stream variant) | Safe/Controversial/Unsafe + 9 categories + refusal detection; 119 languages | **Apache-2.0** [qwen3guard-arxiv][qwen3guard-dev] | Smallest permissive LLM judge. Higress ships a plugin for it [higress-ext] |
| IBM Granite Guardian | Harm, jailbreak, RAG groundedness | Apache-2.0 (Granite 3.0 family) [ibm-granite] | 3.x versions/tags **UNVERIFIED** |

### 3.3 Commercial landscape (competitors, for the pitch only)

| Vendor/product | What it does | Status |
|---|---|---|
| **Lakera** (Guard) | Prompt-injection/data-leak API | **Check Point acquiring (~$300M), announced Sep 2025** [cp-lakera] |
| **Prompt Security** | GenAI security platform | Acquired by **SentinelOne** (Sep 2025 wave) [sw-ma] |
| **Protect AI** (Guardian, LLM Guard, ModelScan) | Model scanning, runtime guard | Acquired by **Palo Alto Networks** [panw-10q]. LLM Guard archived since [llmguard-gh] |
| **CalypsoAI** | Inference-time defense/red teaming | **F5** acquiring, ~$180M [sw-ma] |
| **Pangea** | AI guard APIs | **CrowdStrike** acquiring, ~$260M [sw-ma] |
| **Lasso Security** | MCP gateway (OSS) + SaaS | Ships an OSS MCP gateway (MIT) [lasso-lic]. Corporate status **UNVERIFIED** |
| **Cloudflare Firewall for AI** | WAF detection for LLM endpoints: prompt-injection score, PII, **Llama Guard integrated** into the rules engine | [cf-fw-ai] |
| **Azure AI Content Safety: Prompt Shields** | User-prompt attacks + **document (indirect) attacks**, based on Spotlighting. 10k-char limits | [azure-ps] |
| **AWS Bedrock Guardrails** | Content filters (incl. **Prompt Attack**), denied topics, word filters, **sensitive-info filters (PII + custom regex, block or mask)**, contextual grounding, Automated Reasoning. **`ApplyGuardrail` API decoupled from model invocation** | [aws-bg][aws-apply] |

**Pitch line:** the market consolidated fast. Six pure-play AI-security vendors were bought by platforms between Aug 2024 and Sep 2025 [pipelab]. Banks want a **vendor-neutral, self-hosted** control layer whose policies they own. That's us. Bedrock's "block **or mask**" per sensitive type and its model-independent `ApplyGuardrail` API are the closest commercial analogue to our "Block vs Redact" strictness knob and our standalone `/guard` endpoint.

---

## 4. MCP gateways and proxies

| Project | License | Lang | Auth | Tool filtering / policy | Guardrails/plugins | Footprint | Fit |
|---|---|---|---|---|---|---|---|
| **IBM ContextForge** (`mcp-contextforge-gateway`) | Apache-2.0 [cf-lic] | Python (FastAPI) | Basic/JWT/custom; user-scoped OAuth tokens. `JWT_SECRET_KEY` + `AUTH_ENCRYPTION_SECRET` mandatory [cf-readme] | **Virtual servers** = curated tool bundles; federation of MCP + **A2A** + REST/gRPC→MCP [cf-readme] | **~40 plugins**: `deny_filter`, `regex_filter`, `content_moderation`, `harmful_content_detector`, `schema_guard`, `file_type_allowlist`, `code_safety_linter`, `unified_pdp`, `vault`, `virus_total_checker`, `webhook_notification`, `circuit_breaker`, ... [cf-plugins] | SQLite/Postgres (55+ tables) + Redis; Admin UI; OTel [cf-readme]. **Py ≥3.12, <3.14**, v1.0.11 (28 Sep 2026) [pypi-cf] | Heavy but rich. Read its plugin hook design. Running it alongside us adds a 2nd policy store (bad for "single config source") |
| **Docker MCP Gateway** | MIT [dmcp-lic] | Go | OAuth flows, Docker secrets | Profiles/catalogs; per-server `allowHosts`/`disableNetwork`, `--block-network` | **`--block-secrets` (default on)** scans tool args and responses; `--verify-signatures` image provenance; `--log-calls`; **interceptors** (`before/after:exec/http`); containers with `no-new-privileges` + CPU/mem limits [dmcp-sec][dmcp-run] | Needs Docker (Desktop, or CE with `DOCKER_MCP_IN_CONTAINER=1`) [dmcp-readme] | **Great for sandboxing stdio MCP servers.** Interceptors could call our `/guard` (stretch) |
| **Microsoft MCP Gateway** | MIT [msmcp-lic] | .NET | Bearer/RBAC, data + control plane | Adapters, tool router, stateless routing | n/a | **Kubernetes**. **Breaking change: needs MCP `2026-07-28` clients**, no legacy init [msmcp-readme] | Pitch reference (K8s scale-out) only |
| **Lasso MCP Gateway** | MIT [lasso-lic] | Python | via wrapped `mcp.json` | Server reputation scanner | Plugins: `basic` (token/secret masking), `presidio` (PII), `lasso` (**SaaS key**), `xetrack` (tracing) [lasso-readme] | pip/Docker, wraps stdio servers | Small and readable. Good reference for a **stdio-wrapping** proxy |
| **agentgateway** | Apache-2.0 | Rust | JWT/API key/OAuth | **CEL RBAC per tool**, federation, OpenAPI→MCP | webhook guard | single binary | Adapter (see §2.2) |
| **Envoy AI GW / Agent Router** | Apache-2.0 | Go/Envoy | JWT, ext auth | **CEL authz on MCP** (v0.5) [envoyai-v05] | ext_proc | K8s | Pitch reference |
| Obot | MIT [obot-lic] | Go/TS | | MCP platform/catalog | | | not evaluated |
| MCPJungle | **MPL-2.0** [mcpjungle-lic] | Go | | registry/gateway | | | not evaluated |
| Lunar (MCPX) | MIT (`TheLunarCompany/lunar`) [lunar-lic] | | | | | | not evaluated |
| `sparfenyuk/mcp-proxy` | MIT [mcpproxy-lic] | Python | | stdio ↔ SSE/HTTP bridge | | tiny | **Useful utility** to expose stdio servers over HTTP so our proxy can sit in front |

**Build blocks for our own MCP proxy (recommended):**
- **`mcp`** (official Python SDK) MIT, **2.3.0 (2 Oct 2026)** [pypi-mcp]. Note: the MCP project is moving from MIT to Apache-2.0 (the Go SDK LICENSE says so) [mcp-go-lic].
- **`fastmcp`** Apache-2.0, **4.0.10 (25 Sep 2026)** [pypi-fastmcp][fastmcp-lic]. It has **proxy servers** plus **middleware** hooks (`on_list_tools` to filter/pin tools, `on_call_tool` to allow/deny/rewrite args, `call_next` chain) [fastmcp-mw]. The docs we found are for v2. **Check the v4 API** before coding (UNVERIFIED that names are unchanged).
- **`a2a-sdk`** Apache-2.0, 1.2.1 (30 Sep 2026) [pypi-a2a]. Enough to show an A2A passthrough with policy checks (stretch).

---

## 5. Model artifact scanners

| Scanner | License | Latest (PyPI) | Python | Formats covered | Output/CI | Caveats |
|---|---|---|---|---|---|---|
| **ModelAudit** (promptfoo) | **MIT** [modelaudit-lic] | 0.2.52 (22 Jul 2026) [pypi-modelaudit] | 3.10-3.13 | **40+ scanners**: pickle, PyTorch, NumPy, joblib, **SafeTensors, ONNX, TF SavedModel, Keras, GGUF**, ZIP/TAR/7z (path traversal, symlinks), configs. Also secrets-in-weights, network indicators, TorchScript/JIT, Lambda layers [modelaudit-readme] | text/JSON/**SARIF**, `--strict`, exit codes, **CycloneDX SBOM**, `hf://` and `s3://` sources [modelaudit-readme] | **Telemetry ON by default** (set `PROMPTFOO_DISABLE_TELEMETRY=1`, or it's auto-off when `CI=true`) [modelaudit-readme]. Promptfoo **acquired by OpenAI (announced 9 Mar 2026)**, stays MIT [sb-promptfoo] |
| **picklescan** | MIT [picklescan-lic] | 1.0.5 (1 Jul 2026) [pypi-picklescan] | ≥3.11 | Pickle, PyTorch zip, NumPy `.npy`, directories, URLs, **HF repos** (`--huggingface`) [picklescan-readme] | ClamAV-style exit codes [picklescan-readme] | Denylist bypass CVEs in 2025: **CVE-2025-1716** (`pip` not flagged), **CVE-2025-1889** (non-standard extensions), **CVE-2025-10155** (extension confusion), **CVE-2025-10157** (submodule names) [cve-1716][cve-1889][jfrog-10155][nvd-10157] |
| **ModelScan** (Protect AI) | Apache-2.0 [modelscan-lic] | 0.8.8 (18 Feb 2026) [pypi-modelscan] | **3.9-3.12 (<3.13)** | Pickle (PyTorch), **H5**, **Keras v3**, **TF SavedModel**, sklearn/XGBoost pickle/cloudpickle/dill/joblib [modelscan-readme] | console/JSON, severity levels, exit codes [modelscan-readme] | Owner now Palo Alto. Not archived (as of today) [modelscan-gh]. Its unsafe-globals severity list is reused by R2 |
| **fickling** (Trail of Bits) | **LGPL-3.0+** [fickling-lic] | 0.1.12 (26 Jun 2026) [pypi-fickling] | ≥3.10 | Pickle + PyTorch (incl. **polyglot** detection). Decompiler/static analysis [fickling-readme] | `always_check_safety()` hook; **`activate_safe_ml_environment()` = allowlist of ML imports**, everything else blocked [fickling-readme] | LGPL: import unmodified or run as a subprocess. **Allowlist > denylist** (the lesson from picklescan's CVEs) |

**Recommendation:** an artifact gate endpoint (`POST /v1/artifacts/scan` plus a pull-through download check) that runs **ModelAudit first** (breadth: GGUF/ONNX/SafeTensors/Keras) and then **picklescan or fickling's allowlist** on pickle-family files. **Fail closed** when a scanner errors (R2 lesson). Ship 3-4 benign/malicious sample artifacts in `tests/fixtures/` (generated locally, never downloaded live).

---

## 6. Policy engines: what judges will edit live

| Option | License / status | Hot reload | Expressiveness | Judge-editability | Python availability | Verdict |
|---|---|---|---|---|---|---|
| **Plain YAML + JSON Schema (pydantic)** | n/a | trivial (`watchfiles`, MIT, 1.3.0) [pypi-watchfiles] | declarative only | **Best**: anyone can flip `mode: block → redact` or `threshold: 0.8 → 0.5` | pydantic MIT 2.13.5 [pypi-pydantic] | **Core format** |
| **CEL** (Common Expression Language) | Apache-2.0 [celgo-lic]. Used by agentgateway RBAC and Envoy AI GW authz/token costs [agw-readme][envoyai-rl] | compile on reload (µs-ms) | boolean/arith expressions over request attributes; non-Turing-complete | Good for one-liners: `user.groups.exists(g, g == "quant") && request.model.startsWith("llama")` | `cel-python` (cloud-custodian) 0.5.0, Apache-2.0 [pypi-celpy][celpy-lic]; `common-expression-language` (Rust-backed) 0.10.0, Apache-2.0 [pypi-cel][cel-rs-lic] | **Embed in YAML for `when:` conditions** → interop story with agentgateway/Envoy |
| **OPA / Rego** | Apache-2.0, CNCF graduated. Core maintainers joined Apple (Aug 2025), CNCF governance unchanged; Styra EOPA/Regal open-sourced [opa-note][cnn-opa] | `opa run --server --watch` reloads policy/data on file change [opa-run] | Full policy language, signed bundles, decision logs | Rego is a hurdle for ad-hoc editing by judges | `opa-python-client` (MIT) as REST client [pypi-opaclient]; or embed in Go | Stretch: "enterprise mode, export access rules to Rego" |
| **Cedar** | Apache-2.0, **CNCF Sandbox since 8 Oct 2025**, formally verified in Lean [cncf-cedar][aws-cedar] | reload = re-parse | permit/forbid RBAC/ABAC/ReBAC. Analyzable. **Not suited to thresholds/budgets/content** | Readable (`permit(principal in Group::"quant", action == Action::"invoke", resource == Model::"llama3")`) | `cedarpy` 4.12.1, Apache-2.0 repo [pypi-cedarpy][cedarpy-lic]; `cedar-go` Apache-2.0 [cedargo-lic] | Stretch alternative for the identity → model/tool matrix |

**Recommended shape** (one source of truth, judge-friendly, CEL only where needed):

```yaml
# policy.yaml (excerpt; full schema lives in the design doc)
version: 7                          # bumped by a human; the dashboard also shows the sha256 of the file
defaults: { on_error: block, latency_budget_ms: 300 }
identities:
  groups:                           # mapped from OIDC 'groups' claim (Keycloak/LDAP) or API-key metadata
    quant:     { models: ["llama3.2:3b", "qwen3:8b"], budget: { tokens_per_day: 200000, usd_per_month: 50, gpu_seconds_per_day: 600 } }
    interns:   { models: ["llama3.2:1b"],            budget: { tokens_per_day: 20000 } }
controls:
  - id: pii.pesel
    detector: presidio
    entities: [PL_PESEL, IBAN_CODE, CREDIT_CARD]
    direction: [input, output]
    mode: redact                    # block | redact | audit | off   <- judges flip this live
    min_score: 0.6
  - id: injection.classifier
    detector: prompt_guard_2_22m
    mode: block
    threshold: 0.85                 # "sensitivity"; lower = stricter
    when: 'request.source in ["tool_result", "rag"] || threshold_override == false'   # CEL
  - id: tools.no_shell_for_interns
    detector: tool_policy
    when: '"interns" in user.groups && tool.name.matches("^(bash|exec|shell).*")'   # CEL
    mode: block
feeds:
  - id: gs-threat-intel
    url: file:///feeds/signatures.yaml   # or https://... ; signature-verified (R2 §2.5)
    refresh_seconds: 10
```

Engine behaviour judges will test (build all of it): parse → validate against JSON Schema → compile CEL → **atomic swap**. On error, **keep last-known-good**, emit a `policy_reload_failed` audit event and show a red banner in the dashboard. Every decision logs `policy_version`, `policy_sha256` and `rule_id`.

---

## 7. Supporting components: license check

| Component | License (verified) | Use? |
|---|---|---|
| **Ollama** (server) / `ollama` Python client | MIT [ollama-lic] / MIT 0.6.3 [pypi-ollama] | Yes, local inference |
| **Keycloak** | Apache-2.0 [keycloak-lic] | Yes (OIDC + LDAP user federation for the SSO story) |
| **Dex** | Apache-2.0 [dex-lic] | Lighter OIDC alternative |
| **lldap** | **GPL-3.0** [lldap-lic] | OK as a separate container (no linking) |
| `authlib` / `pyjwt` | BSD-3 / MIT [pypi-authlib][pypi-pyjwt] | JWT/OIDC validation in the gateway |
| **Prometheus** / `prometheus-client` | Apache-2.0 / Apache-2.0 AND BSD-2 [prom-lic][pypi-promclient] | Yes |
| OpenTelemetry SDK | Apache-2.0, 1.45.0 [pypi-otel] | Yes (traces per guard stage) |
| **Grafana** | **AGPL-3.0** [grafana-lic] | Optional sidecar only, unmodified. Our dashboard should be our own UI |
| Streamlit | Apache-2.0 [streamlit-lic] | Fast dashboard option |
| **Redis 8+** | **Tri-license RSALv2 / SSPLv1 / AGPLv3** (≤7.2 BSD) [redis-lic] | Prefer **Valkey** (BSD-3) [valkey-lic] |
| DuckDB | MIT [duckdb-lic] | Audit analytics / CSV-Parquet export |
| ClickHouse | Apache-2.0 [ch-lic] | Overkill |
| Langfuse | MIT core + `ee/` dirs (copyright now ClickHouse, Inc.) [langfuse-lic] | Not needed |
| Arize Phoenix | **Elastic License 2.0** (source-available) [phoenix-lic] | Avoid |
| OpenLIT | Apache-2.0 [openlit-lic] | Optional |
| **Open WebUI** (demo chat client) | **Custom "Open WebUI License"**: branding must stay unless ≤50 users/30 days or EE [owui-lic] | OK as an *unmodified demo client*. Don't rebrand it |
| gitleaks (rules for secrets regex) | MIT [gitleaks-lic] | Port its rule regexes into our T1 detector |
| detect-secrets | Apache-2.0, **last release 1.5.0 (May 2024)** [pypi-detectsecrets] | Usable but stale. Prefer gitleaks-derived regex |
| YARA-X | BSD-3 [yarax-lic] | Signature-feed byte rules (R2) |
| GLiNER | Apache-2.0 (lib), 0.2.29 [gliner-lic][pypi-gliner] | Optional zero-shot PII NER. **Model** licenses vary (UNVERIFIED) |
| CodeShield → requires **semgrep** | CodeShield MIT [codeshield-lic]; semgrep **LGPL-2.1** [semgrep-lic] (fork **opengrep** also LGPL-2.1 [opengrep-lic]) | Stretch (insecure-code output check). Run semgrep as a subprocess |
| Test/red-team: **garak**, **PyRIT**, **promptfoo**, **inspect-ai**, **locust** | Apache-2.0 [garak-lic] / MIT [pypi-pyrit] / MIT [promptfoo-lic] / MIT [pypi-inspect] / MIT [pypi-locust] | garak/promptfoo for attack corpora against our gateway; locust for perf telemetry |

---

## 8. BUILD vs BUILD-ON: recommendation

### 8.1 Options scored against the judging weights (our judgment; 1-5)

| Option | Guardrail robustness (30%) | Arch & perf (20%) | Reporting (20%) | Test suite (15-20%) | Implementability/scale (10-15%) | Live-edit demo | 24 h risk | Weighted* |
|---|---|---|---|---|---|---|---|---|
| **A. Own thin gateway (Python/FastAPI) + reused detection libs** | 5 (we tune every tier) | 4 (measure overhead per stage; Python fine vs LLM latency) | 5 (our events, our schema) | 5 (tests generated from policy) | 4 (stateless pods + Valkey; K8s manifests) | **5** | Medium (streaming + MCP proxy work) | **4.7** |
| B. LiteLLM core + our CustomGuardrails + our dashboard | 3 (hooks only; stream post-call audit-only) | 3 (heavy; Postgres) | 3 (their spend DB + ours) | 3 | 4 | 2 (restart/DB semantics) | Low to start, high later (EE walls, judge perception) | 3.1 |
| C. agentgateway data plane + our "policy brain" (webhook + config compiler) | 4 | 5 (Rust, fast) | 4 | 4 | 5 | 3 (two configs unless we compile ours → theirs) | Medium-high (new v1.6, webhook schema unknown, Rust) | 4.1 |
| D. Envoy + ext_proc (Python/Go processor) | 4 | 5 | 4 | 4 | 5 | 3 | **High** (gRPC ext_proc, body streaming, K8s) | 4.0 |
| E. Fork Squid + ICAP server | 2 (TLS bump; body parsing in ICAP) | 2 | 2 | 2 | 2 (GPL, C++) | 2 | **Very high** | 2.0 |

\*Weighted using 30/20/20/17.5/12.5. Scores are subjective. The ranking (A > C > D > B > E) is what matters.

**Decision: A as the core, C as the stretch adapter.** We own the gateway and policy brain. We **reuse libraries, not gateways**. To show we're gateway-agnostic: (1) the guard pipeline is exposed as a standalone `POST /v1/guard` (input/output/tool-call payload → decision, like Bedrock's `ApplyGuardrail`), and (2) we ship thin adapters: agentgateway webhook config, LiteLLM `CustomGuardrail` shim, Claude Code hook script.

### 8.2 What we BUILD (the differentiators), mapped to the six required capabilities

| Required capability | We build | Reused under the hood |
|---|---|---|
| 1. Centralized policy engine | `policy.yaml` + JSON Schema + CEL `when:` + hot reload (atomic swap, last-known-good, version/hash in every log) | pydantic, watchfiles, cel-python / common-expression-language |
| 2. Hybrid guardrails | Tiered pipeline orchestrator (T0 allowlists → T1 regex/PII/signatures → T2 classifier → T3 LLM judge). Per-control `mode` (block/redact/audit/off) and `threshold`. Short-circuit, parallel T2/T3, per-control timeout + fail-open/closed. **Tool-call mediation on LLM responses** (R1 §11) and MCP `tools/list` pinning | Presidio, gitleaks-derived regex, Prompt Guard 2 or deberta (transformers/onnxruntime), Llama Guard / Qwen3Guard via Ollama (or any-guardrail) |
| 3. Budget & resource governance | Ledger per user/group/key: tokens, **$ via a price table** (commercial), **compute seconds for local models** (from Ollama response timings; field names **UNVERIFIED** here, see the local-models notes). Pre-check estimate + post-call reconcile. Hard/soft limits; 429 with a clear message | Valkey or SQLite; tiktoken (MIT) for estimates [pypi-tiktoken] |
| 4. Historical attack mitigation | Signature-feed loader (R2 schema, signed, hot reload), matcher types (regex/keyword/semantic/YARA/pickle-globals), artifact gate | yara-x, ModelAudit, picklescan/fickling |
| 5. Reporting & auditing | Hash-chained JSONL audit log, Prometheus metrics, dashboard (management view: spend, blocks, posture; security view: events, drill-down, export CSV/JSONL/SIEM-ish) | prometheus-client, OTel, DuckDB for exports |
| 6. Self-testing suite | `pytest` suite **generated from the policy**: each control gets ≥1 positive + ≥1 negative case. Budget-exhaustion tests, feed hot-load tests, **policy-mutation tests** (edit file → assert behaviour flips within N s), perf smoke | pytest, locust, optional garak/promptfoo corpora |

### 8.3 What we REUSE: concrete packages (versions as of 2026-10-03)

**Python (recommended stack; pin Python 3.12):**

| Package | Version | License | Role |
|---|---|---|---|
| fastapi | 0.142.2 | MIT | gateway HTTP [pypi-fastapi] |
| httpx | 0.28.1 | BSD-3 | upstream client, streaming [pypi-httpx] |
| pydantic | 2.13.5 | MIT | policy schema [pypi-pydantic] |
| watchfiles | 1.3.0 | MIT | hot reload [pypi-watchfiles] |
| common-expression-language **or** cel-python | 0.10.0 / 0.5.0 | Apache-2.0 | CEL conditions [pypi-cel][pypi-celpy] |
| presidio-analyzer / presidio-anonymizer | 2.2.364 | MIT | PII detect/redact [pypi-presidio] |
| spacy | 3.8.16 | MIT | Presidio NLP engine [pypi-spacy] |
| transformers | 5.18.0 | Apache-2.0 | classifier inference [pypi-transformers] |
| onnxruntime | 1.30.0 | MIT | faster CPU inference (optional) [pypi-onnxrt] |
| ollama | 0.6.3 | MIT | local LLM judge client [pypi-ollama] |
| any-guardrail | 0.7.7 | Apache-2.0 | optional uniform wrapper over guard models [pypi-anygr] |
| mcp / fastmcp | 2.3.0 / 4.0.10 | MIT / Apache-2.0 | MCP proxy [pypi-mcp][pypi-fastmcp] |
| a2a-sdk | 1.2.1 | Apache-2.0 | A2A passthrough (stretch) [pypi-a2a] |
| modelaudit | 0.2.52 | MIT | artifact scanning [pypi-modelaudit] |
| picklescan | 1.0.5 | MIT | pickle scanning [pypi-picklescan] |
| fickling | 0.1.12 | LGPL-3.0+ | allowlist pickle check (subprocess) [pypi-fickling] |
| yara-x (python binding) | see R2 | BSD-3 | feed byte rules [yarax-lic] |
| tiktoken | 0.14.0 | MIT | token estimates [pypi-tiktoken] |
| authlib / pyjwt | 1.8.0 / 2.15.1 | BSD-3 / MIT | OIDC/JWT [pypi-authlib][pypi-pyjwt] |
| prometheus-client | 0.26.0 | Apache-2.0 AND BSD-2 | metrics [pypi-promclient] |
| opentelemetry-sdk | 1.45.0 | Apache-2.0 | traces [pypi-otel] |
| pytest / locust | 9.1.1 / 2.46.6 | MIT / MIT | tests / perf [pypi-pytest][pypi-locust] |
| mitmproxy (stretch: shadow-AI fence) | 12.2.3 | MIT | egress interception demo [pypi-mitmproxy] |

**Python version constraints found:** llm-guard and modelscan need **<3.13**. mitmproxy needs **≥3.12**. ContextForge needs **≥3.12,<3.14**. picklescan and onnxruntime need **≥3.11**. NeMo needs <3.14 [pypi-*]. → **Pin Python 3.12** in every Dockerfile.

**Go equivalents (if part of the team writes a Go data plane):** `google/cel-go` (Apache-2.0) [celgo-lic], `open-policy-agent/opa` as library (Apache-2.0) [opa-lic], `cedar-policy/cedar-go` (Apache-2.0) [cedargo-lic], `fsnotify/fsnotify` (BSD-3) [fsnotify-lic], `prometheus/client_golang` (Apache-2.0) [promgo-lic], `mark3labs/mcp-go` (MIT) [mcpgo-lic] or `modelcontextprotocol/go-sdk` (MIT→Apache-2.0 transition) [mcp-go-lic], `openai/openai-go` (Apache-2.0) [oaigo-lic], `elazarl/goproxy` (BSD-3) [goproxy-lic], `tiktoken-go/tokenizer` (MIT) [tiktokengo-lic], `go-chi/chi` (MIT) [chi-lic], `coreos/go-oidc` (Apache-2.0) [gooidc-lic]. ML guards would still run in a Python sidecar or Ollama. **Recommendation: single-language Python** unless 2+ teammates are fluent in Go.

### 8.4 License and footprint risk register

| Risk | Where | Mitigation |
|---|---|---|
| **Llama Community Licenses** (attribution, AUP, gated download) | Prompt Guard 2 (Llama 4 license), Llama Guard 3 (Llama 3.x) [anygr-pg][purplellama-readme] | Accept terms and **pre-download before the event**. Add attribution in README/slides. Keep the Apache-2.0 alternatives (Qwen3Guard, deberta v2) behind the same interface |
| **Enterprise-gated features** | LiteLLM `enterprise/` (JWT/OIDC, SSO >5 users, secret detection, per-key guardrails, audit logs) [litellm-ee][litellm-ee-lic]; Bifrost EE (guardrails, SSO, RBAC, clustering) [bifrost-gov]; Kong ≥3.10 [kong-14628] | Don't build core on them |
| **AGPL / SSPL** | Grafana, Tyk AI Studio, new-api, Redis 8 (tri-license) [grafana-lic][tyk-lic][newapi-lic][redis-lic] | Don't embed. Valkey instead of Redis. Grafana only as an optional unmodified sidecar |
| **GPL** | Squid (GPLv2+), lldap (GPL-3.0), Helicone ai-gateway (LICENSE file GPL-3.0) [squid-copying][lldap-lic][hel-gw-lic] | No fork. Separate containers only |
| **LGPL** | fickling, semgrep/opengrep | Use unmodified / subprocess |
| **Source-available** | Arize Phoenix (ELv2), Open WebUI (branding clause) [phoenix-lic][owui-lic] | Avoid Phoenix. Use Open WebUI unmodified if at all |
| **Hidden SaaS calls** (breaks "own setup", leaks data) | Snyk Agent Scan (needs `SNYK_TOKEN`, uploads tool descriptions) [agentscan-readme]; LlamaFirewall AlignmentCheck (Together API) [lf-readme]; Lasso `lasso` plugin (API key) [lasso-readme]; APISIX/Higress/agentgateway SaaS moderation guards [apisix-plugins][agw-readme] | Only local detectors in the default policy. A test asserts **no outbound calls except configured upstreams** (run the test container with network disabled) |
| **Telemetry by default** | ModelAudit [modelaudit-readme] | `PROMPTFOO_DISABLE_TELEMETRY=1` in Dockerfile |
| **Supply chain** | LiteLLM 1.82.7/1.82.8 compromise [ddog-litellm]; picklescan bypass CVEs | `uv lock` / `pip --require-hashes`. Pin images by digest. Turn it into a demo: our artifact gate + a feed signature for the `.pth` IOC pattern (coordinate with R2) |
| **Archived / stale deps** | LLM Guard (archived), Rebuff (archived), Vigil (2024), detect-secrets (2024), invariant-ai (2025), llamafirewall (May 2025) | Don't take runtime deps on them. Borrow ideas. If we must, vendor the small pieces with their license headers |
| **Footprint** | torch+transformers images are multi-GB (size **UNVERIFIED**); Postgres for LiteLLM; ClickHouse for Helicone/TensorZero obs; K8s for Envoy AI GW/MS MCP GW | Use ONNX where possible. Share one model-server container. Compose profiles (`--profile semantic`) so a judge laptop can run deterministic-only |
| **API churn** | agentgateway 1.6 (released the day before), FastMCP v4, MCP spec `2026-07-28` (MS gateway refuses older clients) [agw-rel][msmcp-readme] | Pin versions. Integration-test the exact versions on Saturday morning |

---

## 9. So what for our hackathon (prioritized)

**MVP (must exist by the first judge visit):**
1. **[MVP] Python 3.12 FastAPI gateway**: `/v1/chat/completions` (OpenAI), `/v1/messages` (Anthropic), `/v1/models` (**filtered by the caller's allowed models**), upstream = Ollama. Streaming supported. Tool-call deltas buffered so tool calls can be inspected before release.
2. **[MVP] `policy.yaml` + JSON Schema + CEL `when:` + watchfiles hot reload** with last-known-good and a version/hash on every decision. This is the judges' live-edit test, so rehearse it.
3. **[MVP] Deterministic tier**: model allowlist per group, tool allow/deny, Presidio PII (PL_PESEL/IBAN/CREDIT_CARD/EMAIL) with **block vs redact**, gitleaks-derived secret regexes, invisible-Unicode stripping, size/token limits.
4. **[MVP] Semantic tier**: Prompt Guard 2 (22M first, 86M if CPU allows) with a threshold knob, plus one local LLM judge (Qwen3Guard-Gen-0.6B or Llama Guard 3 1B via Ollama) for content safety. Behind a `Detector` interface so we can swap models. any-guardrail can supply the wrappers.
5. **[MVP] Budget ledger**: tokens + $ (price table) + local compute-seconds per user/group. 429/403 with a human-readable reason. "My quota" endpoint (the team's idea of users seeing their limits and allowed models).
6. **[MVP] Audit log + metrics + dashboard**: blocked/redacted counts by control, spend vs budget per group, top offenders, policy version timeline, latency per stage (p50/p95). Export audit as JSONL/CSV.
7. **[MVP] Generated pytest suite**: positive + negative per control, budget exhaustion, feed hot-load, policy-mutation tests, a perf smoke. A single `make test` that judges can run.

**Strong second wave:**
8. **[MVP→] Signature feed + artifact gate**: R2 schema, ModelAudit + picklescan/fickling, fail-closed.
9. **[MVP→] MCP proxy** with FastMCP: `tools/list` filtering + **description hash pinning** (rug-pull detection), `tools/call` argument scanning via the same guard pipeline.
10. **[STRETCH] OIDC**: Keycloak with a `groups` claim (LDAP federation optional), mapped to `identities.groups`. Fallback is API keys with group metadata.

**Stretch / pitch:**
11. **[STRETCH] Adapters**: agentgateway webhook-guard config, LiteLLM `CustomGuardrail` shim, Claude Code hook (`PreToolUse`) script → slide: "one policy brain, any data plane".
12. **[STRETCH] Egress fence**: docker internal network so agents can only reach the gateway, plus an optional mitmproxy addon (or unmodified Squid allowlist) that logs "shadow AI" attempts to the same audit log.
13. **[STRETCH] Red-team run**: garak/promptfoo against our endpoint, results imported into the dashboard as a "posture score".
14. **[PITCH] K8s story**: stateless gateway Deployment + HPA, Valkey for counters, policy via ConfigMap (watched) or git-sync, feed via signed HTTPS/OCI. Production data plane could be Envoy ext_proc / Agent Router / agentgateway with our brain as the PDP.
15. **[PITCH] Competitive framing**: the 2024-25 acquisition wave (Lakera→Check Point, Protect AI→PANW, Prompt Security→SentinelOne, CalypsoAI→F5, Pangea→CrowdStrike) shows the need. Our angle is **self-hosted, vendor-neutral, policy-as-data, testable**.

**Don'ts:**
- Don't fork Squid. Don't depend on LLM Guard, Rebuff or Snyk Agent Scan at runtime. Don't build on LiteLLM's EE features. Don't put Grafana or Redis 8 in "our" image. Don't fetch models from HF during judging.

---

## 10. Open questions for the team

1. **Language comfort:** is everyone OK with Python 3.12 end-to-end, or do 2+ people want a Go data plane (then the guards go in a Python sidecar)?
2. **Which agents do we demo?** Claude Code (needs `/v1/messages` + managed settings), Codex/OpenAI-style CLI (`/v1/chat/completions` or Responses API), a LangGraph agent, Open WebUI? This decides which API surfaces we must implement first.
3. **Hardware:** any GPU on team laptops? That decides Prompt Guard 86M vs 22M and the LLM-judge size (0.6B vs 1B vs 4B+).
4. **Identity for the demo:** full Keycloak SSO/LDAP (team's original idea; adds ~3-4 h) or API keys mapped to groups for MVP, with SSO as stretch?
5. **Dashboard tech:** React/Vite (nicer, slower to build) or Streamlit (fast, less polish)?
6. **agentgateway adapter:** do we spend ~3 h proving "pluggable into any data plane", or put that time into MCP proxy depth?
7. **Commercial upstreams:** do we show $ budgets with a mock OpenAI-compatible upstream (no paid keys), or only local compute budgets?
8. **Feed source for judges:** local file they can edit, a tiny HTTP "threat intel server" we run, or both?

---

## 11. UNVERIFIED items

- agentgateway **webhook guard request/response schema** (docs site blocked). Also whether its LLM budgets cover local models.
- Portkey Gateway **2.0** actual OSS feature set (README says pre-release; press release says fully open source).
- Kong DB-less reload behaviour on 3.9.1. Higress standalone hot reload. TensorZero config reload. Bifrost file-config reload.
- Whether Bifrost's OSS plugin interface works without an enterprise license (docs link sits under `/enterprise/`).
- Helicone `ai-gateway` license: LICENSE file = GPL-3.0, README badge = Apache.
- Higress CNCF Sandbox status (from a summarized GitHub page, not the CNCF site).
- Lasso Security corporate status. Exact Protect AI deal price (sources vary).
- **Ollama model tags** for Llama Guard 3 / Granite Guardian / Qwen3Guard. Laptop-CPU **latency** of Prompt Guard 2 22M/86M (web-search budget ran out; measure on our machines).
- FastMCP **v4** middleware/proxy API names (docs found were for v2).
- Ollama response timing field names for compute-second accounting (see the local-models notes).
- Docker image sizes for torch/transformers stacks.
- GLiNER PII model licenses (library is Apache-2.0; model cards not checked).

---

## Sources

**AI gateways**
- [litellm-lic] https://raw.githubusercontent.com/BerriAI/litellm/main/LICENSE
- [litellm-ee-lic] https://raw.githubusercontent.com/BerriAI/litellm/main/enterprise/LICENSE.md
- [litellm-readme] https://raw.githubusercontent.com/BerriAI/litellm/main/README.md
- [litellm-ee] https://docs.litellm.ai/docs/enterprise
- [litellm-jwt] https://docs.litellm.ai/docs/proxy/token_auth
- [litellm-db] https://docs.litellm.ai/docs/proxy/ui_store_model_db_setting
- [litellm-cg] https://docs.litellm.ai/docs/proxy/guardrails/custom_guardrail
- [litellm-pg] https://developer.mittwald.de/docs/v2/platform/aihosting/dedicated/litellm/ (secondary: Postgres for keys/budgets)
- [pypi-litellm] https://pypi.org/pypi/litellm/json
- [ddog-litellm] https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
- [arthur-litellm] https://www.arthur.ai/column/litellm-supply-chain-attack-pypi-compromise-2026
- [portkey-lic] https://raw.githubusercontent.com/Portkey-AI/gateway/main/LICENSE
- [portkey-readme] https://raw.githubusercontent.com/Portkey-AI/gateway/main/README.md
- [portkey-pkg] https://raw.githubusercontent.com/Portkey-AI/gateway/main/package.json
- [portkey-manifest] https://raw.githubusercontent.com/Portkey-AI/gateway/main/plugins/default/manifest.json
- [portkey-plugins] https://github.com/Portkey-AI/gateway/tree/main/plugins
- [portkey-pr] https://www.globenewswire.com/news-release/2026/03/24/3261574/0/en/Portkey-s-Gateway-is-Now-Fully-Open-Source-Processing-over-1-Trillion-Tokens-Every-Day.html
- [kong-lic] https://raw.githubusercontent.com/Kong/kong/master/LICENSE
- [kong-plugins] https://github.com/Kong/kong/tree/master/kong/plugins
- [kong-14628] https://github.com/Kong/kong/discussions/14628
- [kong-ai] https://developer.konghq.com/ai-gateway/v1/mcp/govern-mcp-traffic/ and https://docs.konghq.com/hub/ (via search)
- [envoyai-lic] https://raw.githubusercontent.com/envoyproxy/ai-gateway/main/LICENSE
- [envoyai-readme] https://raw.githubusercontent.com/envoyproxy/ai-gateway/main/README.md
- [envoyai-rl] https://aigateway.envoyproxy.io/docs/capabilities/traffic/usage-based-ratelimiting
- [envoyai-v05] https://aigateway.envoyproxy.io/release-notes/v0.5/
- [agw-lic] https://raw.githubusercontent.com/agentgateway/agentgateway/main/LICENSE
- [agw-readme] https://raw.githubusercontent.com/agentgateway/agentgateway/main/README.md
- [agw-gh] https://github.com/agentgateway/agentgateway
- [agw-rel] https://github.com/agentgateway/agentgateway/releases
- [agw-cfg] https://agentgateway.dev/docs/standalone/latest/configuration/overview/
- [agw-guard] https://agentgateway.dev/docs/kubernetes/latest/llm/guardrails/webhook/guardrails/ ; https://agentgateway.dev/docs/standalone/latest/llm/prompt-guards/multi-layer/
- [apisix-lic] https://raw.githubusercontent.com/apache/apisix/master/LICENSE
- [apisix-plugins] https://github.com/apache/apisix/tree/master/apisix/plugins
- [apisix-modes] https://raw.githubusercontent.com/apache/apisix/master/docs/en/latest/deployment-modes.md
- [apisix-airl] https://apisix.apache.org/docs/apisix/plugins/ai-rate-limiting/
- [higress-lic] https://raw.githubusercontent.com/alibaba/higress/main/LICENSE
- [higress-gh] https://github.com/alibaba/higress
- [higress-ext] https://github.com/alibaba/higress/tree/main/plugins/wasm-go/extensions
- [tz-lic] https://raw.githubusercontent.com/tensorzero/tensorzero/main/LICENSE
- [tz-readme] https://raw.githubusercontent.com/tensorzero/tensorzero/main/README.md
- [tz-rl] https://www.tensorzero.com/docs/operations/enforce-custom-rate-limits
- [hel-lic] https://raw.githubusercontent.com/Helicone/helicone/main/LICENSE
- [hel-readme] https://raw.githubusercontent.com/Helicone/helicone/main/README.md
- [hel-gw-lic] https://raw.githubusercontent.com/Helicone/ai-gateway/main/LICENSE
- [hel-gw-readme] https://raw.githubusercontent.com/Helicone/ai-gateway/main/README.md
- [hel-acq] https://ai-startups.dealroom.co/news/feed/mintlify-acquires-open-source-ai-observability-platform-helicone
- [bifrost-lic] https://raw.githubusercontent.com/maximhq/bifrost/main/LICENSE
- [bifrost-readme] https://raw.githubusercontent.com/maximhq/bifrost/main/README.md
- [bifrost-gov] https://www.getmaxim.ai/bifrost/resources/governance
- [plano-lic] https://raw.githubusercontent.com/katanemo/plano/main/LICENSE ; [plano-readme] https://raw.githubusercontent.com/katanemo/plano/main/README.md
- [otari-lic] https://raw.githubusercontent.com/mozilla-ai/otari/main/LICENSE ; [anyllm-readme] https://raw.githubusercontent.com/mozilla-ai/any-llm/main/README.md
- [mlflow-lic] https://raw.githubusercontent.com/mlflow/mlflow/master/LICENSE.txt
- [llmgw-lic] https://raw.githubusercontent.com/theopenco/llmgateway/main/LICENSE
- [tyk-lic] https://raw.githubusercontent.com/TykTechnologies/ai-studio/main/LICENSE.md
- [newapi-lic] https://raw.githubusercontent.com/QuantumNous/new-api/main/LICENSE
- [agt-lic] https://raw.githubusercontent.com/microsoft/agent-governance-toolkit/main/LICENSE ; [agt-readme] https://raw.githubusercontent.com/microsoft/agent-governance-toolkit/main/README.md ; [agt-blog] https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/ ; [pypi-agt] https://pypi.org/pypi/agent-governance-toolkit/json

**Squid / proxies / agent settings**
- [squid-copying] https://raw.githubusercontent.com/squid-cache/squid/master/COPYING ; [squid-readme] https://raw.githubusercontent.com/squid-cache/squid/master/README
- [squid-icap] https://squid.sourceforge.net/icap ; https://docs.safesquid.com/wiki/ICAP (SslBump + ICAP behaviour via search)
- [squid-register] https://www.theregister.com/2023/10/13/squid_proxy_bugs_remain_unfixed/ ; [squid-joshua] https://joshua.hu/squid-security-audit-35-0days-45-exploits
- [pyicap] https://pypi.org/project/pyicap
- [pypi-mitmproxy] https://pypi.org/pypi/mitmproxy/json
- [cc-settings] https://docs.anthropic.com/en/docs/claude-code/settings ; [cc-proxy] https://code.claude.com/docs/en/corporate-proxy

**Guardrails**
- [presidio-readme] https://raw.githubusercontent.com/microsoft/presidio/main/README.MD ; [presidio-transition] https://raw.githubusercontent.com/microsoft/presidio/main/docs/project_transition.md ; [presidio-entities] https://raw.githubusercontent.com/microsoft/presidio/main/docs/supported_entities.md ; [pypi-presidio] https://pypi.org/pypi/presidio-analyzer/json
- [nemo-lic] https://raw.githubusercontent.com/NVIDIA-NeMo/Guardrails/main/LICENSE.md ; [nemo-readme] https://raw.githubusercontent.com/NVIDIA-NeMo/Guardrails/main/README.md ; [pypi-nemo] https://pypi.org/pypi/nemoguardrails/json
- [gr-lic] https://raw.githubusercontent.com/guardrails-ai/guardrails/main/LICENSE ; [gr-readme] https://raw.githubusercontent.com/guardrails-ai/guardrails/main/README.md ; https://github.com/guardrails-ai/guardrails/issues/1560 ; [pypi-guardrails] https://pypi.org/pypi/guardrails-ai/json
- [lf-lic] https://raw.githubusercontent.com/meta-llama/PurpleLlama/main/LlamaFirewall/LICENSE ; [lf-readme] https://raw.githubusercontent.com/meta-llama/PurpleLlama/main/LlamaFirewall/README.md ; [purplellama-readme] https://raw.githubusercontent.com/meta-llama/PurpleLlama/main/README.md ; [pypi-lf] https://pypi.org/pypi/llamafirewall/json
- [meta-pg] https://www.llama.com/docs/model-cards-and-prompt-formats/prompt-guard/ ; [anygr-pg] https://docs.mozilla.ai/any-guardrail/api-reference/index/prompt-injection/prompt-guard
- [hf-deberta] https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2
- [nvidia-lg4] https://build.nvidia.com/meta/llama-guard-4-12b/modelcard
- [qwen3guard-arxiv] https://arxiv.org/abs/2510.14276 ; [qwen3guard-dev] https://docs.mozilla.ai/any-guardrail/api-reference/index/content-safety/qwen3-guard
- [ibm-granite] https://canada.newsroom.ibm.com/2024-10-21-ibm-introduces-granite-3-0-high-performing-ai-models-built-for-business
- [llmguard-lic] https://raw.githubusercontent.com/protectai/llm-guard/main/LICENSE ; [llmguard-readme] https://raw.githubusercontent.com/protectai/llm-guard/main/README.md ; [llmguard-gh] https://github.com/protectai/llm-guard ; [pypi-llmguard] https://pypi.org/pypi/llm-guard/json
- [vigil-lic] https://raw.githubusercontent.com/deadbits/vigil-llm/main/LICENSE ; [vigil-gh] https://github.com/deadbits/vigil-llm ; [vigil-commits] https://github.com/deadbits/vigil-llm/commits/main
- [rebuff-lic] https://raw.githubusercontent.com/protectai/rebuff/main/LICENSE ; [rebuff-gh] https://github.com/protectai/rebuff ; [pypi-rebuff] https://pypi.org/pypi/rebuff/json
- [invariant-lic] https://raw.githubusercontent.com/invariantlabs-ai/invariant/main/LICENSE ; [invariant-gh] https://github.com/invariantlabs-ai/invariant ; [invariant-commits] https://github.com/invariantlabs-ai/invariant/commits/main ; [pypi-invariant] https://pypi.org/pypi/invariant-ai/json
- [snyk-invariant] https://tech.eu/2025/06/24/snyk-acquires-ai-security-pioneer-invariant-labs-for-a-new-era-in-ai-safeguards/ ; https://snyk.io/de/news/snyk-acquires-invariant-labs-to-accelerate-agentic-ai-security-innovation/
- [agentscan-lic] https://raw.githubusercontent.com/snyk/agent-scan/main/LICENSE ; [agentscan-readme] https://raw.githubusercontent.com/snyk/agent-scan/main/README.md ; [pypi-agentscan] https://pypi.org/pypi/snyk-agent-scan/json , https://pypi.org/pypi/mcp-scan/json
- [oaigr-lic] https://raw.githubusercontent.com/openai/openai-guardrails-python/main/LICENSE ; [oaigr-readme] https://raw.githubusercontent.com/openai/openai-guardrails-python/main/README.md ; [pypi-oaigr] https://pypi.org/pypi/openai-guardrails/json
- [anygr-lic] https://raw.githubusercontent.com/mozilla-ai/any-guardrail/main/LICENSE ; [anygr-readme] https://raw.githubusercontent.com/mozilla-ai/any-guardrail/main/README.md ; [pypi-anygr] https://pypi.org/pypi/any-guardrail/json

**Commercial landscape**
- [cp-lakera] https://blog.checkpoint.com/security/check-point-to-acquire-lakera-redefining-security-for-the-ai-era/
- [sw-ma] https://www.securityweek.com/cybersecurity-ma-roundup-40-deals-announced-in-september-2025/
- [panw-10q] https://www.sec.gov/Archives/edgar/data/1327567/000132756725000017/panw-20250430.htm
- [pipelab] https://pipelab.org/blog/ai-agent-security-acquisition-wave-2026/
- [cf-fw-ai] https://blog.cloudflare.com/block-unsafe-llm-prompts-with-firewall-for-ai/
- [azure-ps] https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection
- [aws-bg] https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html ; [aws-apply] https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-use-independent-api.html

**MCP**
- [cf-lic] https://raw.githubusercontent.com/IBM/mcp-context-forge/main/LICENSE ; [cf-readme] https://raw.githubusercontent.com/IBM/mcp-context-forge/main/README.md ; [cf-plugins] https://github.com/IBM/mcp-context-forge/tree/main/plugins ; [pypi-cf] https://pypi.org/pypi/mcp-contextforge-gateway/json
- [dmcp-lic] https://raw.githubusercontent.com/docker/mcp-gateway/main/LICENSE ; [dmcp-readme] https://raw.githubusercontent.com/docker/mcp-gateway/main/README.md ; [dmcp-sec] https://raw.githubusercontent.com/docker/mcp-gateway/main/docs/security.md ; [dmcp-run] https://docs.docker.com/reference/cli/docker/mcp/gateway/gateway_run
- [msmcp-lic] https://raw.githubusercontent.com/microsoft/mcp-gateway/main/LICENSE ; [msmcp-readme] https://raw.githubusercontent.com/microsoft/mcp-gateway/main/README.md
- [lasso-lic] https://raw.githubusercontent.com/lasso-security/mcp-gateway/main/LICENSE ; [lasso-readme] https://raw.githubusercontent.com/lasso-security/mcp-gateway/main/README.md
- [obot-lic] https://raw.githubusercontent.com/obot-platform/obot/main/LICENSE ; [mcpjungle-lic] https://raw.githubusercontent.com/mcpjungle/MCPJungle/main/LICENSE ; [lunar-lic] https://raw.githubusercontent.com/TheLunarCompany/lunar/main/LICENSE ; [mcpproxy-lic] https://raw.githubusercontent.com/sparfenyuk/mcp-proxy/main/LICENSE
- [pypi-mcp] https://pypi.org/pypi/mcp/json ; [pypi-fastmcp] https://pypi.org/pypi/fastmcp/json ; [fastmcp-lic] https://raw.githubusercontent.com/PrefectHQ/fastmcp/main/LICENSE ; [fastmcp-mw] https://gofastmcp.com/v2/servers/middleware ; [pypi-a2a] https://pypi.org/pypi/a2a-sdk/json ; [mcp-go-lic] https://raw.githubusercontent.com/modelcontextprotocol/go-sdk/main/LICENSE

**Model scanners**
- [modelaudit-lic] https://raw.githubusercontent.com/promptfoo/modelaudit/main/LICENSE ; [modelaudit-readme] https://raw.githubusercontent.com/promptfoo/modelaudit/main/README.md ; [pypi-modelaudit] https://pypi.org/pypi/modelaudit/json
- [sb-promptfoo] https://securityboulevard.com/2026/03/openai-acquires-security-startup-promptfoo-to-fortify-ai-agents
- [picklescan-lic] https://raw.githubusercontent.com/mmaitre314/picklescan/main/LICENSE ; [picklescan-readme] https://raw.githubusercontent.com/mmaitre314/picklescan/main/README.md ; [pypi-picklescan] https://pypi.org/pypi/picklescan/json
- [cve-1716] https://vulnerability.circl.lu/vuln/cve-2025-1716 ; [cve-1889] https://db.gcve.eu/cve/CVE-2025-1889 ; [jfrog-10155] https://research.jfrog.com/vulnerabilities/picklescan-cve-2025-10155/ ; [nvd-10157] https://nvd.nist.gov/vuln/detail/CVE-2025-10157
- [modelscan-lic] https://raw.githubusercontent.com/protectai/modelscan/main/LICENSE ; [modelscan-readme] https://raw.githubusercontent.com/protectai/modelscan/main/README.md ; [modelscan-gh] https://github.com/protectai/modelscan ; [pypi-modelscan] https://pypi.org/pypi/modelscan/json
- [fickling-lic] https://raw.githubusercontent.com/trailofbits/fickling/master/LICENSE ; [fickling-readme] https://raw.githubusercontent.com/trailofbits/fickling/master/README.md ; [pypi-fickling] https://pypi.org/pypi/fickling/json

**Policy engines**
- [opa-lic] https://raw.githubusercontent.com/open-policy-agent/opa/main/LICENSE ; [opa-run] https://raw.githubusercontent.com/open-policy-agent/opa/main/cmd/run.go
- [opa-note] https://openpolicyagent.org/blog/note-from-teemu-tim-and-torin-to-the-open-policy-agent-community-2dbbfe494371 ; [cnn-opa] https://cloudnativenow.com/features/apple-buys-styra-brains-opa-remains-open/
- [pypi-opaclient] https://pypi.org/pypi/opa-python-client/json
- [cncf-cedar] https://www.cncf.io/projects/cedar/ ; [aws-cedar] https://aws.amazon.com/blogs/opensource/cedar-joins-cncf-as-a-sandbox-project
- [pypi-cedarpy] https://pypi.org/pypi/cedarpy/json ; [cedarpy-lic] https://raw.githubusercontent.com/k9securityio/cedar-py/main/LICENSE ; [cedargo-lic] https://raw.githubusercontent.com/cedar-policy/cedar-go/main/LICENSE
- [celgo-lic] https://raw.githubusercontent.com/google/cel-go/master/LICENSE ; [celpy-lic] https://raw.githubusercontent.com/cloud-custodian/cel-python/main/LICENSE ; [pypi-celpy] https://pypi.org/pypi/cel-python/json ; [cel-rs-lic] https://raw.githubusercontent.com/hardbyte/python-common-expression-language/main/LICENSE ; [pypi-cel] https://pypi.org/pypi/common-expression-language/json

**Supporting components & packages**
- [ollama-lic] https://raw.githubusercontent.com/ollama/ollama/main/LICENSE ; [keycloak-lic] https://raw.githubusercontent.com/keycloak/keycloak/main/LICENSE.txt ; [dex-lic] https://raw.githubusercontent.com/dexidp/dex/master/LICENSE ; [lldap-lic] https://raw.githubusercontent.com/lldap/lldap/main/LICENSE
- [grafana-lic] https://raw.githubusercontent.com/grafana/grafana/main/LICENSE ; [prom-lic] https://raw.githubusercontent.com/prometheus/prometheus/main/LICENSE ; [streamlit-lic] https://raw.githubusercontent.com/streamlit/streamlit/master/LICENSE
- [redis-lic] https://raw.githubusercontent.com/redis/redis/unstable/LICENSE.txt ; [valkey-lic] https://raw.githubusercontent.com/valkey-io/valkey/master/COPYING ; [duckdb-lic] https://raw.githubusercontent.com/duckdb/duckdb/main/LICENSE ; [ch-lic] https://raw.githubusercontent.com/ClickHouse/ClickHouse/master/LICENSE
- [langfuse-lic] https://raw.githubusercontent.com/langfuse/langfuse/main/LICENSE ; [phoenix-lic] https://raw.githubusercontent.com/Arize-ai/phoenix/main/LICENSE ; [openlit-lic] https://raw.githubusercontent.com/openlit/openlit/main/LICENSE
- [owui-lic] https://raw.githubusercontent.com/open-webui/open-webui/main/LICENSE
- [gitleaks-lic] https://raw.githubusercontent.com/gitleaks/gitleaks/master/LICENSE ; [pypi-detectsecrets] https://pypi.org/pypi/detect-secrets/json ; [yarax-lic] https://raw.githubusercontent.com/VirusTotal/yara-x/main/LICENSE
- [gliner-lic] https://raw.githubusercontent.com/urchade/GLiNER/main/LICENSE ; [pypi-gliner] https://pypi.org/pypi/gliner/json
- [codeshield-lic] https://raw.githubusercontent.com/meta-llama/PurpleLlama/main/CodeShield/LICENSE ; [semgrep-lic] https://raw.githubusercontent.com/semgrep/semgrep/develop/LICENSE ; [opengrep-lic] https://raw.githubusercontent.com/opengrep/opengrep/main/LICENSE
- [garak-lic] https://raw.githubusercontent.com/NVIDIA/garak/main/LICENSE ; [pypi-pyrit] https://pypi.org/pypi/pyrit/json ; [promptfoo-lic] https://raw.githubusercontent.com/promptfoo/promptfoo/main/LICENSE ; [pypi-inspect] https://pypi.org/pypi/inspect-ai/json ; [pypi-locust] https://pypi.org/pypi/locust/json ; [pypi-pytest] https://pypi.org/pypi/pytest/json
- [pypi-fastapi] https://pypi.org/pypi/fastapi/json ; [pypi-httpx] https://pypi.org/pypi/httpx/json ; [pypi-pydantic] https://pypi.org/pypi/pydantic/json ; [pypi-watchfiles] https://pypi.org/pypi/watchfiles/json ; [pypi-spacy] https://pypi.org/pypi/spacy/json ; [pypi-transformers] https://pypi.org/pypi/transformers/json ; [pypi-onnxrt] https://pypi.org/pypi/onnxruntime/json ; [pypi-ollama] https://pypi.org/pypi/ollama/json ; [pypi-tiktoken] https://pypi.org/pypi/tiktoken/json ; [pypi-authlib] https://pypi.org/pypi/authlib/json ; [pypi-pyjwt] https://pypi.org/pypi/pyjwt/json ; [pypi-promclient] https://pypi.org/pypi/prometheus-client/json ; [pypi-otel] https://pypi.org/pypi/opentelemetry-sdk/json
- Go: [fsnotify-lic] https://raw.githubusercontent.com/fsnotify/fsnotify/main/LICENSE ; [promgo-lic] https://raw.githubusercontent.com/prometheus/client_golang/main/LICENSE ; [mcpgo-lic] https://raw.githubusercontent.com/mark3labs/mcp-go/main/LICENSE ; [oaigo-lic] https://raw.githubusercontent.com/openai/openai-go/main/LICENSE ; [goproxy-lic] https://raw.githubusercontent.com/elazarl/goproxy/master/LICENSE ; [tiktokengo-lic] https://raw.githubusercontent.com/tiktoken-go/tokenizer/main/LICENSE ; [chi-lic] https://raw.githubusercontent.com/go-chi/chi/master/LICENSE ; [gooidc-lic] https://raw.githubusercontent.com/coreos/go-oidc/master/LICENSE
