# 07 · Ideas parking lot: every good idea that is not in P0

> **Purpose:** keep good ideas without letting them leak into P0. Nothing here is built before IC4 (H15) unless the spec says so.
> **Sources:** `design/VISION-SPEC.md` §13.3 (P1 ranks and P2 list) and the tier notes in §3-§11; the cut lists in `design/proposals/P1`-`P5`; the judging memos `design/judging/J1`-`J3`; the "so what" build lists in `research/R1`-`R9`; `research/FACT-CHECK.md`. The spec wins over everything else.
> **Related:** open decisions about these items are in `docs/06-open-questions.md` (C3, C11, C13; the former C15 is now decided in its §5).

---

## 1. How to read this file

**Status**

| Status | Meaning |
|---|---|
| **P1 #n** | Ranked P1 item in spec §13.3. Built H12-H16 in rank order, behind a flag, only on a lane that was green at IC3/IC4. |
| **P1 (no rank)** | None left since spec v1.1: the former items (GGUF scan, `window` view + ROT13, SIG-0011, Policy diff / Audit query, role stripping, `models.*.fallback`) are now P2. |
| **P2** | Spec §13.3 or a P2 tier note. A slide or roadmap item, built only if everything else is green. |
| **cut** | A proposal or research note suggested it, and the spec or the judges dropped it. Not planned for the event. |
| **future** | A research idea the spec does not mention. Goes to the post-hackathon roadmap (§5). |

**Value** names the judging criterion it helps and how much: **Rob** = robustness and guardrails (30%), **Arch** = architecture and performance (20%), **Rep** = security reporting (20%), **Test** = self-testing (15-20%), **Prac** = practicality and scalability (10-15%). **H** = answers a judge must-fix or moves the criterion on its own; **M** = a visible improvement; **L** = nice to have.

**Cost** is AI-assisted person-hours from the source named in brackets. "est." marks our own estimate where no source gives a number.

---

## 2. If we finish early: do these 5 in this order

These are spec §13.3 ranks 1-5. Each starts only when its owner's lane is green at IC3 (H12) or IC4 (H15).

| Order | Item | Owner | Est. | Start when | Done means |
|---|---|---|---|---|---|
| 1 | P1 #1 `make bench` → `reports/perf.md` + console perf strip | A | 1.0 h | A's lane green | Overhead p50/p95/p99 per stage measured on the demo Mac; only these numbers go on slides |
| 2 | P1 #2 C11 guard-LLM lane | C | 2.5 h | C's lane green, `docs/06` C3 decided, RAM checked | `llama-guard3:1b` on `:11435` runs in parallel with upstream and gates the first token (1.5 s deadline); cases pass with the flag on |
| 3 | P1 #3 `make eval` + calibration + Polish slice | C + L | 2.0 h | Datasets cached, Polish slice written (`docs/06` C12) | Calibration files say `provisional: false`; held-out TPR/FPR with Wilson CIs sit next to the self-graded numbers |
| 4 | P1 #4 OCSF-shaped export | B | 1.5 h | B7 exports done | `format=ocsf` exports 6003/2004/3004 with `record_integrity`, labelled "OCSF-shaped" |
| 5 | P1 #5 C23 approvals | D + F | 2.5 h | C24 green at the H12 gate | Approval card; a retry token bound to the args hash, single use, TTL 300 s; approver ≠ requester |

**Rules after that:**
- Lanes work in parallel. A green lane takes its own highest-ranked item, so the per-lane queues are A: 1 → 10 → 13 → 15 · B: 4 → 6 → 13 → 17 · C: 2 → 3 → 11 · D: 5 → 9 → 12 → 14 · L: 3 → 6 → 7 → 8 → 12 → 16 · F: 5 → 6 → 7.
- Realistically there is no P1 in the base plan: P0 fills H1-H16, so P1 starts only where a lane finishes early. Plan (b)'s extra 2 h buys about 12 h (ranks 1-5); plan (a) builds no P1 (spec §13.3). Cut from the bottom (spec §13.6), never the reverse.
- Feature freeze is H16. After that: fixes, cases, docs, policy and feed content, and CSS only.
- Nothing marked P2, cut or future starts during the event unless every P1 rank is done or abandoned.

---

## 3. P1 backlog (spec §13.3, ranked)

| Status | Idea | What it is | Value | Cost | Depends on | Risk | Source |
|---|---|---|---|---|---|---|---|
| P1 #1 | `make bench` | oha + Locust overhead bench (via gateway minus direct to mock) at c=1/10/50 and 0/200 ms mock delay; TTFT vs holdback | Arch H | 1.0 h (spec) | mock-llm delay directive, `aicl_stage_seconds`, demo Mac | Numbers worse than hoped; we quote them anyway | spec §10.6; P5 rank 1; R7 §3.10 |
| P1 #2 | C11 guard-LLM lane | `llama-guard3:1b` on its own Ollama lane, in parallel with upstream, gating first-token release | Rob H (J1 probe R11: harmful content in EN/PL) | 2.5 h (spec) | `:11435` lane, `docs/06` C3 | RAM pressure (spec R15); 1.5 s deadline on stage | spec §5.1 T3; J1 §3 gap 1; R4 §3 |
| P1 #3 | `make eval` + calibration | TPR/FPR/F1 with Wilson CIs on held-out sets + the team's Polish slice; writes `policy/calibration/*.json` | Test H · Rep M (J1 must-fix 13) | 2.0 h (spec) | Datasets cached before the event; Polish slice | Wide CIs on small sets; dataset licences | spec §10.5; R8 §10-11 |
| P1 #4 | OCSF-shaped export | OCSF 1.9.0 API Activity 6003, Detection Finding 2004, Entity Management 3004, `record_integrity` | Rep M | 1.5 h (spec); 2-3 h (R9) | B7 export path | Not validator-checked, so "OCSF-shaped" only | spec §9.6; R9 §2.8; FACT-CHECK C6 |
| P1 #5 | C23 approvals | `ask` becomes an approval card; retry token bound to the args hash; one approver ≠ requester | Rob M · Rep M (ASI09 partial → green) | 2.5 h (spec); 3 h (R6) | C24 `ask` cells; console card (F) | Demo needs a second identity; client timeouts (use retry-token mode) | spec §3.5(b); R6 §2.8 |
| P1 #6 | Spend + Agents & MCP pages, console toggles | Full Spend page; inventory, quarantine diff, re-pin and kill switch; `PATCH` toggles through the single-writer path; + `/api/feed` (B). Owners F + L + B | Rep M · Prac M | 4.0 h (spec) | L read APIs; `If-Match` + atomic rename | F is the bottleneck; two writers to `policy.yaml` if done wrong (J3) | spec §9.5, D14 |
| P1 #7 | Exploit Museum cards + replay | One card per exhibit E1-E10 with Replay through the data plane | Rep M · Test M | 1.5 h (spec) | Scripted-agent library; `/api/scenarios/{id}/replay` | Low | spec §8.5; P1 §5 |
| P1 #8 | Mutation kill rate + entitlement matrix + obfuscation mutators | Disable each control in turn and expect a NEG case to fail; group × model and agent × tool tests generated from the policy; + the obfuscation mutators (from L2 in v1.1) | Test H | 2.0 h (spec) | Green `make test` | ~5 min run; survivors need triage | spec §10.1; R8 §3.9; P3 §10 |
| P1 #9 | C34 MCP protocol hardening | Header/body desync, batch rejection, JSON depth and schema-bomb limits, elicitation secret fields, sampling deny | Rob M | 1.0 h (spec) | `docs/06` C4 (middleware or thin proxy) | Low | spec §4; R6 §2.14-2.15 |
| P1 #10 | Anthropic `/v1/messages` + managed-settings clip | Anthropic dialect with `tool_result`-inside-`role:user` treated as tool content; recorded Claude Code clip | Prac M · Rob M | 2.5 h (spec) | A5 streaming; Claude Code ≥ 2.1.285 | Mid-stream `event: error` handling unverified (R7 §7); slow on local models | spec §3.6; R5 §5; FACT-CHECK B3 |
| P1 #11 | Native Ollama durations + `downgrade` | Compute from `/api/chat` durations instead of wall clock; reroute to a local model on a model cap breach; + the `mock-llm` Ollama-native endpoint (A). Owners C + A | Arch M · Prac M (residual T15) | 2.0 h (spec) | A second upstream dialect | Two code paths for one upstream | spec §7.1, §7.4; FACT-CHECK A2 |
| P1 #12 | Live `qwen3:8b` agent + promote-to-case | Real model drives S1-S8; a Playground/Threats event becomes a YAML regression case | Test M · Rep L | 1.5 h (spec) | Warm Ollama | Flaky local tool calling (spec R12) | spec §3.2 #11; P4 §7.2; J1 §5 |
| P1 #13 | C27 n-gram + C16 datamark | System-prompt n-gram overlap check; datamark spotlighting toggle on tool results | Rob L | 1.0 h (spec) | C27 canary; C16 | Datamarking can hurt task quality (R6 §7); n-gram false positives | spec §4 C16/C27; R6 §6 |
| P1 #14 | Thin agent→agent | `kyc-agent` exposed as an MCP tool; the caller's run token is forwarded so the callee inherits taint | Rob M (ASI07 stays partial) | 1.5 h (spec) | C33 run tokens | Taint inheritance edge cases | spec §3.6, D29 |
| P1 #15 | `/v1/guard` + `/v1/decide` + `PreToolUse` hook | Content-inspection API and PDP API so Envoy, Kong, Apigee and a Claude Code hook (OWASP ACS verdicts) reuse our brain | Prac H (J2 stage Q7: "we run Envoy and Apigee") | 2.0 h (spec) | `aicl.core` `decide()` | API surface creep; client config is not a boundary (R5) | spec §11.2, §2.4; FACT-CHECK B5; P4 H1 |
| P1 #16 | kustomize + kubeconform | Deployment, HPA, PDB, default-deny NetworkPolicy, ConfigMap directory mount; validated in CI | Prac M | 1.0 h (spec); 1.5 h (R7) | Final compose | None on stage | spec §3.8; R7 §4 |
| P1 #17 | `package_ioc` rule type | SIG-0013 (`postmark-mcp`) and the bad `nx` versions as package IOCs; skipped and listed until then. Owner B | Rob L · Rep L (MCP04 package IOCs) | 0.5 h (spec) | B3 signature engine | Low | spec §8.4, §13.3 |

---

## 4. Everything else, by theme

### 4.1 Identity, access and self-service

| Idea | What it is | Value | Cost | Depends on | Risk | Source | Status |
|---|---|---|---|---|---|---|---|
| Keycloak/LDAP live | Compose profile: Keycloak issuing the same `groups` claim, optional LDAP federation, device flow + `aictl` for CLIs | Prac M (the team's original idea, live) | 1.5-2.5 h realm + 1-2 h LDAP (R5); ~7 h with device flow and `aictl` (J3) | C01 JWT/JWKS path (P0), so it is an issuer swap | High: RAM, `start-dev` is insecure, login breaks on stage (J1, J3) | P3 §4.1; R5 §6; spec D20 | P2 |
| Directory sync | Poll the IdP every 30 s so leavers lose access before their token expires | Prac M (J2 stage Q6) | n/a | IdP admin API, Valkey | Stale sync must fall back to least privilege | P3 §4.1, §11.1 | cut → future |
| My AI self-service page | Groups, allowed models, budgets and reset times, recent blocks with plain reasons | Prac M · Rep L | ~2 h est. on top of `/v1/me`; ≤ 7 h with the Access pages (J3) | `GET /api/me` (P2 endpoint); F time | F bottleneck | spec §2.3; brief §4.11; P3 §4.2 | P2 |
| Access matrix + explain-access | Group × model/tool matrix, "explain access for user X", unused entitlements, recertification CSV | Prac M · Rep M | part of 7 h (J3) | Entitlement generator (P1 #8) | F time | P3 §9.2 | cut |
| Request access + personal keys | Request-access button routed to the group owner; mint an 8 h personal key | Prac M | n/a | My AI page, C23 | Low | P3 §4.2 | cut |
| Downstream `act` tokens | Gateway as a mini-STS: per-call tokens for MCP upstreams carrying who acts for whom | Rob L · Prac M | 1-2 h (R5) | Per-backend credential injection (P0) | Low | R5 §6.4; P3 §4.1 | future |
| Server-side role field stripping | `control` strips fields per role (Security, Management, Developer) instead of the UI-only switch | Rep L · Prac M | n/a | Per-user admin identity (`docs/06` B6) | Low | spec §11.1, §11.6 | P2 |
| Claude Code `statusLine` + model discovery | `aictl status --short` shows "budget 41% · 3 models"; gateway model discovery fills the `/model` picker | Prac M (the team's "user sees their limit") | 1 h (R5) | P1 #10 | `availableModels` with non-Claude IDs unverified (R5 §10) | R5 §5; P3 §4.2 | future |
| SPIFFE IDs, Keycloak agent delegation, MCP ID-JAG | Workload identity for agents; `may_act`/`act` delegation; standards-track SSO for MCP access | Prac M (pitch) | n/a | A real IdP | Keycloak delegation is a preview feature | R5 §6.6; R6 §6 | future |

### 4.2 Integration and enforcement points

| Idea | What it is | Value | Cost | Depends on | Risk | Source | Status |
|---|---|---|---|---|---|---|---|
| Policy compiler emitters | One policy compiled into Claude Code managed settings + hook, Squid ACLs, k8s NetworkPolicy and Codex `requirements.toml`, with a compiled-target diff per edit | Prac H · Rob L | ≥ 2 h per target (P3's managed-settings renderer alone: 2 h, J3) | Compiled policy IR | N targets = N test surfaces; golden files to maintain (P4 §1.2) | P4 §1-2; P3 §4.3; J1 §7 | cut |
| Envoy `ext_proc` adapter | Envoy (`FULL_DUPLEX_STREAMED`) calls `/v1/decide`: "same brain, any data plane" | Prac H | n/a (pitch in R5) | P1 #15 | Streaming body semantics in ext_proc | spec §3.8; R5 §7 | future |
| Vendor-gateway adapters | agentgateway webhook guard, LiteLLM `CustomGuardrail`, Kong/Apigee callouts, all calling `/v1/decide` | Prac M | ~3 h for agentgateway (R3) | P1 #15 | agentgateway webhook schema unverified (R3 §11); LiteLLM post-call on streams is audit-only | R3 §1-2; J2 §5 | future |
| Stock Squid shadow-AI sensor | Unmodified Squid for non-LLM egress (pip, git, web); lists from the feed; `external_acl` → `/v1/decide`; "shadow-AI attempts by team" tile | Rep M · Prac M | 2-3 h (R5); 4 h with log ingest (J3) | Feed `url_ioc` → `dstdomain`; a separate container | `external_acl` default `ttl=3600` defeats live edits (use 5); GPLv2, so never in our images (spec R19) | spec §2.3; P3 §2; R5 §2 | P2 |
| Gateway's own egress fence | Squid allowlist or Cilium `toFQDNs` for the gateway's outbound traffic | Rob M | n/a | Squid sensor or K8s | Low | spec §3.4, §3.8 | P2 |
| mitmproxy / eBPF endpoint sensor | Local-capture mitmproxy or eCapture uprobes to spot unmanaged AI traffic on hosts (residual T5) | Rep L · Prac M | 1-2 h (R5, R3) | Linux ≥ 6.8, sudo, host network; not the Mac demo | TLS/CA failure modes; observe-only | R5 §3.5; P1 §11 | cut → future |
| Claude Code + Open WebUI on stage | Real clients in containers, governed by config | Prac M | 4 h (J3) | P1 #10 | Open WebUI branding licence; three fragile clients on stage (J3) | P3 §14; P5 §15 | cut |
| Codex `/v1/responses` | Responses API passthrough for Codex | Prac L | 1-2 h (R5) | — | Ollama's Responses API is stateless only | R5 §7; P3 §16 | cut |
| Agent-tree attribution | Cost and blocks per Claude Code sub-agent from `x-claude-code-*` headers | Rep M | 1-2 h (R5) | P1 #10 | Headers are unsigned hints, not identity | R5 §7 | future |
| Docker Model Runner backend | GPU-accelerated upstream on Apple Silicon (OpenAI-, Ollama- and Anthropic-compatible, port 12434) | Arch L · Prac L | ~0.5 h est. (config only: `upstreams.*.base_url`) | — | No auth, so it must sit behind the fence like Ollama; details unverified (R4 §8.2) | FACT-CHECK A6; R4 §8.2 | future |
| CEL `when:` conditions | Context conditions on rules (time, risk, claims), compatible with agentgateway CEL | Prac M · Rob L | 2 h (J3) | cel-python; a policy schema RFC (schema frozen at H1) | A second language for judges to learn | P2 §12; R6 §3 | P2 |

### 4.3 Guardrails and detection

| Idea | What it is | Value | Cost | Depends on | Risk | Source | Status |
|---|---|---|---|---|---|---|---|
| Qwen3Guard-Stream | Token-level output moderation that can cut a stream mid-generation | Rob M (residual T14) | 4 h+ (R7) | transformers or vLLM; not in Ollama (FACT-CHECK A3); GPU | "Likely skip on CPU" (R7); no Metal in Docker | R4 §3; R7 §5 | P2 |
| Semantic output check per sentence | Async classifier on released sentences with a retroactive kill | Rob M (T14) | 3 h (R7) | `guard /v1/inspect` | Leak window if async, TTFT cost if sync | R7 §5; spec §14.2 T14 | future |
| AlignmentCheck judge on sinks | Local LLM compares the user goal with the proposed sink call; monitor first, then `ask` | Rob M (second opinion only) | 2 h (R6) | `qwen3:4b` JSON-schema output | High false positives with small models; 5-11 s per call on CPU | R6 §2.11; P2 C11; P5 §15 | cut |
| Granite Guardian tool-call check | Function-call hallucination and groundedness check on agent→MCP calls | Rob M | n/a (R4 stretch; 2.7 GB model) | Ollama `granite3-guardian:2b` | English-only; latency | R4 §3.3, §15 | future |
| gpt-oss-safeguard policy reasoner | Async "bring your own policy text" model with a rationale in the audit event | Rep M · Rob L | n/a | ~14 GB model (assumed size, R4) | RAM and latency on a laptop | R4 §4 | future |
| Presidio NER for names | Person-name detection for `pl` + `en` | Rob M | 2 h (J3) | Presidio + spaCy models | `pl` language trap, image weight, false positives; spaCy `pl_core_news_*` is GPL-3.0 | P3 §5; R8 §2.1; P4 C07 | cut |
| Pseudonymise + rehydrate | `<PL_PESEL_1>`-style placeholders mapped back in the response, request-scoped | Prac M · Rob L | ~1.5 h est. (logic exists in the mockup) | C07 | Rehydration can put PII back into output | spec §11.6, D36; brief §11 | P2 |
| Cross-message window + ROT13 | Scan the last 3 user/tool messages as one view; add a ROT13 decoder to C08 | Rob M (split-across-turns payloads) | ~1 h est. | C08 | More windows raise T2 latency | spec §5.3 | P2 |
| Honeytoken | A fake key planted in the sandbox filesystem; any use trips the C31 kill path | Rob M (ASI10 detection) | ~0.5 h est. | C31, `filesystem` server | Low | P4 §3 C31 | future |
| Slopsquatting check (C28) | Flag package names in output that are missing from a local index | Rob L (LLM07:2026 partial) | ~1-2 h est. | An offline package-name index | Stale index gives false positives | R1 §9; R2 e6; spec §4 | P2 |
| RAG access control (C29) | Per-user filtering of retrieved documents | Rob L (LLM09 partial) | n/a | A RAG demo | Scope | R1 §9; spec §4 | out of scope |

### 4.4 Agents, MCP and A2A

| Idea | What it is | Value | Cost | Depends on | Risk | Source | Status |
|---|---|---|---|---|---|---|---|
| A2A proxy (C21) | Signed Agent Card verification, card pins, peer graph, `message_id` replay cache, hop limit, taint inheritance | Rob M · Prac L (ASI07 → green) | 4 h (R6; P5) | P1 #14; `a2a-sdk` 1.2.1, PyJWT, rfc8785 | A2A 0.3 vs 1.0 method names unverified (R6 §9) | R6 §2.16; spec D29 | P2 |
| Memory-write guard (C22) | `persistent` label; tainted writes → `ask`; reading a tainted entry taints the run | Rob M (ASI06) | 1.5 h (R6) | A memory MCP server; C24 | Low | R6 §2.12; spec §4 | P2 |
| Call warrants | A tool runs only if the governed model asked for exactly those args (hash bound at the LLM edge, redeemed once at the MCP edge) | Rob M | 3 h (J3) | Tool-call buffering, C24, Valkey `GETDEL` | False denies when args are re-serialised (J3); our own agent only | P4 §2.6 M2; J1 §5 | P2 |
| Four-eyes approvals | Two approvers, neither the requester, for high-risk asks | Rob M · Prac M (residual T8) | 4 h incl. approvals (J3); ~1 h on top of C23 (est.) | P1 #5; two approver identities | Slows the demo | P2 C23; spec D27 | P2 |
| Delegation sub-mandates | `/v1/mandates/{id}/delegate`: child ⊆ parent, budget share, depth limit | Rob M · Prac L | n/a | P1 #14; Lua over all ancestors | Scope | P4 §2.6 M5 | cut (thin P1 #14 instead) |
| Mandate Authority service + Mandates page | A separate authority service and a mandate-tree view per run | Rep M | 3 h service + 8 h pages incl. sparring and diff views (J3) | Pub/sub to PEPs | No versioned pull, so stale PEPs go unnoticed (J2) | P4 §2, §7.2; J2 §4 | cut (Run tab in the drawer instead) |
| Biscuit tokens | Offline-attenuable tokens for cross-organisation A2A | Prac L | n/a | — | Datalog learning curve | P4 §12 | future |
| `tool_sequence` rule (SIG-0011) | A named toxic-flow detection on run state (C24 already enforces the guarantee) | Rob L | n/a ("fiddly", R2) | Run state | Low | spec §8.4; R2 §2.7 | P2 |
| MRTR/elicitation approvals | Approval asked in the agent's own terminal via MCP elicitation | Prac M | n/a | P1 #5; 2026-07-28 clients | Asks the same user, so it is not four-eyes | R6 §2.8 | future |
| Docker MCP Gateway sandbox | Run third-party stdio servers in locked-down containers (`--block-network`, `--block-secrets`) | Rob M | n/a | Docker Desktop or CE | A second policy store | R6 §1.7; R3 §4 | future |
| Unmodified OSS agent (goose) | An off-the-shelf agent governed by config only, as a video | Prac M | ~2 min video (R6) | P1 #10-style config | Slow local models | R6 §6 | future |

### 4.5 Supply chain and model artifacts

| Idea | What it is | Value | Cost | Depends on | Risk | Source | Status |
|---|---|---|---|---|---|---|---|
| HF scanning mirror + GGUF template scan | `/hf/` mirror via `HF_ENDPOINT` with quarantine; Jinja `chat_template` scan (SIG-0008 as regex) | Rob M · Rep L | 2 h (P5); 3-4 h (R5) | C18; mock-hf fixtures | hf-xet may ignore `HF_ENDPOINT` (R5 §10) | spec §3.6, §8.4; P1 §1.1; P5 | P2 |
| Guarded `/ollama/api/pull` | An operator-only model-pull route with a source allowlist | Rob L | 1 h (J3) | C20 | Must not weaken the floor "Ollama admin APIs are never proxied for agents" | P1 §1.1 | cut |
| YARA-X rule type | `yara` feed rules for artifacts | Rob L | n/a | yara-x (BSD-3) | Low | spec §8.4; R2 §2.3 | P2 |
| Model-signing verification | Verify OpenSSF/sigstore model signatures in C18 | Rob M (provenance only; signing ≠ safety, T9) | n/a | sigstore `model-transparency` | Low | R2 sources | future |
| SBOM + signed images | `make sbom`, cosign-signed images, published digests | Prac M · Rob L | ~1 h est. | `uv lock`, image digests | Low | `docs/02` #16; spec T10 | future |
| Extra Museum exhibits | GGUF SSTI, picklescan-bypass globals, CamoLeak, ShellTorch, Amazon Q wiper, LiteLLM compromise | Test M · Rep M | ~0.5 h each as cases (est.) | Feed rules (SIG-0008, SIG-0020) | Low | `docs/02` §3; P1 §5 | cut (10 exhibits kept, spec §8.5) |

### 4.6 Budgets and resources

| Idea | What it is | Value | Cost | Depends on | Risk | Source | Status |
|---|---|---|---|---|---|---|---|
| Budget `approval` breach action | A temporary cap increase via a request card | Prac L | ~1 h est. on top of C23 | P1 #5 | Low | spec §7.4 | P2 |
| Anomaly baseline | Cost and token-velocity anomalies (EWMA z-score; > 2× own p95 and > org p99) | Rep M · Rob L | 2 h (R7) | History; on demo day it can only be seeded and labelled | False positives; no real baseline in 24 h | R7 §5; R9 §1.7; spec C26 | P2 |
| Weighted fair queue | Fair share per principal on a shared local model | Arch M | 2-3 h (R7) | Guard lane (P1 #2) | Low | R7 §1.11, §5 | future |
| KEDA autoscaling | Scale gateways on in-flight streams | Prac L | 1-2 h (R7) | P1 #16 | Low | spec §3.8; R7 §4.4 | P2 |
| Model `fallback` on upstream errors | Route to a fallback model on 5xx or a full Ollama queue | Prac L · Arch L | n/a | Upstream client | Low | spec §5.4 | P2 |

### 4.7 Audit, reporting and console

| Idea | What it is | Value | Cost | Depends on | Risk | Source | Status |
|---|---|---|---|---|---|---|---|
| ECS / CEF / Splunk HEC exports | SIEM formatters plus an OTel Collector config file | Rep M | 2 h (R9) | OCSF mapping (P1 #4) | Schema churn (pin ECS 9.5) | spec §9.6; R9 §2.8 | P2 |
| Merkle / C2SP checkpoints | Transparency-log style checkpoints over the chains | Rep L | 1.5 h (R9) | P0 checkpoints | Low | spec §9.2; R9 §2.7 | P2 |
| Weekly LLM-written executive report | Facts JSON → `qwen3:4b` → numeric validator → HTML | Rep M (management audience) | 3 h (R9) | Local model; facts JSON | Hallucinated numbers; ~40 s on CPU (R9 Q5) | R9 §7 | P2 |
| Threshold what-if slider | Re-evaluate the last N hours at another threshold in DuckDB; gray-zone histogram | Rep M (answers "what does adherence % mean?") | 2 h (R9) | `score` and `threshold` in every event (P0) | Seed data is synthetic | R9 §1.6 | P2 |
| Risky entities | Top users, agents, tools and servers by decayed severity, with sparklines | Rep M | ~2 h (R9 §4.4) | Report API | Pseudonym handling | R9 §1.7 | future |
| Encrypted content vault | Envelope-encrypted L2/L3 content plus `content_access` audit events | Rep M · Prac M | 2 h (R9) | Key management | Low | R9 §2.6 | future |
| DORA incident draft | A button that pre-fills an incident report with CDR 2025/301 Art. 5 clocks and the evidence bundle | Rep M (bank-specific) | 1.5 h (R9) | Threats drawer | Clocks must be quoted exactly (4 h / 24 h / 72 h / 1 month) | R9 §3 | future |
| OTel GenAI spans | One span per guardrail using the GenAI semantic conventions | Rep M · Prac M | 2 h (R7) | Collector | Conventions still in Development status | R7 §3.9; R9 §2.10 | future |
| Feed push webhook | Push instead of the 3 s poll | Arch L | ~0.5 h est. | Feed service | Low | spec §8.2 | P2 |
| Grafana perf dashboard | Provisioned dashboard for SREs | Arch L | 1.5 h (R9) | Prometheus | AGPL; our licence check fails on it (spec R19) | R9 §4 | cut |
| ATLAS Navigator layer export | Coverage as a Navigator layer JSON | Rep L | n/a | Coverage grid | Layer format unverified (R1 §12.4) | R1 §12.4 | future |
| Policy diff/YAML + Audit query pages | Side-by-side policy diff; free audit query | Rep M | n/a (`/api/policy/versions` + `/api/policy/diff` are P2 in §11.3) | L APIs | F time | spec §9.5, §11.3 | P2 |
| Exploit Museum 16-card UI | 16 replayable incident cards with "Replay all" | Rep M · Test M | 5 h (J3) | Scripted agent | One UI person | P1 §5; J3 §2 | cut (10 exhibits; cards at P1 #7) |

### 4.8 Testing and evaluation

| Idea | What it is | Value | Cost | Depends on | Risk | Source | Status |
|---|---|---|---|---|---|---|---|
| Sparring / adversary-twin service | A service that re-attacks the live system after every edit with mutators and reports measured attack success | Test H · Rep H, but duplicates the live self-test | 7 h (J3) | Case runner | A second runner; only known attacks (Goodhart) | P4 §8; J1 §7; J3 §2 | cut (kept as the live self-test, "S4 EXPOSED" and the detectors-off metric) |
| garak attack-success-rate delta | garak probes against Ollama directly vs through the gateway | Test M · Rob M (a corpus we did not write) | 30-60 min install + 10-30 min run (R8) | Image built before the event; a red-team principal with a big budget | 403 is fatal and 429 retries forever in garak; torch-sized image | R8 §9; P1 §7 | P2 |
| PyRIT, AgentDojo, Allure 3 | Multi-turn red teaming (Crescendo, PAIR); agent benchmark through the gateway; nicer reports | Test M | PyRIT 2-4 h (R8) | Local attacker LLM | Slow on CPU | R8 §9, §14.2 | future |
| LLM-paraphrase mutator | Paraphrase NEG cases with a local LLM | Test M | n/a | Local LLM | Non-deterministic runs | P4 §12 | future |
| `make test-fast` | The same cases in-process (ASGITransport + fakeredis Lua), no Docker | Test L | 3 h (J3) | — | Two harnesses that disagree (spec D18) | P1 §7 | cut |
| promptfoo red team | promptfoo red-team plugins against the gateway | Test L | 1-2 h (R8) | Node toolchain | Remote generation by default; AGPL `pliny` prompts | R8 §9 | cut |

### 4.9 Operations and deployment

| Idea | What it is | Value | Cost | Depends on | Risk | Source | Status |
|---|---|---|---|---|---|---|---|
| Signed policy bundles | `deployment: prod` refuses unsigned policy; only Ed25519-signed bundles apply (OPA-style) | Prac M · Rob M | 1-2 h (R7) | Feed signing code (C19) | Judges' live edits must keep working in `demo` | spec §6.5 #12; R7 §4.6 | P2 |
| PR-based policy change management | Policy repo with CODEOWNERS, a CI `policy check`, access diff + verdict replay posted to the PR, shadow-before-enforce promotion, break-glass with two approvers | Prac H | n/a | Policy repo, CI, audit replay | Process, not code | P3 §11.4; J2 §5 | cut → future |
| Tighten-only overlay lattice | Per-business-unit overlays that may only tighten the baseline | Prac H · Rob L | 5 h (J3) | Policy validator | Scope | P3 §6, §11.3; J1 §7 | cut |
| Prebuilt multi-arch images | GHCR images with baked ONNX weights for a faster mentor cold start | Prac M | 2.5 h (J3) | CI build for arm64 + amd64 | Build time, image size | P1 §7, §10 | cut |
| Report storage beyond DuckDB | ClickHouse, or DuckDB over object storage | Prac M | n/a | — | — | spec §3.8 | P2 |

---

## 5. Post-hackathon roadmap: what would make it production-grade at a bank

The demo is one laptop. A bank needs the same brain with real identity, change control, high availability and evidence that survives an audit. In rough order:

| Area | What to build | Why a bank needs it | Source |
|---|---|---|---|
| **Identity** | SSO live: OIDC to the bank IdP (Entra ID, ADFS or Keycloak) through a JWKS URL; AD/LDAP groups arrive as the `groups` claim and map through `group_map` with no code change | Entitlements come from the directory, not from a YAML file | spec §2.3, §12 Q&A, D20; R5 §6 |
| | Directory sync or SCIM, so leavers lose access before their token expires; least privilege when the sync is stale | Leaver revocation is an audit finding if it waits for a token TTL | P3 §4.1, §11.1 |
| | Per-person admin identity and RBAC on `control`; server-side field stripping; a `security_investigator` role to resolve pseudonyms, with `content_access` events | Replaces the single demo admin token; "who looked at whom" | spec §11.1; R9 §1.7 |
| | Workload identity for agents (SPIFFE), token exchange with `act` for MCP upstreams, MCP ID-JAG | Agents become accountable principals across services | R5 §6.4, §6.6; R6 §6 |
| **Policy change** | Git-based policy repo: CODEOWNERS, CI `policy check` with the same validator, access diff and verdict replay on every PR, four-eyes merge | Change management that model-risk and audit teams already understand | P3 §11.4 |
| | Signed policy bundles (Ed25519 or OCI); `deployment: prod` refuses unsigned edits; git-sync or a ConfigMap directory mount on K8s (about 1 min to propagate) | Write access to a file must not equal authority to change policy | spec §6.5 #12, §3.8; R7 §4.6 |
| | Shadow-before-enforce promotion per control; break-glass with two approvers that expires after 4 h; tighten-only overlays per business unit; schema N-1 converters | Safe rollout and multi-team ownership | P3 §11.2-11.4 |
| **Availability and scale** | HA Valkey (managed or Sentinel), keys hash-tagged per tenant, AOF, rehearsed fail modes | Budgets and run state must survive a node loss | spec §3.8, R16 |
| | Gateways as a K8s Deployment with HPA on CPU and in-flight streams, PDB `maxUnavailable: 0`, KEDA | Stateless scale-out with no downtime | spec §3.8; R7 §4.4 |
| | Default-deny NetworkPolicy for the agents namespace, Cilium `toFQDNs` for the gateway's own egress, model pools never reachable from agents | The fence becomes a platform property | spec §3.8; R5 §5.13 |
| | GPU guard pool (vLLM or Ollama) as its own Deployment for 8B guards, with weighted fair queuing, separate from business models | Real semantic depth without starving the business models | spec §3.8; R7 §4.5; R4 |
| | `control` as a single active signer behind a Valkey lease | Exactly one checkpoint signer | spec §3.8 |
| | Existing data planes call `/v1/decide`: Envoy `ext_proc`, Apigee or Kong callouts, agentgateway | Banks keep the proxies they already run | spec §2.4, §3.8 |
| **Audit and evidence** | Per-pod chain → OTel Collector → Kafka → SIEM (Splunk HEC, Elastic ECS, CEF, and OCSF once the validator passes) | Detection and retention live in the SOC, not on a laptop volume | spec §3.8; R9 §2.9 |
| | ClickHouse (or DuckDB over object storage) for the report API | Single-node DuckDB on a volume does not scale (J2 X12) | spec §3.8 |
| | Checkpoints on WORM/object-lock storage, signed by an HSM or KMS key; Merkle/C2SP transparency log | "Tamper-evident" that holds up against an insider | spec §9.2 #5; R9 §2.7 |
| | Envelope-encrypted vault for L2/L3 content, retention policies, HMAC key rotation with versioned refs | Privacy, GDPR and forensics together | R9 §2.6, §9 |
| | DORA incident drafts and EU AI Act Art. 12/19 logging evidence ("supports evidence for", never "compliant") | The regulators' clocks and logging duties | R9 §3; spec §2.5 |
| **Detection quality** | Continuous evaluation: held-out sets, the bank's own red-team corpus, Polish and other languages, garak/PyRIT in CI, calibration per engine version | Thresholds stay honest as models and attacks change | spec §10.5; R8 |
| | Output-side semantic checks (Qwen3Guard-Stream or a per-sentence classifier) on GPU | Closes residual T14 | R4 §3; R7 §5 |
| | Anomaly baselines (cost, token velocity) once 30 days of history exist | Spots rogue agents and LLMjacking early | R9 §1.7; R7 §5 |
| | Coverage gaps: A2A proxy (C21), memory guard (C22), RAG access control (C29), slopsquatting (C28), Anthropic and Responses dialects | Moves ASI06/ASI07 and LLM07/LLM09 from partial to covered | spec §4, §14.2 |
| **Supply chain and hardening** | Signed images, SBOM, hash-locked dependencies, non-root, read-only root filesystem; run-HMAC and pseudonym keys in a KMS with rotation | The gateway is the trust anchor (residual T10) | spec §14.2 T10; `docs/02` #16 |
| | HF scanning mirror with quarantine, GGUF template scan, model-signing verification, safetensors-only by default | Model repositories are a live attack surface | spec §3.6; R2; FACT-CHECK D6 |
| | Stronger sandboxes for third-party MCP servers (gVisor or Docker MCP Gateway) with egress control | Pinning sees definitions, not behaviour (residual T7) | R6 §1.7; spec T7 |
| | MDM-pushed managed settings, endpoint sensors (eBPF or mitmproxy) and Squid for non-LLM egress | Covers unmanaged hosts (residual T5) | R5 §3.5, §5; spec T5 |
| **Operations** | SLOs with alerts, runbooks for every row of the fail-mode table, chaos drills (kill a replica, stop Valkey) in CI | Operability is what a platform team signs off | spec §5.4; J2 §6 |
| | Multi-tenancy on the reserved `tenant` field; rolling upgrades; new detector models shadowed in `monitor` before promotion | One platform, many business units | spec §9.1; P3 §11.2 |
