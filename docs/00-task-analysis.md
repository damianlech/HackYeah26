# 00 · Task analysis: what Goldman Sachs is actually asking for

> Source: the two partner PDFs (`RULES AI Control Layer.pdf`, `CRIETRIA AI Control Layer.pdf`) from the HackYeah 2026 task pack.
> This file restates them, adds what we read between the lines, and maps every requirement to evidence the judges can check.

## 1. The task in one paragraph

Build a **lightweight, flexible AI Control Layer**: a gateway, proxy, middleware or SDK wrapper that **intercepts and governs** traffic between agentic AI systems: *agent→LLM, agent→MCP, agent→agent, app→agent*. It must enforce security, privacy and resource controls from **one centralized policy source**. It must combine **deterministic** (non-AI) and **semantic** (AI-based) guardrails, govern **budgets** for both commercial APIs and **local models**, mitigate **historical attacks** using signatures fed by an **external system**, and produce **reporting** for both security teams and management. It must ship with an **automated test suite** that covers both allowed and blocked/redacted cases.

## 2. Requirements, decomposed

| # | Requirement (PDF wording, shortened) | What it really means for us | Evidence judges will look for |
|---|---|---|---|
| R1 | **Centralized policy engine**: a single config source with controls, sensitivity thresholds (*Block vs Redact or adherence %*), allowed LLM models, resource/financial budgets | One `policy.yaml`, schema-validated, **hot-reloaded**, versioned. Per-control `mode` (block / redact / ask / monitor / off) and `threshold`. Model catalog plus allowlists per group. Budgets. | Judge edits the file and the behaviour changes within seconds. The dashboard shows the new version and a diff. |
| R2a | **Deterministic controls**: e.g. PII/secrets pattern matching, authn/access checks | Regexes with checksum validators (PESEL, IBAN, Luhn), secrets rules, normalizer (unicode/encodings), identity, model/tool allowlists, argument validators | Test cases plus the playground show exact rule ids. |
| R2b | **Semantic controls**: AI-based where possible | Local classifier (prompt injection / jailbreak), embedding similarity to known attacks, guard LLM for gray zones / content policy | Ad-hoc prompts that regex can't catch still get blocked, and you can see the score and threshold. |
| R3 | **Budget & resource governance** for *external commercial APIs and local models*: resource access, compute time, token spend | Tokens + money (price table) + **GPU compute-seconds for Ollama**. Hierarchical budgets (org/team/user/agent/session). Reserve-then-settle. Loop / denial-of-wallet breakers. | A tiny budget gets exhausted, then a clean 429 with a reason. Burn-down chart. A local-model budget in seconds. |
| R4 | **Historical attack mitigation**: malicious code execution, unsafe deserialization, supply-chain exploits on model repos; *signatures fed from an externally managed system* | A signed, versioned **signature feed** served by a separate "threat-intel" service and hot-reloaded. Pickle/model artifact scanning (fail-closed). Tool-argument code guard. AI-infra endpoint rules (Ray, Ollama, Langflow CVEs). | Judge adds a signature to the feed and it blocks within seconds. Malicious pickle is blocked. Rug-pulled MCP tool is quarantined. |
| R5 | **Security reporting & auditing**: real-time metrics (blocks, budget usage) for management; **exportable audit logs** for security teams | Live dashboard (SSE). Append-only **hash-chained** audit log. Exports (JSONL / CSV / OCSF). Posture score. OWASP/ATLAS mapping on every event. | Two audiences, two views. Export works. Tampering is detected. |
| R6 | **Self-testing suite**: automated positive (allowed) and negative (blocked/redacted) tests, *including budget limits and exploit mitigation* | `make test` that is **hermetic** (mock LLM, no Ollama needed), YAML case library, coverage matrix, plus a **live self-test** inside the product that reacts to policy changes | One command, green summary, a control × case matrix. Mutation test: disable a control and see tests fail. |
| D1 | Deliver a functional layer + **simple architecture diagram** | Mermaid / PNG in README and slides | — |
| D2 | **Sample configuration**: documented policy file showing *different strictness/adherence levels and budget rules* | `policy.yaml` with `permissive / balanced / strict` profiles plus group overrides, heavily commented | — |
| D3 | **Simple interactive dashboard**: controls, overall security posture, blocked threats, cost/resource metrics | Our console (see `mockups/dashboard.html`) | — |
| D4 | **Executable test suite** incl. budget limits and exploit mitigation | see R6 | — |

### Things the PDF says that are easy to miss

- *"agent to agent, app to agent, agent to MCP, agent to model"*. Most teams will build only an LLM proxy. Covering **MCP** (tool calls) properly is a cheap differentiator, and **A2A** at least in the design.
- *"signatures of such attacks can be fed from some externally managed system"*. A feed served by a **separate** container, with a version and a signature. A YAML file inside the gateway is not enough.
- *"resilient enough to manage budgets for both external commercial APIs and locally hosted models"*. We need a local-compute unit (seconds of GPU time from Ollama's `eval_duration`) as well as tokens × price. No paid keys are given, so external providers are **simulated** (price table + mock upstream). We have to say that openly.
- *"Judges may modify the configuration files/feeds … how changes are reflected, can they adjust in real-time"*. **Hot reload is a judged feature.** So are invalid edits: keep the last-known-good config and show the error.
- *"You should be able to produce performance telemetry"*. Per-stage latency (Prometheus + `Server-Timing` header) and a benchmark report.
- *"Judges will execute the automated test suite provided by the team"*. In phase 1 the mentors may do this **without us**. The README must make it a one-liner that works offline.
- *"spontaneous, zero-preparation actions … ad-hoc prompts"*. We need a **Playground** in the dashboard (and/or Open WebUI) wired through the gateway that shows *why* something was blocked.
- *"You can build your own agent OR use an already existing agent"*. Agents are **not assessed**, so use the cheapest convincing ones (small Python agent + Claude Code/Open WebUI via config).
- *"make sure you check the license of these tools"*. Keep a license table (see `research/R3-oss-landscape.md`).
- *"review available sources (e.g. OWASP)"*. Map every control to **OWASP LLM Top 10 (2026)**, the **OWASP Agentic Top 10 (ASI01–10)**, the **OWASP MCP Top 10** (beta) and **MITRE ATLAS** ids (see `research/R1-threat-frameworks.md`).

## 3. Judging rubric and what earns points

| Criterion | Weight (CRITERIA PDF) | Weight (RULES PDF) | What wins it | Our main levers |
|---|---|---|---|---|
| Robustness of the solution & quality of guardrails | **30%** | 30% | Breadth (all surfaces) plus depth (bypass resistance: obfuscation, Polish, indirect injection). Guarantees that hold even when a detector is fooled. | Normalizer, layered cascade, taint/provenance for tools, egress fence, fail-closed, artifact allowlists |
| Architecture & performance efficiency | 20% | 20% | Clean separation (data plane / control plane), cheap-first cascade, streaming-correct, measured overhead | Cascade with early exit, holdback stream scanner, per-stage telemetry, ReDoS-safe regex, benchmark |
| Security reporting | 20% | 20% | Real-time + exportable, two audiences, evidence-grade logs | Hash-chained audit, OCSF export, posture score, incident decision trace |
| Completeness of the self-testing suite | **15%** | **20%** | Every control has positive and negative tests. Budgets, exploits, hot reload, perf. Runs alone. | Hermetic `make test`, YAML cases, live self-test, mutation test, coverage matrix |
| Practical implementability & scalability | **15%** | **10%** | Zero-code integration, SSO/groups, K8s story, operability | base_url + managed settings, virtual keys → OIDC, compose → Helm/kustomize, stateless + Valkey |

> ⚠️ **The two PDFs disagree** on the last two weights (15/15 vs 20/10). Ask the mentors which one applies. Either way, testing is worth 15–20% and should not be left until the end.

**Minimum bar:** a project must get **≥ 50% of the points in phase 1** to be eligible for a prize.

**Phase 1:** mentors (≥ 3) evaluate the HackTribe submission. They read the PDF and README, and possibly run the repo.
**Phase 2:** finalists pitch live to a jury. Expect ad-hoc prompts, live config edits and questions about architecture and logs.

## 4. Logistics and hard constraints

- **Window (as written in the RULES PDF):** start solving **no earlier than 11:00 PM on Oct 3**, submit **no later than 11:00 PM on Oct 4** (24 h). *"PM" may be a typo for AM. Confirm with the organizers.* Changes after the deadline are ignored.
- **Team:** 1–6 people (we are 6).
- **Submission (HackTribe, EN or PL):** project title, team name, member list, project description, **≤ 10-slide PDF**. The PDF may include screenshots, repo link, demo links and graphics.
- **No paid AI services are provided.** Everything must run on our own machines (Ollama, OSS libraries). Our laptops are Apple Silicon with 32 GB+. **Docker on macOS gets no Metal GPU**, so run Ollama natively on the host and reach it from containers via `host.docker.internal:11434`.
- **Prizes:** PLN 6,000 / 5,000 / 4,000. IP stays with the authors.

## 5. What "done" looks like on Sunday evening (deliverable checklist)

- [ ] `README.md` starts with: *what it is (3 lines)*, the architecture diagram, **`make demo`** and **`make test`** (both run offline, with the mock LLM).
- [ ] Gateway running in docker-compose: LLM proxy (OpenAI + Anthropic dialects), MCP proxy, policy hot reload, budgets, audit, metrics.
- [ ] `policy.yaml` documented, with ≥ 3 strictness profiles, group overrides and budget rules.
- [ ] Signature feed service, with ≥ 15 rules across several rule types, signed and hot-reloaded.
- [ ] Dashboard: posture, threats with decision trace, spend, controls (live toggles), playground, self-test, audit export.
- [ ] Test suite: ≥ 1 positive and ≥ 1 negative case per control, plus budget, exploit, hot-reload and perf. HTML report. Coverage matrix.
- [ ] Benchmark numbers (overhead p50/p95 per stage) in the README and slides.
- [ ] ≤ 10-slide PDF: problem → architecture → controls → live-demo screenshots → reporting → testing results → scalability → team.
- [ ] Backup demo video (3–4 min) in case the live demo or Wi-Fi fails.
- [ ] License table for every dependency.
- [ ] Submitted **at least 1 h before the deadline**.

## 6. Traceability: requirement → feature → test → slide

| Req | Feature (see `design/VISION-SPEC.md`) | Test family | Slide |
|---|---|---|---|
| R1 | policy engine + hot reload + last-known-good + versions/diff | `tests/policy/` reload, invalid-policy, mutation | 4 |
| R2a | normalizer, PII/secrets, signatures, allowlists, arg validators | `cases/*.yaml` deterministic | 5 |
| R2b | PI classifier, semantic signatures, guard LLM (gray zone) | `cases/semantic.yaml` + `make eval` (precision/recall) | 5 |
| R3 | ledger (tokens, $, GPU-seconds), reserve/settle, loop breaker | `tests/budget/` incl. concurrency race | 6 |
| R4 | signature feed, artifact gate, code guard, infra endpoint rules, MCP pinning | `tests/exploits/` | 6 |
| R5 | audit chain, exports, dashboard, posture | `tests/audit/` verify, export schema | 7 |
| R6 | hermetic suite + live self-test | the suite itself | 8 |
