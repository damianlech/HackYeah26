# 06 · Open questions: what to ask, what to decide, and when

> **Sources:** `design/VISION-SPEC.md` §15 (Q1-Q16) and its caveats (§3.4 fence probe, §5.1 H2 latency rule, §11.6 brief overrides); the "Open questions" section at the end of each `research/R1`-`R9` note; `docs/00-task-analysis.md`; the judging memos `design/judging/J1`-`J3`.
> **Precedence:** the spec wins over everything else, and `research/FACT-CHECK.md` wins over the R notes.
> **How this file works:** every question appears once. Questions the spec already answers are in §5 with the decision, so nobody reopens them. **★** marks the five most consequential questions.
> **Who updates it:** L. When an answer arrives, L writes it in the team chat and replaces the default here.
> **Where the spec's Q1-Q16 went** (lane cards use Q numbers, this file uses A/B/C IDs): Q1 → C8 · Q2 → A1-A3 · Q3 → B2 · Q4 → B4 · Q5 → C3 · Q6 → C11 · Q7 → B5 · Q8 → C12 · Q9 → C16 · Q10 → B3 · Q11 → C13 · Q12 → C6 · Q13 → B6 · Q14 → B7 · Q15 → B8 · Q16 → A4.

---

## 1. The five that matter most

| # | ID | Question | Why it is in the top 5 |
|---|---|---|---|
| 1 | ★ A1 | Deadline wording: 11 PM or 11 AM? | It picks plan (a) (submit H15) or plan (b) (submit H23) of spec §13.4. Plan (a) runs until the answer is confirmed in writing; work uploaded after the deadline is ignored. |
| 2 | ★ A4 | Is our pre-event work (research, design and a throw-away POC) allowed, and may any of it be reused? | A "no" is a rules problem that could disqualify us, not a scope problem. |
| 3 | ★ A5 | How will phase-1 mentors run the repo? | Below 50% of the phase-1 points means no prize, and mentors may run it without us. |
| 4 | ★ C1 | Does the fence hold on the demo Macs (H1 probe)? | It decides whether we can claim the forced chokepoint at all (spec risk R1, "Critical"). |
| 5 | ★ C10 | Is the H12 gate green (detectors-off S4/S5, fence, race)? | It decides whether the headline guarantee exists (spec risk R3, "Critical"). |

---

## 2. A. Ask the organizers or mentors at H0

L asks these in the first 15 minutes. If nobody can answer, the default stands.

| ID | Question to ask (verbatim) | Why it matters | Default if no answer |
|---|---|---|---|
| ★ A1 | "The RULES PDF says start no earlier than 11:00 PM on 3 October and submit by 11:00 PM on 4 October. Is that PM, or 11:00 AM? What is the exact cut-off, and in which time zone?" | It picks plan (a) or (b) of spec §13.4. Work after the deadline is ignored. | Plan (a) of spec §13.4 runs until 23:00 is confirmed in writing: P0 only, P1 frozen, placeholder H8, freeze H11, clean room H12:30, submit H15 (09:00, 2 h before 11:00). H0 = the moment we start building after the kickoff (~18:00), not the official start. On written confirmation switch to plan (b): placeholder H11, freeze H18, submit H23 (6 h before 23:00). Spec Q2, risk R18. |
| A2 | "The CRITERIA PDF weights testing 15% and practicality 15%, the RULES PDF 20% and 10%. Which weights will the jury use?" | Decides whether spare hours go to tests (P1 #3, #8) or practicality (P1 #10, #15, #16). | CRITERIA weights. The test suite stays first-class either way, and the P1 order does not change (spec R18). |
| A3 | "Can we upload a draft submission early and edit it until the deadline? Can the PDF, description, repo link and video link change after the first upload?" | Decides whether the placeholder (H8 in plan (a), H11 in plan (b)) is a real upload or a dry run (C9). | Real upload at the placeholder if edits are allowed. Otherwise a checklist dry run then, and a single upload at submit (H15 in plan (a), H23 in plan (b)). |
| ★ A4 (= spec Q16) | "Before the start we did research and design: notes, a clickable UI mockup, example config files, downloaded models and ONNX exports, plus a small throw-away proof of concept (`poc/`: one gateway, a keyword guard, a mock LLM). Is that allowed? May we show it, may any of it be reused, or must all product code be written after the start?" | The rules say "start solving no earlier than" the start time. Breaking that rule could disqualify us, and describing the POC inaccurately would be worse. | Research and design allowed. The POC is reference-only and is not copied into the product repo created at H0:30 (spec §3.9, B9) unless the answer explicitly allows reuse. The README links this brainstorm repo, POC included, openly as pre-event work. |
| ★ A5 | "In phase 1, will mentors clone and run our repo themselves? On what machines (OS, CPU architecture, RAM, Docker installed?), with or without internet, and for how long?" | A project needs at least 50% of the phase-1 points to be eligible for a prize (`docs/00` §3). A run that fails on a mentor's laptop costs us there. | Assume x86 Windows or Linux, Docker present, no `make`, no Ollama, no HF token, internet only for the image pull. The README leads with the raw `docker compose` test command (spec §3.7, §10.1, D09). |
| A6 | "When do phase-1 mentors start reviewing, and must the repo be public at submission?" | Sets when the repo goes public (C16) and when `make test` must be green on the tag. | Repo public after `gitleaks` (H14 in plan (a), H20 base, H22 in plan (b)); tag `v1.0-submission` at submit (H15 / H21 / H23). |
| A7 | "How long are the phase-2 pitch and the Q&A, and in which language? Can we present from our own laptop over HDMI with Wi-Fi off?" | The demo script is 7 min plus Q&A, with a 3-min cut (spec §12). The Polish attack beats need an English line if the jury doesn't read Polish. | 7 min + Q&A, English slides and narration, Polish prompts with an English caption, our laptop running a tag, Wi-Fi off. |
| A8 | "Will judges poke the system only on our laptop, or also from their own devices over the venue network? Will they use their own clients (curl, OpenAI SDK, Claude Code)?" | `lb` and `control` bind to 127.0.0.1. Remote access needs a LAN binding, a judge key and a check that it opens neither Ollama nor the admin plane. | Our laptop, plus their own clone. JUDGES.md gives the judge key, base URLs and the poke matrix (spec §10.7-10.8, R5 Q5). |
| A9 | "Do the Goldman Sachs judges expect a live SSO/LDAP login, or is a real JWT/JWKS path with a groups claim, plus a slide on Entra ID/AD, enough?" | Live Keycloak/LDAP costs about 7 h and is fragile on stage (J1, J3). It is P2. | JWT/JWKS static issuer + hashed virtual keys. Keycloak/LDAP is a slide and a P2 compose profile (spec D20). |
| A10 | "Does the 10-slide limit include the title and team slides? Is there a PDF size limit? May the PDF link to the repo and a demo video, and where should the video be hosted?" | `make submission-check` enforces ≤ 10 pages and < 20 MB, and the backup video is linked from the PDF and README (spec §13.9). | 10 pages including the title; < 20 MB; an unlisted video link in the PDF and README. |
| A11 | "Are there any limits on AI coding assistants or on pre-trained local models during the event?" | The plan counts AI-assisted hours (spec §13.2) and runs local models. | Allowed, and disclosed in the README. |

---

## 3. B. The team decides before or at H0-H1

| ID | Decision | Options | Recommended default | Who decides | By |
|---|---|---|---|---|---|
| B1 | Who takes which lane: L, A, B, C, D, F (spec §13.1) | by strength; by sleep slot | F = the strongest React/design person (sleeps H5:30-H8:30). D = the strongest async/protocol person (owns the H12 gate). L = whoever owns this spec and can stay awake at every checkpoint. | Team | before H0 |
| B2 (Q3) | Primary demo Mac, hot spare, Docker Desktop versions | any two Macs | The two 64 GB machines, if any. Docker memory ≥ 8 GB and `make doctor` green on both. | L | H1 |
| B3 (Q10) | A second laptop on a LAN cable for the fence fallback and the guard lane | yes / no | Yes, the hot spare. | L | H1 |
| B4 (Q4) | Does every demo laptop have PG2 HF access, and are the ONNX exports on the USB sticks? | PG2-86M on the demo Macs / protectai-v2 only | protectai-v2 default + multilingual kNN; PG2-86M where present. The header shows the engine honestly (spec D09, R23). | C | H0 (pre-event) |
| B5 (Q7) | Is "ask = block with 'approval required'" acceptable at P0, with C23 at P1 #5? | accept / pull C23 into P0 | Accept. | L with D | H1 |
| B6 (Q13) | One shared admin token for the console at P0, with no per-user admin identity? | shared token / per-user admin | Shared token, with the banner "single admin token (demo)". | L | H1 |
| B7 (Q14) | Time zone for budget resets | UTC / Europe/Warsaw | UTC (vendor convention). Decide before the fixtures freeze at H1:30, because `resets_at` appears in the 429 body and in the fixtures. | C | H1 |
| B8 (Q15) | Did the OWASP MCP Top 10 October 2026 release renumber anything? | keep 2025 IDs / switch | Keep `MCPnn:2025`. All IDs live in `frameworks.yaml`, so a switch is a data edit (spec R20). | L | H0 |
| B9 | Repo setup | new repo / reuse this one; private / public | New `aicl` repo (Apache-2.0) at H0:30, private until C16 (spec §3.9). Depends on A4. | L | H0:30 |
| B10 | Does anyone have React/TypeScript experience? The console (D3) depends on one person shipping a React 19 + Vite + shadcn SPA (spec D19, risk R9) | React SPA as specified / server-rendered fallback | If yes: React SPA (D19). If nobody does: FastAPI + Jinja2 + HTMX (+ vendored Chart.js) served by `control`, same `/api` and SSE, CSS reused from `mockups/dashboard.html`; header + Threats + Playground first. Needs L's sign-off (it changes D19). | Team, L decides | before H0 |

---

## 4. C. Decide during the build at a checkpoint

Most defaults here are already written into the spec's checkpoint table (§13.4). This list adds the open technical checks and the decisions the spec leaves to a named time.

| ID | Decision | Trigger (checkpoint) | Owner | Default |
|---|---|---|---|---|
| ★ C1 | Does `host.docker.internal` (or `gateway.docker.internal`) reach host Ollama from the `internal: true` agents network? This is unverified on Docker Desktop (spec §3.4). | CF, H1: `fence-probe` on every demo Mac | L | Fallback ladder: (1) `extra_hosts` to 0.0.0.0 and `dns: [0.0.0.0]`, then re-probe; (2) agent-lane Ollama on the hot spare over a LAN cable; (3) drop the Ollama chokepoint claim, publish the probe output, add residual T5. Never claim more than the probe proves. |
| C2 | Classifier engine and window size | Latency, H2: one window of the default classifier > 150 ms p95 on the demo Mac | C | Switch the demo Macs to PG2-86M. If it is still slow, set `cascade.t2.window_tokens: 256` (spec §5.1). Only numbers from `reports/perf-h2.md` go on slides. |
| C3 (Q5) | Guard-lane model for P1 #2: the community Qwen3Guard-Gen-0.6B GGUF or `llama-guard3:1b`? Is there RAM for it on the demo Mac? | H2 spike result; `make doctor` memory check | C | `llama-guard3:1b` (official Ollama tag, FACT-CHECK A3). The lane stays off if RAM is tight (spec R15). |
| C4 | MCP edge: FastMCP 4.0.10 `create_proxy` + middleware, or a thin JSON-RPC proxy | D1, H2.5: `tools/call` forwarded to a sandbox HTTP server through our middleware | D | Thin JSON-RPC proxy. The middleware logic stays framework-free (spec §13.4, FACT-CHECK B2). |
| C5 | Does Ollama's OpenAI `/v1` stream send a usage chunk when `stream_options.include_usage` is set? Does Ollama stop generating when we close the connection? Both unverified (R4 §17, R7 §7). | The first real Ollama stream through the gateway (H2 latency session) | C with A | If there is no usage chunk, settle `ollama/*` output as `ceil(emitted_chars / 3)` and mark it approximate. Keep wall-clock compute and document the over-count as residual T15. |
| C6 (Q12) | Size and org shape of the seeded history | IC1, H5, before F wires the charts | F with L | 7 days, about 20k events, 3 departments, 6 teams, 12 users, 4 agents, all labelled synthetic (spec §9.5, R9 Q2). |
| C7 | What to do with IC2 items that are red | IC2, H8 | L (A, C, B fix) | Pre-decided: unstable streaming → `stream_mode: buffer`; guard won't load → stub plus "semantic tier degraded" shown; broken feed signing → sha-pinned unsigned bundle, said openly (spec §13.4). |
| C8 (Q1) | Brand: Mandate or another §1.1 candidate. Re-check that no AI-security product uses the name. | Placeholder (H8 in plan (a), H11 in plan (b)) | Team; L breaks ties | Mandate. The code namespace stays `aicl`, so a rename is a string replace in docs and UI. |
| C9 | Placeholder: real upload or dry run | H8 in plan (a), H11 in plan (b) | L | Real upload if A3 says edits are allowed, otherwise a checklist dry run. |
| ★ C10 | The H12 gate is red: detectors-off S4/S5, fence + admin isolation, or the cross-replica race | IC3, H12 (watch it from H11:30); plan (a): merged with IC4 at H10:30 | L | D + A + L swarm on C24/C33 until it is green. Every P1 item is frozen (spec §13.2, §13.4). |
| C11 (Q6) | OCSF export at P0 (J1) or at P1 #4 (J3)? Do we run the OCSF validator? | IC3, H12 | L with B | P1 #4. Labelled "OCSF-shaped" unless the validator passes (spec §2.5, FACT-CHECK C6). |
| C12 (Q8) | Who writes the ~100-prompt Polish slice (50 attacks, 50 benign banking prompts)? | IC3, H12 | L | C + D, at H12-H14. P1 #3 needs it. |
| C13 (Q11) | Who records the Claude Code managed-settings clip (P1 #10), and on which machine? First check the unverified client behaviours: plain-HTTP non-loopback `ANTHROPIC_BASE_URL`, `availableModels` with non-Claude IDs, and mid-stream `event: error` handling. | Start of P1 #10, by H14 | A | A records it on loopback (127.0.0.1) with Claude Code ≥ 2.1.285, relies on `/v1/models` filtering rather than `availableModels`, and uses `stream_mode: buffer` for the clip if mid-stream errors misbehave (R5 §10, R7 §7, FACT-CHECK B3). |
| C14 | A P0 control is still red | IC4, H15 | L | Flag it off in the demo policy and drop it from the slides. Apply the cut lines in spec §13.6 order, never the reverse. |
| C16 (Q9) | Repo visibility: public early, or at H20? | By H16 (plan (a): by H11) | L | Public at H20 (plan (a): H14), after `gitleaks detect` over the full history. While the repo is private, CI runs on smaller runners (R8 Q1), so time `make test` there as well. |
| C17 | Two stage questions with no rehearsed answer in the spec §12 crib: "What happens when someone leaves the bank?" (J2 Q6) and "Where does the audit log go when a pod is evicted?" (J2 Q10) | Before H16 (J3 §8: prepare answers before H16) | L (A for eviction) | Leaver: disabled at the IdP, the JWT expires, the virtual key is removed from the policy and enforced in < 2 s; directory sync is on the roadmap. Eviction: the writer fsyncs every 100 ms or 200 events, the chain ends at the last flushed seq, and checkpoints show where; in production each pod's chain goes through an OTel Collector → Kafka → SIEM, with checkpoints on WORM storage (spec §3.8, §9.2). |
| C18 | Does the mentor path work on x86? | IC5 clean room, H17:30 | L | Clean room on the hot-spare Mac, plus the raw `docker compose` test command on a GitHub Actions x86 Linux runner. Publish the cold time in the README (spec §10.1, J3 must-fix 4). |

The Q1-Q16 mapping is at the top of this file.

---

## 5. Already decided (do not reopen)

These were open questions in the research notes, `docs/00` or the judging memos. The spec has answered them.

| Question (where it was raised) | Decision | Spec § |
|---|---|---|
| Fork Squid, build on a vendor gateway, or write our own? Python or Go? (R2 Q1, R3 Q1, R5 Q4, R7 Q7) | Our own Python 3.12 / FastAPI gateway. No Squid fork, no LiteLLM/Portkey/agentgateway core, no Go data plane. | D02, §2.2-2.3 |
| Which framework IDs lead? (R1 Q1) | OWASP LLM 2026 (2025 in brackets), `MCPnn:2025`, ATLAS v2026.09. | D26 |
| Which agents run on stage? (R1 Q2, R3 Q2, R5 Q1, R6 Q1, R7 Q9, R8 Q5) | The scripted `support-bot` by default. Live `qwen3:8b` is P1 #12. Claude Code only as a recorded clip (P1 #10). No Open WebUI. | D30, §12 |
| Is A2A in scope? (R1 Q3, R6 Q5) | Thin agent→agent at P1 #14, the A2A proxy at P2, ASI07 shown as partial. | D29 |
| Real SSO/LDAP or a mock? Is LDAP visible? (R1 Q4, R2 Q5, R3 Q4, R5 Q3, R5 Q8) | Hashed virtual keys + JWT/JWKS static issuer with a `groups` claim. Keycloak/LDAP is a P2 profile and a slide. | D20 |
| Budget units, money vs compute, group semantics (R1 Q5, R3 Q7, R7 Q1-Q2) | Tokens + integer micro-USD (`sim/*` labelled simulated) + compute-ms (wall clock at P0). Scopes org → pool → seat → agent → run, and every scope must have room. | §7.1-7.2, D21 |
| Fail mode when a detector, Valkey or the audit sink is down (R1 Q6, R4 Q5, R7 Q3, R9 Q1) | Semantic detectors fail to taint. Valkey down: external models 503, local models capped at 10% of the seat. Audit down: strict 503, balanced drops L1 snippets and keeps L0. | D08, D43, §5.4 |
| What goes into our own logs (R1 Q7, R9 Q4) | L0 for allows, L1 post-redaction snippets for everything else, L2 for judges, L3 never. HMAC pseudonyms with the key outside the log store. | §9.1 |
| Signed feed, and how judges edit it (R1 Q8, R3 Q8) | External signed feed with an explicit `make feed-publish`, plus a tighten-only `policy/feeds/local.yaml`. | D17, §8.2-8.3 |
| Where taint lives; a shared run ID (R2 Q2, R6 Q2) | On both edges. Gateway-HMAC run tokens, minted by `POST /v1/runs` with a user credential. | D06, D07 |
| Default verdicts for tainted sinks (R6 Q3) | The §5.6 matrix. Untrusted and spoofed destinations are denied in every profile. | §5.6 |
| Semantic models, the Llama licence, Polish, the guard contract (R2 Q3-Q4, R3 Q3, R4 Q2-Q4) | protectai-v2 INT8 default (ungated), PG2-86M when present, multilingual MiniLM kNN always on, `llama-guard3:1b` for P1 #2, NOTICE file, no Llama Guard 4. Polish: PL exemplars and topic pack at P0, Polish eval slice at P1 #3. `POST /v1/inspect` with a 150 ms + 60 ms-per-window deadline. | D09, D10, §5.1, §10.5 |
| Artifact scanning scope (R2 Q6) | Scan API + `aicl scan`, allowlist-first and fail-closed. The HF mirror is P2. | C18, §3.6 |
| Console tech, Grafana, page count, brief scope (R3 Q5, R9 Q3, J2 must-fix 12, J3 must-fix 6, `docs/dashboard-design-brief.md`) | React 19 + Vite + shadcn + Recharts SPA served by `control`. No Grafana (AGPL). 4 P0 pages + header, with spend as an Overview panel. Toggles P1; role stripping, four-eyes, rehydration and My AI P2. | D19, §9.5, §11.6 |
| Vendor-gateway adapters (R3 Q6, R7 Q7) | None at P0. `/v1/decide` + `/v1/guard` + a Claude Code `PreToolUse` hook at P1 #15. | §2.4, §11.2 |
| TLS interception, TLS on the gateway, Squid lists, live Kubernetes (R5 Q2, Q6, Q10, R7 Q8) | No interception. Plain HTTP on 127.0.0.1 for the demo. Squid stays out of the P0 runtime (sensor at P2). No live cluster: kustomize + kubeconform at P1 #16. | §2.3, §3.7, §3.8, D35 |
| Where users see their budget (R5 Q7) | `GET /v1/me`, filtered `/v1/models`, the 429 body and `x-aicl-budget-remaining`. The My AI page is P2. | §7.6 |
| MCP protocol version (R5 Q9) | 2026-07-28 stateless; the legacy 2025-11-25 `initialize` is answered locally. | §3.6 |
| One policy file or several? Sandbox the MCP servers? (R6 Q4, Q6) | One `policy.yaml` + `local.yaml` + calibration files, pins in Valkey. MCP servers in no-egress containers over Streamable HTTP. | §6.1, D05 |
| Approval UX (R6 Q7) | At P0, `ask` blocks with "approval required". A console card with a single approver at P1 #5. Four-eyes at P2. | D27 |
| Stream mode, regex dialect, block response (R7 Q4-Q5, R8 Q2) | Trigger-aware hold (balanced), buffer (strict). RE2 only. Blocks are 200 `content_filter`, 429 `billing_error`, MCP `isError`, never a TCP reset. | D23, §3.9, §5.7 |
| MVP controls, budget store, harness owner, presets (R8 Q3-Q4, Q6, Q8) | 30 P0 controls; Valkey Lua; L owns one hermetic harness; 85/95/99% adherence via calibration, provisional at P0. | §4, §7.3, D18, §6.3-6.4 |
| garak in the pitch? (R8 Q7) | P2, not built. | §13.3 |
| Items the spec once called P1 without a rank: GGUF `chat_template` scan, cross-message `window` view and ROT13, SIG-0011 `tool_sequence`, Policy diff and Audit query pages, server-side role stripping, `models.*.fallback` (formerly C15 here) | P2 since spec v1.1 (changelog "Tiers made consistent", §13.3 P2 list). Catalogued in `docs/07-ideas-parking-lot.md`. | §13.3 |
| Are judges' live edits visible? (R8 Q9) | Labelled "unsigned local change", with a `control_weakened` finding. No per-person author at P0 (see B6). | §6.5-6.6 |
| Weekly report, chain layout, OCSF vs ECS, posture weights, mapping owner (R9 Q5-Q8, R1 Q9) | Weekly report P2. Per-replica chains + control-signed checkpoints. OCSF first (P1 #4), ECS/CEF/HEC P2. Weights from `contracts/frameworks.yaml`, which L owns (built from R1 §10). | D16, §9.3-9.6, §3.9 |
| Default classifier PG2-22M? (J2 must-fix 14) | Overruled: protectai-v2 by default, because the mentor path must work without gated weights. | D09 |
| Which ops drills run live? (J2 must-fix 10) | `docker compose stop guard` live. Killing `gw-1` and stopping Valkey are recordings. | D44 |
