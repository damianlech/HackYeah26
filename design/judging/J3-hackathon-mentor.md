# J3: Judging memo from a hackathon mentor

> **Who is judging.** An experienced hackathon mentor who has watched hundreds of 24-hour projects succeed or die. I care about:
> - whether six Python developers can actually build this in ~24 h;
> - whether the demo survives a live stage, bad Wi-Fi and a judge typing whatever they like;
> - whether the story fits in one sentence;
> - whether a phase-1 mentor can `git clone`, run the test suite and poke the system **without the team in the room**.
>
> I penalise over-scoping hard (the formula multiplies by feasibility) and reward ruthless prioritisation and visible "wow" moments.
>
> **Inputs.** All five full proposals in `design/proposals/` (P1-P5), the condensed research summaries (`research-summaries.md`), and `research/FACT-CHECK.md` (A2, A3, A4, A6, B2, B4) for claims that change what is buildable.
>
> **Formula (as instructed).** `weighted_total = (0.30·robustness + 0.20·architecture + 0.20·reporting + 0.15·testing + 0.15·practicality) × 10 × feasibility/10`. The criterion scores rate the **design as specified at P0 plus realistic P1**. Feasibility rates the odds that the P0 actually exists, works end to end and demos reliably by H21. Both are mentor judgment, not measurements.
>
> **Tone.** Blunt, as requested.

---

## 0. Bottom line

1. **On paper the ranking is P2 > P4 > P1 > P3 > P5. After feasibility it inverts to P5 > P1 > P4 > P3 > P2.** The two best designs (Warden, Mandate) are the two least likely to exist at H21. The least exciting design (Governor) is the only one whose P0 fits the team.
2. **All five proposals share the same ~85-person-hour core.** That core is a Python L7 gateway with streaming, a FastMCP proxy, Valkey reserve/settle budgets, RE2/Aho-Corasick detectors, an ONNX classifier, a signed feed, a pickle allowlist gate, a hash-chained audit log, mock-llm, demo MCP servers, a hermetic test suite and a 5-page console. With 3 h of sleep, meals and pitch prep, six people have about **95-100 build hours**. The core alone uses 85-90% of that. **Every proposal except P5 puts 25-50% more on top and still calls it P0.**
3. **P5 (Governor) has the best plan and the weakest product.** Its contracts at H1, walking skeleton at H5, checkpoint gates, offline mode, "the demo is a test" and placeholder submission at H11 are exactly what wins phase 1. But it pushes the headline security guarantee (C24 taint + provenance) and the forced chokepoint (C13 fence) to P1. Its thesis ("works when the Wi-Fi doesn't") is a delivery promise, not a reason for Goldman Sachs judges to remember us.
4. **The single best wow moment across all five comes from P2 and P4.** A judge switches off the AI detectors live, the model is fully hijacked by a poisoned ticket, and the exfiltration email is **still denied**, because the destination never came from the user. P2 makes it a hermetic test and the H12 gate. P4 makes it a positive allowlist minted from the user's own request. That one beat is worth more than P1's 16-incident museum, P3's Keycloak and P4's sparring service combined.
5. **The second-best wow is P1's live-edit loop.** A judge edits `policy.yaml`. The header shows "v17 applied in 0.4 s on 2/2 replicas", posture drops 91→79, the auto-run self-test marks ASI01 as GAP, and a broken regex is rejected with the YAML path while v16 stays active. P1, P4 and P5 all have a version of this. P1 specifies it best.
6. **Recommendation:** build **P5's chassis**. Promote exactly three things into P0: C24 taint + destination provenance (P4's positive allowlist, P2's ingress anchoring), the C13 internal-network fence with a bypass test, and 2 gateway replicas with the cross-replica race. Bolt on **P1's live-edit evidence loop and global header**. Pitch it with **P2/P4's "detectors are evidence, authority is the guarantee"** framing. Do **not** build P3's Keycloak/Squid/overlays, P4's sparring service, warrants or compiler emitters, P2's 36 controls and 10 pages, or P1's duplicate in-process test harness at P0.

---

## 1. Scoreboard

| Rank | Proposal | Robustness (30) | Architecture (20) | Reporting (20) | Testing (15) | Practicality (15) | Base (0-100) | Feasibility | **Weighted** |
|---|---|---|---|---|---|---|---|---|---|
| 1 | **P5 Governor** (delivery lead) | 7.0 | 6.5 | 7.5 | 9.0 | 7.0 | 73.0 | **6.5** | **47.5** |
| 2 | **P1 Proctor** (score maximiser) | 7.5 | 8.0 | 8.5 | 9.0 | 7.0 | 79.5 | 5.0 | **39.8** |
| 3 | **P4 Mandate** (contrarian) | 8.5 | 7.5 | 8.0 | 9.5 | 7.0 | 81.3 | 4.5 | **36.6** |
| 4 | **P3 Gatehouse** (enterprise steelman) | 6.5 | 8.0 | 8.5 | 8.0 | 9.0 | 78.0 | 4.0 | **31.2** |
| 5 | **P2 Warden** (security architect) | 9.0 | 7.5 | 8.5 | 9.5 | 6.0 | 82.3 | 3.5 | **28.8** |

How to read it:
- **Base scores are bunched (73-82). Feasibility is not (3.5-6.5).** That spread is the whole story.
- P5 has the lowest base and still wins by about 8 points, because a plan that ships beats a design that doesn't.
- The self-assessments in the proposals (7.65-8.4) are all base scores with feasibility 10. None of them priced in their own scope.

---

## 2. The capacity math (why feasibility dominates)

My estimates, AI-assisted focused hours, with integration and debugging overhead included. These are judgment, not measurements.

**Capacity.** 6 people × 24 h, minus 3 h sleep, about 2 h of meals and breaks, and 3-4 h at the end for video, slides, rehearsal and submission. That leaves about **16 build hours per person, so ~95-100 person-hours**. One of the six is the only UI builder, so ~16 of those hours can only go to the console.

**The common core every proposal needs (~80-90 h):**

| Block | h |
|---|---|
| OpenAI `/v1/chat/completions` proxy, SSE holdback, tool-call delta buffering, wire contracts | 8 |
| Policy engine: schema, watch + hash poll, RE2 compile, LKG, `policy_change` events | 4 |
| Deterministic detectors: C06, C07 checksums, C08, C09, C12, C17, C20 | 7 |
| Semantic sidecar: ONNX classifier, client, stub engine | 4 |
| Budgets: Valkey Lua reserve/settle, `/v1/me`, 429, limits, loop breaker | 6 |
| MCP proxy: FastMCP 4, list filtering, pins, description scan, result scan | 7 |
| Shared tool validators: path, SSRF, SQL, email, amount | 4 |
| Signed feed service + verifying client + embedded vectors | 5 |
| Artifact gate: pickle opcode allowlist, fixtures | 3 |
| Audit writer, hash chain, verify, CSV/JSONL export | 4 |
| mock-llm, 5 demo MCP servers, scripted agent | 7 |
| Case runner, meta-test, hermetic compose, ~150 cases (spread across owners) | 8 |
| Live policy-aware self-test, posture, coverage grid | 4 |
| Console: header + 5 pages + read API + SSE (one person) | 16 |
| README, JUDGES.md, slide content | 3 |

**What each proposal adds at P0 on top of that core:**

| Proposal | P0 extras beyond the core (approximate h) | Total vs capacity |
|---|---|---|
| **P5** | Walking-skeleton and storyline tests (2), `demo-offline` / doctor / warm / reset (3), placeholder submission (0.5). These are insurance, not features. ≈ **+6** | **~90-95%: tight but real** |
| **P1** | C24 taint + provenance (3), C13 fence + test (1.5), 2 replicas + nginx + cross-replica race (2), 16-incident Exploit Museum with replay UI (5), Attack Range "sent vs seen" diff (2), multilingual kNN (2), `/ollama/api/pull` guard (1), mutation run (1.5), **a second test harness** (`test-fast`, in-process with fakeredis + Lua, 3), multi-arch GHCR images with baked weights (2.5), console quick-toggle writes via ruamel (2.5), OCSF in P0 (1.5), MSW + 20k seeded events (2). ≈ **+30** | **~115-125%** |
| **P4** | Mandate store mint/narrow/revoke (4), call warrants bind/redeem (3), destination extraction (2), compat auto-mint (1.5), separate Authority service with IR over pub/sub (3), honeypot + revocation cascade (2), **sparring service** with 8 mutators + shadow run + ASR posture (7), detector-independence suite (1.5), mandate tree + sparring heatmap + compiled-diff pages (8), promote-to-case (1), CEL conditions (2). Drops 2 replicas, OCSF, C20, Spend and Audit pages to P1. ≈ **+33** | **~120-130%** |
| **P3** | Keycloak realm + device flow + `aictl` apiKeyHelper + JWKS (7), stock Squid + rendered lists + reconfigure loop + log ingest (4), tighten-only overlay lattice + provenance view (5), managed-settings renderer (2), Claude Code + Open WebUI containers (4), Presidio `pl`+`en` (2), Access matrix + explain + My AI pages (7), entitlement-matrix test generator (2), `/v1/messages` (3), 2 replicas (2), OCSF (1.5). **Taint is P1.** ≈ **+40** | **~125-135%** |
| **P2** | Run tokens + ingress anchoring + taint + provenance (5), multi-view normaliser with confusables, folds, decoders and window (4), obfuscation matrix with 10 mutators incl. Polish (3), MCP protocol hardening (2), admin-plane listener (1), 6 networks + sandbox containers via `mcp-proxy` bridges (3), **four-eyes approvals at P0** (4), `/v1/messages` (3), PG2-86M + Qwen3Guard spike (2), 2 replicas (2), `make eval` with a hand-written Polish corpus (3), **10 dashboard pages** for one person (+12). ≈ **+45-50** | **~140-150%** |

**Feasibility scores follow directly:** P5 6.5 (their own estimate: P0 70% by H12, 90% by H16), P1 5.0 (it has a "ship unfinished as monitor/GAP at H16" valve, which earns half a point), P4 4.5 (the novel parts are where the bugs live), P3 4.0 (identity and client plumbing on stage), P2 3.5 (36 controls plus 10 pages is not a 24 h project).

One more hard truth. **Even P5 is ambitious.** Its 22 P0 controls are each "a few hours", and few-hour estimates at 03:00 are optimistic by 50%. Every graft I recommend below has to be paid for by a cut.

---

## 3. Per-proposal assessment (in rank order)

### 3.1 P5 Governor: 47.5. The plan that ships, with the pitch that doesn't

**One line:** the best hackathon *execution* document I've seen in this panel, wrapped around a generic product.

**What is excellent (steal all of it):**
- **Contracts frozen at H1** (`contracts/`: policy schema, `aicl.audit/v1`, detector interface, OpenAPI + fixtures, block/error contract, header conventions), with CODEOWNERS and CI schema tests. It even catches the control-id collision in the example audit event (C09/C10/C20/C03 swapped against the R1 catalog). Nobody else noticed.
- **Walking skeleton green at H5** with a concrete 8-assertion test (`test_walking_skeleton.py`): key → allowlist → secret redaction → mock → Valkey settle → chained audit → console row → policy edit flips the verdict in < 2 s.
- **Checkpoint gates with pre-decided "if red" actions:** IC1 H5, D1 FastMCP go/no-go at H2.5, IC2 H8, placeholder submission H11, IC3 H12, freeze H16, clean-room offline run H17.5, submit H21. Fallbacks are written down: `stream_mode: buffer`, a thin JSON-RPC MCP proxy, a stub guard, an unsigned sha-pinned feed. This is what prevents the 04:00 argument.
- **`test_demo_storyline.py`: the pitch is a test**, run at every checkpoint and 10 minutes before stage. If a beat is red, it leaves the pitch. I wish every team did this.
- **Phase-1 mentor path:** `make doctor`, `make test` (hermetic, < 90 s), `make demo-offline` (no model at all), a raw `docker compose` command for Windows mentors without `make`, `extra_hosts: host-gateway` for Linux. This is the only proposal that seriously thought about a mentor on an x86 Windows laptop.
- **The UI owner also owns the read-side API.** That removes the classic "backend didn't give me the field" blocker.
- **CLAUDE.md as a delivery tool**: contracts are law, RE2 only, mutate JSON in place, no case no merge. Six AI assistants will drift without it.
- **Feature flags everywhere.** "Flag off, not code" after H18.

**What is weak:**
- **The headline guarantee is P1.** C24 taint + provenance is P1 rank 2, and C13 egress fence is P1 rank 9. Without them, the "model fooled, data didn't leave" moment rests on the C14 email-domain allowlist. That still blocks `audit@evil.test`, but it also blocks a legitimate external customer reply, so it is a blunt instrument and a sharp judge will see that.
- **Architecture is the weakest of the five.** One process, one replica at P0, no fence at P0, only two of the four edges at P0. "One process" is a delivery virtue, but it reads as "toy" to a platform judge unless 2 replicas + race are shown.
- **The thesis is a delivery story.** "The AI control layer that still works when the Wi-Fi doesn't" will not be remembered in the jury room. "Governor" is a generic name.
- **L is overloaded.** L owns contracts, harness, self-test, posture, storyline test, README, JUDGES, PDF, video and submission, and sleeps H7-H10 during IC2.
- **Fewest wow moments.** The demo beats are correct but flat until beat 5.

**Phase-1 runnability:** the best. One must-fix: default the guard to the ungated Apache-2.0 `protectai/deberta-v3-base-prompt-injection-v2`, not gated PG2-22M, so `make up` works for a mentor with no HF token (FACT-CHECK A4/A5).

**Why these scores:** robustness 7.0 (strong deterministic core, both-edge tool mediation, but taint and fence are P1 and the normaliser decodes base64 to depth 1 only). Architecture 6.5. Reporting 7.5 (5 pages + header is the right size; OCSF P1; no run/taint view). Testing 9.0. Practicality 7.0. **Feasibility 6.5.**

---

### 3.2 P1 Proctor: 39.8. The best judge-facing spec, about 25% too big

**One line:** P1 understands exactly how judges score. It then tries to earn every point at P0.

**What is excellent:**
- **The live-edit loop as product** (§1.4): the edit is validated, compiled, swapped atomically on 2/2 replicas, and auto-runs a ~60-case policy-aware canary self-test. The UI shows the posture delta, newly uncovered OWASP/ATLAS cells and GAP-vs-FAIL. Crucially, **posture reflects what the gateways actually loaded** (`/admin/state`), so an invalid edit shows "file v17 rejected, v16 active". That detail is what separates a real demo from a fake one.
- **The global header strip**: `policy v17 · sha · 2/2 replicas · applied 0.4 s ago · feed #43 · chain ✓ · self-test 58/60, 2 GAP · posture 79.4 ▼11.6`. It is the best-specified version across the five and should be copied verbatim.
- **C24 taint + provenance is P0**, and so are the C13 fence and 2 replicas. Those are the right promotions.
- **Exploit Museum**: each incident is a feed rule, a test case and a replay card. It is a great way to make "historical attack mitigation" tangible. Sixteen incidents is too many for P0; eight to ten is right.
- **Attack Range "what you sent vs what the model saw" diff** plus `Server-Timing` per tier. That answers "show me telemetry" in one second.
- **JUDGES.md "Try to break Proctor"** with a judge key, EN/PL prompts and expected outcomes. **mock-llm fallback** when Ollama is absent, with a visible "LLM: mock" badge.
- **Honest scoring.** It says "about 7.2 if only P0 ships". That is the most self-aware line in any proposal.

**What is weak:**
- **P0 is ~115-125% of capacity.** It has 24 controls, 2 replicas, a 16-incident museum UI, an Attack Range diff, multilingual kNN, mutation runs, GHCR multi-arch images and OCSF at P0. Its own hour estimates are 18-20 h per person with zero slack.
- **Two test harnesses.** `make test` (Docker) plus `make test-fast` (in-process, fakeredis + Lua) means the same cases have to behave the same in two runtimes. That is a 3-hour cost and a permanent flakiness tax. Pick one.
- **Two writers to `policy.yaml`.** Console quick toggles write with ruamel while a judge edits the same file in an editor. That is a race condition on the centrepiece demo.
- **"Demo zero" at H8 is late.** P5 gets an end-to-end proof at H5.
- **Provenance is not ingress-anchored.** It compares against "user text". A hijacked agent writes `role:user` messages too (P2 §2.7 explains the laundering hole). With our own demo agent this doesn't bite, but a security judge can ask.
- **Multi-arch GHCR images with baked ONNX weights** are great for phase 1 but cost 2-3 h of CI work, and the images must be public.

**Why these scores:** robustness 7.5, architecture 8.0, reporting 8.5, testing 9.0, practicality 7.0. **Feasibility 5.0.** The "unfinished controls ship as monitor/GAP at H16" rule is a genuine safety valve, and it is why this isn't 4.5.

---

### 3.3 P4 Mandate: 36.6. The best idea, packaged as three projects

**One line:** "Agents get mandates, not keys" is the most memorable sentence in the panel. Building the full machinery behind it in 24 h is not realistic.

**What is excellent:**
- **The framing.** A delegation-of-authority matrix for agents, with four-eyes co-sign. For Goldman Sachs judges this lands instantly. The four edges in the brief become four moments of one object's life (mint, spend, redeem, attenuate), which gives one audit chain answering "under whose authority?".
- **Trusted destinations as a positive allowlist** extracted only from the authenticated task text (emails, hosts, IBANs). Tool output can never add one. This closes the paraphrase weakness of substring provenance ("evil dot test" gains nothing). It is the strongest version of C24 in the panel, and it is cheap.
- **Detector-independence as a measured number and a test** (`policy/test-detectors-off.yaml`, 12 cases). "Detection is evidence. Authority is the guarantee."
- **Honeypot → revoke the whole tree.** Cheap, memorable, near-zero false positives.
- **"Weaken the authority, get caught":** the judge sets `mail_send_email.to: any`, and seconds later the re-attack shows "S4 EXPOSED since v19". That is a superb beat.
- **Promote-to-case** from the Playground, so a judge's successful bypass becomes a regression test.
- **The seven-framings table** (§1.2) is honest analysis. It shows why F0 "smart gateway" scores ~7.0 and what moves the 30% criterion.

**What is weak:**
- **Three pillars at P0** (authority, compiler, twin) plus seven services (authority, gateway, mcp-proxy, guard, intel, sparring, console) and IR distribution over Valkey pub/sub. Hot reload now crosses a service boundary, which adds a failure mode to the centrepiece demo.
- **Internal inconsistencies.** The P0 Policy page shows a "compiled-target diff" and P0 `make test` includes "compiler golden files (managed-settings.json, squid ACL, NetworkPolicy)", but the emitters are P1. Spend & Budgets and Audit & Export pages are P1, yet the brief explicitly asks for cost/resource metrics and exportable audit logs in the dashboard. Overview tiles and a Threats export button only half-cover that.
- **Call-warrant binding** hashes `JCS(args)` from the model's JSON string and compares it with the MCP client's re-serialised call. Number types, floats, defaulted fields and whitespace in string values all drift, which means false denials on stage. The `direct` fallback exists, but then the novel property is gone.
- **Posture defined as measured attack-success rate from sparring** means the headline number is only as fresh as the last sparring run, and sparring is the newest code in the system.
- **Conceptual load for phase-1 mentors** reading a repo cold: mandate, warrant, narrow, attenuate, sparring, compile target. Four new nouns before they reach `make test`.
- 2 replicas are P1, so the scale proof is weaker than P1's.

**Why these scores:** robustness 8.5, architecture 7.5, reporting 8.0, testing 9.5, practicality 7.0. **Feasibility 4.5.**

---

### 3.4 P3 Gatehouse: 31.2. The right operating model, invested in the wrong 15%

**One line:** this is what a bank platform team would ship in a quarter. In 24 h it spends the guardrail budget on identity plumbing.

**What is excellent:**
- **It respects the team's original idea.** The "what survives of the Squid plan" table (§2) is the best way to tell six people their idea was half right without losing them. Use it as a slide.
- **Explicit fail-mode table** (§11.1): Valkey down means external fails closed and local fails open with a capped budget; guard down means taint; a stale feed is never unloaded; replica sha divergence alerts. Plus a live drill (`docker kill gw-1`, `docker stop valkey`).
- **Error messages that explain themselves.** The 400 for an ungranted model carries a request-access link. It copies the vendor contract (429 `billing_error`, `x-should-retry: false`).
- **Entitlement-matrix tests generated from the policy** (role × model × tool). That gives many meaningful cases for little effort.
- **Competitive table vs the Claude apps gateway** (FACT-CHECK B4: OIDC only, fail-open by default, Postgres). It is the answer to "isn't this just X?".
- **Replica-sha consistency** in the header.

**What is weak:**
- **Robustness, the 30% criterion, is under-invested, and P3 admits it.** C24 taint and provenance are P1. PG2-22M is English-only. The agentic demo beat shows quarantine, not a "hijacked yet blocked" guarantee.
- **Keycloak device flow + `aictl` + Claude Code statusLine on stage.** Token expiry, login state and Claude Code's huge system prompt against a local 8B model (R4/R5: minutes per turn on CPU, still slow on Metal) make beats 2 and 4 fragile. Identity alone is ~7 person-hours, and P3 itself says ~1.5 person-days go to operating-model features.
- **Stock Squid at P0** is a GPL run-only container, a reconfigure loop and log ingestion, for a fence the internal Docker network already provides. It earns little in the rubric.
- **Open WebUI as a core demo client** comes with a custom licence with a branding clause (R3), another container and more RAM next to Keycloak and two Ollama instances.
- **Nine P0 console pages** (incl. Access matrix, Explain access, My AI portal) for one person.
- **A five-persona cast plus a live ops drill** in 7 minutes is too much choreography.

**Why these scores:** robustness 6.5, architecture 8.0, reporting 8.5, testing 8.0, practicality 9.0 (the best in the panel). **Feasibility 4.0.**

---

### 3.5 P2 Warden: 28.8. The best security design, and the clearest case of over-scoping

**One line:** if I were a CISO, I'd hire this author. As a mentor, I'd stop this plan at H0.

**What is excellent (and must survive into the final design):**
- **The classifier-off hijack test as the H12 gate.** "S4 with C10 and C16 disabled must still be blocked by C24/C33 in `make test`". This is the single best engineering gate in the panel, because it forces the guarantee to exist before anything cosmetic.
- **Ingress-anchored trusted text.** Text is trusted by the credential that delivered it, never by its `role` field. A sticky per-principal run means dropping the run header doesn't reset taint.
- **Fail-to-taint** as the default failure posture for semantic detectors: an outage tightens the downstream sink rules instead of failing open or killing traffic.
- **Config-tamper semantics** (§2.9). Typo keys are rejected (`additionalProperties: false`). **Controls are opt-out** (deleting one shows red "removed"). **Permissions are opt-in** (deleting `models:` blocks everything, never opens everything). Hard floors live in code. This is the most judge-proof policy design in the panel.
- **Multi-view normaliser**: decode Unicode tags to *read* the hidden instruction rather than only strip it, a confusable skeleton for homoglyph destination spoofs, Polish diacritic folding. Plus an **obfuscation matrix** over negative cases.
- **Residual-risk register** (15 items) as the closing slide. Security judges reward honesty.

**What is weak:**
- **Scope.** 36 controls including 4 new ones (C33-C36), approvals with four-eyes at P0, the Anthropic edge at P0, protocol hardening, 6 compose networks with sandbox containers behind stdio→HTTP bridges, and **10 dashboard pages for one person**. The author's own risk table lists scope as High/High.
- **Gated and community models in the default path.** PG2-86M is gated on HF. Qwen3Guard has only a community GGUF (FACT-CHECK A3). A phase-1 mentor without HF approval cannot reproduce `make up`.
- **Holdback k=128** means ~0.6 s to first visible token, which is visible on stage (R7).
- **Six networks on Docker Desktop for Mac** multiply the unverified `internal: true` vs `host.docker.internal` behaviour. P2 flags this itself as "Critical".

**Why these scores:** robustness 9.0 (the best), architecture 7.5, reporting 8.5, testing 9.5 (the best, alongside P4), practicality 6.0. **Feasibility 3.5.**

---

## 4. Fatal flaws (if shipped as written)

| Proposal | Fatal or near-fatal flaw |
|---|---|
| **P5** | (1) The headline guarantee (C24 taint + provenance) and the forced chokepoint (C13 fence) are P1, so the robustness story at P0 is "a better filter plus an email allowlist". (2) The thesis is a delivery promise ("works offline"), not a product idea, so the phase-2 pitch has no memorable hook. (3) There is no scale proof at P0: one process, one replica. |
| **P1** | (1) P0 is ~115-125% of capacity, and its self-estimates leave zero slack. (2) Two test harnesses (Docker + in-process fakeredis-Lua) must agree. (3) Two writers to `policy.yaml` (console ruamel writes and the judge's editor) during the centrepiece demo. (4) The first end-to-end proof is at H8. |
| **P4** | (1) Three pillars plus seven services at P0. Hot reload crosses the Authority→PEP pub/sub boundary. (2) Bound-mode warrant hashing will false-deny on argument re-serialisation. (3) P0 promises compiled-target diffs and golden files for emitters that are P1. (4) The Spend and Audit pages are P1 although the brief requires cost metrics and exportable audit in the dashboard. (5) The headline posture depends on the newest service (sparring). |
| **P3** | (1) The 30% criterion is under-funded: taint is P1, and the semantic tier is English-only. (2) Live Keycloak device flow + Claude Code against local models + Open WebUI on stage: three fragile clients. (3) Nine console pages for one person. (4) Open WebUI branding-clause licence and lldap GPL-3.0 in the demo stack need explaining. |
| **P2** | (1) 36 controls, 10 pages and 6 networks cannot land in 24 h. The H12 gate will slip, and by its own estimate robustness and reporting then drop ~1 point each. (2) Gated PG2-86M and a community Qwen3Guard GGUF in the default path break phase-1 reproducibility. (3) Approvals with four-eyes at P0 is a whole feature consumed before the core is green. |
| **All** | **The Docker Desktop fence is unverified** (P3 §3.2 is the only one that says so explicitly). If `host.docker.internal` is reachable from an `internal: true` network on the demo Macs, agents can bypass the gateway to unauthenticated Ollama. That breaks the C13 claim and the "forced chokepoint" story. It must be probed at H1 on every demo laptop, with the socat-bridge / shared-secret fallback ready (P3 §15 #2). |

---

## 5. Ideas to graft (tagged by source)

**Delivery chassis (take as-is):**
1. **[P5]** Contracts frozen at H1 in `contracts/`, with CODEOWNERS, CI schema validation of every fixture, event and policy, and R1 control ids only.
2. **[P5]** Walking skeleton green at H5, defined by an executable 8-assertion test.
3. **[P5]** Checkpoint gates (IC1 H5, FastMCP go/no-go H2.5, IC2 H8, placeholder H11, IC3 H12, freeze H16, clean room H17.5, submit H21) with the "if red → decision" table written in advance.
4. **[P5]** `test_demo_storyline.py`: the pitch as a test, run 10 minutes before stage.
5. **[P5]** `make doctor`, `make warm`, `make reset-demo`, an offline/mock mode, and a raw `docker compose` command for mentors without `make`.
6. **[P5]** CLAUDE.md rules for AI assistants; "no case, no merge"; every feature behind a policy flag; unknown feed rule types are skipped, never fatal.
7. **[P5]** The UI owner owns the read-side API; fixtures from H1:30; SSE with a polling fallback; page cut order.
8. **[P1/P2]** A red-team swap at H14-H16: pairs attack each other's controls, and every bypass becomes a test case or a residual-risk entry.

**The headline guarantee:**
9. **[P2]** "Classifier-off hijack" as a hermetic test and the **H12 gate**: S4 with C09/C10/C16 disabled must still be denied.
10. **[P4]** Trusted destinations as a **positive allowlist** minted from the authenticated task text plus policy allowlists. Tool output never adds a destination.
11. **[P2]** **Ingress-anchored** trusted text via `POST /v1/runs` (user credential), plus a sticky per-principal run when the header is missing or forged.
12. **[P2]** Fail-to-taint (`on_error: taint`) as a third failure posture next to open and closed.
13. **[P4]** Honeypot tool → kill the run/agent (C31 + C26). About 1 h, very memorable.
14. **[P4]** The pitch line "Agents get mandates, not keys" / delegation-of-authority analogy, used as **framing** for C24 + per-run budget envelopes **without** building warrants, delegation or the Authority service.

**The judge-facing evidence loop:**
15. **[P1]** The global header strip, specified exactly as in P1 §6.2 (policy version, sha, replicas, applied-ago, feed serial, chain, self-test, posture delta) plus toasts on every `policy_change`.
16. **[P1]** Auto-run of the policy-aware canary self-test after every reload. GAP (amber) vs FAIL (red). Posture and grid are computed from **what the gateways actually loaded**, not the file on disk.
17. **[P4]** "Weaken the authority, get caught": after `mail_send_email.to: any`, the auto self-test shows "S4 EXPOSED since v19". Implement it as a canary case in the existing runner, **not** as a sparring service.
18. **[P1]** Attack Range / Playground with a "what you sent vs what the model saw" diff and per-tier `Server-Timing`.
19. **[P1]** Exploit Museum trimmed to **8-10** incidents. Each one is a feed rule plus a test case plus one card; "Replay all" is P1.
20. **[P4]** Promote-to-case from a Threats or Playground event into `tests/cases/promoted.yaml`.
21. **[P4]** A measured column next to configured posture: attack-success rate per OWASP item from the same self-test run.
22. **[P2]** The residual-risk register as the last slide.

**Policy robustness against judges:**
23. **[P2]** `additionalProperties: false` / pydantic `extra="forbid"` (typo keys rejected); controls opt-out; permissions opt-in; hard floors in code.
24. **[P1/P2/P5]** RE2-only patterns, compile-then-swap, LKG, watch the directory plus 1 s sha polling (Docker Desktop bind mounts drop events).
25. **[P2]** Decode Unicode tag characters into a readable view, so the trace shows the hidden instruction, plus a confusable skeleton check on destinations.
26. **[P2]** Obfuscation mutators applied to NEG cases: a **subset** of base64, zero-width, Unicode tags, homoglyph and pre-translated Polish.

**Operability and practicality (cheap versions):**
27. **[P3]** The "what survives of the Squid plan" table as a slide, to keep the team's idea visible.
28. **[P3]** The fail-mode table, plus one safe live drill: `docker compose stop guard` → DEGRADED banner and taint posture. Don't kill Valkey on stage.
29. **[P3]** Error contract with explanations: 400 + request-access link; 429 `billing_error` + `x-should-retry: false` + `retry-after`.
30. **[P3]** Entitlement-matrix tests generated from the policy.
31. **[P3]** Replica-sha consistency in the header ("2/2 same sha").
32. **[P3/P1]** A **static** managed-settings bundle in `examples/` (Claude Code `managed-settings.json` + `managed-mcp.json`), shown in a recorded clip, never live on stage.
33. **[P1]** One unified spend number: local compute converted at `compute_usd_per_hour`, caps still expressible in compute-seconds, priced mock commercial aliases **labelled simulated**.
34. **[P3]** The competitive table vs the Claude apps gateway, Microsoft AGT and LiteLLM, for Q&A.

---

## 6. What the final design MUST fix

1. **P0 must fit in ~85% of capacity (≤ ~85 person-hours).** Start from P5's P0 list. Promote exactly: C24 taint + positive-allowlist provenance via `/v1/runs`, the C13 internal-network fence + bypass test, 2 gateway replicas + cross-replica race, and the C31 honeypot → kill switch. Pay for them by merging pages and trimming the museum, not by "working harder". Everything else is ranked P1 behind flags.
2. **One headline wow, made a hermetic test and the H12 gate:** "detectors off, model hijacked, exfil still denied". All other beats support it.
3. **Verify the Docker Desktop fence at H1** on every demo Mac (`internal: true` vs `host.docker.internal`, unauthenticated Ollama). Have the socat-bridge fallback ready. If it can't be proven, don't claim it.
4. **The phase-1 path must work on a mentor's x86/Linux/Windows laptop with no Ollama, no HF token and no internet after pull.**
   - Make the ungated Apache-2.0 `protectai/deberta-v3-base-prompt-injection-v2` ONNX the default; PG2 is an optional plugin.
   - mock-llm fallback with a visible badge; stub guard in `make test`.
   - Measure and publish the **cold** `make test` time (build included) on a clean machine.
   - Repo public before phase 1.
5. **One test harness** (hermetic Docker compose). Policy-mutating tests run serially. No second in-process runtime.
6. **Five P0 console pages + header, maximum:** Overview (posture, coverage grid, spend tiles + burn-down), Threats (trace drawer, export, Verify chain), Controls & Policy (Run self-test, history, rejected edits), Playground/Attack Range, and a Runs/taint-chain view **or** Spend page. Cost/resource metrics and exportable audit logs are explicit brief requirements and must be P0.
7. **A single writer for policy.** The file is the source of truth. Console toggles (if any) go through the same validator and an atomic rename that the watcher picks up. The UI always shows the *loaded* version.
8. **Strictness and adherence must be in the sample policy at P0**, because the brief demands "documented sample policy file with configurable strictness/adherence levels". Ship profiles mapping to thresholds at P0, document what "adherence %" means, and add calibration (`make eval`) at P1.
9. **Block/error wire contract fixed at H1**: 200 `content_filter`; 429 `billing_error` + `x-should-retry: false`; 400 `model_not_allowed`; MCP `isError`; never a TCP reset. Tests assert on headers and audit events, never on model prose.
10. **Naming hygiene:** R1 control ids only; OWASP LLM **2026** ids (2025 in brackets); "simulated commercial pricing", "OCSF-shaped", "tamper-evident", "supports evidence for". No Polish-detection claims without a measured slice.
11. **Four edges, honestly.** agent→LLM and agent→MCP deep. app→agent = `POST /v1/runs` (needed anyway for ingress anchoring). agent→agent = thin at P1 (agent-as-MCP-tool), with ASI07 shown as partial. Don't promise an A2A proxy.
12. **Keep the team's original idea visible:** group → allowed models and budgets, `/v1/me` "my limits" (one small panel, not a portal), forced chokepoint via the fence, the Squid-survival slide. Keycloak/LDAP is a slide plus an OIDC `groups` field in the schema.
13. **Scripted agent is the default for every agentic beat**; the live Ollama agent is a bonus. Ollama runs natively (FACT-CHECK A6). P0 compute-ms comes from wall-clock (FACT-CHECK A2).
14. **Name, tagline and placeholder submission by H11.** Final submission at H21. The demo laptop runs a tag, never `main`.
15. **Pre-event checklist executed, not planned:** models pulled, ONNX exported, wheelhouse, image tarballs on USB, HF gated access requested, Wi-Fi-off rehearsal.

---

## 7. What I would actually build (mentor's cut)

**P0 (≈ 80-85 person-hours):** P5's P0 list, plus:

| Addition | Owner (P5 lanes) | h | Paid for by |
|---|---|---|---|
| `POST /v1/runs` ingress anchoring + trusted-destination extraction (emails, hosts, IBAN mod-97) | A | 1.5 | Spend page merged into Overview (F −2 h) |
| C24 taint labels + Rule of Two + positive-allowlist provenance, both edges | D | 3 | Museum trimmed to 8 cards, no replay UI (−2 h); C17 as feed regex pack only, no shlex parser (−1 h) |
| C13 `internal: true` agents network + bypass test (probe at H1) | L | 1.5 | `demo-offline` = env flag, not a third compose file (−1 h) |
| 2 replicas behind Caddy/nginx + cross-replica race | A | 1.5 | OCSF stays P1 (as in P5) |
| C31 honeypot → C26 kill | D | 1 | — |
| Detector-independence test (detectors-off overlay) = H12 gate | L | 1 | — |

**P1, ranked:** `make bench` → `reports/perf.md`; Exploit Museum "Replay all"; mutation kill rate; C23 approvals (retry-token); OCSF 1.9 export; multilingual kNN + Polish exemplars; `make eval` + adherence calibration; `/v1/messages` + managed-settings clip; thin agent→agent; Keycloak only if everything is green.

**7-minute storyline (one hook, every beat in `test_demo_storyline.py`):**
1. **0:00 Hook (30 s).** 175k exposed Ollama hosts and SR 26-2 excluding agentic AI. "Your agents have keys. We give them mandates." One architecture slide.
2. **0:30 The team's idea delivered (40 s).** Intern requests the simulated `gpt-4.1` → 400 with an explanation; `/v1/me` shows the remaining budget; then a 429 `billing_error` with no retry.
3. **1:10 Deterministic in 3 ms (40 s).** PESEL + IBAN + AWS example key redacted; trace drawer; `Server-Timing`.
4. **1:50 The hijack (90 s, the hook).** Ticket 42 hides a Unicode-tag instruction; the decoded view shows it; the run is tainted and the email to `audit@evil.test` is denied. **A judge disables C09/C10/C16 in `policy.yaml`.** The header shows v18 on 2/2 replicas and posture drops with ASI01 amber. Rerun: the model is fully hijacked, and the email is **still denied**, because the destination never came from the user.
5. **3:20 Weaken it, get caught (40 s).** `mail_send_email` provenance set to `monitor` → self-test shows "S4 EXPOSED since v19". Revert. A typo key and a ReDoS regex are both rejected, and LKG stays.
6. **4:00 Historical exploits (60 s).** Signed feed serial 43 is live in < 5 s; a one-byte tamper is rejected; the pickle `posix.system` is blocked and never loaded; a truncated pickle fails closed; the rug pull is quarantined with a diff; the honeypot kills the agent.
7. **5:00 Evidence (60 s).** Audit tamper → Verify names the seq; CSV export; Run self-test → 150+ cases with a GAP shown; race "200 fired, 50 admitted, 0% overshoot".
8. **6:00 Adoption and scale (40 s).** One `base_url`, one MCP URL, managed-settings clip, stateless replicas + Valkey, kustomize validated, all permissive licences, fully offline. Residual-risk slide.

---

## 8. Questions you will get (prepare answers before H16)

| Question (phase-1 mentor or phase-2 judge) | Who answers it best today |
|---|---|
| "I ran `make up` with no Ollama and no HF token. What should I see?" | P5 (offline mode), P1 (mock badge) |
| "I turned off your classifier. Why is the exfil still blocked?" | P2, P4 |
| "I wrote `enabeld: false`. Did I just disable PII?" | P2 (schema rejects it) |
| "I deleted the `models:` section. Is everything allowed now?" | P2 (permissions opt-in) |
| "Show me per-stage latency for this exact request." | P1 (`Server-Timing` + Attack Range) |
| "How do you know your tests actually exercise each control?" | P1/P4 (mutation kill rate), P5 (meta-test) |
| "What if the threat-intel server serves an old bundle?" | all (serial anti-rollback); rehearse it |
| "How is this different from the Claude apps gateway / LiteLLM?" | P3 (§12 table) |
| "Two gateways, one budget: prove no overshoot." | P1, P2, P3 (cross-replica race) |
| "What does your system *not* stop?" | P2 (residual register) |

---

## 9. Verdict

**Winner on the formula: P5 Governor (47.5), but it is not the final design.** It is the only plan whose P0 fits six people in 24 hours, and its delivery machinery is what wins phase 1. Its product story is the weakest, and its robustness guarantee sits in P1.

**The final design should be P5's chassis carrying P2/P4's guarantee and P1's evidence loop.** Concretely:
- contracts at H1, skeleton at H5, gates, offline mode, and the storyline as a test (P5);
- "detectors off, hijacked model, exfil still denied" as the H12 gate and the pitch hook, using P4's positive-allowlist destinations, P2's ingress anchoring and fail-to-taint, and P4's "mandates, not keys" line;
- P1's global header, auto self-test after each edit, GAP-vs-FAIL, "file rejected, LKG active" and a trimmed Exploit Museum;
- P2's strict schema and opt-in permissions;
- P3's error contract, fail-mode table and "what survived of the Squid plan" slide.

Budget the grafts at **≤ 10 person-hours, paid for by explicit cuts**. If a graft can't name what it replaces, it's P1.

**Do not build at P0:**
- P3's Keycloak, Squid, overlays or portal;
- P4's Authority service, call warrants, sparring service or compiler emitters;
- P2's 36 controls, 10 pages or six-network sandbox;
- P1's second test harness or 16-card museum UI.

All of these are good ideas. None of them is worth missing H12 for.
