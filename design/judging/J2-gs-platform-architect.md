# J2: Judging memo from a Goldman Sachs platform and infrastructure architect

> **Who is judging.** A platform and infrastructure architect on the jury. I weight **architecture and performance efficiency (20%)** and **practical implementability and scalability (15%)** most heavily. I look at:
> - latency overhead and streaming correctness;
> - fail modes and statelessness;
> - horizontal scale on Kubernetes;
> - zero-code integration;
> - SSO/LDAP integration;
> - policy change management and operability;
> - whether the design could run at a large bank.
>
> I still score all five official criteria.
>
> **Inputs.** I read the five full proposals in `design/proposals/` (P1-P5), the condensed research summaries, and `research/FACT-CHECK.md`, R5, R6 and R7 for the load-bearing infrastructure claims.
>
> **Formula (as instructed).** `weighted_total = (0.30·robustness + 0.20·architecture + 0.20·reporting + 0.15·testing + 0.15·practicality) × 10 × feasibility/10`.
>
> **Tone.** Blunt, as requested.

---

## 0. Bottom line

1. **On design quality alone, P1-P4 are a statistical tie.** Their unmultiplied base scores are 7.85 to 7.95. P5 is clearly last on architecture (7.05). All four "big" designs converge on the same core:
   - a Python L7 gateway;
   - FastMCP proxy middleware;
   - Valkey Lua reserve/settle;
   - RE2 + Aho-Corasick;
   - a signed feed;
   - a JCS hash-chained audit log;
   - a hermetic `make test`.

   What separates them is **what they bolt onto that core** and **whether six people can actually ship it in 24 h**.
2. **Feasibility decides the ranking, and only P5 has a credible delivery plan.** It is the only proposal with:
   - hour-level work packages and dependencies;
   - integration gates (H1 / H5 / H8 / H12);
   - a ranked P1 list behind flags;
   - a clean-room offline run;
   - the demo storyline as an automated test.

   The other four are scoped as if each person had 30+ hours.
3. **P5 is also the proposal I would least like to see in production as written.** It is:
   - a single-process monolith in which the data plane, admin API, DuckDB report API, SSE hub, self-test runner and MCP proxy with stdio children all share one event loop and one container;
   - exposing admin routes on the port agents use;
   - running with no egress fence at P0;
   - running one replica at P0.

   Every one of these is cheap to fix and must be fixed.
4. **Recommendation:** use P5's execution plan as the backbone, then graft on:
   - **P3's** data/control-plane split, fail-mode table, identity path and change-management story;
   - **P2's** trust zones, admin-plane separation, gateway-signed run tokens, sandboxed MCP servers and fail-to-taint;
   - **P4's** `/v1/decide` PDP API and detector-independence metric;
   - **P1's** global header strip and Attack Range.

   Move taint + provenance and the fence to P0. Cut Keycloak-as-P0, Squid, the overlay lattice, A2A and a "sparring as a separate service".

---

## 1. Scoreboard

| Proposal | Robustness (30) | Architecture (20) | Reporting (20) | Testing (15) | Practicality (15) | Base (CRITERIA) | Base (RULES) | Feasibility | **Weighted total** |
|---|---|---|---|---|---|---|---|---|---|
| **P5 Governor** | 7.0 | 6.0 | 7.5 | 8.5 | 6.5 | 7.05 | 7.15 | **8.0** | **56.4** |
| P3 Gatehouse | 7.0 | **8.0** | 8.5 | 8.0 | **9.0** | **7.95** | 7.90 | 5.5 | 43.7 |
| P4 Mandate | 8.0 | 7.5 | 8.0 | 9.0 | 7.0 | 7.90 | 8.00 | 5.5 | 43.5 |
| P1 Proctor | 7.5 | 7.5 | 8.5 | 9.0 | 7.0 | 7.85 | 7.95 | 5.5 | 43.2 |
| P2 Warden | **8.5** | 7.0 | 8.0 | 9.0 | 6.5 | 7.88 | 8.00 | 5.0 | 39.4 |

**Ranking: P5 > P3 ≈ P4 ≈ P1 > P2.** The 0.5-point spread between P3, P4 and P1 is noise. If I drop the feasibility multiplier, the order is P3 > P4 > P2 > P1 >> P5. That inversion is the whole story of this panel: **the best architectures are the least deliverable, and the most deliverable architecture is the weakest.**

The self-assessments are uniformly inflated by about 0.5-1.0 on architecture and practicality. Every proposal scores itself as if its P1 list ships.

---

## 2. Cross-cutting findings (apply to every proposal)

These are the questions I will ask on stage. Most proposals get some of them wrong.

| # | Topic | Finding | Who gets it right / wrong |
|---|---|---|---|
| X1 | **Python data plane** | Acceptable. RE2 + Aho-Corasick deterministic tiers measured at ≤ 5 ms, Valkey Lua at 0.30 ms, and Go only ~1.5× cheaper (R7). The real cost centre is the CPU classifier, not Python. Say this with numbers from `make bench` on an M-series Mac, not from R4/R7 sandbox numbers. | All say "re-measure"; only P3 commits to an SLO table |
| X2 | **Classifier latency** | PG2-22M-class INT8 ≈ 40 ms @ 200 tokens; mDeBERTa-base (PG2-86M class) ≈ 75 ms; ProtectAI deberta-v3-base ≈ 104 ms on m5.xlarge ONNX (R4 summary). Tool results are long (web pages), so a 512-token window means **multiple inferences per result**. Nobody budgets chunking for long tool results. | **P1** quotes 15-40 ms for deberta-v3-base (optimistic by ~2-3×). **P2** pays for PG2-86M + multi-view. **P3/P4/P5** use PG2-22M (English-centric) |
| X3 | **Local compute accounting** | FACT-CHECK A2: Ollama `*_duration` fields exist **only on native `/api/chat` and `/api/generate`**, not on the OpenAI `/v1` or Anthropic `/v1/messages` paths these gateways proxy. | **P4, P5 correct** (wall-clock P0, native when available). **P1, P2, P3 wrong**: their compute-ms budgets would silently read zero or garbage |
| X4 | **`Server-Timing` on streams** | Headers go out before the first byte, so `upstream;dur=412` cannot be in the header of a streamed response. Only pre-flight stages can. Upstream and stream timings belong in the audit event and a trailing SSE comment. | P1, P4 and P5 show upstream in the header; R7 states the constraint |
| X5 | **Holdback** | k=128 costs about 0.6 s time-to-first-visible-token on every stream; k=64 costs about 0.2 s (R7). Holding back only while a link/image token is unterminated is strictly better. | **P5** trigger-aware holdback (best). P2/P3 k=128 (worst UX). P5 also has a `stream_mode: buffer` fallback |
| X6 | **Admin-plane exposure** | A hijacked agent that can reach `PATCH /api/controls`, approvals or policy endpoints defeats every other control (ASI09, confused deputy). | **P2** separate listener + admin network (but inside each data-plane replica, see P2). **P3** admin network. **P1** routes `/api` to the console through the same nginx the agents can reach, with no stated auth. **P5** serves `/admin` and `/api` on the gateway's agent-facing `:8080` |
| X7 | **Run identity** | Taint, loop breakers, run budgets and provenance are all keyed by run id. If the client asserts the run id, a hijacked agent drops or rotates the header and starts clean. | **P2** gateway-HMAC run tokens minted only by a user credential, with a sticky per-principal fallback (correct). **P4** HMAC mandate ids + sticky compat mandate (correct). **P1, P3, P5** client-supplied or gateway-minted-on-absence (escapable) |
| X8 | **Provenance anchoring** | "User text" taken from `role:user` messages is agent-controlled and can be laundered. Anchor it to the credential that delivered it. | **P2** (explicit), **P4** (mint from task text). Others are unspecified |
| X9 | **MCP server placement** | Spawning stdio servers, including deliberately malicious demo servers, *inside the enforcement container* puts attacker code next to HMAC keys, Valkey credentials and upstream credentials. It also gives every replica its own child processes. | **P2** separate no-egress sandbox containers (correct). **P1/P3** separate container (fine). **P4** MCP PEP spawns stdio (`facts` and `vault` honeypot inside the PEP). **P5** gateway process spawns stdio, including the malicious `facts` |
| X10 | **Fence on macOS Docker Desktop** | Whether `host.docker.internal` resolves and routes from an `internal: true` network is **unverified**, and Ollama has no auth. If it leaks, agents bypass every budget and allowlist. | **P2/P3** probe at H1 with a socat-bridge fallback (correct). **P1** asserts it works. **P5** pushes the fence to P1 rank 9 |
| X11 | **Policy propagation across replicas** | Each replica must report the sha it *actually* loaded, and the console must show divergence. Pub/sub alone is fire-and-forget. | **P3** replica-sha consistency + divergence alert (best). **P1** `/admin/state` read-back (good). **P4** IR over Valkey pub/sub with no versioned pull or heartbeat, so a PEP that misses a message is silently stale |
| X12 | **Audit at scale** | Per-replica JSONL + DuckDB is fine for a demo. In a bank, ephemeral pods lose unflushed audit, and DuckDB is single-node. The production story is a per-replica chain plus OTel/Kafka to SIEM, with documented backpressure. | **P3** has the only real production path and profile-dependent backpressure. **P2** "no audit, no action" 503 everywhere couples availability to disk |
| X13 | **Valkey as SPOF** | Budget correctness and run state depend on one Valkey. The fail posture must be explicit and demonstrated. | **P3** external fail-closed / local fail-open capped at 10% per replica, demonstrated live (best). Others set a flag and do not rehearse it |
| X14 | **Hot reload on K8s** | ConfigMap volumes take about 1 min, and `subPath`/env never update (R7). The demo uses a file watcher; production uses signed bundles or git-sync. | P2/P3 say so explicitly; P1/P4/P5 mention kustomize only |

---

## 3. Per-proposal assessment

### P1 Proctor (score-maximizer): 43.2

**What I like as an architect:**
- A real data-plane / control-plane split: the console is its own service.
- Two stateless replicas behind an SSE-safe nginx at **P0**.
- A cross-replica budget race (200 → exactly 50).
- A verdict cache keyed by `policy sha + feed serial + message hash`, so only new messages are scanned.
- A T2 deadline.
- `/admin/state` read-back, so the header shows the policy the gateways *loaded*, not the file on disk.
- A `/v1/guard` API for other data planes.
- `make test-fast` in-process (ASGITransport + fakeredis with Lua) for a sub-minute developer loop.

The global header strip is the best judge-facing operational surface in the set.

**What I don't:**
- **Admin plane reachable from agents.** The agents network reaches only the LB, but the LB routes `/api` to the console: `PATCH /api/controls`, `POST /api/approvals/{id}/decision`, `PUT /api/policy`. No authentication is specified. A hijacked agent can turn C24 to `monitor` and approve itself. In a design whose pitch is "forced chokepoint", that is embarrassing.
- **Run id is client-asserted** (`X-AICL-Run-Id`), so taint and run breakers are escapable. Provenance "user text" is not anchored to the ingress credential.
- **Compute-ms from Ollama durations** through the OpenAI-compat path does not exist (X3).
- **Classifier latency claim** of 15-40 ms for deberta-v3-base is optimistic; expect 75-100+ ms on CPU, and a 150 ms deadline with `on_error: open` fails open under load. The model is also archived and English-only.
- **Two writers to `policy.yaml`**: the console writes through ruamel and judges edit by hand, with no version check, so updates can be lost.
- **Scope:** 24 P0 controls, a 16-incident museum, OCSF at P0, mutation tests at P0, prebuilt multi-arch GHCR images with baked weights, and 6 pages. That does not fit in about 19 h per person. The "P0 = 1 POS + 2 NEG + visible in trace" definition hides a lot of shallow controls.

**Practicality:** `base_url`, `/v1/guard`, an SDK and the PreToolUse hook are good. SSO is virtual keys until P1, and managed settings are P1.

### P2 Warden (security architect): 39.4

**What I like:**
- The strongest security architecture on the table:
  - six trust-zone networks;
  - admin plane on a separate listener and network (C35);
  - sandbox containers with no egress for MCP servers;
  - gateway-HMAC run tokens with a sticky fallback;
  - ingress-anchored provenance;
  - hard floors in code;
  - multimodal default-deny for agents;
  - a classifier-off hijack test as the H12 gate.
- Fail-to-taint is an elegant failure posture: detector failure tightens what happens downstream instead of failing open or failing the service.
- The residual-risk register is what a bank risk committee wants to see.

**What I don't:**
- **The "control plane" is a port, not a service.** `:8081` with the report API, SSE, approvals, pins and DuckDB sits *inside each gateway replica*. With two replicas:
  - which replica serves the dashboard?
  - each has its own chain file;
  - approvals and pin state must round-trip through Valkey;
  - SSE shows half the traffic.

  It is a network separation without a process separation.
- **Latency at the high end.** PG2-86M plus max-over-views classification, and k=128 holdback by default (+0.6 s time-to-first-token on every stream).
- **Operational coupling.** Fail-to-taint under guard overload turns a capacity problem into an approval storm, and nothing in the design alerts on that before users feel it. "No audit, no action" 503 on queue-full makes audit disk an availability dependency in every profile.
- **Integration friction.** Full taint value requires apps to call `POST /v1/runs`. Without it, a sticky 30-minute per-principal run over-taints users who do several unrelated tasks, which means false `ask`s in daily use.
- **Feasibility is the worst in the set:** 36 controls, the 10-way obfuscation matrix including Polish, four-eyes approvals at P0, protocol hardening at P0, 10 dashboard pages, a gated PG2-86M and a Qwen3Guard spike. A reference monitor that is 70% built proves nothing; a half-finished fence is worse than none.
- Compute-ms has the same gap as X3.

### P3 Gatehouse (enterprise steelman): 43.7, best architecture and practicality

**What I like:**
- This is the only proposal written by someone who has run a platform.
- **The fail-mode table (§11.1) is the best artefact in the whole panel.** It covers replica loss, Valkey down, guard down, guard LLM slow, feed unreachable or tampered, IdP down, directory staleness, audit backpressure, Squid down and upstream 5xx, each with detection, a default, a knob and a console banner. The ops drill demo (kill `gw-1`, stop Valkey) is exactly what I will ask for.
- A real OIDC relying-party path: JWKS cache, groups claim → roles → entitlements.
- A static test issuer, so hermetic tests run without Keycloak.
- Service principals, and agents as first-class principals with owner, cost centre and kill switch.
- A rendered managed-settings bundle.
- `/v1/models` as the authoritative per-user filter.
- Replica-sha consistency.
- Schema N-1 converters, unknown feed rule types skipped, a policy check CLI in CI, and shadow-before-enforce.
- The competitive table answers "isn't this just the Claude apps gateway?" before I ask it.

**What I don't:**
- **The lens eats the rubric.** Keycloak + `aictl` device flow, stock Squid with rendered lists and log ingest, and the tighten-only overlay lattice are all **P0**. Run taint and provenance are **P1**. The single most convincing robustness proof, "model hijacked, data still didn't leave", is therefore not guaranteed. The proposal admits this.
- **Presidio with spaCy `pl` + `en` runs inside the async gateway hot path.** That is CPU-bound NER on the event loop. It belongs in guard-svc or a process pool. P5 is right that its own checksum validators are more precise for PESEL, IBAN and PAN.
- **The one-person console has about 9 P0 pages:** Access matrix + explain, Spend & Chargeback, My AI, Shadow-AI tile and more. Not deliverable.
- Squid costs a GPL container and a reconfigure loop for a tile judges barely poke. The fence is already the internal network.
- Compute-ms has the same gap as X3. PG2-22M is weak on Polish.

**Practicality 9/10:** this is the version I could take to a bank change board on Monday. Feasibility 5.5 because of the identity, Squid, lattice and console load.

### P4 Mandate (contrarian): 43.5

**What I like:**
- The PDP/PEP split with `decide()` in-process, so there is no network hop per decision.
- **`/v1/decide` for out-of-process enforcement points** (Claude Code hook, Squid `external_acl`, and Envoy ext_proc in production). This is the most bank-realistic integration surface in the set: we already run Envoy, Apigee and Kong, and we will not rip them out for a Python proxy.
- Compile-then-swap with LKG and compiled-target diffs, so one edit shows what changes in the gateway, the MCP proxy, managed settings and NetworkPolicy.
- Destinations as a **positive allowlist** minted from the authenticated task.
- Feed action rules compiled into exclusions that no policy can authorize.
- **Detector independence as a measured number** ("12/12 agentic attacks still blocked with every content detector off"). That is the metric I would put in a board pack.
- Compute accounting handled correctly (X3).

**What I don't:**
- **IR distribution over Valkey pub/sub** with no versioned pull or heartbeat. A PEP that reconnects after a blip runs stale policy indefinitely, and the header can claim v18 when a replica runs v17.
- **The MCP PEP spawns stdio servers inside its own container**, including the malicious `facts` and the `vault` honeypot (X9). It also breaks statelessness: each replica has its own children.
- **Call warrants** (120 s TTL, args-hash bound) add a Valkey round trip per tool call. They will false-deny human-in-the-loop clients that wait for approval longer than the TTL, and frameworks that coerce argument types. The proposal mitigates this with `direct` mode for third-party clients, so the headline property only holds for its own agent.
- **Compat mode is what judges will actually use** (curl, the Playground, any OpenAI SDK). In compat mode, destinations are anchored to "the first user message", which is a much weaker guarantee than the pitch implies.
- **Requirement (5) is under-delivered at P0.** Spend & Budgets and Audit & Export pages are P1, and two replicas are P1, so statelessness is unproven at P0.
- **Conceptual load.** Six people with AI assistants building a new vocabulary (mint, bind, narrow, delegate, revoke, warrant) is where code drift is most likely. A judge also has to learn the vocabulary in 30 seconds. The mechanics are good; the branding is a pitch choice.

### P5 Governor (delivery lead): 56.4, wins on the formula, worst architecture

**What I like:**
- The only proposal I believe will be demoable at H12 and runnable by a mentor at H24:
  - contracts frozen at H1, including a detector Protocol whose `compile()` can reject a reload;
  - a walking skeleton by H5 with an explicit assertion list;
  - a FastMCP go/no-go at H2.5 with a thin JSON-RPC fallback;
  - a ranked P1 behind flags;
  - freeze at H16;
  - a clean-room run with Wi-Fi off;
  - `test_demo_storyline.py`;
  - `make doctor`, `make warm` and `make reset-demo`;
  - a hot-spare laptop;
  - `CLAUDE.md` rules for the AI assistants.
- Trigger-aware holdback plus a `stream_mode: buffer` fallback is the best streaming engineering in the set.
- Handles FACT-CHECK A2 honestly.
- Own checksum PII instead of Presidio.
- Contracts reuse the existing `examples/`.

**What I don't (and the final design must fix):**
- **A single-process monolith.** Data plane, admin API, DuckDB report API, SSE hub, self-test runner and MCP proxy with stdio children share one event loop and one container.
  - A security analyst running an export or a big threat query competes with every agent request. DuckDB and JCS hashing are CPU-bound.
  - The design blocks its own scale-out. With two replicas, each gateway's read API sees only its own JSONL, so the dashboard shows half the events. No wonder two replicas are P1 rank 13, which means they will be cut.
- **The admin plane is on the agent-facing port.** `/admin/*` and `/api/*` share `:8080` with `/v1/*` and `/mcp/*`. Only `/admin/demo/reset` is gated, by `TEST_MODE`, and admin authentication is unspecified. P1 adds approvals on the same surface.
- **No fence at P0.** C13 is P1 rank 9. At P0 nothing stops the agent container from calling `host.docker.internal:11434` directly and bypassing budgets, allowlists and audit. The team's own idea, "managed agent settings force agents to use the proxy", is then not demonstrated, and that is the first thing I will try.
- **Malicious MCP servers run as stdio children of the gateway** (X9).
- **Escapable run ids.** The gateway mints a run id only when one is absent, so a client can rotate it. Taint and provenance are P1 rank 2, so the "fooled model, data didn't leave" moment is a stretch goal.
- **No SSO code path at all,** not even a mocked JWT/JWKS. "LDAP-named groups on virtual keys" is a weak answer to "how does this plug into Entra ID / AD?"

**Feasibility 8:** about 22 P0 controls is still a lot, but the hour estimates add up and the cut lines are pre-decided.

---

## 4. Fatal flaws (if shipped as written)

| Proposal | Fatal flaws |
|---|---|
| P1 | Console admin API reachable from the agents network through the shared LB, with no auth. Client-asserted run id makes taint escapable. Compute-ms reads Ollama durations that the proxied API does not return. The P0 scope cannot be delivered, so many shallow controls ship in `monitor`. |
| P2 | Scope makes it the most likely to ship a half-built reference monitor. The control plane is co-located in every data-plane replica, so the dashboard, approvals and chains split across replicas. k=128 holdback plus PG2-86M multi-view puts latency at the top of the range. Full taint needs app integration, and the fallback over-taints. |
| P3 | Taint and provenance are only P1, so the strongest robustness demo is not guaranteed. Keycloak + device flow + Squid + overlay lattice at P0 consume robustness hours. About 9 P0 console pages for one person. Presidio NER on the async hot path. |
| P4 | Pub/sub IR distribution has no versioned pull, so stale PEPs go undetected. Malicious demo stdio servers are spawned inside the MCP PEP. Compat mode, which judges will use, carries weak guarantees. Spend and Audit pages and two replicas are only P1. A novel vocabulary raises integration-drift risk. |
| P5 | Single-process monolith with no data/control split, which obstructs its own scale-out. Admin and report APIs on the agent-facing port. No egress fence at P0. Malicious stdio MCP servers spawned inside the gateway. Escapable run id, with taint only at P1. No SSO/JWT path. |

---

## 5. Ideas to graft (tagged by source)

**Delivery backbone**
- [P5] Contracts frozen at H1:
  - policy schema with `extra=forbid`;
  - `aicl.audit/v1` with R1 control ids;
  - the Detector Protocol with a `compile()` hook that can reject a reload;
  - OpenAPI including the block/error contract.

  Also from P5: a walking skeleton by H5 with an assertion list; IC gates; ranked P1 behind flags; freeze at H16; a clean-room offline run; the storyline as an e2e test; `CLAUDE.md` rules for assistants; `make doctor`, `make warm`, `make reset-demo` and `make demo-offline`.
- [P5] A FastMCP 4 spike with a go/no-go at H2.5, plus framework-free middleware logic and a thin JSON-RPC fallback.

**Data plane and streaming**
- [P5] Trigger-aware holdback (hold only while `![`, `](` or `http` is unterminated, max 1 KB) and a `stream_mode: buffer` fallback.
- [P1] A verdict cache keyed by policy sha + feed serial + message hash; scan only new messages; per-tier deadlines.
- [P5/P4] Compute-ms as upstream wall-clock at P0, with native `/api/chat` durations when available (FACT-CHECK A2).
- [P2] A separate Ollama guard lane (`:11435`), so agent load cannot starve the guards.

**Topology and security architecture**
- [P2] Trust-zone networks: `agents`, `core`, `sandbox`, `admin` and `upstream`, plus a fence test at H1 on every laptop that includes `host.docker.internal`.
- [P2] An admin plane on its own listener and network (C35), so agents have no route to approvals or policy.
- [P2] Gateway-HMAC run tokens that only a user credential can mint, a sticky per-principal fallback, and ingress-anchored trusted text (C33).
- [P2] Untrusted MCP servers in no-egress sandbox containers, never children of the enforcement process; registry-only upstreams; no token passthrough.
- [P2] `on_error: taint` (fail-to-taint); detectors may only add restrictions; hard floors in code.
- [P2] Multi-view scanning (stripped, tag-decoded, NFKC, confusable skeleton, folded, bounded decoders, window), destination canonicalisation with homoglyph-spoof alerts, and multimodal default-deny for agents.
- [P2] The classifier-off hijack test as the H12 gate and a live demo beat.

**Operability and change management**
- [P3] A fail-mode table per dependency (detection, default, knob, banner) and a rehearsed ops drill: kill `gw-1`, stop Valkey.
- [P3] When the ledger is down: external models fail closed; local models fail open with a per-replica conservative cap (10% of the seat cap) and `degraded=true`.
- [P3] Replica-sha consistency (`2/2 replicas same sha`), `policy.reloaded` pub/sub, and an alert after 10 s of divergence.
- [P3] `policy check` CLI in CI. Shadow-before-enforce with "would have blocked" counts. Break-glass. An "unsigned local change" label in dev mode. Signed bundles in prod mode. Schema N-1 compatibility. Unknown feed rule types skipped, never fatal.
- [P3] An SLO table measured by `make bench`: deterministic p95 ≤ 25 ms, with classifier ≤ 60 ms, escalation rate < 5%, edit→enforced < 2 s, 0% overshoot, 100% audit completeness.

**Identity and integration**
- [P3] OIDC relying party: JWKS cache, groups claim → roles → entitlements, effective = user ∩ agent, agents as principals with owner, cost centre and kill switch; a static test issuer for hermetic tests; explain-access with provenance.
- [P3] A rendered managed-settings bundle (`ANTHROPIC_BASE_URL`, `apiKeyHelper`, `allowedProviders: [customEndpoint]`, `managed-mcp.json`), with `/v1/models` filtering as the authoritative control. Never set `forceLoginMethod`.
- [P4] A `/v1/decide` PDP API, so existing data planes (Envoy ext_proc, Apigee/Kong callouts, the Claude Code PreToolUse hook, Squid `external_acl`) reuse the same brain. [P1] `/v1/guard` is the content-inspection subset of the same idea.
- [P3] The 429 `billing_error` contract with `x-should-retry: false`, and a downgrade to a local model.

**Evidence and reporting**
- [P1] The global header strip (policy vN + sha + replicas + applied-ago, feed serial, chain ✓ seq, self-test x/y, posture Δ), driven by the policy actually loaded.
- [P1] Attack Range: "what you sent vs what the model saw" diff with a `Server-Timing` breakdown, and Exploit Museum "Replay all".
- [P4] A detector-independence metric, plus measured posture (attack and FP rates per framework item) alongside configured posture, and promote-to-test-case from the Playground.
- [P4] Honeypot hit → revoke the whole run tree, with a non-retryable 403.
- [P4] Compiled-target diff on every policy edit.
- [P3] Policy-generated entitlement-matrix tests.
- [P1/P2/P3] A cross-replica budget race on two replicas at **P0** (200 → exactly 50).
- [P2] Telemetry for guard-lane queue depth, fail-to-taint counter and escalation rate.

---

## 6. What the final design MUST fix

1. **Split the control plane into its own service.** Policy compile/validate, report API (DuckDB over the shared audit volume), SSE, self-test runner, approvals, exports and per-replica state aggregation live in a `control` service on the `admin` network, with admin authentication. The data plane is stateless gateways only. No admin route may exist on the agent-reachable listener.
2. **Put the fence at P0.** Probe at H1 on macOS Docker Desktop: from the agent container, `host.docker.internal:11434`, Valkey, MCP containers, `control` and the internet must all fail. If it leaks, fall back to a core-only socat bridge. The bypass test goes in `make test`.
3. **Run two gateway replicas at P0** behind an LB with buffering off. The cross-replica budget race goes in `make test`. Audit chains are per replica (`chain_id = gw-N/date`) and merged by `control`. The header shows per-replica loaded sha.
4. **Fix run identity.** The gateway signs run tokens; a missing or forged token falls into a sticky per-principal run; trusted text is anchored to the authenticating credential. **Taint + destination provenance are P0**, and the classifier-off hijack test is a hard gate.
5. **Compute accounting** uses wall-clock from dispatch to the final chunk, with `NUM_PARALLEL=1` on the agent lane or native `/api/chat` durations. Never claim Ollama durations through the OpenAI-compat path.
6. **MCP servers run in their own no-egress sandbox containers**, speaking Streamable HTTP or bridged. The enforcement process never spawns tool code. Upstreams come from the registry only. Pins live in Valkey.
7. **Keep the event loop clean.** ONNX, any NER, DuckDB and bulk hashing run in guard-svc, a process pool or `control`. Long tool results get a chunk cap, a tier deadline and an explicit `on_error` (`taint` by default for untrusted inputs).
8. **Policy propagation reports truth.** Use a file watch plus sha poll per replica and a heartbeat key in Valkey (`replica → sha, loaded_at`). The console shows divergence. Pub/sub may be an accelerator, never the only path.
9. **Streaming contract.**
   - `Server-Timing` carries pre-flight stages only.
   - Upstream and stream timings go into the audit event and a final SSE comment.
   - Trigger-aware holdback with configurable k.
   - Inject `include_usage` and settle under `asyncio.shield`.
   - Never reset the TCP connection. Mutate JSON in place.
10. **A fail-mode table with defaults and console banners** for Valkey, guard, guard LLM, feed, IdP, audit backpressure and upstream errors. Rehearse two drills (kill a replica, stop Valkey) and record them.
11. **Identity at P0 means a real JWT/JWKS validation path** (static test issuer or mock IdP) with groups → roles → entitlements, plus hashed virtual keys for services and judges. Keycloak is an optional profile (`DEMO_NO_SSO`). LDAP stays on the slide.
12. **Size the scope honestly.** One ranked P0 list at about 12-14 h per person, with pre-decided cut lines. The single console owner gets at most 6 P0 surfaces (header, Overview, Threats + drawer, Playground, Controls/Self-test, Spend) on fixtures from H1. Everything else is P1 behind flags.
13. **One writer per policy file.** Judges edit the file. Console quick-toggles go through the same validator with an optimistic version check (etag), or the console is read-only. No silent overwrite.
14. **Quote only measured numbers.** Re-measure classifier and pipeline latency on an M-series Mac in H2. The default classifier is PG2-22M INT8, with the multilingual model only on language-ID or in the gray zone. Every number on a slide comes from `reports/perf.md`.
15. **Audit durability and backpressure are per profile.** Strict mode returns 503 "no audit, no action". Balanced mode keeps L0 metadata and drops L1 snippets. Use batched fsync, and document OTel/Kafka → SIEM as the production path.

---

## 7. Questions I will ask on stage (prepare answers)

1. "Kill one gateway mid-stream. What does the client see, what happens to its budget reservation, and what does the audit chain show?"
2. "Stop Valkey. Which models still work, and how do you stop the local path from being an unlimited free lunch?"
3. "From the agent container, `curl host.docker.internal:11434/api/generate`. What happens?"
4. "Your classifier is down for 10 minutes at peak. Fail open, closed or taint? Show me the counter."
5. "What is the p95 overhead *you* measured on this laptop, deterministic only and with the classifier? Time-to-first-token with your holdback?"
6. "How does this plug into Entra ID groups without code changes? What happens when someone leaves the bank?"
7. "We already run Envoy and Apigee. Do I have to replace them?" The answer should be `/v1/decide` / `/v1/guard`.
8. "A judge edits the policy on replica 1's mount only. How do I know replica 2 is stale?"
9. "Can the agent reach the approvals API? Prove it can't."
10. "Where does the audit log go when a pod is evicted?"

---

## 8. Verdict

**Build P5's plan, not P5's architecture.** Its delivery discipline is worth more points than any single architectural idea, because a 7.9-quality design that is 60% built scores below a 7.0-quality design that works on a mentor's laptop.

Within that plan, spend the roughly 6-8 extra person-hours on:
- splitting out a `control` service;
- the P0 fence with the H1 macOS probe;
- two replicas at P0;
- gateway-signed run tokens with taint + provenance at P0;
- sandboxed MCP containers;
- P3's fail-mode table.

Pay for them by cutting Squid, Keycloak-as-P0, the overlay lattice, A2A, a standalone sparring service (run it as `make test-live` on reload) and P1's museum UI breadth.

That hybrid would score about 8 on architecture and 8 on practicality from me, at a feasibility I would still rate about 7.
