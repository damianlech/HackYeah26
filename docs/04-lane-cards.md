# Lane cards: what each of the six owns, from minute 0

> **Source of truth:** `design/VISION-SPEC.md` (product "Mandate", code namespace `aicl`). If a card disagrees with the spec, the spec wins. Where a research note disagrees with `research/FACT-CHECK.md`, the fact-check wins.
> **Derived from:** spec §3.2, §3.9, §4, §5.7, §10, §11, §12, §13, §15; `research/FACT-CHECK.md`; `design/judging/J1-gs-appsec-lead.md` (red-team probes R1-R12), `J2` (X1-X14), `J3`; `docs/dashboard-design-brief.md`.
> **Snapshot:** 2026-10-03, synced to spec **v1.1**. Times are hours after the **build start** (H0 = when the team starts building, after the kickoff). Spec §13.4 maps them to the real deadline, and plan (a) (11:00 Oct 4, compressed) runs until Q2 is confirmed. Control IDs are the spec's `C01`-`C36`.

> **Legend.** Hn = hours after build start; H4.5 = H4:30. CF = contracts frozen (H1). IC1-IC5 = integration checkpoints (§10). WP = work package. POS/NEG = test case expected allowed / blocked-or-redacted. LKG = last-known-good policy. GAP = self-test state for a control a judge disabled (amber); FAIL = an enabled control regressed (red). Taint = the run has read untrusted content. S1-S8 = MCP attack scenarios (R6 §4.4); E1-E10 = Exploit Museum exhibits (spec §8.5); "beat n" / ★ = demo-script step / 3-min cut (spec §12). R1-R9 = research notes; "risk Rnn" = spec §14.1; "J1 Rn" / "J2 Xn" = judge-memo probes; Dnn = spec §16 decision; Tnn = residual threat (spec §14.2). PG2 = Llama Prompt Guard 2; TR39 = Unicode confusables skeleton; JCS = RFC 8785 canonical JSON.

---

## 0. How to use these cards

1. Read §1 (roles), §2 (critical path) and **your own card**. That is your brief for the first hour.
2. The kickoff (§3) runs H0-H1 for everyone. Contracts freeze at **H1:00 (CF)**.
3. The WP tables are copied from spec §13.2. The **checkpoint table (§10 here, spec §13.4) is binding**; the gantt in the spec is indicative.
4. "Needs" and "Delivers" are promises between lanes. By **H1:30** every lane exposes a contract-shaped stub of its interface, so nobody waits on real code.
5. If you will miss a "Delivers" time, tell L before the next checkpoint. L makes the call from the "If red" column (§10), with no debate.
6. Point your AI assistant at `CLAUDE.md`, your card and the spec sections listed under "Read first" on your card. (L creates `CLAUDE.md` at H0:30 in the `aicl` repo; until then use §3.4 below.)
7. Section 12 lists the spec issues that v1.1 did not resolve. L resolves them at kickoff, or they go to an RFC.

---

## 1. The six roles at a glance

| Role | Lane | Mission (one line) | H12-gate items owned (IC3) | On stage |
|---|---|---|---|---|
| **L** | Lead / integrator: contracts, harness, evidence, delivery | Keep six lanes building against frozen contracts and turn every claim into a passing test | **C13 fence test + C35 admin isolation**; **detectors-off overlay + S4/S5 invariant cases** (L4); case runner (L2); runs the gate swarm if it is red | Narrates; fence, testing and residual-risk Q&A |
| **A** | Gateway core and streaming | Build the data plane every request passes through: policy engine, identity, run tokens, pipeline, streaming, two replicas | A2 policy engine (H4.5); **A3 `/v1/runs` + run tokens (H8)**; **A6 two replicas** (prerequisite of the race) | Architecture and performance Q&A |
| **B** | Deterministic detection, feed, audit | Deterministic detectors, the signed feed, the tamper-evident audit chain and the read APIs over it | **B4 destination extractor to D by H7** (C24 depends on it); C07 (B6) by H9:30 for IC3 beats 2 and 4 | Guardrails and feed Q&A; "security analyst" in beat 8 |
| **C** | Models, budgets, semantic, artifacts | Hard budgets in Valkey, the semantic guard sidecar, the topic pack, the artifact gate and the local models | **C1 Valkey ledger (H5)**; **C6 cross-replica race test (H11)** | Budgets and models Q&A |
| **D** | Agents, MCP, taint | MCP edge, sandboxed demo servers, tool policy and the C24/C33 guarantee | **Owns the H12 gate:** D1 → D2a → D3a → D5a → **D4 (C24/C33)** by H11 | Runs the agent terminal (scripted `demo-agent` + curl) |
| **F** | Console (UI only) | Header + 4 pages, designed with Claude Design and built with Claude Code, on fixtures first and live data later | None of the H12 gate. IC3 needs **Threats + drawer on live data** and the **Playground on fixtures + one live call** (fully live by IC4) | Drives the console; "CISO" in beat 10 |

---

## 2. Critical path to the H12 gate (spec §13.2)

The gate is: **detectors-off S4/S5 exfiltration still denied**, **fence + admin isolation green**, and **cross-replica race 200 → exactly 50**. There is 30-60 min of buffer before H12. **If the gate is red at H11:30, D + A + L swarm on it and every P1 item is frozen.**

```mermaid
flowchart LR
  A1["A1 app + mock-llm<br/>A · H3"]
  L2["L2 case runner + steps<br/>L · H4.5"]
  A2["A2 policy engine<br/>A · H4.5"]
  C1["C1 Valkey ledger<br/>C · stub H2, real H5"]
  B3["B3 signature engine<br/>B · H7"]
  B4["B4 destination extractor<br/>B · H7"]
  A3["A3 /v1/runs + run tokens<br/>A · H8"]
  A6["A6 lb + gw-2<br/>A · H8"]
  D1["D1 MCP spike<br/>D · go/no-go H2.5"]
  D2a["D2a web, crm, bankdb, mail<br/>D · H4"]
  D3a["D3a aicl.tools core<br/>D · H6:30"]
  D5a["D5a MCP call path + taint marking<br/>D · H8"]
  D4["D4 C24/C33 run state + sink matrix<br/>D · H11"]
  L4["L4 detectors-off overlay<br/>+ S4/S5 invariant cases<br/>L · H11"]
  C6["C6 cross-replica race test<br/>C · H11"]
  L1["L1 fence probe<br/>L · H1"]
  LF["fence + admin isolation test<br/>L · H11"]
  GATE{{"H12 GATE<br/>detectors-off S4/S5 denied<br/>fence + C35 green<br/>race: 200 fired, exactly 50 admitted"}}

  A1 --> L2
  D1 --> D2a --> D3a --> D5a --> D4
  C1 --> D3a
  B3 -.->|"stub H4.5, engine H7"| D3a
  C1 --> A3
  A3 --> D4
  B4 --> D4
  B4 --> L4
  D4 --> L4
  L2 --> L4
  A2 --> A6
  A6 --> C6
  C1 --> C6
  L1 --> LF
  L4 --> GATE
  C6 --> GATE
  LF --> GATE
```

| Step | Owner | Done by |
|---|---|---|
| C1 Valkey ledger | C | H5 |
| A2 policy engine | A | H4.5 |
| L2 case runner with `steps` | L | H4.5 |
| B4 destination extractor | B | H7 |
| A3 `/v1/runs` + tokens | A | H8 |
| D1 → D2a → D3a → D5a → D4 | D | H11 |
| L4 invariant cases + overlay policy | L | H11 |
| A6 two replicas → C6 race test | A → C | H11 |
| L1 fence probe → fence test | L | H11 |

---

## 3. H0-H1 kickoff (whole team)

### 3.1 Agenda (15-minute blocks)

| Time | Block | Who | Output by end of block |
|---|---|---|---|
| **H0:00-0:15** | **1. Read your card** (10 min, silent). Then answer the H0 questions: Q2 (deadline wording, weights, can the submission be edited; this picks plan (a) or (b) of spec §13.4, and plan (a) runs until it is confirmed), Q4 (PG2 access on every demo laptop), Q15 (OWASP MCP Top 10 renumbered in Oct 2026?), Q16 (is pre-event design allowed?) | all 6 | Q2/Q4/Q15/Q16 answered or defaults logged in team chat |
| **H0:15-0:30** | **2. Open questions Q1-Q16** (§3.2): confirm each default, name who closes it. Close Q3, Q7, Q10, Q13 and Q14 now (due H1). L resolves the §12 spec issues or assigns them | all 6 | defaults logged; §12 issues decided |
| **H0:30-0:45** | **3. Freeze contracts** (§3.3). L creates the repo layout (spec §3.9) and walks through each `contracts/` file; its producer and consumers sign off. A gap becomes a v1.2 RFC, not an edit. F stays for `openapi-control.yaml`, `sse-events.md` and fixtures, then starts F1 at about H0:40 | all; F leaves early | sign-off list in the contracts PR |
| **H0:45-1:00** | **4. Fence probe + working rules.** Run `fence-probe` on every demo Mac (primary + hot spare, Q3/Q10); L collects `reports/fence.json`. While it runs: CLAUDE.md rules (§3.4), branch/merge and checkpoint conventions (§3.5) | L, A, B, C, D | fence result logged; **CF declared at H1:00** |

**H0:30 contracts review includes the pre-CF RFCs in `docs/06-open-questions.md` §6** (lead recommends accept; each verdict goes in the contracts PR).

The probe tests every host target **by name and by raw host IP**, plus `model-runner.docker.internal` if Docker Model Runner is enabled (it should be off on demo Macs). Fence leak at H0:45? Apply the ladder from spec §3.4 in order: (1) `extra_hosts: ["host.docker.internal:0.0.0.0", "gateway.docker.internal:0.0.0.0"]` + `dns: [0.0.0.0]` on agent services, then re-probe by name and raw IP (the override only renames hosts); (2) agent-lane Ollama on the hot spare over a LAN cable; (3) do not claim the Ollama chokepoint, put the probe output in the README and record it as residual T5.

### 3.2 Open questions Q1-Q16 (spec §15): defaults to confirm

| Q | Question | Default if unanswered | By | Natural owner (suggested) |
|---|---|---|---|---|
| Q1 | Brand: Mandate, or another name from §1.1? | Mandate | H11 | team, L decides |
| Q2 | Deadline wording (11 PM vs 11 AM), CRITERIA vs RULES weights, can the submission be edited after upload? | plan (a) of spec §13.4 until confirmed (placeholder H8, submit H15) | **H0** | L |
| Q3 | Primary demo Mac and hot spare? Docker Desktop versions? Fence result on both? | the two 64 GB machines, if any | H1 | L + C |
| Q4 | Did every demo laptop get PG2 HF access? | protectai-v2 default + multilingual kNN | **H0** | C |
| Q5 | Qwen3Guard-Gen-0.6B community GGUF spike: go or no-go vs `llama-guard3:1b`? | `llama-guard3:1b` (official tag) | H2 | C |
| Q6 | OCSF at P0 (J1) or P1 rank 4 (J3)? | P1 rank 4 | H12 | L + B |
| Q7 | Is "ask = block with 'approval required'" acceptable at P0, since C23 is P1? | yes | H1 | team |
| Q8 | Who writes the ~100-prompt Polish slice (50 attack / 50 benign banking)? | C + D, at H12-H14 | H12 | C + D |
| Q9 | Repo public from H0 or at H20? | public at H20 after `gitleaks` | H16 | L |
| Q10 | Second laptop on a LAN cable for the fence fallback and the guard lane? | yes, the hot spare | H1 | L |
| Q11 | Who records the Claude Code managed-settings clip (P1 #10), on whose machine? | A | H14 | A |
| Q12 | Seeded synthetic history size and org shape (3 depts, 6 teams, 12 users, 4 agents)? | as stated, labelled synthetic | H5 | L + F |
| Q13 | Single shared admin token for the console at P0? | yes, with the banner "single admin token (demo)" | H1 | L |
| Q14 | Budget reset timezone: UTC or Europe/Warsaw? | UTC | H1 | C |
| Q15 | Has the OWASP MCP Top 10 October 2026 release renumbered anything? | keep 2025-edition IDs | **H0** | L |
| Q16 | Rule compliance: is pre-event work allowed (this spec, research notes, text/schema drafts of `contracts/`, and a small throw-away POC in `poc/`: one gateway, a keyword guard, a mock LLM)? May we show it, may any of it be reused, or must all product code be written after the start? | design docs are allowed; the POC is reference-only and not copied into the `aicl` repo unless the answer explicitly allows reuse; if design is not allowed, L writes `contracts/` in H0-H1 and CF may slip to H1:30 | **H0** | L |

### 3.3 Contracts frozen at H1 (`contracts/`, CODEOWNERS: L)

FROZEN AT H1: §5.7 wire contract, §6 policy schema, §9.1 audit event, §11 API, §10.3 case format. After H1 a change needs a one-paragraph RFC in team chat, L's approval and a version bump.

| File | Freezes | Sign-off (producer first) |
|---|---|---|
| `policy.schema.json` | `aicl.policy/v1` (§6), generated from A's pydantic model | A, B, C, D |
| `audit-event.schema.json` | `aicl.audit/v1` with the H1 additive deltas (§9.1: `controls[].mode` gains `mask/modify/strip/quarantine`, `controls[].fail_mode` gains `taint`, new `controls[].origin` and `controls[].view`, top-level `run`, `decision.degraded_reasons[]`, `latency.stages`, `evidence.forwarded`, `change.weakened[]`; v1.1: `controls[].verdict` gains `flag`, budget `scope` prefixes `org:/pool:/seat:/agent:/run:`, top-level `synthetic`) | B, D, L, F |
| `feed-bundle.schema.json` | signed feed format (§8.1) incl. the per-type match fields and `metadata.tier` (§8.4, v1.1) | B, C, D |
| `case.schema.json` | YAML case format (§10.3; v1.1 adds `expect.headers`; the profile field is `by_profile`) | L, everyone |
| `frameworks.yaml` | schema and format: framework item → required/supporting controls (R1 §10). Content is filled by L6 by H13, with no RFC needed | L, F |
| `openapi-dataplane.yaml` | `/v1/*`, `/mcp/{server}`, `/v1/artifacts/scan`, request/response headers (§11.2) | A, C, D |
| `openapi-control.yaml` | `/api/*` (§11.3, incl. the new shapes) | L, B, C, D, F |
| `sse-events.md` | SSE events and `id:` format (§11.4) | L, B, F |
| `errors.md` | the wire contract (§5.7) | A, C, D |
| `canonical.py` | rfc8785 JCS, used by the audit writer **and** verifier | B, D, L |
| `detector.py` | detector `compile()` protocol (§6.5 step 4) | A, B, C, D |
| `fixtures/api/*.json`, `fixtures/events/*.json`, `fixtures/stream.jsonl` | UI fixtures and example events; generated by `tools/make_fixtures.py`, committed by **H1:30** | L, F |

### 3.4 Rules for every AI assistant (spec §3.9 `CLAUDE.md`)

1. `contracts/` is law. A contract change is an RFC, not an edit.
2. Use `google-re2` for every policy- or feed-supplied pattern. Never use Python `re`.
3. Mutate request JSON in place. Never re-serialise it through a strict schema (it breaks Claude Code's beta-header pairing).
4. Every control PR adds ≥ 1 POS + ≥ 2 NEG YAML cases, tagged with control and framework IDs. **No case, no merge.**
5. Never assert on LLM prose. Assert on headers, verdicts and audit events.
6. Every new feature sits behind a policy flag, default off until its cases pass.
7. No CPU-heavy work on the gateway event loop.
8. Use R1 control IDs only, and LLM 2026 framework IDs.
9. Secrets and PII in fixtures are generated at runtime (GitHub push protection).
10. Never spawn tool code in the gateway.

Start each assistant session with: "Read `CLAUDE.md`, my card in `docs/04-lane-cards.md` and the spec sections it lists. Treat `contracts/` as read-only."

### 3.5 Branch, merge and checkpoint conventions (spec §13.8)

- **Trunk-based.** Branches live < 2 h. A PR needs unit + schema checks green (CI < 3 min). Merge at least every 2 h.
- **No pushes to `main` in the 15 minutes before a checkpoint.**
- **One owner per file.** `contracts/` is CODEOWNERS: L.
- **Stubs first:** every lane exposes a contract-shaped fake by H1:30. The IC1-critical stubs are due by H4.5 at the latest: B's rule-engine stub and static dev feed bundle file, and C's `GUARD_ENGINE=stub`.
- **One base image (H1):** L builds `aicl-pybase` from the real `uv.lock` (Python deps + `curl`, `netcat-openbsd`, `ca-certificates`) and saves it to both USB sticks. Every Dockerfile starts `FROM aicl-pybase`, so `apt-get` is never needed offline.
- **Flags:** every new feature is a policy flag, default off until its cases pass.
- **Tags:** the demo laptop runs a tag, never `main` (`ic1`, `ic2`, `ic3`, `rc1`, `v1.0-submission`).
- **Stand-ups:** 15 minutes, only at checkpoints, in front of `make demo-check` output (the storyline test), not opinions.

---

## 4. Card L: lead / integrator

**Mission.** Freeze the contracts, own the one test harness and the evidence (self-test, posture, coverage), call every checkpoint, and ship the submission.
**Read first:** spec §3.4, §3.9, §9.3-9.4, §10, §11.3-11.5, §13, §15.

**You are done when (P0):**
- **Plan (a)** (deadline 11:00 Oct 4, the default until confirmed): follow `docs/09-plan-a-p0-lite.md` §3.3 lane tables instead of the WP times below.
- **CF (H1):** `contracts/` committed, CI green on stubs, fence probe run and logged on every demo Mac; fixtures published at H1:30.
- **IC1 (H5):** `tests/e2e/test_walking_skeleton.py` green (all 9 steps of §13.5), tag `ic1`.
- **H12 gate:** detectors-off S4/S5, fence + admin isolation (`tests/fence/test_bypass.py`) and run-token-escape cases green; `make test` ≤ 2 min warm with all five meta-tests enforced; tag `ic3`.
- **IC4 (H15):** live self-test (GAP vs FAIL), posture, coverage, controls and Playground endpoints live (policy history moved to B in v1.1); `test_demo_storyline.py` beats 1-10 green offline; tag `ic4`.
- **Submit (H21):** IC5 clean room 100%, repo public with `gitleaks` clean, PDF ≤ 10 slides, tag `v1.0-submission`.

**Owns.**
- **Files:** `contracts/`, `CLAUDE.md`, `Makefile`, CI, `deploy/compose*.yaml` (6 networks: agents, edge, core, sandbox, admin, upstream), `src/aicl/testkit/` (case runner + `steps` executor; the mutators are P1 #8), `tests/{fence,invariants,e2e}/`, `policies/test.yaml`, `policies/test-detectors-off.yaml`, `tools/{fence_probe.sh,keys.py,make_fixtures.py,submission_check.py,doctor.sh}`, the `aicl-pybase` image, README, `docs/JUDGES.md` (build-repo path, spec §3.9), PDF, submission.
- **Components:** `fence-probe`, `tests`; `control` (skeleton, admin auth, SSE hub, self-test, posture/coverage, Playground endpoint).
- **Controls:** C13, C35; the live self-test (§10.4), posture (§9.3) and coverage (§9.4).
- **Endpoints:** `/api/header`, `/api/replicas`, `/api/health`, `/api/posture`, `/api/coverage`, `/api/controls`, `/api/selftest/*`, `/api/playground/inspect`, `/api/stream`. (`/api/policy/history` is B's since v1.1; you supply the derived diff and posture delta.)
- **Make targets:** `make test`, `make test-live`, `make demo-offline`, `make reset-demo`, `make keys`, `make fence`, `make doctor`, `make warm` (both from C in v1.1), `make demo-check`, `make submission-check`, `make licenses`.
- **Decisions:** every "if red" call (§10), the cut order (§11). Do not copy `poc/` code into the `aicl` repo unless the A4/Q16 answer allows it.

**P0 work packages (spec §13.2).**

| WP | What | Est. h | Needs (from, by) | Delivers (to, by) |
|---|---|---|---|---|
| L1 | repo, `contracts/` commit (drafted before H0 as text/schema only; code starts at H0, Q16), CI, CLAUDE.md, CODEOWNERS, compose with 6 networks, `fence-probe` (by name and raw IP); **run the probe on every demo Mac**; build `aicl-pybase` from the real lock (§13.8) | 2.0 | this spec | everyone, **H1** |
| L2 | case runner (YAML → pytest, incl. a `steps` executor for raw MCP/LLM calls), meta-tests, `rich` summary, JUnit/HTML, `compose.test.yaml` (v1.1: the mutators moved to P1 #8) | 2.5 | `mock-llm` (A1, H3) | case writing for all owners, H4.5 |
| L3 | `control` skeleton: admin auth, SPA static, audit tailer → SSE hub, `/api/header`, `/api/replicas`, `/api/health` | 2.0 | B1 events, A2 heartbeats | F, H5 (stream) / H8 (header) |
| L4 | invariant suites: fence/admin isolation, **detectors-off overlay with S4/S5 cases**, run-token escape | 1.0 | D4, B4 | **H11 → H12 gate** |
| L5 | live self-test runner (states, exposure), auto-run on reload, `/api/selftest/*` | 2.0 | A4 | F, H11 |
| L6 | posture + coverage + `frameworks.yaml` content (format frozen at H1); `/api/posture`, `/api/coverage`, `/api/controls` (v1.1: `/api/policy/history` moved to B7) | 1.5 | L5 | F, H13 |
| L7 | `/api/playground/inspect` (calls through `lb` as a demo principal, composes stages from the audit event) | 1.0 | L3, A4 | F, H10 |
| L8 | `test_walking_skeleton.py` (IC1), `test_demo_storyline.py` (IC4), `make demo-offline/reset-demo/keys`, `make doctor/warm` (v1.1: from C7; checks per `docs/08` §2.6; the scripted-agent CLI moved to D6) | 1.5 | all; C's Ollama/ONNX check list | H5 / H6 (doctor) / H14 |

**P1 (spec §13.3), only after your lane is green at IC3/IC4, top-down:** #3 `make eval` + calibration + Polish slice + held-out numbers on Self-test (C + L, 2.0) · #6 full Spend page + Agents & MCP page + `PATCH` toggles via the single-writer path (F + L + B, 4.0) · #7 Exploit Museum cards + scenario replay through the data plane (L + F, 1.5) · #8 mutation kill rate + entitlement-matrix tests + the obfuscation mutators (from L2) (L, 2.0) · #12 live `qwen3:8b` agent + promote-to-test-case (D + L, 1.5) · #16 kustomize + kubeconform in CI (L, 1.0). Your lane is 13.5 h of P0, so P1 only starts if you finish early. Plan (b) adds 2 h, and plan (a) builds no P1.

**Libraries and licences that matter here.**
- pytest (+ xdist; policy-mutating tests in one serial group), `rich`, Faker; FastAPI 0.142 for `control`; Docker compose `internal: true` networks.
- `frameworks.yaml`: OWASP LLM **2026** IDs with the year suffix (2025 ID in brackets); `MCPnn:2025` ("2025 edition, beta"; MCP06 is now "Intent Flow Subversion"); ASI08 "Cascading Failures"; ATLAS from `dist/v6/ATLAS-2026.09.yaml` (format 6.0.0), **not** the deprecated `dist/ATLAS.yaml` frozen at 5.6.0 (FACT-CHECK C1-C4).
- Licence gate: `make licenses` fails on GPL/AGPL/SSPL (no Squid, Grafana or Open WebUI in images). NOTICE needs "Built with Llama" plus a copy of the Llama licence if PG2 or Llama Guard 3 ship (FACT-CHECK A4). Repo licence is Apache-2.0.

**Top 5 gotchas.**
1. **The fence is unverified on Docker Desktop.** `host.docker.internal` may route from an `internal: true` network, and Ollama has no auth. Probe at H1 on every demo Mac and never claim what the probe did not prove (spec §3.4, J1 R8, J2 X10).
2. **No impersonation, no admin on the data plane.** The self-test runs through `lb` as `svc-selftest`, the Playground as `judge`/`alice`/`ola`. `lb` returns 404 for `/admin/*` and `/api/*`. If `control` dies, the data plane must keep enforcing and auditing (D31, C35, J1 must-fix 1).
3. **GAP is amber, never red.** Resolve every expectation against the policy the replicas **loaded** (heartbeat sha), not the file on disk. FAIL means an enabled control regressed (§10.4).
4. **Keep the harness hermetic.** `make test` must work with no Ollama, no HF token and no internet after the image pull. Policy-mutating tests run serially. Generate secrets and PII at runtime, and run `gitleaks detect` on the full history before the repo goes public at H20.
5. **A green coverage cell needs a tagged passing case** (meta-test). Kubernetes slide (P1): mount the ConfigMap as a **directory**, never with `subPath`, which never updates; say out loud that propagation takes about 1 min (J2 X14).

**Tests you must write.** Minimum per control: ≥ 1 POS + ≥ 2 NEG (one NEG is a false-positive guard).
| Family | Target |
|---|---|
| C13, C35 per-control cases | ≥ 6 |
| Fence & admin isolation (`tests/fence/test_bypass.py`): valkey, control, guard, mcp-*, mock, `host.docker.internal:11434` (also by raw host IP), internet unreachable; `model-runner.docker.internal` too if DMR is on; `lb /admin/*` and `/api/*` → 404 | 7 targets (+ DMR) + 2 paths |
| Invariants under `policies/test-detectors-off.yaml` (C09, C10, C11, C16 off; C08 still decodes): S4 + S5 denied; forged, absent and rotated run token stay in the tainted fallback run; paraphrase "audit at evil dot test" never trusted; homoglyph `bаnk.example` denied + critical | ≈ 8, all `invariant: detectors_off` |
| Meta-tests: ≥ 1 POS + ≥ 2 NEG per enabled control; every feed rule has vectors; every green cell has a tagged passing case; each NEG → exactly one decision event with the right `primary_control`; blocked content never reached upstream (`/_mock/calls`) | 5 |
| E2E: walking skeleton (9 steps), storyline (one test per beat), `tests/integration/test_api_contract.py` (fixture vs live) | 3 files |
| Live self-test canary subset (`canary: true`) | ~60 cases |

**Demo and Q&A.** You narrate every beat; beats 0 (hook + architecture) and 11 (adoption + residual risks) are yours. You own `test_demo_storyline.py`, and `make reset-demo` + `make warm` 10 minutes before stage. Your evidence shows in beat 1 (`make fence` 7/7), beat 5 (header `v18 · 2/2 replicas`, self-test GAP), beat 6 ("S4 EXPOSED since v19", posture capped at 70) and beat 10 (self-test, GAP vs FAIL). Q&A: "curl `host.docker.internal:11434` from the agent container?" (`reports/fence.json`), "Can the agent reach approvals or policy?" (C35 + fence test), "Isn't this the Claude apps gateway?" (§2.4 table), "What does it not stop?" (§14.2), "How do you know the tests exercise each control?" (meta-tests).

**First 60 minutes (H0:00-H1:00, while chairing the kickoff).**
- [ ] Before H0: contracts drafted as text/schema only (no code; Q16) and the fence-probe script drafted (by name and raw IP; DMR target if enabled).
- [ ] H0:00 open the kickoff; get Q2, Q4 and Q15 answered.
- [ ] H0:30 create the repo per spec §3.9: `CLAUDE.md` (the 10 rules), CODEOWNERS (`contracts/` → L), CI (unit + schema checks on fixtures, events and policies, < 3 min).
- [ ] Commit `contracts/` after sign-off. Compose with the 6 networks and `fence-probe` on `agents`.
- [ ] H0:45 fence probe on every demo Mac → `reports/fence.json`; on a leak, apply the ladder.
- [ ] H1:00 declare CF. Next: build `aicl-pybase` from the real `uv.lock` and `docker save` it to both USB sticks; `tools/make_fixtures.py` → `contracts/fixtures/api/*.json` + `events/*.json` + `stream.jsonl` for F by H1:30; start L2 against `case.schema.json`.

**Sleep:** a 90-min nap H18:00-H19:30, after PDF v1 (H17:00) and the IC5 clean room, plus an optional 30-min nap before IC3 if the gate is green early. You are awake at every checkpoint from CF to Submit and at every rehearsal (H21-H24). Plan (a): a 60-min nap H15:30-H16:30, after submitting.

---

## 5. Card A: gateway core and streaming

**Mission.** Build the stateless data plane every request passes through: policy engine with hot reload, identity, run tokens, pipeline, streaming holdback, `lb` with two replicas, and `mock-llm`.
**Read first:** spec §3.5(a)(c), §5.1-5.2, §5.5, §5.7, §6 (all), §7.3 step 1, §11.2.

**You are done when (P0):**
- **Plan (a)** (deadline 11:00 Oct 4, the default until confirmed): follow `docs/09-plan-a-p0-lite.md` §3.3 lane tables instead of the WP times below.
- **IC1 (H5), walking-skeleton steps 2, 3 and 7:** the AWS-key request returns `x-aicl-decision: redact`, an event ID and `Server-Timing`; `vk_ola` + `sim/gpt-4.1` → 400 `model_not_allowed`; an unknown key → 401; a `tools/mint_jwt.py` JWT for alice is accepted; `C06_secrets.mode: block` flips the verdict within 2 s with `x-aicl-policy` bumped.
- **IC2 (H8):** streaming through the gateway against the mock; `gw-2` behind `lb` with both shas in `/api/replicas`; `/v1/runs` mints tokens and the fallback run works; reload verdict flip < 2 s on 2/2.
- **H12:** forged, absent or rotated run tokens land in the tainted fallback run; the LLM-edge C14/C24 hook is live with D (A5 full, H11); C27 canary in (A7).
- **IC4 (H15):** C01, C02, C12, C26, C27, C30, C32 and C36 each have ≥ 1 POS + ≥ 2 NEG passing; every §5.7 row is asserted; the policy-edit rows of the judge-poke matrix (§10.8) are green.

**Owns.**
- **Files:** `services/gateway/`, `services/mock_llm/`, `src/aicl/core/{policy,pipeline,identity,runs}/` (runs = token mint/verify/bind + fallback run), `src/aicl/proxy/` (LLM edge + streaming), `deploy/caddy/Caddyfile`, the pydantic model behind `contracts/policy.schema.json`, `tools/mint_jwt.py` (v1.1; IC1 step 3).
- **Components:** `lb`, `gateway` ×2 (core, streaming, identity), `mock-llm`.
- **Controls:** C01, C02, C12 (holdback mechanics + URL extraction; B owns the rule packs and allowlist semantics), C26, C27, C30, C32, C36, and C33's identity half (mint, verify, agent binding, sticky fallback).
- **Endpoints:** `POST /v1/chat/completions`, `GET /v1/models`, `GET /v1/me` (route; C supplies budget data), `POST /v1/runs`, `GET /healthz`, gateway `:9090` (metrics + state, core only); every `x-aicl-*` response header and `Server-Timing`.
- **Machinery:** verdict cache, Prometheus metrics, Valkey version map (`get-or-incr`), replica heartbeats, `policy_change` events.

**P0 work packages (spec §13.2).**

| WP | What | Est. h | Needs (from, by) | Delivers (to, by) |
|---|---|---|---|---|
| A1 | app factory, settings, `/healthz`; `mock-llm` v0 (OpenAI SSE, directives, `sim/*` pricing, `/_mock/calls`; v1.1: the Ollama-native mock moved to P1 #11) | 1.5 | contracts | L2, H3 |
| A2 | policy engine: pydantic model → `policy.schema.json`, limits, watch + 1 s sha poll, compile protocol, LKG, version map, heartbeat, `policy_change` | 2.5 | contracts | all detectors, H4.5 |
| A3 | identity (vk + JWT/JWKS + `group_map`), effective rights, C02 + `/v1/models` + `/v1/me`, C26, C36, **`/v1/runs` + run tokens + sticky fallback**; `tools/mint_jwt.py` (v1.1, IC1 step 3) | 2.5 | C1 | IC1 (keys/models/JWT) H5; runs **H8** |
| A4 | pipeline engine: tiers, combine, short-circuit, redaction apply, C32 fail modes, verdict cache, Server-Timing, Prometheus | 2.0 | B2 | minimal H5, full H9 |
| A5 | streaming: SSE pass-through, **trigger-aware holdback**, C12 sanitizer (holdback mechanics + URL extraction; B owns the rule packs and allowlist semantics), tool-call buffering, **LLM-edge C14/C24 hook** (pair with D), `include_usage`, termination, trailing timing comment, `stream_mode: buffer` | 4.0 | D3, D4 | basic stream at IC2 H8; full H11 |
| A6 | `lb` Caddyfile + `gw-2` + heartbeat wiring | 0.5 | A2 | IC2 H8 |
| A7 | C27 canary: inject, trigger, tool-arg check | 0.5 | A5 | H12 |

**P1 (spec §13.3), top-down once green (your lane is 13.5 h of P0, so this is plan (b) or early-finish time):** #1 `make bench` → `reports/perf.md` + console perf strip (A, 1.0) · #11 with C: the `mock-llm` Ollama-native `/api/chat` endpoint (moved from A1 in v1.1) · #10 Anthropic `/v1/messages` (tool_result-in-user handled) + managed-settings clip (A, 2.5) · #13 C27 n-gram overlap + C16 datamark toggle (A + B, 1.0) · #15 `/v1/guard` + `/v1/decide` + Claude Code `PreToolUse` hook script (A, 2.0).

**Libraries and licences that matter here.**
- Python 3.12, FastAPI 0.142, uvicorn + uvloop, httpx, pydantic v2 (`extra="forbid"`), ruamel.yaml, watchfiles, google-re2, PyJWT, cryptography, valkey-py, prometheus-client (all MIT/BSD/Apache-2.0); Caddy 2 (Apache-2.0) with `flush_interval -1`.
- **Ollama ≥ 0.14** (MIT). We proxy its OpenAI `/v1` path, which carries **no** duration fields; those exist only on native `/api/chat` (FACT-CHECK A2).
- P1 #10: Ollama's `/v1/messages` does not support `count_tokens`, `tool_choice` or `cache_control`, so stub or strip them (FACT-CHECK A1). Managed settings: `permissions.disableBypassPermissionsMode` is the **nested string** `"disable"`; `allowedProviders: ["customEndpoint"]` needs Claude Code ≥ 2.1.285 and `ANTHROPIC_BASE_URL` pinned in the same managed `env` block (FACT-CHECK B3). P1 #1: `oha` and Locust (MIT).

**Top 5 gotchas.**
1. **Mutate JSON in place.** Never re-serialise a request through a strict schema: it drops unknown fields and breaks Claude Code's beta-header pairing (CLAUDE.md rule 3, R7).
2. **Never a TCP reset.** Also never `overloaded_error` or Anthropic `stop_reason: refusal`. A mid-stream block ends with `finish_reason: "content_filter"` + `[DONE]`; while holding, send `: hold` every 2 s. `Server-Timing` carries pre-flight stages only, because headers leave before the first byte (§5.5, §5.7, J2 X4).
3. **Hot reload.** Watch the **directory, not the inode** (editors swap files), plus a **1 s sha256 poll** (Docker Desktop bind mounts drop events). Before parsing, reject > 1 MB, > 10k nodes, anchors/aliases and non-UTF-8. Patterns compile with RE2 only: non-RE2 syntax (lookaround, backreferences) is rejected, while a ReDoS shape such as `(a+)+$` is **accepted**, because RE2 is linear-time (Python `re` stalled 380-740 ms on it). Keep LKG on any failure. Heartbeats are the only truth for "what is loaded". On Kubernetes the same rule applies: mount the ConfigMap as a directory, never with `subPath`, which never updates (§6.5-6.6, §3.8).
4. **Run tokens are never client-minted.** Only `POST /v1/runs` with a **user** credential mints one; agent keys cannot. Missing, forged or mismatched → sticky fallback run `fb:{principal}:{agent}` that keeps its taint. `X-AICL-Agent` is attribution only (C33, J1 R6, J2 X7).
5. **Settle under `asyncio.shield`.** Starlette cancels the generator on disconnect, so settle in `finally` under `asyncio.shield`, charging `input + ceil(emitted_chars / 3)`, never 0. Keep CPU off the event loop (ONNX in `guard`, hashing in the background writer). On the Anthropic wire (P1), `tool_result` blocks sit **inside `role:user`**: classify them as tool content, never as trusted user text (J1 R6).

**Tests you must write.**
| Family | Target |
|---|---|
| C01, C02, C12, C26, C27, C30, C32, C36 (≥ 1 POS + ≥ 2 NEG each) | ≥ 24 |
| Hot reload & tamper: flip < 2 s on 2/2 (time recorded); typo key, YAML bomb, non-RE2 regex (lookaround / backreference), failing rule vector → rejected with LKG kept; `(a+)+$` → accepted and linear-time; relaxation → `control_weakened`; delete `models:` → everything denied | ≥ 8 rows in `tests/integration/test_live_edits.py` |
| Wire contract (§5.7): 401, 403 `agent_disabled`, 400 codes, 413, 429 `rate_limited`, 200 `content_filter`, mid-stream block, removed tool call, response headers | one case per row |
| Output cases with the "split across stream chunks" mutator (C12, C06/C07 on output, C27) | per output NEG |
| Run-token escape (forged, absent, rotated), shared with L4 | 3 |

**Demo and Q&A.** Support: beat 1 (400 + "granted to quant-analysts" hint, `/v1/me`), beat 2 (`Server-Timing`, T1 = 2 ms), beat 3(d) (canary C27 blocks the Polish prompt extraction), beat 5 (`v18 · 2/2 replicas · applied 0.6 s`), beat 6 (typo and lookahead regex rejected, LKG kept; `(a+)+$` accepted and harmless: "ReDoS can't happen here"), beat 7 (C26: 403 on every edge), beat 10 (perf strip, P1). Q&A is yours on architecture and performance: p95 overhead (`reports/perf.md` only), "kill one gateway mid-stream?" (recorded drill), "replica 2 stale?" (`/api/replicas`, amber after 10 s), "Entra ID / AD groups?" (JWT `groups` claim → `group_map`), "We run Envoy/Apigee" (`/v1/decide`, P1), "I typed `enabeld: false`" (strict schema, rejected), "I deleted `models:`" (permissions opt-in → deny).

**First 60 minutes (H1:00-H2:00).**
- [ ] `services/gateway`: app factory, settings, `/healthz` (A1).
- [ ] By H1:30, a contract-shaped stub: `/v1/chat/completions` returning the §5.7 headers (`x-aicl-decision`, `x-aicl-event-id`, `x-aicl-policy`, `x-aicl-replica`).
- [ ] `mock-llm` v0: OpenAI chat (non-stream + SSE), `[[mock:reply:…]]`, `/_mock/calls` (L2 needs it by H3).
- [ ] Pydantic policy model (`extra="forbid"`) that loads the §6.2 `policy/policy.yaml` and matches `contracts/policy.schema.json`.
- [ ] Agree the ledger stub interface with C (C1 stub at H2), so A3 is not blocked.

**Sleep:** H19:30-H22:00 (2.5 h), after clean-room fixes and the video; you rejoin for the last rehearsal. Plan (a): 90 min, H13:30-H15:00.

---

## 6. Card B: deterministic detection, feed, audit

**Mission.** Ship the deterministic tier (C06-C09), the destination extractor C24 depends on, the signed external feed, and the tamper-evident audit chain with the read APIs over it.
**Read first:** spec §5.3, §5.6 (destinations), §8, §9.1-9.2, §9.6, §11.3 (B rows), §6.6.

**You are done when (P0):**
- **Plan (a)** (deadline 11:00 Oct 4, the default until confirmed): follow `docs/09-plan-a-p0-lite.md` §3.3 lane tables instead of the WP times below.
- **IC1 (H5):** the alice event validates against `contracts/audit-event.schema.json` and `aicl audit verify` passes; C06 turns `AKIAIOSFODNN7EXAMPLE` into `[SECRET:aws_access_key]`.
- **H4.5:** rule-engine stub (frozen `contracts/detector.py` interface) and a static dev feed bundle file (unsigned, sha-pinned) up, for D3a and IC1.
- **H7:** `destinations.py` (extract, canonicalise, TR39 skeleton) handed to D. **IC2 (H8):** signature engine with ≥ 5 rules. **H8:30:** `/api/threats` and `/api/events/*` live for F. **H9:30:** C07 (B6) live, **before** the feed service, for IC3 beats 2 and 4.
- **H12:30:** signed feed (B5). IC3 runs on the dev bundle; the signed feed is first needed at IC4 (beat 8, feed suite).
- **IC4 (H15):** feed suite and audit suite green; C06, C07, C08, C09, C19, C20 and C25 each have ≥ 1 POS + ≥ 2 NEG; the ~40 feed vectors pass; integrity, export (JSONL/CSV) and policy-history endpoints live (H13-H14).

**Owns.**
- **Files:** `src/aicl/audit/`, `src/aicl/detectors/` (C06, C07, C08 views, signature engine), `src/aicl/core/destinations/`, `src/aicl/feed/` (gateway client), `services/feed/` (+ `feedctl`), `feed/rules/*.yaml` (seed SIG-0001..0021), the implementation behind `contracts/canonical.py`, the checkpoint signer and DuckDB queries inside `services/control/`.
- **Components:** `feed`; the per-replica audit writer in the gateway; the `witness` volume (written by `control`).
- **Controls:** C06, C07, C08, C09, C19, C25, and **C20 (v1.1): the `http_request` packs and the Ollama-admin-API floor**, while D wires the call-site hook. You also own the rule engines that other controls use: `url_ioc` and the allowlist semantics (C12; A owns the holdback mechanics and URL extraction), the SIG-0017 regex pack (C17), `pickle_globals`/`hash` (C18). `package_ioc` is P1 #17 and is skipped and listed until then.
- **Endpoints:** `/api/threats`, `/api/events/{id}`, `/api/events/{id}/related`, `/api/kpis`, `/api/policy/history` (v1.1, from L), `/api/integrity` + `POST /api/integrity/verify`, `/api/export` (JSONL/CSV), the `/api/runs/{run_id}` route (D supplies the data). `/api/feed` moved to P1 #6.
- **CLI / make:** `aicl audit verify`, `make feed-publish`.

**P0 work packages (spec §13.2).**

| WP | What | Est. h | Needs (from, by) | Delivers (to, by) |
|---|---|---|---|---|
| B1 | audit event builder, per-replica chain writer (bounded queue, batched fsync), `canonical.py`, `aicl audit verify` | 2.5 | contracts | skeleton **H3.5** |
| B2 | C06 secrets (~30 patterns + entropy) | 1.0 | A2 compile hook | skeleton H4.5 |
| B3 | signature engine: regex / keyword / http_request / url_ioc / hash / pickle_globals (v1.1: `package_ioc` moved to P1 #17 and is skipped and listed until then); `applies_to` mapping; unknown types skipped; **C20 rules** (`http_request` packs compiled into hard exclusions + the Ollama-admin-API floor) | 1.5 | frozen `contracts/detector.py` | rule-engine stub + static dev feed bundle file (unsigned, sha-pinned) **H4.5** (D3a, IC1); engine to D3, C5, H7 |
| B4 | C08 multi-view normaliser + `destinations.py` (extract, canonicalise, TR39 skeleton). Order inside B4: the `stripped`, `tag_decoded`, `nfkc` and `skeleton` views first (≈ 45 min, so S4's `audit@evil.test` is extracted from `tag_decoded` and L4's homoglyph case has `skeleton`), then `destinations.py` (to D by H7), then `decoded[]` and `folded` (H8:30) | 2.5 | — | extractor to D by **H7**; views H8:30 |
| B6 | C07 checksum PII + PL false-positive guards (v1.1: before B5) | 1.0 | B4 | **H9:30** (IC3 beats 2 and 4) |
| B5 | feed service (`feedctl publish`: validate, vectors, serial, sign; `GET /bundle`) + gateway client (verify, **persisted serial**, expiry/stale, vectors, swap, `feed_update`, local override tighten-only) | 2.5 | B3, B6 | **H12:30** (v1.1: IC3 runs on the dev bundle; the signed feed is first needed at IC4, for beat 8 and the feed suite) |
| B7 | in `control`: `/api/threats`, `/api/events/*`, `/api/kpis` (DuckDB, threats by H8:30); `/api/policy/history` (v1.1, from L6); checkpoint signer + witness; `/api/integrity` + verify; `/api/export` (JSONL/CSV) (v1.1: `/api/feed` moved to P1 #6) | 2.5 | L3; L's derived policy diff | threats H8:30; policy history H13; rest H14 |

**Order (v1.1):** B6 (C07) comes before B5 (feed service), so C07 lands by H9:30 for IC3 beats 2 and 4. IC3 runs on the static dev feed bundle, so the signed feed may land at H12:30.

**P1 (spec §13.3), only if you finish P0 early (13.5 h) or in plan (b):** #4 OCSF-shaped export: 6003 / 2004 / 3004 + `record_integrity` (B, 1.5, `format=ocsf`) · #6 `/api/feed` for the Agents & MCP page · #13 C27 n-gram overlap + C16 datamark toggle + a nested-quantifier lint (warning) (A + B, 1.0) · #17 `package_ioc` rule type (B, 0.5).

**Libraries and licences that matter here.**
- `google-re2` (BSD) for every editable pattern; `pyahocorasick` (BSD-3) over `folded` + `raw`; `rfc8785` + SHA-256; `cryptography` Ed25519; DuckDB (MIT) for `read_json` over the JSONL; `jsonschema`.
- stdlib `unicodedata` + vendored Unicode `confusables.txt` (Unicode licence); ~30 gitleaks-derived secret patterns (MIT, attributed). **No Presidio** (the `pl`-language trap and the image weight).
- OCSF (P1): target **1.9.0**. `ai_operation` dates from 1.8.0; `record_integrity` (`prev_event`, `chain_uid`, `attestation_list`) is new in 1.9.0. Say "OCSF-shaped" until the validator passes (FACT-CHECK C6).

**Top 5 gotchas.**
1. **RE2 only, never Python `re`.** RE2 rejects lookaround and backreferences, so R2's lookahead SIG-0002 becomes a `url_ioc` rule. A ReDoS shape like `(a+)+$` compiles and runs in linear time, so it is accepted ("ReDoS can't happen here"). Unknown rule types, rules above the gateway's `metadata.tier` and unknown `applies_to` values are **skipped and listed**, never fatal. The per-type match fields (`extract`, `host_not_in`, `json_field`, `not_regex`, `query_has`, `field`, `topics`, `exemplar_groups`, …) are in spec §8.4 (CLAUDE.md rule 2, §8.2, §8.4).
2. **One canonicaliser.** The writer and the verifier both use `contracts/canonical.py` (JCS), so hashing never drifts. `prev_hash` sits inside the hashed body. Only `control` holds the checkpoint key, never a gateway. Say "tamper-evident", never "tamper-proof" (§9.2, J1 R9).
3. **Pseudonyms use a keyed HMAC.** The key is a gateway secret outside the audit volume, because a plain hash of a PESEL can be brute-forced. Snippets are post-redaction and ≤ 512 chars; a test checks that no raw PESEL/IBAN appears in any snippet (§9.1).
4. **Feed publish is explicit.** `feedctl publish` runs on demand, never on file save. `last_serial` is persisted per `key_id` in Valkey (AOF), so a gateway restart followed by a serial-41 replay is rejected. An expired bundle turns stale (amber) and is never unloaded. Local overrides only tighten and are tagged `origin: local-unsigned` (§8.2-8.3, J1 must-fix 12).
5. **PII and destinations.** C07 validates checksums (PESEL, IBAN mod-97, Luhn, NIP mod-11) and carries Polish false-positive guards; `44051401358` (bad checksum) must pass through untouched. `destinations.py` extracts from **every** view, including `tag_decoded`, and canonicalises (IDNA, lowercase, `+tag` strip, IBAN mod-97, E.164); membership is a set lookup, never a substring match. `control` reads only complete lines from JSONL that is still being written (R22, owners L / B).

**Tests you must write.**
| Family | Target |
|---|---|
| C06, C07, C08, C09, C19, C20, C25 (≥ 1 POS + ≥ 2 NEG each; FP guards: security-education prompts, Polish diacritics, failing checksum; C20 cases with D) | ≥ 21 |
| Feed rule vectors (two per rule, SIG-0001..0021) | ~40 |
| Feed suite: publish applies < 5 s; tampered bundle, rolled-back serial and serial replay after a gateway restart rejected; expired → stale; unknown rule type skipped and listed | 6 |
| Audit suite (`test_audit_completeness.py` + verify): one event per request; chain verifies; an edited line fails at the right `seq`; recompute-after-edit caught by checkpoints; truncation caught; no raw PESEL/IBAN in snippets | 6 |
| Obfuscated NEG cases, hand-written at P0 (base64, zero-width, Unicode tags, pre-translated Polish; the full mutator matrix incl. homoglyph, leetspeak and letter spacing is P1 #8); deterministic controls must be **100% invariant** | per NEG |
| Exploit Museum rules: E6 (SIG-0002), E7 (SIG-0001), E8 (SIG-0012), E10 (SIG-0009/0016) | 4 exhibits |

**Demo and Q&A.** Own: beat 8 as the "security analyst" (`feed/rules/90-judge.yaml` + `make feed-publish` → header `feed #43 ✓` in < 5 s; a hand-edited byte → rejected, red feed cell; C's pickle scan and the C20 Ray deny happen in the same beat). Support: beat 2 (`[PL_PESEL] [IBAN] [SECRET:aws_access_key]`, bad checksum untouched), beat 3 (`decoded[0]` + `folded` views; Evidence reveals the Unicode-tag sentence), beat 4 (Run tab: `audit@evil.test` came from `web_fetch.1`, tag-decoded view), beat 10 (Export CSV; Verify names the edited `seq`). Q&A on guardrails and the feed: "What if the threat-intel server serves an old bundle?" (persisted serial), "I recomputed the whole chain" (signed checkpoints), "Polish detection?" (measured slices only, §2.5).

**First 60 minutes (H1:00-H2:00).**
- [ ] Audit event builder against `contracts/audit-event.schema.json` (with the H1 deltas), using `contracts/canonical.py`.
- [ ] Chain writer skeleton: bounded queue (10k), batched fsync (100 ms / 200 events), `audit/gw-N-YYYY-MM-DD.jsonl`, `seq` + `prev_hash` + `hash`.
- [ ] By H1:30, stubs: a no-op detector implementing `contracts/detector.py` and a static dev feed bundle (IC1 needs `feed` up).
- [ ] Draft the ~30 C06 patterns in RE2 syntax, plus runtime fixture generators (`{{ secret("aws") }}`).
- [ ] `aicl audit verify` skeleton (seq, hash, prev_hash).

**Sleep:** H15:30-H18:00 (2.5 h), right after IC4. Merge or abandon open work first. Clean-room items in your lane are flagged off or fixed by A/C. Plan (a): 90 min, H11:00-H12:30.

---

## 7. Card C: models, budgets, semantic, artifacts

**Mission.** Make budgets hard (Valkey Lua reserve → settle across replicas), run the semantic tier (guard sidecar, multilingual kNN, C11 topic pack), gate model artifacts, and keep the local models and the demo Mac healthy.
**Read first:** spec §5.1-5.4, §7 (all), §8.4 (`semantic`), C18 row in §4, §11.3 spend shapes, FACT-CHECK A2-A6, D4, D6.

**You are done when (P0):**
- **Plan (a)** (deadline 11:00 Oct 4, the default until confirmed): follow `docs/09-plan-a-p0-lite.md` §3.3 lane tables instead of the WP times below.
- **Latency (H2):** `reports/perf-h2.md` holds classifier and kNN p95 per window count, measured on the demo Mac, and the H2 rule has been applied.
- **IC1/IC2:** real Lua ledger by H5 (alice's settled spend visible in Valkey and `/v1/me`); by H8, real reserve/settle including a 429 `billing_error` with **zero upstream calls**.
- **H12 gate:** `tests/integration/test_budget_race.py`: 200 concurrent requests across both replicas at a cap worth 50 → **exactly 50 admitted, 0% overshoot**.
- **H4.5:** `GUARD_ENGINE=stub` up for IC1 (the first 0.5 h of C3). **H6:** the gateway-side guard client (calls `/v1/inspect` with the §5.1 deadline and hands errors to A4's C32 fail modes).
- **H9-H11:30:** guard ONNX engine with windows and batching; multilingual kNN + EN/PL exemplars + C11 topic pack.
- **IC4 (H15):** budget suite green; C18 gate with E1 fixtures (H14); spend endpoints and seeded history (`tools/seed.py`, H13); C03, C04, C05, C10, C11 and C18 each have ≥ 1 POS + ≥ 2 NEG.

**Owns.**
- **Files:** `src/aicl/budget/` (Lua reserve/settle, leases, concurrency ZSET, GCRA, price table, client), `deploy/valkey/users.acl`, `services/guard/` + the gateway-side guard client, `src/aicl/artifacts/`, `tools/seed.py` (v1.1), the EN+PL exemplar and topic-pack content (SIG-0010, SIG-0018, SIG-0019) that ships in B's feed, spend queries inside `services/control/`, `tests/integration/test_budget_race.py`, `reports/perf-h2.md`. (`tools/doctor.sh` moved to L in v1.1; you supply the Ollama and ONNX checks.)
- **Components:** `valkey`, `guard`, host Ollama (agent lane `:11434`; guard lane `:11435` at P1).
- **Controls:** C03, C04, C05 (numbers and ledger side; D owns the per-run counters), C10, C11 (P0 floor: topic pack + harm kNN), C18. **Tool units:** you own the `tool_units` ledger unit (C1's Lua); D wires the per-tool `cost_units` at the call site (D3b).
- **Endpoints:** guard `POST /v1/inspect`, `POST /v1/artifacts/scan` + `aicl scan <file>`, `/v1/me` data, `/api/spend/summary`, `/api/spend/burndown`.
- **Make:** P1 `make eval`. (`make doctor` and `make warm` moved to L8 in v1.1.)

**P0 work packages (spec §13.2).**

| WP | What | Est. h | Needs (from, by) | Delivers (to, by) |
|---|---|---|---|---|
| C1 | Valkey ACL/requirepass; Lua reserve/settle over all scopes and units (incl. `tool_units`), leases, concurrency ZSET, GCRA, price table, warn thresholds, ledger-down modes | 3.0 | contracts | stub H2, **real H5** |
| C2 | C04 hygiene (`max_tokens`/`n`/options/size), compute-ms wall clock, `/v1/me` data, 429 contract, run USD hook (v1.1: the per-tool cost-unit hook was double-counted with D3b and now lives only there) | 1.0 | C1 | H6.5 |
| C3 | `guard`: **`GUARD_ENGINE=stub` first (0.5 h)**, then ONNX engines (protectai-v2 baked; PG2-86M optional), windows + batching, process pool, `/v1/inspect`, health; the **gateway-side guard client** (calls `/v1/inspect` with the §5.1 deadline and hands errors to A4's C32 fail modes); **H2 latency measurement on the demo Mac** | 3.0 | pre-exported ONNX | stub **H4.5** (IC1), client H6, ONNX **H9** |
| C4 | multilingual MiniLM-L12 kNN; EN+PL exemplars (injection, jailbreak, harm); **C11 topic pack** EN+PL | 2.5 | C3, B3 | H11:30 |
| C5 | C18 artifact gate lite: pickle allowlist walk, fail-closed, torch zip, safetensors header, hashes, `/v1/artifacts/scan` + `aicl scan` + fixture generator | 2.0 | B3 (pickle_globals) | H14 |
| C6 | in `control`: `/api/spend/summary`, `/api/spend/burndown`; **cross-replica race test** (gate) + ledger-down test | 1.5 | C1, A6 | race H11; spend H13 |
| C7 | v1.1: `make doctor` / `make warm` moved to L8; C supplies the Ollama and ONNX checks | — | — | — |
| C8 | `tools/seed.py` (v1.1, previously unowned): 7 days, ~20k events, `synthetic: true`, written with B1's event builder, org shape per Q12 | 0.5 | B1 (H3.5), Q12 (H5) | F (Overview charts), C6, H13 |

**P1 (spec §13.3), top-down once green (your lane is 13.5 h of P0, so this is plan (b) or early-finish time):** #2 C11 guard-LLM lane: `llama-guard3:1b` on `:11435`, in parallel with upstream, gating the first token; Qwen3Guard-Gen-0.6B only if the spike passed (C, 2.5, `C11_content_safety.guard_llm.enabled`) · #3 `make eval` + calibration + Polish slice + held-out numbers (C + L, 2.0) · #11 native Ollama `/api/chat` compute durations + `downgrade` breach action, with A's Ollama-native mock endpoint (C + A, 2.0, `models.*.downgrade_to`).

**Libraries and licences that matter here.**
- **`valkey/valkey:8` (BSD-3), not Redis 8**, which is tri-licensed RSALv2/SSPLv1/AGPLv3 (FACT-CHECK D4); valkey-py.
- onnxruntime (MIT), tokenizers (Apache-2.0).
- **Default classifier `protectai/deberta-v3-base-prompt-injection-v2` INT8** (Apache-2.0, ungated, baked into the image): **English only, does not detect jailbreaks**, not for system prompts (FACT-CHECK A5).
- **Llama Prompt Guard 2 86M** INT8: Llama 4 Community Licence, **gated** (request HF access), **text-only, so fine for an EU team**, **not evaluated on Polish**; ship the "Built with Llama" notice (FACT-CHECK A4).
- `paraphrase-multilingual-MiniLM-L12-v2` INT8 (Apache-2.0) for kNN.
- **Ollama ≥ 0.14**, native on macOS: **Docker on macOS has no Metal passthrough** (FACT-CHECK A6). Models: `qwen3:8b`, `qwen3:4b` (Apache-2.0); **`llama-guard3:1b` is the official tag** (Llama 3.2 CL, text-only).
- **Qwen3Guard is community-only** on Ollama (`sileader/qwen3guard:0.6b`); Qwen3Guard-Stream needs transformers/vLLM. Never Llama Guard 4 12B or Llama Guard 3 11B-Vision: the EU multimodal clause covers them (FACT-CHECK A3-A4).
- C18: stdlib `pickletools.genops`. picklescan-style denylists are not a boundary (repeated CVSS 9.3 bypasses); fickling is LGPL-3.0, so don't bundle it (FACT-CHECK D6).

**Top 5 gotchas.**
1. **Ollama runs natively on the Mac**, reached via `host.docker.internal`, with `OLLAMA_KEEP_ALIVE=-1`, `OLLAMA_NUM_PARALLEL=1` and `OLLAMA_CONTEXT_LENGTH=16384`. The `/v1` path has no `*_duration` fields, so P0 compute-ms is **wall clock** from dispatch to the final chunk (residual T15; FACT-CHECK A2, J2 X3).
2. **The ledger is all-or-nothing.** One `EVALSHA reserve.lua` covers every scope (org → pool → seat → agent → run). Settle in `finally` under `asyncio.shield`, never 0. Lease TTL = `max_wall_s`. Estimate input as `ceil(chars / 2)` (chars/4 undercounts Polish by 22-44%). Reserve `n × max_tokens` or clamp `n`. Strip `options`, `keep_alive`, `num_ctx` and `num_predict`. Unknown models cost $5 / $25 per Mtok, never 0 (§7, J1 R7).
3. **Valkey needs `requirepass` + ACL users `gw` and `control`,** with `default` disabled, AOF on, and only on `core`. The ledger-down mode for external models is 503 `spend_limit_unavailable`; local models are capped at 10% of the seat cap per replica with `degraded` set (§5.4, J1 R12).
4. **Sliding windows beat the padding bypass.** 512-token windows with stride 448; every window of every distinct view goes into one batched ONNX call; caps of 8 (prompt) / 16 (tool result) emit `unscanned_tail` (taint + flag under balanced). Semantic errors **fail to taint**, never open, on untrusted input. ONNX runs in the guard process pool, never on the gateway loop (§5.3-5.4, J1 R2, R10).
5. **Claim only what you measured.** H2 rule: if one window of the default classifier exceeds 150 ms p95 on the demo Mac, switch the demo laptops to PG2-86M; if that is still too slow, set `window_tokens: 256`. Never claim indirect-injection or Polish recall. Pickles: scan, never load; any parse error blocks (nullifAI); an unknown format blocks (§5.1, §2.5, C18).

**Tests you must write.**
| Family | Target |
|---|---|
| C03, C04, C05, C10, C11, C18 (≥ 1 POS + ≥ 2 NEG each; semantic cases use the deterministic `GUARD_ENGINE=stub` markers) | ≥ 18 |
| Budget suite: pre-flight 429 with zero upstream calls; `max_tokens ≤ 0` → 400; `n=50` clamped; Ollama options stripped; warn thresholds; **race 200 → exactly 50**; 4th identical call blocked; ledger down → external 503 / local capped | ≥ 8 |
| Exploit Museum: E1 (malicious + truncated pickle, generated at session start, scanned never loaded; safetensors twin allowed), E9 (`n=50`, `max_tokens: -1`, `num_ctx: 131072`, identical tool loop) | 2 exhibits |
| Polish slice (Q8, with D, H12-H14; feeds P1 `make eval`) | ~100 prompts |

**Demo and Q&A.** Support: beat 1 (429 `billing_error`, `x-should-retry: false`, "resets 00:00 UTC"; `/v1/me` shows 1,950/2,000), beat 3 (score vs `block_at`; stub-guard fallback), beat 8 (`aicl scan evil.pt` blocked on the `posix.system` GLOBAL, truncated pickle fails closed, safetensors allowed), beat 9 (`n=50` / `max_tokens: -1` → `400 invalid_max_tokens`; burn-down; race tile "200 fired, 50 admitted, 0% overshoot, 2 replicas"), beat 10 (`docker compose stop guard` → DEGRADED + fail-to-taint counter). Q&A is yours on budgets and models: "Stop Valkey?" (recorded clip + fail-mode table), "Classifier down for 10 minutes at peak?" (fail-to-taint), "Two gateways, one budget?" (race test), "Why wall-clock compute?" (FACT-CHECK A2), "Which classifier, and why English-only by default?" (ungated mentor path; PG2 when present).

**First 60 minutes (H1:00-H2:00).**
- [ ] On the demo Mac: Ollama ≥ 0.14 native; `qwen3:8b`, `qwen3:4b` and `llama-guard3:1b` pulled; the three `OLLAMA_*` env vars set.
- [ ] Measure classifier (protectai-v2 INT8; PG2-86M INT8 if present) and MiniLM kNN p95 per window count → `reports/perf-h2.md` **by H2:00**; apply the H2 rule.
- [ ] `valkey/valkey:8` service with `requirepass`, `deploy/valkey/users.acl` (`gw`, `control`, `default` off), AOF volume, `core` only.
- [ ] Ledger stub interface (reserve/settle signatures + the §7.6 429 body) to A **by H2**.
- [ ] Plan the `GUARD_ENGINE=stub` (deterministic marker-driven scores) for **H4.5** at the latest: IC1 needs `guard` healthy.
- [ ] Q5 (Qwen3Guard spike) decided by H2; the default is `llama-guard3:1b`.

**Sleep:** H19:30-H22:00 (2.5 h), after clean-room fixes (eval is P1); you rejoin for the last rehearsal. Plan (a): 90 min, H13:30-H15:00.

---

## 8. Card D: agents, MCP, taint

**Mission.** Mediate every agent→MCP call in the gateway, run the demo servers in no-egress sandboxes, and build C24/C33 so a hijacked agent with every detector off still cannot exfiltrate. **You own the H12 gate.**
**Read first:** spec §3.5(b), §5.6 (all), §6.2 `tools:` / `mcp:` / `destinations:`, §10.3, R6 §4.4 (S1-S8), FACT-CHECK B1-B2.

**You are done when (P0):**
- **Plan (a)** (deadline 11:00 Oct 4, the default until confirmed): follow `docs/09-plan-a-p0-lite.md` §3.3 lane tables instead of the WP times below.
- **D1 (H2.5):** go/no-go decided; the MCP edge forwards `tools/call` to a sandbox HTTP server through our middleware.
- **IC2 (H8):** one MCP `tools/call` blocked by a validator, with an audit event.
- **H11 → H12 gate:** under `policies/test-detectors-off.yaml`, **S4 and S5 exfiltration still denied** by C24/C33 (+ C14 email). S4-POS (the reply to the CRM-derived customer) is allowed with a flag. A paraphrased destination is never trusted; a homoglyph destination → deny + critical.
- **IC4 (H15):** S1-S8 each pass with their allowed twin (S8 loops on `facts_flaky`, now in the §6.2 registry and support-bot's grant); C15 pins/quarantine/diff (`make demo-rugpull`); C31 honeypot → run killed + agent quarantined (403 on every edge); the C20 call-site hook denies B's `http_request` exclusions; C14, C15, C16, C17, C24, C31 and C33 each have ≥ 1 POS + ≥ 2 NEG; `/api/runs/{id}` and `/api/mcp/tools` data live; the scripted-agent CLI (D6) drives the demo terminal.

**Owns.**
- **Files:** `src/aicl/mcp/`, `src/aicl/tools/`, `src/aicl/core/taint/` + run state in `src/aicl/core/runs/` (shared with A: A mints, you hold the state), `services/mcp_demo/` (`mcp-tools`: filesystem, mail, bankdb, web, crm; `mcp-untrusted`: facts, vault), `services/demo_agent/` (`aicl_demo.agent`, scripted S1-S8, and the CLI over case steps, D6, moved from L8 in v1.1).
- **Components:** `mcp-tools`, `mcp-untrusted`, `demo-agent`; the MCP edge inside the gateway.
- **Controls:** C14, C15, C16, C17 (hook), **C24**, C31, C33 (run state + sink half), C05 per-run counters, the C20 call-site hook (B owns the rules), per-tool `cost_units` wiring (C owns the `tool_units` ledger unit).
- **Endpoints:** `POST /mcp/{server}` (+ `GET` for streams); data for `/api/runs/{run_id}` and `/api/mcp/tools[/{name}]`.
- **Make:** `make demo-rugpull`, `make repin`.

**P0 work packages (spec §13.2).**

| WP | What | Est. h | Needs (from, by) | Delivers (to, by) |
|---|---|---|---|---|
| D1 | **MCP spike**: FastMCP 4 `create_proxy` to a remote HTTP server + middleware, *or* a thin JSON-RPC proxy (tools/list, tools/call, local `initialize`, `server/discover`). **Go/no-go at H2.5** | 1.5 | — | **H2.5** |
| D2a | gate-critical demo servers as Streamable HTTP containers: `web` (`ticket-42` with tag-smuggled text), `crm`, `bankdb`, `mail` | 1.5 | D1 | H4 |
| D3a | `aicl.tools` core: registry, labels, risk ceiling/visibility, jsonschema args, SSRF + SQL + email validators | 2.0 | frozen `contracts/detector.py` + B3's rule-engine stub (H4.5), C1 stub (H2); the full engine (H7) drops in behind the same interface | A5, H6:30 |
| D5a | MCP middleware call path: call → tools, C16 result-scan hook, label-based taint marking, vouched hashes | 1.5 | D3a | H8 |
| D4 | **C24/C33 run state + sink matrix + destination sets** (with B's extractor) + spoof + fallback-run semantics; A pairs on the LLM-edge hook | 2.5 | A3, B4 | **H11 → H12 gate** |
| D2b | remaining servers: `filesystem`, `facts` (v1/v2 flag + `facts_flaky` for S8 / beat 9), `vault` (honeypot) | 1.0 | D2a | H13 |
| D3b | path / amount / IBAN / entropy validators, C17 hook, C05 counters, per-tool `cost_units` wiring (C owns the ledger unit), **C20 call-site hook** (≤ 0.5 h; B owns the rules) | 1.5 | D3a, B3 | H14 |
| D5b | C15 pins/scan/quarantine/diff records (+ `/api/mcp/tools` data), C31 honeypot → kill | 1.5 | D2b | H15 |
| D6 | scripted-agent CLI over case steps for the demo terminal (`demo-agent`; v1.1, from L8) | 0.5 | L2 | storyline + demo terminal, H14 |

Load 13.5 h (v1.1: + D6 0.5 h, + the C20 hook 0.5 h in D3b). The separate 1 h of gate slack is gone: if the gate needs H11-H12, the post-gate WPs (D2b, D3b, D5b, D6) slide toward freeze, and the IC4 flag-off rule applies. Start D4 by H8 at the latest (risk R3). D3a builds against the frozen `contracts/detector.py` and B's rule-engine stub (H4.5); the full engine (H7) drops in behind the same interface.

**P1 (spec §13.3), only in plan (b) or if you finish early:** #5 C23 approvals: retry token, args-hash bound, single approver ≠ requester, + console card (D + F, 2.5, `C23_approvals.enabled`) · #9 C34 MCP protocol hardening (D, 1.0, `C34_protocol`) · #12 live `qwen3:8b` agent + promote-to-test-case (D + L, 1.5, CLI flag) · #14 thin agent→agent: kyc-agent as an MCP tool, run-token taint inheritance (D, 1.5).

**Libraries and licences that matter here.**
- **`fastmcp==4.0.10`** (Apache-2.0): use `fastmcp.server.create_proxy(...)`, **not `as_proxy`** (gone in 4.x); policy goes in a `Middleware` subclass (`on_list_tools`, `on_call_tool`, `on_read_resource`, `on_get_prompt`, `on_initialize`, `on_discover`) (FACT-CHECK B2).
- **`mcp` SDK 2.3** (MIT): FastMCP was renamed **`MCPServer`** (`from mcp.server.mcpserver import MCPServer`); `from mcp.server.fastmcp import FastMCP` raises `ModuleNotFoundError` on `mcp>=2`.
- MCP spec **2026-07-28** (stateless) plus the legacy 2025-11-25 `initialize` answered locally; `jsonschema`; `sqlglot` (verb/table + forced `LIMIT`); stdlib `ipaddress` (all resolved IPs, metadata, IPv4-mapped); `rfc8785` for JCS pins and `sha256(tool‖JCS(args))`; openai SDK + mcp client in `demo-agent`; sqlite for `bankdb`.

**Top 5 gotchas.**
1. **Hard spike gate at H2.5.** The FastMCP 4 API may differ from its docs. Keep the middleware logic as framework-free functions in `src/aicl/tools/`, so switching to the thin JSON-RPC proxy costs nothing (risk R5).
2. **MCP 2026-07-28 is stateless:** no `initialize`, no `Mcp-Session-Id`, and `Mcp-Method`/`Mcp-Name` headers on every POST. FastMCP caches tool lists for 300 s, so re-check pins at **call** time (`recheck_on_call: true`, `list_cache_ttl_s: 0`) (FACT-CHECK B1, C15).
3. **Never spawn tool code in the gateway.** Servers run in `sandbox` containers with no egress and are reached over Streamable HTTP from the registry only. Strip the agent's `Authorization` and inject the per-backend credential (no token passthrough) (CLAUDE.md rule 10, J1 R12, J2 X9).
4. **Chat content never mints destinations, whatever its `role`.** On the Anthropic wire `tool_result` sits inside `role:user` (J1 R6). An unvouched `role:tool` message is untrusted, and taint is monotonic. Membership is a set lookup on canonicalised values: a paraphrase → `unknown`, a homoglyph → `spoof` (deny + critical). `web_fetch` is **both** `untrusted_source` and `sink`. The derived-trusted class (CRM) is what keeps the legitimate customer reply working (§5.6, J1 R3/R5/R6).
5. **Wire and fail modes.** An MCP block is a JSON-RPC **result** with `isError: true` and `Blocked by AICL (C24.provenance_untrusted). Ref …`; JSON-RPC errors are only for protocol violations. With Valkey down, sink tools ask/deny and taint is assumed. Annotations can only raise risk. The scripted agent is the default in every beat; never assert on LLM prose (§5.4, §5.7, D30).

**Tests you must write.**
| Family | Target |
|---|---|
| C14, C15, C16, C17, C24, C31, C33 (≥ 1 POS + ≥ 2 NEG each; FP guard e.g. `SELECT … LIMIT 5`) | ≥ 21 |
| C24 provenance classes: user, policy, derived (S4-POS-001), untrusted (S4-NEG-001), unknown → ask, spoof → deny + critical; trifecta (tainted ∧ private_read ∧ unknown) | ≥ 6 |
| MCP S1-S8 (R6 §4.4), each with its allowed twin, driven by raw JSON-RPC and the scripted agent: **S4/S5 at the H12 gate**, the rest at IC4. S7 at P0 expects "approval required (C23 not enabled)" | 16 |
| Exploit Museum: E2 (Ray/Langflow/`/api/pull` via `web_fetch`, with C20), E3 (tool poisoning), E4 (rug pull), E5 (toxic flow) | 4 exhibits |
| C20 cases (hook: you; rules: B): S6 `web_fetch("http://127.0.0.1:11434/api/pull")`, Ray `POST /api/jobs/` | ≥ 3 |

**Demo and Q&A.** You run the agent terminal (scripted `demo-agent` + curl) for every agentic beat: beat 1 curl as ola, **beat 4 ★** (S4: ticket redacted, run tainted, `LIMIT 100` added, mail to `audit@evil.test` DENIED, Run tab provenance), **beat 5 ★** (re-run S4 with detectors off: the model follows the hidden instruction, the mail is **still denied**), beat 7 (poisoned `facts` quarantined → `make demo-rugpull` diff → honeypot → run killed, agent quarantined), beat 9 (`facts_flaky` loop → 4th identical call, circuit open), beat 10 (re-run S4 with `guard` stopped). Q&A: "I turned off your classifier, why is the exfil still blocked?" (destination never came from the user), "Won't taint block legitimate replies?" (derived-trusted + flag), "What about a malicious MCP server?" (sandbox, no egress, Valkey ACL).

**First 60 minutes (H1:00-H2:00).**
- [ ] `fastmcp==4.0.10`: `create_proxy("http://…/mcp")` + a `Middleware` with `on_list_tools` / `on_call_tool` that logs and can deny.
- [ ] One Streamable HTTP server with `mcp` 2.3 `MCPServer`: `web` serving `ticket-42` with Unicode-tag smuggled text, on the `sandbox` network, no egress.
- [ ] Sketch the thin JSON-RPC fallback (tools/list, tools/call, local `initialize`, `server/discover`), so the H2.5 decision is a real choice.
- [ ] Put policy logic in plain functions under `src/aicl/tools/` and `src/aicl/mcp/`, independent of the framework.
- [ ] Copy S4-NEG-001 and S4-POS-001 from spec §10.3 into `tests/cases/` (with L) and validate them against `case.schema.json`.

**Sleep:** H15:30-H18:00 (2.5 h), right after IC4. Merge or abandon open work first. Clean-room items in your lane are flagged off or fixed by A/C. Plan (a): 90 min, H11:00-H12:30.

---

## 9. Card F: console (UI only)

**Mission.** Build the header and 4 P0 pages (Overview with the spend panel, Threats + drawer, Controls & Self-test, Playground), designed with Claude Design and built with Claude Code, on fixtures from H1:30 and on live data as endpoints land.
**Read first:** spec §9.5, §11 (esp. §11.3 shapes, §11.4 SSE, §11.5, §11.6), §12; brief banner, §2-3 (shell, visual language), §7.0 (P0 Claude Design prompt), §9-10 (a11y, perf, mock server); docs/08 §1.10, §2.4, §4.2 (do these before H0).

**You are done when (P0):**
- **Plan (a)** (deadline 11:00 Oct 4, the default until confirmed): follow `docs/09-plan-a-p0-lite.md` §3.3 lane tables instead of the WP times below.
- **H2:** Claude Design visual system + 4 page mocks (F1).
- **IC1 (H5):** SPA scaffold, header, SSE hook + polling fallback, fixtures mode, token login; a live Threats row appears via SSE within 1 s (walking-skeleton step 6), wired **before you sleep at H5:30**.
- **IC3 (H12):** Threats + drawer (Trace, Run, Evidence) on live data; the Playground on fixtures + one live call (fully live by IC4).
- **IC4 (H15):** header + 4 pages on live data. The header turns red or amber within 2 s of a bad edit, a tampered feed, a broken chain, a diverged replica or a guard outage, and greys out after 15 s of SSE silence.
- **After freeze:** screenshots for the PDF (v2 at H20:30, with L), video (H18:00, with A), slide visuals.

**Owns.**
- **Files:** `ui/` (Vite app; `ui/mock_server.py` from brief §10, serving `contracts/fixtures/` directly).
- **Work products:** the Claude Design brief + visual system, seeded-history rendering, slide visuals, screenshots.
- **Pages:** global header, Overview (with spend panel), Threats + decision drawer, Controls & Self-test, Playground.
- **You do not own any endpoint.** Chase these people:

| Page | Endpoints | Owner, live by |
|---|---|---|
| Header | `/api/header`, `/api/replicas`, `/api/stream` | L: stream H5 (Threats rows live over SSE at IC1), header H8 |
| Threats + drawer | `/api/threats`, `/api/events/{id}`, `/api/events/{id}/related`, `/api/runs/{run_id}`, `/api/mcp/tools/{name}`, `/api/export`, `/api/integrity/verify` | B: DuckDB-backed filters and drawer data H8:30, rest H14; D: runs and MCP data, MCP by H15 |
| Playground | `/api/playground/inspect` | L, H10 |
| Overview | `/api/posture`, `/api/coverage`, `/api/kpis`, `/api/spend/summary`, `/api/spend/burndown`, `/api/health`, `/api/policy/history?limit=5` | L: posture/coverage H13, health H8; B: policy history H13, KPIs H14; C: spend + seeded history H13 |
| Controls & Self-test | `/api/controls`, `/api/selftest/runs`, `/api/selftest/matrix`, `/api/policy/history` | L: self-test H11, controls H13; B: policy history H13 |

**P0 work packages (spec §13.2).**

| WP | What | Est. h | Needs (from, by) | Delivers (to, by) |
|---|---|---|---|---|
| F1 | brief → Claude Design: visual system + 4 page mocks (with L) | 1.5 | brief + this spec | H2 |
| F2 | SPA scaffold, router, header, SSE hook + polling fallback, fixtures mode, token login; Threats table with live SSE rows | 2.0 | fixtures (L, H1:30), L3 | **IC1 H5** |
| F3 | Threats drawer (Trace, Run, Evidence; MCP and Integrity tabs if time) | 3.0 | B7 | H11 |
| F5 | Playground page: built on fixtures before F's sleep, **one live call by IC3**, fully live by IC4 | 2.5 | fixtures, L7 (H10) | IC3 H12 (fixtures + one live call); IC4 H15 (live) |
| F6 | Overview page (posture, KPI band, coverage grid (a list if late), **spend panel**, health, recent changes) | 2.0 | L6, C6, B7 | H14 |
| F7 | Controls & Self-test page: the controls table + **Run self-test** button (matrix and history only if time) | 1.0 | L5, L6 | IC4 H15 |

There is no F4: it was removed, and IDs are not renumbered (the earlier draft's stand-alone Spend page is now the spend panel in F6, D19).

**Sequencing (v1.1):**
1. H2-H4: F2.
2. H4-H5:30: build F5 on fixtures, before you sleep.
3. H8:30-H11:30: F3.
4. Make one live Playground call for IC3 (L7 lands at H10). The Playground is fully live by IC4.
5. F6 (2.0 h), then F7: a table + Run button (1.0 h).

If you are late, the Overview coverage grid drops to a list. Apply the §11 console cut order at IC2 if you are behind.

**P1 (spec §13.3):** #5 C23 approvals card (D + F) · #6 full Spend page + Agents & MCP page (inventory, quarantine diff, re-pin, kill switch, feed panel via B's `/api/feed`) + `PATCH` toggles via the single-writer path (F + L + B, 4.0) · #7 Exploit Museum cards with Replay (L + F, 1.5).

**Libraries and licences that matter here.** React 19, Vite 8, Tailwind 4, shadcn `dashboard-01` (generate the block **while online, before the event**: the shadcn registry is online-only), Recharts 3, TanStack Query (5), TanStack Virtual, lucide-react (all MIT); fonts Archivo + IBM Plex Mono; the FastAPI mock server from brief §10; `VITE_API=fixtures|live`. `@xyflow/react` (taint graph) is P1 only.

**Top 5 gotchas.**
1. **The spec overrides the brief's scope (§11.6).** Don't paste the brief's §7 Claude Design prompt unedited: it asks for 10 screens, `<PL_PESEL_1>` re-hydration, ROUTE LOCAL, threshold sliders and what-if lines. P0 is 4 pages + header. The Controls page is read-only (toggles are P1). Placeholders are `[PL_PESEL]`, `[IBAN]`, `[PAN]`, `[EMAIL]`, `[SECRET:<kind>]`. Model IDs are `sim/gpt-4.1`, `ollama/qwen3:8b`, `ollama/qwen3:4b`, `mock/scripted` (not `ext/gpt-4o`).
2. **Money is integer micro-USD and times are UTC.** The mockup's `DATA` uses plain USD. `/api/header` has the spec's shape (§11.3: replicas, guard, selftest, posture, `llm_mode`), not brief §6's `header.json`. Fixtures come from `contracts/fixtures/api/`, not hand-written `ui/mocks/`.
3. **SSE.** One stream per tab, opened with `@microsoft/fetch-event-source` (MIT), not the native `EventSource`: `EventSource` cannot send headers, and `/api/stream` needs `Authorization: Bearer <admin token>` like every route. Never put the token in the URL (spec §11.4). `decision` payloads are projections, so the drawer fetches `/api/events/{id}`. Prepend rows and cap them at 200; never refetch the list. Fall back to 2 s polling; grey "stale" after 15 s of silence. Charts read `metrics_tick` or REST, never raw events, with Recharts animations off.
4. **GAP is amber, never red, and state is never colour-only.** Pills carry words, severity carries a shape, coverage cells carry IDs + `aria-label`. Required labels: "synthetic" on seeded history, "simulated commercial pricing" on `sim/*`, the `LLM: mock` badge, the "unsigned local change" chip, the "single admin token (demo)" banner (Q13), and a banner saying management sees the same data (server-side role stripping is P2).
5. **Auth and routing.** The base URL is `http://127.0.0.1:3000/api`, served by `control`, not the gateway. The admin bearer token goes on every route; ask for it once and keep it in `sessionStorage`. The Playground posts to `/api/playground/inspect`, which goes through the data plane as `judge`, `alice` or `ola`; there is no arbitrary-principal picker.

**Tests.** No case quota (UI only). Your acceptance is the storyline test with each beat visibly right on the console. L's `test_api_contract.py` checks live responses against the fixtures you build on.

**Demo and Q&A.** You drive the console in every beat and play the **CISO in beat 10 ★** (Threats → Export CSV; Verify names the `seq`; header DEGRADED; Run self-test → GAP vs FAIL; perf strip). The results must read at a glance in beats 2-3 (Playground stage list, sent vs forwarded, Evidence reveal), 4 (drawer Run tab: where `audit@evil.test` came from), 5 (header `v18 · 2/2 replicas · applied 0.6 s`, posture ▼, LLM01/ASI01 amber, GAP), 6 ("S4 EXPOSED since v19"; red header with the YAML path), 7 (MCP tab diff), 8 (feed cell `#43 ✓`, then red) and 9 (spend panel: "RUNAWAY LOOP STOPPED", race tile). Q&A: console and reporting questions.

**First 60 minutes (H0:40-H1:40, after kickoff blocks 1-3).**
- [ ] Paste the brief's §7.0 P0 Claude Design prompt (already cut to spec scope: 4 pages + header + spend panel; `[PL_PESEL]`; `sim/*` IDs; no toggles, what-if or ROUTE LOCAL). Attach `mockups/dashboard.html` for visual tone only.
- [ ] Generate the visual system (tokens from brief §3.2, light + dark), the 4 page mocks and the header states (normal, transitional, bad, stale).
- [ ] H1:30: run `uvicorn ui.mock_server:app --port 8000` from the repo root, straight against `contracts/fixtures/` (no copy). `tools/make_fixtures.py` names files by path with `/` → `-` (`/api/spend/burndown` → `api/spend-burndown.json`) and events as `events/<event_id>.json`. If the fixtures are not committed by H1:45, save the brief §6 samples into `ui/mocks/` with the same layout, run with `AICL_FIXTURES=ui/mocks`, and switch back at H2:30.
- [ ] Note every gap between the fixtures and the design; send them to L as RFCs (contracts are frozen).
- [ ] H2:00: scaffold the Vite app (F2).

**Sleep:** H5:30-H8:30. The UI runs on fixtures and nothing of yours is gated at IC2; wire the live Threats row for IC1 (and the fixtures Playground) before you sleep. Plan (a): no sleep before freeze, then 90 min H15:00-H16:30, after submitting.

---

## 10. Integration checkpoints (spec §13.4, binding; condensed)

Times are build-start hours for the base plan. **Plan (a)** (deadline 11:00 Oct 4; the default until Q2 is confirmed) works like this:
- P0 only, with P1 frozen.
- §13.6 cuts 1-5 apply at H0, and cuts 6-7 at IC2 if a lane is red.
- IC2 at H7, the placeholder at H8, and IC3 + the gate merged with IC4 at H10:30.
- Freeze at **H11**, clean room at **H12:30**, submit at **H15** (09:00).
- Nobody sleeps before freeze.

**Plan (b)** (deadline 23:00 Oct 4) runs this table up to IC4, then freezes at H18 and moves every later checkpoint 2 h later (submit H23). Spec §13.4 has the full mapping with clock times.

| Checkpoint | Time | Green means | If red (L decides, no debate) |
|---|---|---|---|
| **CF** | H1:00 | `contracts/` committed (§3.3; `frameworks.yaml` format only, content by H13); CI green on stubs; fence probe run on every demo Mac (by name and raw IP) and logged | contracts ship as-is, gaps → v1.2 RFC; fence leak → §3.4 ladder |
| **Latency** | H2:00 | C measured classifier/kNN p95 per window count on the demo Mac (`reports/perf-h2.md`) | apply the §5.1 H2 rule (engine / window size) |
| **D1** | H2:30 | the MCP edge forwards `tools/call` to a sandbox HTTP server with our middleware | switch to the thin JSON-RPC proxy |
| **IC1** walking skeleton | H5:00 | `test_walking_skeleton.py` green (§13.5); tag `ic1` | L + A pair until green; the Overview spend panel drops to KPI tiles; UI stays on fixtures until IC3 |
| **IC2** | H8:00 | streaming via the gateway on the mock; real Valkey reserve/settle incl. 429; `gw-2` behind `lb`, both shas in `/api/replicas`; `/v1/runs` mints tokens, fallback run works; one MCP `tools/call` blocked by a validator with an audit event; ≥ 5 signature rules; `guard /v1/inspect` (stub minimum); reload flip < 2 s on 2/2 | streaming unstable → `stream_mode: buffer`; guard won't load → stub + "semantic tier degraded" shown honestly; feed signing broken → sha-pinned unsigned bundle, said openly |
| **Placeholder** | H11:00 | name + tagline; title, team, description v1, PDF v0 uploaded (if edits are allowed) | checklist dry run |
| **IC3 + H12 gate** | H12:00 | **detectors-off S4/S5 green**, fence + admin isolation green, race green; ≥ 85% of P0 cases green; `make test` ≤ 2 min warm; storyline beats 1, 2, 4, 5 green offline (the dev feed bundle is enough); Threats + drawer on live data; Playground on fixtures + one live call (fully live by IC4); tag `ic3` | **D + A + L swarm on C24 until green; all P1 frozen** |
| **IC4** P0 complete | H15:00 | every P0 control enabled with ≥ 1 POS + ≥ 2 NEG passing; beats 1-10 green offline; header + 4 pages on live data; tag `ic4` | any P0 control still red → flag off in the demo policy and off the slides; P1 continues only on green lanes |
| **Red-team swap** | H13:30-H14:30 | pairs attack another lane: A→D, D→B, B→C, C→A, L→all; every bypass becomes a case or a residual-register entry | — |
| **Freeze** | H16:00 | P1 merged behind flags or abandoned; tag `rc1` | after this: fixes, cases, docs, policy/feed content and CSS only |
| **IC5 clean room** | H17:30 | fresh `git clone` on the hot spare, Wi-Fi off: `make doctor && make test && make demo-offline && make demo`; storyline test 100% | each red item: a ≤ 30 min fix by an awake owner or A/C, or a cut (flag off + slide edit) |
| **Video** | H18:00 | 3-4 min full storyline + 20-40 s clips per beat (F + A) | — |
| **PDF** | H17:00 v1 (L, before IC5 and L's nap) · H20:30 v2 (L + F) | ≤ 10 slides, screenshots from `rc1` | — |
| **Repo public** | H20:00 | `gitleaks detect` clean on history; `make licenses`; NOTICE | — |
| **Submit** | H21:00 | PDF, repo public, video linked, tag `v1.0-submission`; a second person watching the screen; confirmation screenshot | — |
| Pitch prep | H21-H24 | 3 rehearsals (L, F, B, D; A and C join at H22); storyline test 10 min before stage | `main` locked |

Sleep plan (spec §13.7, v1.1): F H5:30-H8:30 · B, D H15:30-H18:00 · L nap H18:00-H19:30 · A, C H19:30-H22:00. So F sleeps 3 h, A, B, C and D 2.5 h, and L takes a 90-min nap and stays for the rehearsals. Never more than two asleep at once; never an owner asleep at their own gate. Plan (a): nobody sleeps before freeze; then B, D H11:00-H12:30 · A, C H13:30-H15:00 · F H15:00-H16:30 · L 60 min H15:30-H16:30.

---

## 11. Cut order and never-cut (spec §13.6, §9.5)

**Cut in this order, never the reverse.** Each cut is a flag flip + a slide edit.
1. P1 ranks 17 → 7 (`package_ioc`, k8s, `/v1/guard`, agent→agent, n-gram, live agent, downgrade, Anthropic, C34, mutation, museum cards).
2. Console: the Overview spend panel → KPI tiles; the Overview coverage grid → a list; drawer MCP tab → Evidence. (Controls is already a table + Run self-test since v1.1.)
3. P1 ranks 6 → 4 (Spend/Agents pages, approvals, OCSF).
4. C11 guard-LLM lane (the P0 topic pack + kNN still carry C11).
5. Obfuscation matrix → base64 + tags + zero-width + Polish only. (In force at P0 since v1.1: the mutators are P1 #8.)
6. C18 → pickle allowlist + fail-closed only (no torch zip, no safetensors header check).
7. Multilingual kNN → EN+PL exemplars for the C09 keyword packs only (the classifier remains).

**F's console cut order if behind at IC2 (§9.5):**
1. Overview spend panel → KPI tiles.
2. Overview coverage grid → a list. Controls is already a read-only table + Run self-test, F7 1.0 h.
3. Overview drops the measured column.
4. The drawer MCP tab merges into Evidence.

**Plan (a)** applies cuts 1-5 at H0 and cuts 6-7 at IC2 if a lane is red. The storyline shrinks to the ★ beats 0, 1, 2, 4, 5, 8-lite, 10, 11.

**Never cut:**
- the guarantees: C13, C24, C33, C35 and the detectors-off test;
- C01-C10, C12, C14-C17, C19, C20, C25, C26, C30, C32;
- the hermetic `make test`, the live self-test, the header + Threats (drawer Trace + Run tabs) + Playground, the storyline test, offline mode, the two replicas and the race test;
- C11 topic-pack floor (EN+PL deterministic); C18 lite (pickle GLOBAL allowlist walk + fail-closed on parse error); Overview KPI tiles incl. spend MTD and local compute-seconds; Controls table + Run self-test; JSONL/CSV export + Verify.

Why (lead decision): every formal requirement R1-R6 (incl. unsafe deserialization / model supply chain) must remain demonstrable under plan (a).

---

## 12. Spec issues noticed (status after spec v1.1)

v1.1 resolved the earlier issues 3-16:
- Threats timing; C07 vs IC3; D3a vs B3; IC1 stubs; F's lane.
- The C12 split; the unowned C20, guard client, `seed.py` and `mint_jwt.py`.
- Tool units; the R22 owner; `frameworks.yaml`.
- Pre-drafted contracts (now Q16); the S8 flaky tool; the sleep plan; F4.

Issue 1 (capacity) is fixed in the per-lane loads. What remains:

**Timing:**
1. **Zero slack.** P0 is 79.5 h against 81 h. L, A, B, C and D are each at 13.5 h, which fills H1-H16, so their last P0 hour lands between IC4 (H15) and freeze (H16), and D has lost its separate gate hour. The tightest lane is still A: A5 (4.0 h), A7 and the rest of A4 all fall between H8 and H12. The IC4 flag-off rule, not slack, absorbs the overrun. There is realistically no P1 in the base plan; plan (b)'s extra 2 h buys about 12 h (ranks 1-5).
2. **L before H5.** L1 (2.0 h) is due at H1 while L chairs the kickoff. IC1 at H5 needs L3's SSE stream, and the gantt now starts L3 at H4:30, still tight. Suggestion: build L3's tailer → SSE slice before L2's polish. (The spec's Appendix B follow-ups were all done before H0.)
3. **Plan (a) capacity.** With a deadline of 11:00 Oct 4 there are about 9 h per person before freeze (≈ 54 h) for 79.5 h of P0. D's gate chain alone is about 9 h, so the gate merges with IC4 at H10:30. Expect most P0 outside the never-cut list to be flagged off; the storyline is the ★ beats.

**Other:**
4. **Examples vs spec tiers:** resolved. `examples/feed/signatures.yaml` now carries the v1.1 tiers (SIG-0008 and SIG-0011 `tier: P2`, SIG-0013 `tier: P1`).
