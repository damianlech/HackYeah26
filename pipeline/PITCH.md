# Clearance: pitch kit (one page)

## The one-liner

> ### No AI request leaves the firm without clearance.
> Admins build a pipeline of gates: identity, budget, word filters, an AI judge.
> Every agent request is checked, rewritten or stopped, and every decision is on the record.

Why this one:
- **"The firm"** is how Goldman Sachs people talk about Goldman Sachs.
- **"Clearance"** means two things in this room: security clearance (airport gates), and clearing, which is what banks do.
- It promises **control** (nothing leaves unchecked) and **evidence** (on the record) in nine words.

**Polish:** *Żadne zapytanie do AI nie opuści firmy bez odprawy.* ("odprawa" is airport clearance)

**Alternatives, if the team prefers:**
- "Airport security for AI agents: every request walks through the gates you choose, and every gate stamps its verdict."
- "Build your AI policy from gates like Lego. Every agent request is checked, rewritten or stopped, and leaves a receipt."

**Name:** *Clearance* (used in the mockup as a single constant, so it's easy to change). Check for trademark clashes before the final submission. The earlier working name *Mandate* reads as "traffic fine" in Polish.

## The 30-second summary (use as the HackTribe description and on slide 1)

**Problem.** Agents call models and tools with keys that open everything, and nobody sees what they send.
The April 2026 US model-risk guidance (SR 26-2, Fed / OCC / FDIC) explicitly leaves generative and agentic AI out of scope.

**Solution.** Clearance sits between agents and models in three layers:
- **L1** decrypts the request (one setting in the agent: the base URL).
- **L2** runs it through a **pipeline of gates** that an admin builds without code.
- **L3** re-encrypts it with the real key and sends it to the model. Agents never hold real keys.

Each gate (identity, model allowlist, budget, word filter, PII mask, attack signatures, an AI judge) answers **allow, deny or modify**, and writes down why.
The model's answer goes back through gates too.

**Proof in the demo:**
- A request naming "Goldman Sachs" is masked before it leaves the firm.
- A disguised slur is caught once the normalizer gate is added.
- A prompt injection is stopped by the AI judge.
- An over-budget user is refused.
- Every decision lands in a tamper-evident audit log.

## Why it scores (differentiator → judging criterion)

| What judges see | Criterion |
|---|---|
| Every decision explained gate by gate: decision, reason, milliseconds, policy version | Security reporting (20%) |
| Policy assembled from gates, the same gate reused with different settings, live on the next request | Robustness & guardrails (30%) |
| Fail-closed by default, identity gate locked first, health check before Save | Robustness & guardrails (30%) |
| Cheap rules first, AI judge last. ~2 ms per gate hop, measured (`bench/RESULTS.md`) | Architecture & performance (20%) |
| Each gate testable alone. Admin-written tests run on Save. Simulate any request | Self-testing (15–20%) |
| One base-URL setting to adopt. Agents never hold real keys. Gates scale independently | Practicality & scalability (10–15%) |

## 90-second click path through the mockup

1. **Overview:** read the tagline aloud, then click the pin on **L2 · The pipeline**. *(10 s)*
2. **Pipeline:** click the pin **One gate, three jobs** (the word filter used three times). *(15 s)*
3. **Simulate → "Mentions Goldman Sachs" → Run.** The flow strip turns blue at the mask gate. The diff shows *Goldman Sachs → Firm*. The model's answer gets masked on the way back. *(20 s)*
4. **"Obfuscated SLUR" → Run:** it slips through. On Pipeline, the Health check suggests **Add normalize**. Click the fix and run again: stopped. *(20 s)*
5. **Advanced: break things:** mark the AI judge as down and run the *benign* question. Even that is denied, because the pipeline fails closed rather than guessing. *(10 s)*
6. **Audit:** open the record and click **Verify**: the chain is intact. *(15 s)*

Or press **Take the 60-second tour**, which walks the same path with explanations.

## Short answers to the questions judges will ask

| Question | Answer |
|---|---|
| Is this real? | The gate contract is defined (`contract.md`). The 3-layer prototype runs (`claude-proxy/`: L1/L2/L3 with the JEV judge, simulated). The mockup simulates gates with the same logic: word filter, budget, JEV scoring ported from the prototype. |
| What's the overhead? | ~1.7 ms per gate hop with one shared HTTP client, measured. The AI judge dominates, which is why it runs last. Read-only gates can run in parallel. |
| What if a gate is down? | Each gate has an "if unavailable" rule, deny by default. We can show it live. |
| Can an admin break it? | The identity gate is locked first. The health check runs before Save. Admin-written tests block a bad save. Every version is kept, and every log line says which version decided. |
| How does it scale? | The pipeline is stateless. Gates are separate services, each scaled on its own (the AI judge on GPU nodes). Budgets live in a shared store (Redis/Valkey). |
| Why not Claude apps gateway / LiteLLM? | Those govern their own models and budgets. We are vendor-neutral, policy is built from gates, and every single decision can be audited. |

## Say / don't say

- Say "mockup with simulated gates" and "working prototype". Don't claim production traffic or customers.
- Say "tamper-evident", not "tamper-proof".
- Say "the AI judge is simulated in the prototype; the real model plugs in behind the same contract".
- Quote only measured numbers (`bench/RESULTS.md`) and name the machine.
