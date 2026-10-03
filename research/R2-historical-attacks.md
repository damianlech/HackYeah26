# R2: Historical attacks on AI infrastructure and agents (2022-2026) + signature feed design

> **Scope / intent:** This is a *defender's* catalog for building an AI Control Layer (gateway/proxy) for the Goldman Sachs HackYeah 2026 task. For each real, publicly-documented incident it records the date, identifier, one-line description, source, root cause, **what a control layer could have detected or blocked**, and a **detection-rule sketch** (what the gateway matches on). Reproduction notes are deliberately limited to "use a benign, non-functional stand-in" guidance for our own test suite. Nothing here is an exploit how-to.

> **TL;DR (5 lines)**
> 1. Nearly every real AI incident 2023-2026 reduces to six root causes: executable artifacts deserialized on load; unauthenticated admin/exec APIs on AI servers; the agent "lethal trifecta" (private data + untrusted input + exfil channel); leaky output channels (markdown images, invisible Unicode); poisoned supply chain (npm/MCP/rules-files/hallucinated packages); and stolen-key denial-of-wallet.
> 2. A gateway that sees requests, responses, tool lists, tool calls and artifact downloads can deterministically block a large share, because most incidents leave a byte-level or structural fingerprint.
> 3. Denylists get bypassed (picklescan had multiple 2025 bypass CVEs), so our design is allowlist-first + fail-closed for artifacts, taint/egress control for agents, with signatures as one layer.
> 4. We propose one ed25519-signed, versioned, hot-reloaded YAML signature feed with 10 rule types and embedded positive/negative test vectors (the feed doubles as the self-test corpus).
> 5. Hackathon plan: ~15 signatures covering all 7 categories, a replay harness built from the test vectors, and a live "judge edits a rule -> block changes in <2s" demo.

---

## 0. How to read each entry

**Detection classes** referenced throughout:

| Code | Meaning | Cost | Where in pipeline |
|---|---|---|---|
| `SIG` | Deterministic signature (regex / literal / hash / IOC / structural) | microseconds | request, response, tool traffic |
| `ART` | Artifact scan (pickle opcodes, archive structure, file hash) | ms-seconds | model/file download path |
| `SEM` | Semantic / local-model classifier (prompt-injection, jailbreak) | 10-500 ms | prompt + tool-output text |
| `POL` | Policy / authz (allowlist of models, tools, domains; read-only scopes) | microseconds | every call |
| `BUD` | Budget / rate / resource governance | microseconds | every call |
| `TAINT` | Data-flow: mark untrusted content, block it reaching sink tools | ms | agent tool-call graph |

**Demo-ability (1-5):** how cleanly we can show it to a judge in a 24h build, with a *benign* stand-in (no working malware). 5 = trivial and safe; 1 = needs infra we will not have.

Framework mappings used: **OWASP LLM Top 10 (2025)** [LLM01..LLM10], **OWASP Agentic Top 10 (2026)** [ASI01..ASI10], **MITRE ATLAS** [AML.Txxxx].
