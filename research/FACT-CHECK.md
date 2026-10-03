# Fact-check of load-bearing research claims

> Done 2026-10-03 by 4 skeptical verifier agents. Each one tried to **refute** a claim against primary sources (official repos, release notes, license files, regulator pages).
> Treat this file as the **errata** for `R1`–`R9`: where it disagrees with a research note, this file wins.

## Corrections and nuances that change what we build

| # | Correction | Impact |
|---|---|---|
| A2 | Ollama's duration fields (`eval_duration` etc.) appear **only on the native `/api/chat` and `/api/generate`** (final `done:true` chunk), **not** on the OpenAI `/v1/*` or Anthropic `/v1/messages` endpoints. | For GPU-seconds budgets, either call Ollama natively for the business model or measure upstream wall-clock time in the gateway. The vision spec uses wall-clock by default and native durations when available. |
| A3 | **Qwen3Guard is not in the official Ollama library** (only a community upload `sileader/qwen3guard:0.6b`). Qwen3Guard-Stream needs transformers/vLLM. | Default tier-2 guard = `llama-guard3:1b` (official). Qwen3Guard is a spike/stretch item. |
| A4 | The Llama EU restriction is in the **AUP and covers multimodal models only**. Prompt Guard 2 (text-only), Llama Guard 3 1B and 8B are **fine for an EU team**. **Avoid Llama Guard 4 12B and Llama Guard 3 11B-Vision.** Prompt Guard 2 86M was not evaluated on Polish. PG2 HF repos are gated, so request access early. Ship a "Built with Llama" notice. | Model stack stays as planned. Do not claim Polish detection quality without measuring it. |
| A5 | ProtectAI deberta PI v2 is **English-only and does not detect jailbreaks**. LLM Guard (archived 2026-07-09) and Rebuff (archived 2025-05-16) are unmaintained. | Use the models directly, not those libraries. Pair with an LLM guard / embeddings for jailbreaks and non-English input. |
| A6 | **Docker Model Runner** is a GPU-accelerated alternative on Apple Silicon (OpenAI-, Ollama- and Anthropic-compatible APIs, port 12434, no auth). | Keep Ollama native as the default. Make the upstream base URL configurable. |
| B2 | FastMCP 4.x uses `create_proxy(...)` (**not** `as_proxy`), and the official `mcp` SDK 2.x renamed FastMCP to `MCPServer`. | Pin `fastmcp==4.0.10`. Don't write `from mcp.server.fastmcp import FastMCP` against `mcp>=2`. |
| B3 | `permissions.disableBypassPermissionsMode` is a **nested string** `"disable"`. `allowedProviders` needs Claude Code **≥ 2.1.285**. | Already reflected in `examples/agent-config/claude-code/`. |
| B4 | Claude apps gateway: OIDC only (**no SAML/LDAP**), **no CI service tokens**, Postgres required, **fail-open by default**, no Helm chart. | These are our differentiation points. Copy its error contract (400 ungranted model; 429 `billing_error`, `x-should-retry: false`, `retry-after`). |
| C3 | Cite as **"OWASP MCP Top 10 (2025 edition, beta)"**, not "v0.1". MCP06 is now **"Intent Flow Subversion"**. A new release is planned for **Oct 2026**, so re-check before the demo. | Update IDs in the coverage grid. |
| C5 | SR 26-2 was co-issued by the **Fed, OCC (Bulletin 2026-13) and FDIC**. | Name all three in the pitch. |
| C6 | OCSF `ai_operation` profile dates from **1.8.0**. `record_integrity` (hash chains) is **new in 1.9.0**. | Use `record_integrity` fields for the audit hash chain in the OCSF export. |
| C7 | Digital Omnibus = **Reg. (EU) 2026/1744**: Annex III high-risk (incl. Art. 12 logging) from **2 Dec 2027**, Annex I product-embedded from **2 Aug 2028**. | Say it exactly like that. |
| D2 | LiteLLM *can* change config live when models/settings are stored in its DB (reload every 30 s). Only YAML edits need a restart. | Our critique of LiteLLM should say that. |
| D3 | Envoy AI Gateway was renamed **Agent Router** (Agentic AI Foundation). agentgateway hot reload excludes its top-level startup `config` block. | Use the new name in slides. |
| D6 | picklescan has a long, ongoing bypass record (3× CVSS 9.3 in Sep 2025 and more since). | **Allowlist + safetensors-only by default + fail-closed.** Scanners are just one layer. |
| D7 | ShadowRay CVE-2023-48022 is **disputed / unpatched by design**. The Amazon Q payload **never executed** (syntax error). The AI-CLI abuse in Nx is from vendor research, not the Nx advisory. | Phrase incidents precisely in slides. |

## Open items added after the fact-check (2026-10-03 review; not yet verified)

These claims are used in the pitch or the docs but were **not** among the 26 checks below. Until someone verifies them against the primary source, they carry a `[verify]` marker wherever they appear, and they leave the slides if they can't be confirmed before PDF v1.

| # | Claim or erratum | Where it is used | Status / what to do |
|---|---|---|---|
| E1 | ~175,000 Ollama hosts exposed on the internet without auth, in 130 countries (SentinelLABS + Censys, Jan 2026) | spec §12 beat 0; `docs/05` slide 1, §6; `docs/08` | **Unverified.** Source chain is R2 row b4 (The Hacker News, SecurityWeek). Open the SentinelLABS report once; if it can't be confirmed, say "exposed AI infrastructure" without a number. |
| E2 | OWASP LLM01:2026 cites adaptive attacks succeeding > 90% of the time against most of 12 published defences (Nasr et al., 2025), and the OWASP 2026 line "Stop trying to build a model that cannot be fooled. Build the system around it" | spec §2.1, §2.2, §14.2 T6; `docs/03` TL;DR; `docs/05` §1.1, slide 3, §6 | **Unverified.** R1 §2 gives "> 90% adaptive for most of 12 defenses (Nasr et al., 2025)". Say "most of 12 published defences", never "most defences" or "all classifiers". Check the LLM01:2026 text and the quote verbatim. |
| E3 | When the Claude apps gateway enforces spend caps (before the request or after the fact) | spec §2.4 vendor table | **Unverified.** B4 confirms only the caps and the 429 `billing_error` on a breach. The table now says "enforcement timing unverified"; don't claim "metered after the fact" on stage. |
| E4 | **Erratum for R9:** R9's control numbers predate the canonical catalog. In R9 (the §2.4 example event, the posture worked example, the console sketches) C09 = PI classifier, C10 = signature feed, C20 = budgets, C03 = model allowlist. Canonical (spec §4): C09 = signatures, C10 = semantic, C19 = feed, C03 = budgets, C02 = model allowlist | B (audit, `primary_control`), F (console) | Use `examples/audit/event-example.json` as the reference event, never R9's. R9's Merkle/C2SP checkpoints, ECS/CEF/HEC exports and the weekly report are P2 (spec §9.2, §9.6). |

## All checks

### Ollama, local models, licenses

#### A1 — Ollama serves Anthropic /v1/messages (≥0.14.0) and OpenAI /v1/responses (≥0.13.3); Claude Code can target it

**Verdict:** ✅ confirmed

Confirmed. The Ollama v0.14.0 release notes say "Anthropic API compatibility: support for the `/v1/messages` API", and Ollama's blog post of 2026-01-16 says "Ollama v0.14.0 and later". The OpenAI-compatibility doc lists /v1/responses with "Note: Added in Ollama v0.13.3". The v0.13.3 release notes themselves do not mention it. Other OpenAI-compatible endpoints: /v1/chat/completions, /v1/completions, /v1/embeddings, /v1/models and /v1/models/{model}. The Responses endpoint is stateless (no previous_response_id). Ollama's Claude Code integration doc gives this setup: ANTHROPIC_AUTH_TOKEN=ollama (required but ignored), ANTHROPIC_API_KEY="" and ANTHROPIC_BASE_URL=http://localhost:11434. It also offers a one-step `ollama launch claude` and recommends a context length of 64k or more. Features /v1/messages does NOT support: /v1/messages/count_tokens, tool_choice, metadata, prompt caching (cache_control), the Batches API, citations, PDF documents, and server-sent errors during streaming. Images work only as base64, not URLs. budget_tokens is accepted but not enforced.

**Impact on the hackathon:** Require Ollama 0.14.0 or later (say >=0.14 in the README / setup check). A gateway sitting between Claude Code and Ollama must not depend on count_tokens, prompt caching or tool_choice passing through, so stub or strip these. Use a model with a 64k+ context window for Claude Code.

**Sources:** <https://github.com/ollama/ollama/releases/tag/v0.14.0> · <https://github.com/ollama/ollama/releases/tag/v0.13.3> · <https://github.com/ollama/ollama/blob/main/docs/api/openai-compatibility.mdx> · <https://github.com/ollama/ollama/blob/main/docs/api/anthropic-compatibility.mdx> · <https://github.com/ollama/ollama/blob/main/docs/integrations/claude-code.mdx> · <https://registry.ollama.ai/blog/claude>

#### A2 — Ollama native responses carry nanosecond duration fields usable for compute accounting

**Verdict:** ✅ confirmed

Confirmed. The Ollama API docs (api.md) list these fields in the final response of /api/generate and /api/chat: total_duration, load_duration, prompt_eval_count, prompt_eval_duration ("time spent in nanoseconds evaluating uncached prompt tokens"), eval_count and eval_duration. The Conventions section says "All durations are returned in nanoseconds." When streaming, these fields only appear in the final chunk (done: true). The OpenAI-compatible (/v1/*) and Anthropic-compatible (/v1/messages) endpoints return only token usage, not these duration fields. prompt_eval_duration covers only uncached prompt tokens.

**Impact on the hackathon:** To get latency and throughput metrics (tokens/s = eval_count / eval_duration * 1e9), the gateway should call the native /api/chat (or read the done:true chunk). If it proxies /v1/messages, it has to measure wall-clock time itself. Expect prompt_eval numbers to drop when the KV cache is reused.

**Sources:** <https://github.com/ollama/ollama/blob/main/docs/api.md>

#### A3 — Guard models on Ollama (llama-guard3, granite3-guardian, shieldgemma, gpt-oss-safeguard); Qwen3Guard Apache-2.0

**Verdict:** ✅ confirmed

Confirmed, with some details added. llama-guard3 is in the Ollama library with 1b (1.6GB) and 8b (default, 4.9GB) tags. granite3-guardian is there with 2b (2.7GB, 8K context) and 8b (5.8GB) tags; it answers with a single Yes/No token. shieldgemma is there with 2b, 9b and 27b tags; it is Gemma-2 based, covers 4 harm categories, and answers Yes/No. gpt-oss-safeguard is in the official Ollama library with 20b (14GB, fits 16GB VRAM) and 120b (65GB) tags under Apache 2.0, a release with OpenAI and ROOST. Qwen3Guard is Apache-2.0 per the HF LICENSE files. It ships as Qwen3Guard-Gen and Qwen3Guard-Stream, each in 0.6B, 4B and 8B (so the Stream variant also comes in three sizes), alongside Qwen3-4B-SafeRL. Caveat: Qwen3Guard is NOT in the official Ollama library. Only a community upload exists (sileader/qwen3guard:0.6b, Q4_K_M). The Stream variant uses a token-level classification head, so it most likely cannot run under Ollama/llama.cpp and needs transformers/vLLM (inferred from its architecture, not verified). The Qwen3Guard license was confirmed through HF search results and the HF LICENSE link, because huggingface.co was blocked for direct fetch.

**Impact on the hackathon:** Use the official library models (llama-guard3, granite3-guardian, shieldgemma, gpt-oss-safeguard) for one-command `ollama pull`. For Qwen3Guard-Gen, either rely on a community GGUF upload or import a GGUF yourself. Qwen3Guard-Stream needs a Python/transformers sidecar. gpt-oss-safeguard:20b needs about 16GB of memory, so check team laptops.

**Sources:** <https://ollama.com/library/llama-guard3> · <https://ollama.com/library/granite3-guardian> · <https://ollama.com/library/shieldgemma> · <https://ollama.com/library/gpt-oss-safeguard> · <https://ollama.com/blog/gpt-oss-safeguard> · <https://github.com/QwenLM/Qwen3Guard> · <https://huggingface.co/Qwen/Qwen3Guard-Stream-8B> · <https://huggingface.co/collections/Qwen/qwen3guard> · <https://ollama.com/sileader/qwen3guard>

#### A4 — Prompt Guard 2 license (Llama 4) and the EU restriction

**Verdict:** 🟡 partially

Partly right. Llama Prompt Guard 2 (86M and 22M) is under the Llama 4 Community License (HF license_name: llama4), and its HF repos are gated (you must accept the license). The 86M model uses a multilingual mDeBERTa base and was evaluated on 8 languages; Polish is not among them. The 22M model is English-focused. The EU restriction is NOT in the Llama 4 license text itself. It is in the Acceptable Use Policy, which the license incorporates by reference, and it covers ONLY multimodal models. The Llama 4 AUP says: "With respect to any multimodal models included in Llama 4, the rights granted under Section 1(a)... are not being granted to you if you are an individual domiciled in, or a company with a principal place of business in, the European Union." It does not apply to end users of a product that incorporates such models. The Llama 3.2 AUP has the same multimodal-only clause. Consequences for a Polish (EU) team: (1) Prompt Guard 2 is a text-only DeBERTa classifier, so the EU clause does not apply. (2) Llama Guard 3 1B is under the Llama 3.2 license (not Llama 4) and is text-only, so it is not affected. (3) Llama Guard 3 8B is under the Llama 3.1 license, which has no EU clause. (4) Llama Guard 4 12B (multimodal, derived from Llama 4 Scout) and Llama Guard 3 11B-Vision ARE covered by the EU restriction for EU-domiciled individuals and companies. Other Llama 4 license obligations that still apply when you redistribute or ship a product: display "Built with Llama", include a copy of the license, and follow the AUP.

**Impact on the hackathon:** The team in Poland can legally use Prompt Guard 2, Llama Guard 3 1B and Llama Guard 3 8B. Avoid Llama Guard 4 12B and Llama Guard 3 11B-Vision. Request HF gated access for Prompt Guard 2 ahead of time, since approval is not instant. Add a "Built with Llama" notice if you ship it. Don't claim Polish-language detection quality without testing it.

**Sources:** <https://github.com/meta-llama/llama-models/blob/main/models/llama4/USE_POLICY.md> · <https://github.com/meta-llama/llama-models/blob/main/models/llama4/LICENSE> · <https://github.com/meta-llama/llama-models/blob/main/models/llama3_2/USE_POLICY.md> · <https://github.com/meta-llama/PurpleLlama/tree/main/Llama-Prompt-Guard-2> · <https://github.com/meta-llama/PurpleLlama/blob/main/Llama-Prompt-Guard-2/86M/MODEL_CARD.md> · <https://github.com/meta-llama/PurpleLlama/blob/main/Llama-Guard3/1B/MODEL_CARD.md> · <https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M/blob/main/README.md> · <https://www.llama.com/faq/>

#### A5 — ProtectAI deberta PI v2 Apache-2.0; LLM Guard archived Jul 2026; Rebuff archived May 2025

**Verdict:** ✅ confirmed

Confirmed. protectai/deberta-v3-base-prompt-injection-v2 is licensed under the Apache License 2.0 per its HF model card. It is a fine-tune of microsoft/deberta-v3-base with binary labels (0 = benign, 1 = injection). Limitations: it is English-only, does not detect jailbreak attacks, and is not recommended on system prompts because of false positives. The GitHub banner on protectai/llm-guard says "This repository was archived by the owner on Jul 9, 2026. It is now read-only." That repo is MIT-licensed. The banner on protectai/rebuff says "archived by the owner on May 16, 2025". That repo is Apache-2.0.

**Impact on the hackathon:** Using the ProtectAI DeBERTa model directly (transformers or ONNX) is fine. Don't build on the LLM Guard or Rebuff libraries: they are unmaintained, though copying ideas or code under MIT/Apache is fine. For Polish or other non-English input, pair it with Prompt Guard 2 86M or an LLM guard, and don't count on it to catch jailbreaks.

**Sources:** <https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2> · <https://github.com/protectai/llm-guard> · <https://github.com/protectai/rebuff>

#### A6 — Docker on macOS has no Metal GPU; run Ollama natively

**Verdict:** ✅ confirmed

Confirmed. The Ollama FAQ says: "GPU acceleration is not available for Docker Desktop in macOS due to the lack of GPU passthrough and emulation." Docker's own blog (2026-02-26) says "there is no GPU passthrough for Metal in containers". So run Ollama natively on the Mac. Containers reach host services through the Docker Desktop DNS name host.docker.internal (here host.docker.internal:11434). Under Colima, OrbStack or Rancher Desktop you may need OLLAMA_HOST=0.0.0.0 (not verified). Docker Model Runner (DMR) is a real GPU-accelerated alternative on Apple Silicon. On macOS its inference engines run natively on the host in a seatbelt sandbox, not in a container. It uses llama.cpp with GGUF and Metal, plus vLLM via vllm-metal (MLX models) since Feb 2026. DMR exposes three API styles: (1) OpenAI-compatible (/engines/v1/chat/completions, /completions, /embeddings, /models). (2) Ollama-compatible (/api/tags, /api/chat, /api/generate, /api/embeddings). (3) Anthropic-compatible (/anthropic/v1/messages); Docker's 2026-01-26 blog post shows Claude Code with ANTHROPIC_BASE_URL=http://localhost:12434. Containers reach DMR at http://model-runner.docker.internal, and the host reaches it at localhost:12434 once TCP is enabled (`docker desktop enable model-runner --tcp`). The DMR API has no authentication. A further option, not verified from a primary source: Podman with libkrun/krunkit gives containers Vulkan GPU access on macOS (FOSDEM 2026 talk on API remoting for llama.cpp).

**Impact on the hackathon:** Keep the plan to run Ollama natively on Mac and use host.docker.internal:11434, and make the base URL configurable. Optionally support DMR as a second backend: its Ollama- and Anthropic-compatible routes mean little code change, but the model naming and port (12434) differ. Neither Ollama nor DMR has auth, so the gateway must enforce access control.

**Sources:** <https://github.com/ollama/ollama/blob/main/docs/faq.mdx> · <https://www.docker.com/blog/docker-model-runner-vllm-metal-macos/> · <https://www.docker.com/blog/run-claude-code-locally-docker-model-runner/> · <https://github.com/docker/docs/blob/main/content/manuals/ai/model-runner/_index.md> · <https://github.com/docker/docs/blob/main/content/manuals/ai/model-runner/api-reference.md> · <https://docs.docker.com/desktop/features/networking/networking-how-tos/>

### MCP, Claude Code, A2A, ACS

#### B1 — MCP spec 2026-07-28 is stateless (no initialize, no Mcp-Session-Id, Mcp-Method/Mcp-Name headers, MRTR)

**Verdict:** ✅ confirmed

Confirmed from the spec changelog in the official repo and the official MCP blog. MCP 2026-07-28 shipped on 28 Jul 2026. The release candidate was locked on 21 May 2026, and the previous revision is 2025-11-25. Changes from the changelog: (1) protocol-level sessions and the Mcp-Session-Id header are removed (SEP-2567). (2) The initialize / notifications/initialized handshake is removed (SEP-2575). Each request now carries protocolVersion and clientCapabilities in _meta, and a version mismatch returns UnsupportedProtocolVersionError. (3) Streamable HTTP POST requests must carry the Mcp-Method and Mcp-Name headers, and tool parameters can add custom headers through x-mcp-header (SEP-2243). (4) Multi Round-Trip Requests (MRTR, SEP-2322) replace the server-initiated roots/list, sampling/createMessage and elicitation/create requests. The server returns an InputRequiredResult with resultType "input_required" and inputRequests, and the client retries the original call with inputResponses. Every result now has a required resultType field ("complete" or "input_required"). (5) Deprecated: the Roots, Sampling and Logging features; the HTTP+SSE transport (already deprecated since 2025-03-26, now formally Deprecated with at least a 12-month window); the includeContext values thisServer/allServers; and OAuth Dynamic Client Registration. Also removed: SSE stream resumability (Last-Event-ID), so a broken stream means re-issuing the request with a new ID. Elicitation is NOT deprecated; it only moved to MRTR. Note that modelcontextprotocol.io itself was blocked by the egress proxy, so the spec pages were checked through the GitHub repo.

**Impact on the hackathon:** Build any gateway or proxy against 2026-07-28. Route on the Mcp-Method/Mcp-Name headers and do not depend on sticky sessions or Mcp-Session-Id. Handle InputRequiredResult round-trips when passing elicitation through. Do not build new features on Roots, Sampling, Logging, HTTP+SSE or DCR. Older clients (2025-11-25) still exist, so either support both eras or say which one the demo targets.

**Sources:** <https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/docs/specification/2026-07-28/changelog.mdx> · <https://github.com/modelcontextprotocol/modelcontextprotocol/tree/main/schema> · <https://blog.modelcontextprotocol.io/posts/2026-07-28/> · <https://modelcontextprotocol.io/specification/2026-07-28/changelog>

#### B2 — FastMCP 4.x proxy + middleware hooks; MCP Python SDK license

**Verdict:** ✅ confirmed

Confirmed from PyPI and the fastmcp-slim 4.0.10 wheel source. FastMCP 4.0.10 (PrefectHQ/fastmcp) was uploaded 2026-09-25 and is the latest release. 4.0.0 came out 2026-08-31, and the 3.x line ended at 3.4.7. The license is Apache-2.0 (License-Expression: Apache-2.0). The fastmcp package is a meta-package that depends on fastmcp-slim[client,server]==4.0.10, which holds the code. Proxying: fastmcp.server.create_proxy(target, mode=None, **settings) accepts a Client, ClientTransport, FastMCP instance, URL, Path to a .py/.js script (spawned over stdio), or an MCPConfig/dict. MCPConfig entries with a command become StdioTransport, and there are Uvx/Npx/Python/Node stdio transports. Lower-level classes are FastMCPProxy and ProxyProvider. The old FastMCP.as_proxy method is not in 4.x. By default the proxy mirrors the front connection's protocol era to the backend, so modern MRTR and legacy push sampling/elicitation both pass through. The Middleware class has these hooks: on_message, on_request, on_notification, on_initialize, on_discover, on_call_tool, on_list_tools, on_list_resources, on_list_resource_templates, on_read_resource, on_list_prompts, on_get_prompt. Built-in middleware includes authorization, rate_limiting, caching, logging, timing, error_handling, response_limiting, tool_injection and ping. The official MCP Python SDK (PyPI package mcp, latest 2.3.0 on 2026-10-02) is MIT-licensed, Copyright (c) 2024 Anthropic, PBC. In SDK 2.x, FastMCP was renamed to MCPServer (from mcp.server.mcpserver import MCPServer), and importing mcp.server.fastmcp raises ModuleNotFoundError pointing to the migration guide. Only the 1.x line (latest 1.30.0) still ships mcp.server.fastmcp, the original FastMCP 1.0 code. The standalone fastmcp package is separate (PrefectHQ, Apache-2.0).

**Impact on the hackathon:** Pin fastmcp==4.0.10. Use create_proxy (not as_proxy) with an MCPConfig to front stdio servers, and put policy in a Middleware subclass using on_call_tool, on_list_tools, on_read_resource and on_get_prompt; on_initialize/on_discover cover the handshake and discovery. Do not write 'from mcp.server.fastmcp import FastMCP' against mcp>=2. In attributions, list the MCP SDK as MIT and FastMCP as Apache-2.0.

**Sources:** <https://pypi.org/project/fastmcp/4.0.10/> · <https://pypi.org/pypi/fastmcp/json> · <https://github.com/PrefectHQ/fastmcp> · <https://pypi.org/pypi/mcp/json> · <https://github.com/modelcontextprotocol/python-sdk/blob/main/LICENSE> · <https://py.sdk.modelcontextprotocol.io/v2/migration/#fastmcp-renamed-to-mcpserver>

#### B3 — Claude Code managed settings keys (allowedProviders, apiKeyHelper, managed-mcp.json, ...)

**Verdict:** ✅ confirmed

All the named items exist in the current Claude Code docs, with these exact names and shapes. File paths for managed-settings.json: macOS /Library/Application Support/ClaudeCode/managed-settings.json, Linux and WSL /etc/claude-code/managed-settings.json, Windows C:\Program Files\ClaudeCode\managed-settings.json. The legacy C:\ProgramData path is not read. An optional managed-settings.d/*.json drop-in directory and managed-mcp.json live in the same system directory. Managed settings can also come from the macOS profile domain com.anthropic.claudecode, the HKLM/HKCU\SOFTWARE\Policies\ClaudeCode 'Settings' registry value, or server-managed settings. Settings details: 'env' is a settings object, and ANTHROPIC_BASE_URL is set in it. 'apiKeyHelper' is a shell command whose output is sent as X-Api-Key and Authorization: Bearer, cached for 5 min by default (CLAUDE_CODE_API_KEY_HELPER_TTL_MS). 'allowedProviders' is managed-scope only and needs Claude Code v2.1.285 or later. Its values are anthropic, bedrock, vertex, foundry, anthropicAws, mantle, customEndpoint and gateway. ["customEndpoint"] is admitted only when ANTHROPIC_BASE_URL matches the exact value pinned in a managed env block. 'availableModels' is an array of aliases or IDs that uses prefix matching; related keys are enforceAvailableModels, availableModelsMatch and deniedModels. 'allowedMcpServers' and 'deniedMcpServers' take entries with exactly one of serverName, serverCommand or serverUrl; related keys are allowManagedMcpServersOnly and managedMcpServers. Bypass mode is disabled with the nested 'permissions.disableBypassPermissionsMode': "disable" (a string, not a boolean, and not top-level), with a matching permissions.disableAutoMode. CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY=1 is an env var that fills the /model picker from the gateway's /v1/models, still filtered by availableModels; its timeout is set by CLAUDE_CODE_GATEWAY_MODEL_DISCOVERY_TIMEOUT_MS (default 3000). 'statusLine' is {type:"command", command, padding?, refreshInterval?, hideVimModeIndicator?}.

**Impact on the hackathon:** Use these exact keys in the sample managed-settings.json. Write "permissions": {"disableBypassPermissionsMode": "disable"}, not a top-level boolean. Pair allowedProviders ["customEndpoint"] with ANTHROPIC_BASE_URL in the same managed env block. Note that allowedProviders needs v2.1.285 or later. Ship the Windows path as C:\Program Files\ClaudeCode. The docs say server-managed delivery is not available on gateway configurations, so deliver availableModels for a custom gateway through a file or MDM.

**Sources:** <https://code.claude.com/docs/en/managed-settings> · <https://code.claude.com/docs/en/settings-reference> · <https://code.claude.com/docs/en/llm-gateway> · <https://code.claude.com/docs/en/authentication> · <https://code.claude.com/docs/en/env-vars> · <https://code.claude.com/docs/en/managed-mcp> · <https://code.claude.com/docs/en/permissions> · <https://code.claude.com/docs/en/statusline>

#### B4 — Anthropic "Claude apps gateway" exists with SSO, group model allowlists, spend limits

**Verdict:** ✅ confirmed

The exact name is 'Claude apps gateway'. The /login screen labels it 'Cloud gateway', and its allowedProviders value is "gateway". It is Anthropic's self-hosted gateway, built into the claude binary and run with `claude gateway --config gateway.yaml`. It needs PostgreSQL 14 or later, HTTPS, and a private-network address. Developers sign in through an OIDC IdP (authorization-code flow plus the OAuth device flow, urn:ietf:params:oauth:grant-type:device_code). SAML and LDAP are not supported, there is one issuer per gateway, and there is no service-token flow for CI. IdP groups map to model allowlists and to managed-settings policies (managed.policies). Requests for models a group is not granted return 400, and the /model picker is filtered to availableModels. Per-user, per-group and org spend limits are set daily, weekly or monthly through an admin API. Over a cap, the gateway returns 429 with error.type billing_error, header x-should-retry: false, and a retry-after header (gateway v2.1.225 or later). Enforcement fails open by default; enforcement.fail_closed_on_error turns that off. Claude Code warns at 75% and 95% of a cap. Telemetry goes out as OTLP. Upstreams are Amazon Bedrock, Claude Platform on AWS, Google Cloud Agent Platform, Microsoft Foundry and the Anthropic API, with failover. A running gateway serves its protocol at GET /protocol. There is no Helm chart.

**Impact on the hackathon:** Call it 'Claude apps gateway' and link to https://code.claude.com/docs/en/claude-apps-gateway. Any custom gateway we build will be compared against it, so explain what ours adds, such as MCP or tool governance. It is positioned for orgs routing through their own cloud provider. Copy its error contract: 400 for an ungranted model, and 429 billing_error with x-should-retry: false and retry-after for spend caps. Do not plan on CI or service-token auth through it.

**Sources:** <https://code.claude.com/docs/en/claude-apps-gateway> · <https://code.claude.com/docs/en/claude-apps-gateway-spend-limits> · <https://code.claude.com/docs/en/claude-apps-gateway-config> · <https://code.claude.com/docs/en/gateways> · <https://code.claude.com/docs/en/llm-gateway>

#### B5 — OWASP Agent Control Standard v0.1.0 (allow/deny/modify/ask/defer, Claude Code hook shim)

**Verdict:** ✅ confirmed

The repo is github.com/GenAI-Security-Project/agent-control-standard. Its default branch is 'integration', and main exists as well. OWASP announced ACS as an OWASP GenAI Security Project standard on 2026-09-01. The spec schemas sit in specification/v0.1.0/, but the repo version.txt reads 0.1.2 and the git tags are v0.1.1 and v0.1.2; there is no v0.1.0 tag. The decision enum in response-envelope.json is ["allow","deny","modify","ask","defer"], with separate schemas for ask-details, defer-details and modifications. A defer falls back to deny or ask. Fail posture is set in the handshake: 'proceed' (fail-open, the default) or 'deny'. The Claude Code reference shim is reference-implementations/agt/hosts/claude-code/acs-hook.ts (TypeScript, run with bun). It registers PreToolUse for ^(Bash|WebFetch)$ and PostToolUse for ^Bash$, posts an ACS envelope to an AGT-based Guardian, and returns hookSpecificOutput.permissionDecision. Licensing: Apache-2.0 for code and spec, CC BY-SA 4.0 for prose docs, and MIT (Microsoft) for agt/policy/lib.

**Impact on the hackathon:** Cite it as 'ACS spec v0.1.0 (repo release v0.1.2)'. Reuse the five-way decision enum and the acs-hook.ts / settings.json pattern for the Claude Code PreToolUse integration. The shim needs bun and a running Guardian. Keep the Apache-2.0 and CC BY-SA split in mind if we copy schemas versus docs. The spec is pre-1.0 and may change.

**Sources:** <https://github.com/GenAI-Security-Project/agent-control-standard> · <https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/specification/v0.1.0/response-envelope.json> · <https://github.com/GenAI-Security-Project/agent-control-standard/tree/main/reference-implementations/agt/hosts/claude-code> · <https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/LICENSING.md> · <https://genai.owasp.org/2026/09/01/owasp-genai-security-project-unveils-2026-top-10-for-llm-applications-new-agent-control-standard-and-sponsors-as-community-tops-30000-members/>

#### B6 — A2A v1.0 (Mar 2026), signed Agent Cards (JWS over JCS)

**Verdict:** ✅ confirmed

A2A v1.0.0 was tagged and released on 2026-03-12, according to the CHANGELOG and tag date; v1.0.1 followed on 2026-05-28 and is the latest. The repo README says A2A 'is an open source project under the Linux Foundation, contributed by Google', under Apache-2.0, and v1.0 added the LF prefix to the proto package. The v1.0 announcement lists Signed Agent Cards as an enterprise feature. Spec section 8.4: Agent Cards MAY be signed with JWS (RFC 7515), and the card MUST first be canonicalized with JCS (RFC 8785), leaving out the signatures field. AgentCardSignature has protected, signature and optional header fields. Signing is optional, not mandatory. The signatures field first appeared in v0.3.0; v1.0 clarified the canonicalization and verification steps.

**Impact on the hackathon:** Say 'A2A v1.0 (March 2026, latest v1.0.1)'. Describe Agent Card signing as optional ('MAY'), done as JWS over a JCS-canonicalized card. If the gateway checks cards, it has to canonicalize per RFC 8785 with the signatures field excluded and protobuf field-presence rules respected.

**Sources:** <https://github.com/a2aproject/A2A/releases> · <https://github.com/a2aproject/A2A/blob/v1.0.1/CHANGELOG.md> · <https://github.com/a2aproject/A2A/blob/v1.0.1/docs/specification.md> · <https://github.com/a2aproject/A2A/blob/v1.0.1/docs/announcing-1.0.md> · <https://github.com/a2aproject/A2A/blob/v1.0.1/README.md>

### OWASP, ATLAS, regulation, OCSF

#### C1 — OWASP LLM Top 10 2026 (published 2026-08-04) IDs and 2025 IDs

**Verdict:** ✅ confirmed

Confirmed from the official GitHub repo. GenAI-Security-Project/GenAI-LLM-Top10 says the 2026 edition was 'published August 4, 2026' and lists LLM01:2026 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Excessive Agency, LLM04 Supply Chain, LLM05 Data and Model Poisoning, LLM06 Unbounded Consumption, LLM07 Misinformation, LLM08 Hidden Context Exposure, LLM09 Vector and Embedding Weaknesses and LLM10 Improper Output Handling. Its official title is 'OWASP GenAI LLM Top 10 2026', and it has a Zenodo concept DOI, 10.5281/zenodo.22109014. Hidden Context Exposure is the renamed 2025 'System Prompt Leakage'. Excessive Agency moved up from 6 to 3, and Improper Output Handling dropped from 5 to 10. The 2025 list is also confirmed exactly from the files in the repo's 2025/ folder and in OWASP/www-project-top-10-for-large-language-model-applications/2_0_vulns: LLM01 PromptInjection, LLM02 SensitiveInformationDisclosure, LLM03 SupplyChain, LLM04 DataModelPoisoning, LLM05 ImproperOutputHandling, LLM06 ExcessiveAgency, LLM07 SystemPromptLeakage, LLM08 VectorAndEmbeddingWeaknesses, LLM09 Misinformation, LLM10 UnboundedConsumption. Active development has moved from the old OWASP/www-project-... repo, which is now a legacy archive, to GenAI-Security-Project/GenAI-LLM-Top10.

**Impact on the hackathon:** Use the 2026 IDs (LLM01:2026..LLM10:2026) as the main taxonomy. Keep a 2025 to 2026 mapping table, because the same number now means a different risk in each edition. For example, 2025 LLM03 is Supply Chain but 2026 LLM03 is Excessive Agency, and 2025 LLM07 System Prompt Leakage became 2026 LLM08 Hidden Context Exposure. Always attach the year suffix to the ID.

**Sources:** <https://github.com/GenAI-Security-Project/GenAI-LLM-Top10> · <https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2025> · <https://github.com/OWASP/www-project-top-10-for-large-language-model-applications> · <https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/tree/main/2_0_vulns> · <https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/>

#### C2 — OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10)

**Verdict:** ✅ confirmed

The OWASP GenAI Security Project announced the OWASP Top 10 for Agentic Applications for 2026 in a post at genai.owasp.org/2025/12/09/..., dated 9 Dec 2025. One secondary summary says 10 Dec, but the official URL is dated 12/09. The entries are ASI01 Agent Goal Hijack, ASI02 Tool Misuse & Exploitation, ASI03 Identity & Privilege Abuse, ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution, ASI06 Memory & Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation and ASI10 Rogue Agents. OWASP's own Q1-2026 Exploit Round-up uses 'ASI08: Cascading Failures'. The OWASP crosswalk repo labels it 'Cascading Agent Failures', so naming is slightly inconsistent even inside OWASP. The genai.owasp.org pages themselves were blocked by the network proxy, so this verdict rests on official URLs and search snippets from genai.owasp.org plus the OWASP crosswalk repo on GitHub.

**Impact on the hackathon:** The ASI01-ASI10 names are safe to use as given. Use 'Cascading Failures' for ASI08. The OWASP crosswalk repo already maps ASI to LLM Top 10, ATLAS and EU AI Act, so we can reuse it. However, its ATLAS technique names are partly wrong (for example, it calls AML.T0020 'Backdoor via Poisoned Memory'), so don't copy its ATLAS names.

**Sources:** <https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/> · <https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/> · <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/> · <https://genai.owasp.org/2026/04/14/owasp-genai-exploit-round-up-report-q1-2026/> · <https://github.com/GenAI-Security-Project/crosswalk/blob/main/agentic-top10/Agentic_MITREATLAS.md>

#### C3 — OWASP MCP Top 10 beta "v0.1"

**Verdict:** 🟡 partially

The beta status is right. The OWASP MCP Top 10 index.md says 'Phase 3 – Beta Release and Pilot Testing - We are here right now', and 'Phase 5 – Continuous Improvement & Next Release in October 2026' is planned. The IDs are year-suffixed, MCP01:2025 through MCP10:2025. The primary repo never says 'v0.1': the sidebar info.md lists 'Version 0.0.0' and 'Incubator Project', and '0.1' appears only in secondary write-ups. MCP01 'Token Mismanagement & Secret Exposure' and MCP10 'Context Injection & Over-Sharing' are correct. MCP06 was renamed in Jan 2026 (commit 'add-intent-flow-subversion'). The live index.md calls it 'Intent Flow Subversion', but the repo README still says 'Prompt Injection via Contextual Payloads'. The full current list is: MCP01 Token Mismanagement & Secret Exposure, MCP02 Privilege Escalation via Scope Creep, MCP03 Tool Poisoning, MCP04 Software Supply Chain Attacks & Dependency Tampering, MCP05 Command Injection & Execution, MCP06 Intent Flow Subversion, MCP07 Insufficient Authentication & Authorization, MCP08 Lack of Audit and Telemetry, MCP09 Shadow MCP Servers, MCP10 Context Injection & Over-Sharing. The last commits were on 29 Jul 2026.

**Impact on the hackathon:** Cite it as 'OWASP MCP Top 10 (2025 edition, beta)' rather than 'v0.1'. Use 'Intent Flow Subversion' for MCP06. A new release is planned for October 2026, which is this month, so check the repo again just before the demo in case IDs or names change.

**Sources:** <https://raw.githubusercontent.com/OWASP/www-project-mcp-top-10/main/index.md> · <https://raw.githubusercontent.com/OWASP/www-project-mcp-top-10/main/info.md> · <https://github.com/OWASP/www-project-mcp-top-10> · <https://github.com/OWASP/www-project-mcp-top-10/commits/main> · <https://owasp.org/www-project-mcp-top-10/>

#### C4 — MITRE ATLAS v2026.09 and technique IDs

**Verdict:** ✅ confirmed

Confirmed by downloading the data and checking it. MITRE ATLAS v2026.09 was released 2026-09-15 (dist/manifest.yaml, file dist/v6/ATLAS-2026.09.yaml, format-version 6.0.0, collection version '2026.09'). It has 16 tactics, 120 top-level techniques plus 88 sub-techniques (208 technique objects in total), 40 mitigations and 73 case studies. Exact names: AML.T0051 'LLM Prompt Injection' (subs .000 Direct, .001 Indirect, .002 Triggered); AML.T0054 'LLM Jailbreak'; AML.T0010 'AI Supply Chain Compromise' (subs include .005 AI Agent Tool); AML.T0011 'User Execution', whose sub-technique AML.T0011.000 is 'Unsafe AI Artifacts' (other subs: .001 Malicious Package, .002 Poisoned AI Agent Tool, .003 Malicious Link); AML.T0109 'AI Supply Chain Rug Pull' (created 2026-03-30); AML.T0110 'AI Agent Tool Poisoning' (created 2026-03-30); AML.T0034 'Cost Harvesting'. Related IDs: AML.T0053 AI Agent Tool Invocation, AML.T0086 Exfiltration via AI Agent Tool Invocation, AML.T0098 AI Agent Tool Credential Harvesting, AML.T0099 AI Agent Tool Data Poisoning. Note that dist/ATLAS.yaml is deprecated and frozen at legacy format 5.6.0.

**Impact on the hackathon:** Load dist/v6/ATLAS-2026.09.yaml (or dist/v6/ATLAS-latest.yaml) in format 6.0.0, where 'techniques' is a dict keyed by ID. Do not use the deprecated dist/ATLAS.yaml, which is frozen at 5.6.0 and lacks the newer techniques. For 'unsafe AI artifacts', use the sub-technique AML.T0011.000 rather than the parent AML.T0011. Say '120 techniques + 88 sub-techniques'.

**Sources:** <https://github.com/mitre-atlas/atlas-data/releases> · <https://github.com/mitre-atlas/atlas-data> · <https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/manifest.yaml> · <https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/ATLAS-2026.09.yaml>

#### C5 — SR 11-7 rescinded 2026-04-17; SR 26-2 excludes GenAI/agentic AI

**Verdict:** ✅ confirmed

On 17 Apr 2026, the Federal Reserve (SR 26-2), the OCC (Bulletin 2026-13) and the FDIC jointly issued 'Revised Guidance on Model Risk Management'. It supersedes SR 11-7 (2011) and SR 21-8 (BSA/AML models), and the OCC also withdrew Bulletins 2011-12 / 2021-19 / 1997-24 and the MRM handbook booklet. The attachment says: 'Generative AI and agentic AI models are novel and rapidly evolving, and as such, they are not within the scope of this guidance.' The principles apply to traditional statistical and quantitative models and to non-generative, non-agentic AI models. The Fed letter says it is most relevant to banking organizations with over $30B in total assets. One correction: the FDIC was a third co-issuer, so it was not only the Fed and OCC. The federalreserve.gov and occ.treas.gov pages were blocked by the network proxy, so this rests on search-index snippets of those official pages and PDFs (SR2602.htm, SR2602a1.pdf, OCC bulletin-2026-13a.pdf).

**Impact on the hackathon:** Don't present agent governance as 'SR 11-7 / SR 26-2 compliance'. SR 26-2 explicitly excludes GenAI and agentic AI and leaves them to banks' general risk management and governance practices. That gap is a fair pitch angle: there is no prescriptive US banking MRM standard for agents. Cite SR 26-2 / OCC 2026-13 as the source of that exclusion, and name all three agencies.

**Sources:** <https://www.federalreserve.gov/supervisionreg/srletters/SR2602.htm> · <https://www.federalreserve.gov/supervisionreg/srletters/SR2602.pdf> · <https://www.federalreserve.gov/supervisionreg/srletters/SR2602a1.pdf> · <https://www.occ.treas.gov/news-issuances/bulletins/2026/bulletin-2026-13.html> · <https://www.occ.treas.gov/news-issuances/bulletins/2026/bulletin-2026-13a.pdf> · <https://www.federalreserve.gov/newsevents/speech/bowman20260501a.htm>

#### C6 — OCSF 1.9.0 ai_operation + record_integrity profiles; classes 6003/2004

**Verdict:** 🟡 partially

OCSF schema v1.9.0 was released Aug 3rd, 2026 (CHANGELOG '## [v1.9.0] - Aug 3rd, 2026'; version.json = 1.9.0). It does include profiles/ai_operation.json (caption 'AI Operation') and profiles/record_integrity.json (caption 'Record Integrity', which carries attestation_list). However, ai_operation is not new in 1.9.0: it was introduced in v1.8.0 (Mar 18, 2026). 1.9.0 added the optional 'delegation' attribute and the 'ai_agent' attribute, and attached the profile to the system, network, application and iam base classes plus email_activity. record_integrity is new in 1.9.0 (PR #1661) and is applied at base_event, so any class can carry it, with attributes attestation_list, prev_event, authority_uid and chain_uid for hash chains. Class UIDs are confirmed: API Activity has uid 3 in category Application (6), so class_uid 6003. Detection Finding has uid 4 in category Findings (2), so class_uid 2004. In 1.9.0, API Activity inherits the ai_operation profile through the application base class.

**Impact on the hackathon:** Target OCSF 1.9.0. Emit agent tool calls as API Activity (6003) with metadata.profiles ['ai_operation','record_integrity'], filling ai_agent, ai_model, delegation and message_context. Use record_integrity attestation_list / prev_event / chain_uid to build the tamper-evident hash chain instead of inventing our own. Put detections in Detection Finding (2004). Don't say ai_operation is new in 1.9.0.

**Sources:** <https://github.com/ocsf/ocsf-schema/releases> · <https://raw.githubusercontent.com/ocsf/ocsf-schema/v1.9.0/CHANGELOG.md> · <https://raw.githubusercontent.com/ocsf/ocsf-schema/v1.9.0/profiles/ai_operation.json> · <https://raw.githubusercontent.com/ocsf/ocsf-schema/v1.9.0/profiles/record_integrity.json> · <https://raw.githubusercontent.com/ocsf/ocsf-schema/v1.9.0/events/application/api_activity.json> · <https://raw.githubusercontent.com/ocsf/ocsf-schema/v1.9.0/events/findings/detection_finding.json> · <https://raw.githubusercontent.com/ocsf/ocsf-schema/v1.9.0/categories.json>

#### C7 — EU AI Act high-risk obligations postponed to 2 Dec 2027; Art. 12 logging

**Verdict:** 🟡 partially

The Digital Omnibus on AI is Regulation (EU) 2026/1744 of 8 July 2026. It amends the AI Act (Reg. 2024/1689); the political agreement came on 7 May 2026, and it was published in the OJ and entered into force 27 July 2026. It fixes split dates for high-risk obligations, not one date. Chapter III Sections 1-3 apply from 2 Dec 2027 for high-risk systems under Art. 6(2)/Annex III, and from 2 Aug 2028 for systems under Art. 6(1)/Annex I (product-embedded, e.g. lifts and toys). So '2 Dec 2027' is correct only for Annex III. Art. 12 (record-keeping) is in Chapter III Section 2 and applies to high-risk AI systems: they must 'technically allow for the automatic recording of events (logs) over the lifetime of the system' to support risk identification, post-market monitoring and operational monitoring. Annex III point 1(a) remote biometric ID systems have extra minimum log fields. Art. 12 therefore follows the same split dates. I found no evidence that the Omnibus changed Art. 12's substance. EUR-Lex and the EU AI Act Service Desk were blocked by the network proxy, so this rests on search-index snippets of those official pages plus secondary legal summaries.

**Impact on the hackathon:** Say 'Annex III high-risk obligations, including Art. 12 logging, apply from 2 Dec 2027; Annex I product-embedded high-risk from 2 Aug 2028 (Reg. (EU) 2026/1744)'. Present Art. 12 automatic event logging (with provider and deployer log retention under Arts. 19/26) as the legal hook for the tamper-evident audit trail.

**Sources:** <https://eur-lex.europa.eu/eli/reg/2026/1744/oj/eng> · <https://eur-lex.europa.eu/eli/reg/2024/1689/2026-07-27/eng> · <https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-113> · <https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-12> · <https://www.consilium.europa.eu/en/press/press-releases/2026/05/07/artificial-intelligence-council-and-parliament-agree-to-simplify-and-streamline-rules/> · <https://artificialintelligenceact.eu/article/12/>

### OSS projects, supply chain, historical incidents

#### D1 — LiteLLM PyPI compromise 2026-03-24 (1.82.7/1.82.8)

**Verdict:** ✅ confirmed

Confirmed. On 24 Mar 2026, litellm 1.82.7 and 1.82.8 were uploaded to PyPI straight from a hijacked maintainer PyPI account (krrishdholakia). The upload claimed by 'TeamPCP' did not go through the project's GitHub CI/CD, whose releases stopped at v1.82.6.dev1. In 1.82.7 the payload sits in litellm/proxy/proxy_server.py. Version 1.82.8 also adds litellm_init.pth, which runs on every Python start. The payload steals credentials (SSH keys, cloud and Kubernetes secrets, .env files, wallets). PyPI quarantined the package after roughly 40 minutes to 3 hours. Both versions are now gone from PyPI history, which goes from 1.82.6 (22 Mar) straight to 1.83.0 (31 Mar 2026), the first clean release from a rebuilt pipeline. The maintainers say other versions should also be audited.

**Impact on the hackathon:** Pin litellm>=1.83.0 with hash-checked installs (pip --require-hashes or a uv lock file). Check every environment for litellm_init.pth. This is a strong real-world example for supply-chain and AI-gateway threat scenarios. Also note: v1.83.0 fixed a missing admin-role check on /config/update (PYSEC-2026-2597), another reason to stay on 1.83.x or later.

**Sources:** <https://github.com/BerriAI/litellm/issues/24518> · <https://pypi.org/project/litellm/#history> · <https://www.bitsight.com/blog/litellm-versions-1-82-7-1-82-8-supply-chain-compromise> · <https://hpc.vub.be/news/2026/hydra-litellm-security/>

#### D2 — LiteLLM enterprise gating; config.yaml needs restart

**Verdict:** 🟡 partially

The enterprise gating is confirmed in the source code. ui_sso.py contains `_raise_if_sso_exceeds_free_user_limit` ('Free tier allows SSO for up to 5 billable users; beyond that requires an Enterprise license'). user_api_key_auth.py rejects JWT auth without a license ('JWT Auth is an enterprise only feature'). custom_guardrail.py gates tag-based guardrails and dynamic per-request guardrail params behind premium_user, and the hide-secrets guardrail ships in the enterprise package. Other gated settings include enforced_params, allowed_ips and worker_registry. The restart claim is only half right. The proxy does not watch config.yaml, so file edits need a restart. But with store_model_in_db, models and settings stored in the DB can be changed through the Admin UI or API (/config/update, /config/field/update) with no restart. The proxy reloads DB config every 30 s by default (proxy_config_reload_interval_seconds / PROXY_CONFIG_RELOAD_INTERVAL_SECONDS).

**Impact on the hackathon:** Plan for the OSS limits: at most 5 SSO users, no JWT auth, and no tag-based or dynamic guardrails without a license. A free 7-day trial key exists. If live changes are needed in a demo, use store_model_in_db with Postgres and the UI/API rather than editing config.yaml, or describe the YAML approach as 'restart required' only. For JWT/OIDC auth, consider fronting LiteLLM with agentgateway or another gateway.

**Sources:** <https://github.com/BerriAI/litellm/blob/main/litellm/proxy/management_endpoints/ui_sso.py> · <https://github.com/BerriAI/litellm/blob/main/litellm/proxy/auth/user_api_key_auth.py> · <https://github.com/BerriAI/litellm/blob/main/litellm/integrations/custom_guardrail.py> · <https://github.com/BerriAI/litellm/blob/main/litellm/proxy/proxy_server.py> · <https://github.com/BerriAI/litellm/blob/main/litellm/constants.py> · <https://docs.litellm.ai/docs/enterprise> · <https://docs.litellm.ai/docs/proxy/ui_store_model_db_setting>

#### D3 — agentgateway (LF, Apache-2.0, LLM+MCP+A2A, hot reload, v1.6.0); Envoy AI Gateway renamed

**Verdict:** ✅ confirmed

agentgateway: the README says it is a Linux Foundation project under Apache-2.0, written mainly in Rust (with Go for the Kubernetes controller). It has LLM, MCP and A2A gateways and 'fine-grained RBAC with CEL policy engine'. In standalone mode it watches its config file and reloads it in place. Exception: startup settings in the top-level `config` block (adminAddr, storage, database, logging, tracing) only apply at process start, though config.modelCatalog does reload. GitHub releases list v1.6.0 on 2 Oct 2026 (rc.1 on 1 Oct, v1.5.0 on 27 Aug 2026). Envoy AI Gateway has been renamed Agent Router and is now an Agentic AI Foundation project (LF Projects) instead of an Envoy/CNCF sub-project. The repo moved from envoyproxy/ai-gateway to theagentrouter/agent-router and the site to theagentrouter.ai. Code, maintainers and the Apache-2.0 license are unchanged, and the CRD API group (aigateway.envoyproxy.io), the `aigw` CLI and the envoy-ai-gateway-system namespace stay the same. The rename date of 10 Sep 2026 comes from search snippets of the AAIF and Tetrate announcements, which I could not open directly.

**Impact on the hackathon:** Target agentgateway v1.6.0. Note that hot reload does not cover the top-level startup `config` block. Refer to the former Envoy AI Gateway as 'Agent Router (formerly Envoy AI Gateway)' and update links to theagentrouter.ai and theagentrouter/agent-router. Existing manifests, CRDs and aigw commands still work.

**Sources:** <https://github.com/agentgateway/agentgateway> · <https://github.com/agentgateway/agentgateway/releases> · <https://agentgateway.dev/docs/standalone/latest/setup/update/> · <https://github.com/envoyproxy/ai-gateway> · <https://github.com/theagentrouter/agent-router> · <https://aaif.io/blog/agent-router-joins-aaif>

#### D4 — Redis 8 tri-license vs Valkey BSD-3

**Verdict:** ✅ confirmed

Redis LICENSE.txt: 'Starting with Redis 8, Redis Open Source is moving to a tri-licensing model', where users choose RSALv2, SSPLv1 or AGPLv3. Redis 7.2 and earlier stay under BSD-3-Clause. Valkey's COPYING file is the BSD 3-Clause License (Copyright 2024-present Valkey contributors; 2006-2020 Redis Ltd.).

**Impact on the hackathon:** For a permissive, OSI-approved cache or rate-limit store, choose Valkey. Redis 8 under AGPLv3 is OSI open source but carries copyleft network obligations. Both work with LiteLLM and agentgateway Redis clients.

**Sources:** <https://github.com/redis/redis/blob/unstable/LICENSE.txt> · <https://github.com/valkey-io/valkey/blob/unstable/COPYING>

#### D5 — Keycloak 26.x token exchange + AI-agent delegation preview

**Verdict:** ✅ confirmed

Keycloak is Apache-2.0 (LICENSE.txt). The latest stable release is 26.8.0 (1 Oct 2026); there is no 27.x yet. Standard Token Exchange (RFC 8693, internal-to-internal) arrived in 26.2.0. The 26.8.0 notes add 'Token exchange delegation with consent, FGAP authorization, and audit trail (preview)', aimed explicitly at 'AI agents and automation tools'. Users delegate through the new parameterized scope `delegation:client:<client-id>`. The resulting token carries an `act` claim naming the client as actor. Access is controlled through FGAP v2 `delegate` / `delegate-members` scopes. A new client-policy executor can restrict the `may_act` claim, and standard token exchange rejects subject tokens that carry delegation claims. Parameterized (formerly dynamic) scopes also moved to preview in 26.8.0. I did not verify the exact preview feature-flag name.

**Impact on the hackathon:** Use Keycloak 26.8.0. Standard token exchange (GA since 26.2) is enough for on-behalf-of agent tokens. If the demo uses the new consent-based delegation with `act` claims, label it as a preview feature that must be enabled explicitly, and check the feature flag and parameterized-scope settings in the 26.8 docs.

**Sources:** <https://github.com/keycloak/keycloak/releases/tag/26.8.0> · <https://github.com/keycloak/keycloak/releases/tag/26.2.0> · <https://github.com/keycloak/keycloak/blob/main/LICENSE.txt> · <https://github.com/keycloak/keycloak/releases>

#### D6 — picklescan bypass CVEs; ModelScan Apache-2.0; fickling LGPL-3.0; nullifAI

**Verdict:** ✅ confirmed

picklescan: JFrog found three critical bypasses, published in Sept 2025: CVE-2025-10155 (file-extension mismatch; GHSA published 10 Sep 2025, NVD 17 Sep), CVE-2025-10156 (bad-CRC ZIP) and CVE-2025-10157 (submodule unsafe-globals bypass). Each scores CVSS 4.0 9.3 and is fixed in 0.0.31. More followed: a 'Multiple Scanner Bypass' critical in Nov 2025 and further critical advisories from Dec 2025 to Mar 2026. Over 100 unreviewed CVEs filed in mid-2026 cover versions up to 0.0.34. ModelScan (protectai/modelscan) is Apache-2.0, and fickling (trailofbits/fickling) is LGPL-3.0, both per their LICENSE files. ReversingLabs disclosed 'nullifAI' on 6 Feb 2025: two Hugging Face models used PyTorch files compressed with 7z instead of ZIP, plus deliberately broken pickle streams that ran a reverse-shell payload before deserialization failed. Hugging Face's Picklescan-based scanning did not flag them; HF removed them within 24h and Picklescan was updated to handle broken pickles.

**Impact on the hackathon:** Do not present a pickle denylist scanner as a security boundary. picklescan has a long and ongoing bypass record. Prefer safetensors and refuse pickle formats by default. If pickles must be accepted, layer scanners (ModelScan, fickling, latest picklescan) and load inside a sandbox. Note fickling's LGPL-3.0 license if you bundle it.

**Sources:** <https://github.com/advisories?query=CVE-2025-10155> · <https://github.com/mmaitre314/picklescan/security/advisories> · <https://nvd.nist.gov/vuln/detail/CVE-2025-10155> · <https://github.com/protectai/modelscan/blob/main/LICENSE> · <https://github.com/trailofbits/fickling/blob/master/LICENSE> · <https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face> · <https://www.reversinglabs.com/press-releases/reversinglabs-identifies-novel-ml-malware-hosted-on-leading-hugging-face-ai-model-platform>

#### D7 — Historical incident CVEs (ShadowRay, Probllama, Langflow, EchoLeak, mcp-remote, MCP Inspector, postmark-mcp, Cursor, Keras, Amazon Q, Nx)

**Verdict:** ✅ confirmed

All items check out, with these specifics. (1) ShadowRay, CVE-2023-48022: Ray Jobs API unauthenticated RCE (GHSA, critical, Nov 2023), named by Oligo in Mar 2024. Anyscale disputes it as by-design, so it is still unpatched; run Ray only on isolated networks. (2) Probllama, CVE-2024-37032 (Wiz): unvalidated digest leads to path traversal through a malicious manifest's digest field via /api/pull, then file overwrite and RCE; fixed in Ollama 0.1.34. (3) Langflow CVE-2025-3248: unauthenticated code injection at /api/v1/validate/code in langflow <1.3.0; CVSS 9.3, on CISA KEV. (4) EchoLeak, CVE-2025-32711: zero-click M365 Copilot prompt-injection data exfiltration (Aim Labs), CVSS 9.3, fixed server-side by Microsoft in May/June 2025. (5) mcp-remote CVE-2025-6514: OS command injection when connecting to a malicious MCP server (JFrog, GHSA July 2025). (6) MCP Inspector CVE-2025-49596: no auth between Inspector client and proxy, leading to RCE (critical, June 2025). (7) postmark-mcp: malicious npm package that BCC'd every email to phan@giftshop[.]club starting in v1.0.16 (released 17 Sep 2025), reported by Koi Security, about 1,643 downloads. (8) Cursor CVE-2025-54135 'CurXecute' (Aim, CVSS 8.5) and CVE-2025-54136 'MCPoison' (Check Point, CVSS 7.2; versions 1.2.4 and below), disclosed Aug 2025 with matching GHSAs on cursor/cursor dated 1-2 Aug 2025. (9) Keras CVE-2024-3660: code injection through Lambda layers in model loading for keras <2.13.1rc0 (CVSS 9.3). (10) Amazon Q Developer VS Code extension v1.84.0 (July 2025): an injected 'wipe to factory state / delete cloud resources' prompt, AWS-2025-015 / CVE-2025-8217 / GHSA-7g7f-ff96-5gcw. AWS says the injected code was inert because of a syntax error; fixed in v1.85.0. (11) Nx 's1ngularity' (26-27 Aug 2025): a malicious postinstall telemetry.js harvested secrets into public s1ngularity-repository repos. Security researchers (Wiz, JFrog, OX) report it invoked Claude, Gemini and Amazon Q CLIs with --dangerously-skip-permissions / --yolo / --trust-all-tools to search for secrets. The official Nx GHSA quotes the 'file-search agent' prompt but does not name the CLIs.

**Impact on the hackathon:** These are safe to cite as motivating incidents. Add these nuances: CVE-2023-48022 is disputed and unpatched by design; the Amazon Q payload never actually ran (syntax error); the AI-CLI abuse in Nx comes from vendor research, not the Nx advisory. Each one maps to a gateway control: auth on internal AI services, model and registry integrity, MCP server allowlisting with pinned versions, and egress/DLP for agents.

**Sources:** <https://github.com/advisories?query=CVE-2023-48022> · <https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild> · <https://github.com/advisories?query=CVE-2024-37032> · <https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032> · <https://github.com/advisories/GHSA-rvqx-wpfh-mfx7> · <https://www.tenable.com/cve/CVE-2025-32711> · <https://github.com/advisories?query=CVE-2025-6514> · <https://github.com/advisories?query=CVE-2025-49596> · <https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html> · <https://github.com/cursor/cursor/security/advisories?page=3> · <https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison> · <https://github.com/advisories/GHSA-x4wf-678h-2pmq> · <https://github.com/aws/aws-toolkit-vscode/security/advisories> · <https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c> · <https://wiz.io/blog/s1ngularitys-aftermath> · <https://research.jfrog.com/post/nx-supply-chain-attack-targets-ai-tool-users/>
