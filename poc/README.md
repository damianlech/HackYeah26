# Warden POC: a minimal slice of the AI Control Layer

One gateway that takes an OpenAI-style request, runs it through a configurable pipeline of controls,
modifies or blocks it, and forwards it upstream. The model's answer then goes through the same
pipeline on the way back. Everything is driven by one file, `policy.yaml`, which hot-reloads on change.

```
client ──► gateway :8080 ──(request pipeline)──► mock LLM :9000 (or Ollama)
             │   auth → model_allowlist → budget → clamp_max_tokens
             │   → signatures (external feed) → pii → guard ──► guard-svc :9100 (separate service)
             │   → system_prompt
             ◄──(response pipeline: signatures → pii → budget_charge)
             └─ audit.jsonl + control plane /control/*
```

## Run (no installs needed: Python 3.12+, fastapi, uvicorn, httpx, pyyaml)

```bash
./poc/run.sh      # terminal 1: starts all 3 services
./poc/demo.sh     # terminal 2: 9 scripted scenarios, then restores policy.yaml
```

Diagrams of the flow and 16 step-by-step test scenarios: **[WALKTHROUGH.md](WALKTHROUGH.md)**.

## What it proves

| Claim | How to see it |
|---|---|
| The gateway **modifies** requests before forwarding | The mock LLM echoes what it received: injected system prompt, `max_tokens` clamped, PII replaced by `[EMAIL]`, `[PL_PESEL]`, `[CARD]` |
| It **blocks** requests | Prompt injection (guard), s1ngularity prompt (SIG-0012 from `examples/feed/signatures.yaml`), disallowed model |
| It governs the **response** too | `"leak"` makes the mock return PII and a markdown-image exfil link: SIG-0002 blocks it, or PII gets redacted |
| Controls are **separate services** | `guard` is a remote HTTP service. `on_error: closed` blocks if it's down |
| One **policy source**, live control | `PATCH /control/controls/{name}` or edit `policy.yaml` by hand. The next request uses the new policy. A broken edit is rejected and the last-known-good policy stays active |
| Pipeline is **configurable** | Reorder or remove steps under `pipeline:` in `policy.yaml` |
| **Audit** | Every decision is written to `audit.jsonl`, listing each control's verdict. View it with `GET /control/audit` |

## Control plane

```bash
curl localhost:8080/control/status                     # policy sha, pipeline, controls, budgets
curl -X PATCH localhost:8080/control/controls/pii -d '{"mode":"block"}' -H 'Content-Type: application/json'
curl localhost:8080/control/audit?n=5
curl -X POST localhost:8080/control/budget/reset
```

Any OpenAI client works: `base_url="http://127.0.0.1:8080/v1"`, `api_key="sk-alice"` (or `sk-judge`, which may also use `ollama/*`).

## Deliberately out of scope

No streaming, keys are plaintext, budgets are kept in memory, there are no containers or network fences, and the guard is a keyword heuristic standing in for a classifier. Writing through `PATCH` drops the comments in `policy.yaml`.
