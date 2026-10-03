# Gate contract (proposal, 1 page)

This keeps your design: the pipeline POSTs to a gate, and the gate answers **allow / deny / modify**.
Two things change. Config and context move from headers into a JSON body (the *envelope*), and every answer carries a reason.

## 1. Pipeline → gate

```http
POST http://127.0.0.1:8704/evaluate          # URL comes from `registry:` in pipeline.yaml
Content-Type: application/json
X-Trace-Id: t-8f3a21c0                        # the same id in every gate call and in the audit record
X-Gate-Id: filter_kill                        # instance id from pipeline.yaml
X-Pipeline-Version: 12
Authorization: Bearer <internal gate token>   # a gate refuses calls without it
```

```json
{
  "phase": "request",
  "input":   {"model": "claude-sonnet-5-5", "max_tokens": 512,
              "messages": [{"role": "user", "content": "how do I kill the stuck job?"}]},
  "config":  {"pattern": "kill", "decision": "deny", "ignore_case": true, "whole_word": true},
  "context": {"identity": {"user": "alice", "team": "payments"},
              "restart": 0,
              "trail": [{"id": "auth", "decision": "allow"}, {"id": "model_allowed", "decision": "allow"}]}
}
```

- **`input`**: the current request body (Anthropic or OpenAI JSON). After a `modify` it is the modified body.
  In the `response` phase it is the model's answer, and `context.request` holds the request that produced it.
- **`config`**: this instance's `config:` block from `pipeline.yaml`. It is JSON, so lists, nesting and Polish characters just work.
- **`context`**: what earlier gates established. **Only the pipeline writes it.** A gate can propose updates, see `context` below.

> **Why not headers?** We tested it (FastAPI + uvicorn + httpx). A config like `"replacement": "Firma Ś"` in a header makes
> httpx raise `UnicodeEncodeError`, so the call never leaves the pipeline. Sent as UTF-8 bytes instead, uvicorn decodes it as
> latin-1, and the gate masks with `Firma Å\x9a`. Headers also land in access logs, and proxies such as nginx reject header lines
> over 8 KB by default, so a long word list breaks the moment there's a proxy in between.

## 2. Gate → pipeline (HTTP 200 whenever the gate itself worked)

```json
{
  "decision": "deny",
  "reason":   "matched \"kill\" (whole word) in messages[0]",
  "findings": [{"path": "messages[0].content", "start": 9, "end": 13, "match": "kill"}],
  "output":   null,
  "context":  null,
  "score":    null
}
```

| Field | Required | Meaning |
|---|---|---|
| `decision` | yes | `allow` · `deny` · `modify` · `flag` (new: allow, but record it as suspicious) |
| `reason` | yes | One human-readable line. It goes into the audit log, the trace view and the error message the agent sees |
| `findings` | no | What matched and where. Lets the UI highlight it, and lets reports count it |
| `output` | for `modify` | The **whole new input**. The pipeline validates it (see §4) and diffs it for the audit log |
| `context` | no | Proposed context updates, e.g. auth returns `{"identity": {...}}`. Accepted only from gates whose `/describe` says `provides: [identity]` |
| `score` | no | Numeric score for gates such as JEV (0-100) |

Later, if there's time: `ask` (human approval) and `route` (send to a local model instead). The OWASP Agent Control Standard
uses allow / deny / modify / ask / defer, so our vocabulary is a subset of a published standard. Say that in the pitch.

## 3. Errors and timeouts

| Situation | Pipeline treats it as | Then |
|---|---|---|
| Non-200, timeout (`timeout_ms`), connection refused | gate **error** | apply the instance's `on_error`: `deny` (default) · `allow` · `skip` |
| Invalid JSON, unknown `decision`, `modify` without `output` | gate **error** | same |
| `output` fails validation (§4) | gate **error** | same, and the reason says what was wrong |

The audit record shows `decision: error` plus what `on_error` did. **A gate never answers HTTP 403 to mean "deny".**
Otherwise the pipeline can't tell "the gate denied the request" from "the gate rejected our call".

## 4. Guard rails on `modify`

1. `output` must still parse as a valid request for the target API, using the same pydantic model as L1.
2. The pipeline diffs `output` against `input`. A gate may only change the paths it declares in `/describe` (`modifies: ["messages[*].content"]`).
   A word filter that suddenly changes `model`, `tools` or `system` is treated as a gate error.
3. The diff goes into the audit record, so the trace can show "Goldman Sachs → Firm" for that gate.

## 5. Every gate also serves

```http
GET /healthz    -> {"ok": true}
GET /describe   -> {"type": "word_filter", "version": "0.3.0", "phases": ["request", "response"],
                    "decisions": ["allow", "deny", "modify", "flag"], "stateful": false,
                    "needs": ["input.messages"], "provides": [], "modifies": ["messages[*].content"],
                    "config_schema": { ...JSON Schema of `config`... }}
```

`config_schema` lets the Pipeline Builder render each gate's form automatically and validate `pipeline.yaml` on save.
`needs` / `provides` let the builder catch ordering mistakes, such as budget_check before auth.
`stateful` tells the runner never to re-run the gate on a restart (§6).

## 6. Runner loop (sketch, ~40 lines of real code)

```python
client = httpx.AsyncClient()       # ONE client, created at startup. A new client per call costs ~48 ms (see bench/RESULTS.md).

async def run(pipe, phase, body, ctx):
    gates, trail, restarts, i = pipe[phase], [], 0, 0
    while i < len(gates):
        g = gates[i]
        if restarts and g.stateful:          # auth / budget / rate_limit: never twice per request
            i += 1; continue
        ans = await call_gate(g, phase, body, ctx)          # envelope in, Answer out; errors become on_error
        if g.mode == "monitor" and ans.decision in ("deny", "modify"):
            ans = Answer(decision="flag", reason="monitor mode, would " + ans.decision + ": " + ans.reason)
        trail.append(record(g, ans))
        if ans.decision == "deny":
            return "deny", body, trail       # short-circuit: later gates are 'not reached'
        if ans.context and g.may_provide(ans.context):
            ctx = {**ctx, **ans.context}
        if ans.decision == "modify":
            new = validate_modify(g, body, ans.output)     # schema + allowed paths, else gate error
            changed = digest(new) != digest(body)
            body = new
            if pipe.on_modify == "restart" and changed and restarts < pipe.max_restarts:
                restarts, i = restarts + 1, 0               # re-run the CONTENT gates on the new text
                continue
        i += 1
    return "allow", body, trail
```

`call_gate` posts the envelope with `timeout=g.timeout_ms/1000`. Any exception or invalid answer becomes
`Answer(decision="deny"|"allow", reason="gate error: ...")` according to `g.on_error`, and `skip` behaves like `allow`.
The full trail (instance id, type, decision, reason, ms, diff) goes into **one audit record per request**, together with
`pipeline.version`. That record is what the judges asked to see.
Wrap the whole request in `try / finally`: `budget_settle` and the audit write run in `finally`, so a deny, a gate error or an upstream
error never leaks a budget reservation or loses an audit record.
