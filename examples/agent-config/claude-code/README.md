# Claude Code governed by the AI Control Layer (zero code change)

Install `managed-settings.json` and `managed-mcp.json` in the **system** directory. Users can't override them.

| OS | Directory |
|---|---|
| macOS | `/Library/Application Support/ClaudeCode/` |
| Linux / WSL | `/etc/claude-code/` (this is what the demo agent container uses) |
| Windows | `C:\Program Files\ClaudeCode\` (the legacy `C:\ProgramData` path is **not** read) |

What each key does (verified against code.claude.com docs on 2026-10-03, see `research/FACT-CHECK.md`):

- `env.ANTHROPIC_BASE_URL` points Claude Code at our gateway (`/v1/messages`). The gateway forwards to Ollama's Anthropic-compatible `/v1/messages`.
- `allowedProviders: ["customEndpoint"]` (managed-only, **Claude Code ≥ 2.1.285**) *pins* the gateway: sessions pointed anywhere else are refused. It only admits the exact `ANTHROPIC_BASE_URL` from this managed `env`.
- `apiKeyHelper` runs a command whose stdout is sent as `X-Api-Key` and `Authorization: Bearer`. `aictl token` can return a virtual key or a short-lived OIDC token from a device-flow login (SSO + LDAP groups). It is cached for `CLAUDE_CODE_API_KEY_HELPER_TTL_MS`.
- `CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY=1` makes the `/model` picker call our `GET /v1/models`, which returns **only the models the caller's groups may use**. It is still filtered by `availableModels`.
- `allowManagedMcpServersOnly` + `managed-mcp.json` mean only our MCP proxy routes load, so every agent→MCP call is governed.
- `permissions.disableBypassPermissionsMode: "disable"` (a nested **string**) rejects `--dangerously-skip-permissions`.
- `statusLine` shows `budget 41% · models: qwen3:8b, qwen3:4b` inside Claude Code.
- `CLAUDE_CODE_MAX_CONTEXT_TOKENS` is required for local models, because Claude Code otherwise assumes 200K context.
- **Do not** set `forceLoginMethod`. It blocks `apiKeyHelper` credentials.

Caveats:

- Managed config is **UX, not a security boundary**: a local admin can edit it, and vendors say so. The real control is the network fence: the agent network has no route out except the gateway and Squid.
- Anthropic does not officially support routing Claude Code to non-Claude models through a gateway. Ollama documents it and it works in practice. Keep the Python agent and the Playground as primary demo clients, and Claude Code as the "real agent" showcase.
- In the demo compose stack, `lb` is the only host reachable from the `agents` network, hence `http://lb:8080` (spec §3.3–§3.4). On a Mac host without the container, use `http://localhost:8080`.
- The Anthropic `/v1/messages` route is **P1** in the spec (rank 10). Until it ships, Claude Code is a recorded clip, not a live beat.
- Optional (P2): if the stock Squid shadow-AI sensor runs, add `HTTPS_PROXY=http://squid:3128` and `NO_PROXY=lb,localhost,127.0.0.1` to `env` so pip/git/web traffic goes through it.
