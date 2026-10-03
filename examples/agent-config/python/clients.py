"""Integrating an app and an agent with the control layer: change base_url, use your own key. No SDK fork.

Canonical contract: design/VISION-SPEC.md §5.7 (wire contract), §11.2 (data-plane API), C33 (run tokens).

Two credentials, two roles:
  * A USER credential (virtual key or IdP JWT) mints a run with POST /v1/runs. Agent keys cannot mint runs.
    The task text is the run's trust anchor: destinations in it become the run's trusted destinations.
  * The AGENT uses its OWN key for every LLM and MCP call and presents the run token as `X-AICL-Run`.
Agent identity always comes from the credential. `X-AICL-Agent` is attribution only (logged, never trusted).
A missing, forged or mismatched run token does not error: the call lands in a sticky fallback run
(policy destinations only, taint kept) and the response carries `x-aicl-run-fallback: true`.
"""
import httpx
from openai import OpenAI

GATEWAY = "http://127.0.0.1:8080"  # `lb`: the only host agents can reach. Data plane only: no /api, no /admin.
USER_KEY = "vk_alice_…"            # PLACEHOLDER from `make keys`: alice (groups quant-analysts, support)
AGENT_KEY = "vk_support_bot_…"     # PLACEHOLDER from `make keys`: the support-bot agent's own key
INTERN_KEY = "vk_ola_…"            # PLACEHOLDER from `make keys`: ola (group interns)

# 1. App -> agent: alice mints a run for support-bot.
#    201 {run_id, run_token, expires_at, trusted_destinations: [...]}
r = httpx.post(f"{GATEWAY}/v1/runs", headers={"Authorization": f"Bearer {USER_KEY}"},
               json={"agent": "support-bot", "task": "Summarise ticket 42 and reply to the customer", "ttl_s": 1800})
r.raise_for_status()
run = r.json()
print(run["run_id"], run["expires_at"], run["trusted_destinations"])

# 2. Agent -> LLM: the agent's own key plus the run token `rt_<run_id>.<hmac>` (bound to this agent).
#    Effective models = user ∩ agent; in the sample policy alice ∩ support-bot = ollama/qwen3:8b.
agent = OpenAI(base_url=f"{GATEWAY}/v1", api_key=AGENT_KEY,
               default_headers={"X-AICL-Run": run["run_token"],
                                "X-AICL-Agent": "support-bot"})  # optional, attribution only
raw = agent.chat.completions.with_raw_response.create(
    model="ollama/qwen3:8b", messages=[{"role": "user", "content": "Summarise ticket 42."}])
print(raw.parse().choices[0].message.content)
# x-aicl-decision, x-aicl-event-id, x-aicl-policy, x-aicl-replica, x-aicl-run, x-aicl-budget-remaining
print({k: v for k, v in raw.headers.items() if k.startswith("x-aicl-")}, raw.headers.get("server-timing"))

# 3. Users calling a model directly need no run. Model ids are namespaced: ollama/* local, sim/* simulated commercial.
for key, model in [(USER_KEY, "sim/gpt-4.1"),        # alice via quant-analysts
                   (INTERN_KEY, "ollama/qwen3:4b")]:  # ola via interns (2,000 tokens/day, then 429 billing_error)
    out = OpenAI(base_url=f"{GATEWAY}/v1", api_key=key).chat.completions.create(
        model=model, messages=[{"role": "user", "content": "Hello"}])
    print(model, out.choices[0].message.content)

# MCP: point any MCP client at f"{GATEWAY}/mcp/<server>" (Streamable HTTP) with the same two headers:
#   Authorization: Bearer <AGENT_KEY>   and   X-AICL-Run: <run_token>.
# Anthropic SDK (POST /v1/messages) is P1: same base_url, same headers.
