"""Any app or agent integrates by changing base_url and using its virtual key. No SDK fork."""
from openai import OpenAI
from anthropic import Anthropic

GATEWAY = "http://localhost:8080"
KEY = "vk_alice_eng_123"          # virtual key -> user alice, groups [eng]; or an OIDC access token

oa = OpenAI(base_url=f"{GATEWAY}/v1", api_key=KEY,
            default_headers={"X-Ctl-Agent-Id": "invoice-bot", "X-Ctl-Run-Id": "run_7f3a"})
r = oa.chat.completions.create(model="qwen3:4b", messages=[{"role": "user", "content": "Hello"}])
print(r.choices[0].message.content, r.model_extra)          # verdict headers are also on the raw response

an = Anthropic(base_url=GATEWAY, api_key=KEY)
m = an.messages.create(model="qwen3:4b", max_tokens=256, messages=[{"role": "user", "content": "Hello"}])
print(m.content[0].text)

# MCP: point any MCP client at http://localhost:8080/mcp/<server> (Streamable HTTP).
