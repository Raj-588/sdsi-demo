"""Claude / Anthropic SDK through AI-EDR (pip install anthropic). Claude Code: export ANTHROPIC_BASE_URL=http://localhost:8080"""
import anthropic

client = anthropic.Anthropic(base_url="http://localhost:8080",           # <- AI-EDR gateway
                             default_headers={"X-AI-EDR-Upstream": "mock"})  # remove for real Claude
msg = client.messages.create(model="claude-sonnet-4-5", max_tokens=200, messages=[{"role": "user", "content": "Hello!"}])
print(msg.content[0].text)
