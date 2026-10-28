"""Gemini / google-genai SDK through AI-EDR (pip install google-genai)."""
from google import genai
from google.genai import types

client = genai.Client(api_key="YOUR_KEY", http_options=types.HttpOptions(
    base_url="http://localhost:8080",                                     # <- AI-EDR gateway
    headers={"X-AI-EDR-Upstream": "mock"}))                               # remove for real Gemini
print(client.models.generate_content(model="gemini-2.5-flash", contents="Hello!").text)
