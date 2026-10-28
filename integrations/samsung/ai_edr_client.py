"""Minimal, dependency-free AI-EDR client for Samsung FabriX workflows and AI Pro pipelines (Mode 2 hook API)."""
from __future__ import annotations

import json
import os
import urllib.request


class AIEDRBlocked(Exception):
    def __init__(self, verdict: dict):
        super().__init__(verdict.get("reason", "blocked by AI-EDR"))
        self.verdict = verdict


class AIEDRClient:
    def __init__(self, base_url: str | None = None, api_key: str | None = None, timeout: float = 5.0):
        self.base = (base_url or os.getenv("AI_EDR_URL", "http://localhost:8080")).rstrip("/")
        self.key = api_key or os.getenv("AI_EDR_KEY", "")
        self.timeout = timeout

    def _post(self, path: str, body: dict) -> dict:
        headers = {"content-type": "application/json"}
        if self.key:
            headers["X-AI-EDR-Key"] = self.key
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read())

    def inspect_payload(self, platform: str, payload: dict, headers: dict | None = None) -> dict:
        """Inspect a provider-native payload (e.g. a FabriX agent request). Returns the verdict."""
        return self._post("/v1/ai-edr/inspect", {"source_platform": platform, "payload": payload, "headers": headers or {}})

    def guard(self, platform: str, payload: dict, headers: dict | None = None) -> dict:
        """Return the payload that is safe to send to the model, or raise AIEDRBlocked."""
        v = self.inspect_payload(platform, payload, headers)
        if v["verdict"] == "BLOCKED":
            raise AIEDRBlocked(v)
        return v.get("sanitized_payload") or payload
