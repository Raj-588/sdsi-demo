"""HTTP client for the AI-EDR control plane."""
from __future__ import annotations

import httpx


class ControlPlaneClient:
    def __init__(self, server: str, timeout: float = 5.0):
        self.server = server.rstrip("/")
        self._http = httpx.Client(timeout=timeout)
        self.agent_id = ""
        self.token = ""

    def _headers(self) -> dict:
        return {"X-Agent-Id": self.agent_id, "X-Agent-Token": self.token}

    def enroll(self, enroll_token: str, info: dict) -> dict:
        r = self._http.post(f"{self.server}/v1/cp/agent/enroll", json={"enroll_token": enroll_token, **info})
        r.raise_for_status()
        return r.json()

    def heartbeat(self, hb: dict) -> dict:
        r = self._http.post(f"{self.server}/v1/cp/agent/heartbeat", json=hb, headers=self._headers())
        r.raise_for_status()
        return r.json()

    def content(self) -> dict:
        r = self._http.get(f"{self.server}/v1/cp/agent/content", headers=self._headers())
        r.raise_for_status()
        return r.json()

    def send_events(self, events: list[dict]) -> None:
        r = self._http.post(f"{self.server}/v1/cp/agent/events", json={"events": events}, headers=self._headers())
        r.raise_for_status()

    def close(self) -> None:
        self._http.close()
