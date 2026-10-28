"""Runtime settings and tenant policy loading (architecture §8)."""
from __future__ import annotations

import copy
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = Path(os.getenv("AI_EDR_CONFIG_DIR", ROOT / "config"))
DATA_DIR = Path(os.getenv("AI_EDR_DATA_DIR", ROOT / "data"))


@dataclass
class Settings:
    # "mock" sends ALLOWED traffic to the built-in vulnerable mock LLM (offline demo);
    # "real" forwards to the real provider endpoints below.
    upstream_mode: str = os.getenv("AI_EDR_UPSTREAM_MODE", "mock")
    openai_base: str = os.getenv("AI_EDR_OPENAI_UPSTREAM", "https://api.openai.com")
    anthropic_base: str = os.getenv("AI_EDR_ANTHROPIC_UPSTREAM", "https://api.anthropic.com")
    gemini_base: str = os.getenv("AI_EDR_GEMINI_UPSTREAM", "https://generativelanguage.googleapis.com")
    fabrix_base: str = os.getenv("AI_EDR_FABRIX_UPSTREAM", "")
    aipro_base: str = os.getenv("AI_EDR_AIPRO_UPSTREAM", "")
    # Optional shared secret for the hook/admin API. Empty = open (local demo only).
    api_key: str = os.getenv("AI_EDR_API_KEY", "")
    default_tenant: str = os.getenv("AI_EDR_DEFAULT_TENANT", "default")
    # In proxy mode, a request with this header picks the tenant policy.
    tenant_header: str = "X-AI-EDR-Tenant"
    max_body_bytes: int = int(os.getenv("AI_EDR_MAX_BODY_BYTES", str(25 * 1024 * 1024)))
    file_extract_timeout_s: float = float(os.getenv("AI_EDR_FILE_TIMEOUT", "3.0"))
    store_full_payloads: bool = os.getenv("AI_EDR_STORE_PAYLOADS", "1") == "1"
    data_dir: Path = field(default_factory=lambda: DATA_DIR)


settings = Settings()


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


class PolicyStore:
    """Loads ai_edr_policies.yaml and re-reads it when the file changes."""

    def __init__(self, path: Path | None = None):
        self.path = path or CONFIG_DIR / "ai_edr_policies.yaml"
        self._mtime = 0.0
        self._raw: dict[str, Any] = {}
        self.reload()

    def reload(self) -> None:
        mtime = self.path.stat().st_mtime
        if mtime != self._mtime:
            self._raw = yaml.safe_load(self.path.read_text()) or {}
            self._mtime = mtime

    @property
    def version(self) -> int:
        return int(self._raw.get("version", 1))

    def for_tenant(self, tenant_id: str) -> dict[str, Any]:
        self.reload()
        defaults = self._raw.get("defaults", {})
        tenant = (self._raw.get("tenants") or {}).get(tenant_id, {})
        return _deep_merge(defaults, tenant)

    def field_map(self, platform: str) -> dict[str, Any]:
        self.reload()
        return (self._raw.get("platform_field_maps") or {}).get(platform, {})


def load_signature_seed() -> dict[str, Any]:
    return json.loads((CONFIG_DIR / "initial_risk_signatures.json").read_text())


policy_store = PolicyStore()
