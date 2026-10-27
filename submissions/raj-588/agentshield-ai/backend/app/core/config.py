"""Environment-based configuration for AgentShield AI.

All runtime configuration is sourced from environment variables (or a .env
file in local development). No secrets are hardcoded. See `.env.example`.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- App ---
    app_name: str = "AgentShield AI — IntentLock"
    app_version: str = "0.1.0-mvp"
    environment: str = "development"  # development | production
    demo_mode: bool = True

    # --- Persistence (SQLite for MVP, PostgreSQL-ready URL) ---
    database_url: str = "sqlite:///./agentshield.db"

    # --- LLM provider selection ---
    # "ollama" (local), "openai" (OpenAI-compatible: OpenAI/Azure/proxies),
    # or "anthropic". Anything else or a missing key -> deterministic mock.
    llm_provider: str = "ollama"
    # Hosted-provider credentials/overrides (leave blank for Ollama).
    llm_api_key: str = ""
    llm_base_url: str = ""   # e.g. https://api.openai.com/v1 (optional override)
    llm_model: str = ""      # e.g. gpt-4o-mini / claude-3-5-sonnet (optional)
    llm_timeout_seconds: float = 30.0

    # --- Ollama (local) ---
    ollama_enabled: bool = False  # Kept in codebase; default OFF to avoid network hangs
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    ollama_timeout_seconds: float = 30.0

    # When true, the agent uses the deterministic mock regardless of provider.
    force_mock_agent: bool = False

    # --- Fixed synthetic trusted identity for the local demo ---
    demo_user_id: str = "user-demo-001"
    agent_id: str = "agent-intentlock-001"

    # --- Limits ---
    max_request_bytes: int = 256_000
    default_task_ttl_minutes: int = 60

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
