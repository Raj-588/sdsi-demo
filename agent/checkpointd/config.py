"""checkpointd configuration (CLI flags override environment, environment overrides defaults)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

HOME = Path.home()

# Process names / command lines that identify an AI agent. Everything those processes start is "AI lineage".
DEFAULT_AI_PROCESSES = ["claude", "gemini", "cursor", "aider", "codex", "copilot", "windsurf", "ollama", "llama-server",
                        "lm-studio", "open-interpreter", "goose", "continue"]

# Credentials an AI agent has no business reading or sending anywhere.
DEFAULT_PROTECTED = [HOME / ".ssh", HOME / ".aws", HOME / ".config" / "gcloud", HOME / ".azure", HOME / ".kube",
                     HOME / ".docker" / "config.json", HOME / ".netrc", HOME / ".git-credentials", HOME / ".npmrc",
                     HOME / ".pypirc"]

# Destinations AI agents may talk to. Anything else from AI lineage is an egress alert (or a kill with --block-egress).
DEFAULT_EGRESS_ALLOW = ["api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com", "claude.ai",
                        "gemini.google.com", "github.com", "api.github.com", "pypi.org", "files.pythonhosted.org",
                        "registry.npmjs.org"]

DOC_EXTENSIONS = {".pdf", ".docx", ".html", ".htm", ".md", ".txt", ".csv", ".json", ".xml", ".rtf", ".py", ".js", ".ts",
                  ".java", ".go", ".rs", ".yaml", ".yml"}


def _list(env: str, default: list) -> list:
    v = os.getenv(env)
    return [x.strip() for x in v.split(",") if x.strip()] if v else list(default)


@dataclass
class AgentConfig:
    server: str = os.getenv("CHECKPOINTD_SERVER", "http://127.0.0.1:8080")
    enroll_token: str = os.getenv("CHECKPOINTD_ENROLL_TOKEN", "enroll-demo-default")
    state_dir: Path = Path(os.getenv("CHECKPOINTD_STATE_DIR", str(HOME / ".checkpointd")))
    watch_dirs: list[Path] = field(default_factory=lambda: [Path(p).expanduser() for p in _list("CHECKPOINTD_WATCH", [])])
    ai_processes: list[str] = field(default_factory=lambda: _list("CHECKPOINTD_AI_PROCESSES", DEFAULT_AI_PROCESSES))
    protected_paths: list[Path] = field(default_factory=lambda: list(DEFAULT_PROTECTED))
    egress_allow: list[str] = field(default_factory=lambda: _list("CHECKPOINTD_EGRESS_ALLOW", DEFAULT_EGRESS_ALLOW))
    block_egress: bool = os.getenv("CHECKPOINTD_BLOCK_EGRESS", "0") == "1"
    ring: str | None = os.getenv("CHECKPOINTD_RING")              # requested at enrollment only
    tenant_policy: str = os.getenv("CHECKPOINTD_TENANT", "default")
    process_poll_s: float = 0.05
    file_poll_s: float = 1.0
    net_poll_s: float = 1.0
    heartbeat_s: float = float(os.getenv("CHECKPOINTD_HEARTBEAT", "10"))
    flush_s: float = 2.0
    max_file_bytes: int = 25 * 1024 * 1024
    healthy_after_s: float = 60.0                                  # crash counter resets after this long
    safe_mode_after_crashes: int = 2
