"""checkpointd configuration (CLI flags override environment, environment overrides defaults)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

HOME = Path.home()
IS_WINDOWS = os.name == "nt"

# Process names / command lines that identify an AI agent. Everything those processes start is "AI lineage".
DEFAULT_AI_PROCESSES = ["claude", "gemini", "cursor", "aider", "codex", "copilot", "windsurf", "ollama", "llama-server",
                        "lm-studio", "open-interpreter", "goose", "continue"]

# Credentials an AI agent has no business reading or sending anywhere, relative to each user's home.
POSIX_SECRETS = [".ssh", ".aws", ".config/gcloud", ".config/gh/hosts.yml", ".azure", ".kube", ".docker/config.json",
                 ".netrc", ".git-credentials", ".npmrc", ".pypirc"]
WINDOWS_SECRETS = [".ssh", ".aws", ".azure", ".kube", ".docker/config.json", "_netrc", ".git-credentials", ".npmrc",
                   ".pypirc", "AppData/Roaming/gcloud", "AppData/Roaming/GitHub CLI", "AppData/Roaming/Microsoft/Credentials",
                   "AppData/Local/Microsoft/Credentials", "AppData/Roaming/Microsoft/Protect",
                   "AppData/Local/Google/Chrome/User Data/Default/Login Data",
                   "AppData/Local/Microsoft/Edge/User Data/Default/Login Data"]
_NOT_USERS = {"public", "default", "default user", "all users", "shared", "guest", "lost+found"}


def _privileged() -> bool:
    if IS_WINDOWS:
        if "systemprofile" in str(HOME).lower():           # running as LocalSystem (the installed service)
            return True
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0


def user_homes() -> list[Path]:
    """The current user's home; every local user's home when the agent runs as root / SYSTEM (as a service)."""
    homes = [HOME]
    if _privileged():
        root = Path(os.getenv("SystemDrive", "C:") + "\\Users") if IS_WINDOWS else Path("/Users" if os.uname().sysname == "Darwin" else "/home")
        try:
            homes += sorted(p for p in root.iterdir() if p.is_dir() and p.name.lower() not in _NOT_USERS)
        except OSError:
            pass
        if not IS_WINDOWS and Path("/root").is_dir():
            homes.append(Path("/root"))
    return [h for h in dict.fromkeys(homes) if "systemprofile" not in str(h).lower()]


def default_protected() -> list[Path]:
    rel = WINDOWS_SECRETS if IS_WINDOWS else POSIX_SECRETS
    return [h / r for h in user_homes() for r in rel]


DEFAULT_PROTECTED = default_protected()

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
    state_dir: Path = Path(os.getenv("CHECKPOINTD_STATE_DIR", str(HOME / ".checkpointd")))       # service: %ProgramData%\\checkpointd
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
