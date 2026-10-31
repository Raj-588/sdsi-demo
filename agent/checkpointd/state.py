"""Durable agent state: identity, last good content bundle, crash counter and the offline event outbox."""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path


class AgentState:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        self.identity_path = root / "identity.json"
        self.bundle_path = root / "content_bundle.json"
        self.crash_path = root / "crash_count"
        self.outbox_path = root / "outbox.jsonl"
        self.quarantine_dir = root / "quarantine"
        self.vault_dir = root / "vault"
        self._lock = threading.Lock()

    # identity ---------------------------------------------------------------
    def identity(self) -> dict | None:
        return json.loads(self.identity_path.read_text()) if self.identity_path.exists() else None

    def save_identity(self, ident: dict) -> None:
        self._write(self.identity_path, json.dumps(ident, indent=2))

    # content ----------------------------------------------------------------
    def bundle(self) -> dict | None:
        try:
            return json.loads(self.bundle_path.read_text()) if self.bundle_path.exists() else None
        except ValueError:
            return None

    def save_bundle(self, bundle: dict) -> None:
        self._write(self.bundle_path, json.dumps(bundle))

    # crash counter (boot-loop guard) -----------------------------------------
    def bump_crash_count(self) -> int:
        n = int(self.crash_path.read_text() or 0) + 1 if self.crash_path.exists() else 1
        self._write(self.crash_path, str(n))
        return n

    def reset_crash_count(self) -> None:
        self._write(self.crash_path, "0")

    # outbox -------------------------------------------------------------------
    def queue_events(self, events: list[dict]) -> None:
        with self._lock, open(self.outbox_path, "a") as fh:
            for e in events:
                fh.write(json.dumps(e) + "\n")

    def take_outbox(self, limit: int = 500) -> list[dict]:
        with self._lock:
            if not self.outbox_path.exists():
                return []
            lines = self.outbox_path.read_text().splitlines()
            batch, rest = lines[:limit], lines[limit:]
            self._write(self.outbox_path, "".join(line + "\n" for line in rest))
        return [json.loads(line) for line in batch if line.strip()]

    def outbox_size(self) -> int:
        if not self.outbox_path.exists():
            return 0
        return sum(1 for _ in open(self.outbox_path))

    def _write(self, path: Path, text: str) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(text)
        os.chmod(tmp, 0o600)
        tmp.replace(path)                          # atomic: a crash never leaves a half-written file
