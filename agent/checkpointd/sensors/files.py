"""Workspace file sensor: pre-scans documents an AI agent is about to read.

Watches the configured workspaces (agent working directories, Downloads, RAG drop folders) and reports new
or changed documents. Scanning on arrival means the verdict is ready before the agent opens the file, which
keeps the kernel file checkpoint (eBPF LSM file_open / ES AUTH_OPEN) a cache lookup.
"""
from __future__ import annotations

import os
from pathlib import Path

from ..config import DOC_EXTENSIONS

SKIP_SUFFIXES = (".sanitized.txt", ".tmp", ".part", ".crdownload", ".swp")
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".idea", ".vscode"}


class FileSensor:
    name = "file-poll"

    def __init__(self, roots: list[Path], max_bytes: int, max_files: int = 20000):
        self.roots = [r for r in roots if r.is_dir()]
        self.max_bytes = max_bytes
        self.max_files = max_files
        self.seen: dict[str, tuple[int, int]] = {}
        self.ignore: set[str] = set()             # files the agent itself just wrote

    def poll(self) -> list[Path]:
        changed = []
        count = 0
        for root in self.roots:
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
                for fn in filenames:
                    count += 1
                    if count > self.max_files:
                        return changed
                    if fn.startswith(".") or fn.endswith(SKIP_SUFFIXES):
                        continue
                    p = Path(dirpath) / fn
                    if p.suffix.lower() not in DOC_EXTENSIONS:
                        continue
                    try:
                        st = p.stat()
                    except OSError:
                        continue
                    sig = (st.st_mtime_ns, st.st_size)
                    key = str(p)
                    if self.seen.get(key) == sig:
                        continue
                    self.seen[key] = sig
                    if key in self.ignore:
                        self.ignore.discard(key)
                        continue
                    if 0 < st.st_size <= self.max_bytes:
                        changed.append(p)
        return changed
