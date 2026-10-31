"""Linux kernel checkpoint bridge (BPF LSM): runs checkpoint-loader, fills its policy maps, reads its events.

The kernel program (agent/kernel/linux/checkpoint.bpf.c) denies credential reads and unapproved egress by
AI-lineage processes *inside the syscall*, so there is no fork/exec or polling race. checkpointd keeps the
maps up to date:
  ai_pids          AI agent roots found by the process sensor (the kernel inherits them on fork)
  protected_inodes (dev, ino) of every file under the protected credential paths
  egress_allow     IPv4 addresses of the allowed LLM / dev endpoints

Requires root, CONFIG_BPF_LSM and `make` in agent/kernel/linux. Not available on macOS / Windows, where the
production build uses Endpoint Security / minifilter + WFP instead.
"""
from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import socket
import struct
import subprocess
import threading
from pathlib import Path

log = logging.getLogger("checkpointd.ebpf")
LOADER = Path(__file__).resolve().parents[2] / "kernel" / "linux" / "checkpoint-loader"
PIN = Path("/sys/fs/bpf/checkpointd")


def available() -> bool:
    lsm = Path("/sys/kernel/security/lsm")
    return (platform.system() == "Linux" and os.geteuid() == 0 and LOADER.exists()
            and shutil.which("bpftool") is not None and lsm.exists() and "bpf" in lsm.read_text())


def _hex(data: bytes) -> list[str]:
    return [f"0x{b:02x}" for b in data]


def _map_update(name: str, key: bytes, value: bytes) -> None:
    subprocess.run(["bpftool", "map", "update", "pinned", str(PIN / name), "key", *_hex(key), "value", *_hex(value)],
                   check=False, capture_output=True)


class KernelCheckpoint:
    name = "ebpf-lsm"

    def __init__(self, enforce: bool):
        self.enforce = enforce
        self.events: list[dict] = []
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._registered: set[int] = set()

    def start(self, protected_paths: list[Path], allow_domains: list[str]) -> None:
        args = [str(LOADER)] + (["--enforce"] if self.enforce else [])
        self._proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        threading.Thread(target=self._reader, daemon=True).start()
        for _ in range(50):
            if (PIN / "config").exists():
                break
            threading.Event().wait(0.1)
        self.protect(protected_paths)
        self.allow(allow_domains)
        log.info("kernel checkpoint attached (%s)", "ENFORCE" if self.enforce else "MONITOR")

    def protect(self, roots: list[Path]) -> int:
        n = 0
        for root in roots:
            files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()] if root.is_dir() else []
            for f in files:
                st = f.stat()
                _map_update("protected_inodes", struct.pack("<QQ", _kdev(st.st_dev), st.st_ino), b"\x01")
                n += 1
        return n

    def allow(self, domains: list[str]) -> None:
        for d in domains:
            try:
                for ai in socket.getaddrinfo(d, 443, socket.AF_INET):
                    _map_update("egress_allow", socket.inet_aton(ai[4][0]), b"\x01")
            except OSError:
                continue

    def register_ai_root(self, pid: int) -> None:
        if pid not in self._registered:
            self._registered.add(pid)
            _map_update("ai_pids", struct.pack("<I", pid), struct.pack("<I", pid))

    def set_enforce(self, enforce: bool) -> None:
        self.enforce = enforce
        _map_update("config", struct.pack("<I", 0), struct.pack("<I", 1 if enforce else 0))

    def drain(self) -> list[dict]:
        with self._lock:
            out, self.events = self.events, []
        return out

    def _reader(self) -> None:
        for line in self._proc.stdout:
            try:
                evt = json.loads(line)
            except ValueError:
                continue
            if evt["kind"] == "EXEC":
                try:
                    evt["cmdline"] = Path(f"/proc/{evt['pid']}/cmdline").read_bytes().replace(b"\0", b" ").decode().strip()
                except OSError:
                    evt["cmdline"] = evt.get("path", "")
            with self._lock:
                self.events.append(evt)

    def stop(self) -> None:
        if self._proc:
            self._proc.terminate()
        shutil.rmtree(PIN, ignore_errors=True)


def _kdev(dev: int) -> int:
    """User-space st_dev -> the kernel's internal dev_t encoding (MKDEV: major << 20 | minor)."""
    return (os.major(dev) << 20) | os.minor(dev)
