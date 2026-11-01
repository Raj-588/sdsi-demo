"""Linux kernel checkpoint bridge (BPF LSM): runs checkpoint-loader, fills its policy maps, reads its events.

The kernel program (agent/kernel/linux/checkpoint.bpf.c) denies credential reads and unapproved egress by
AI-lineage processes *inside the syscall*, so there is no fork/exec or polling race. checkpointd keeps the
maps up to date:
  ai_comms         AI agent process names; the kernel marks a matching process as an AI root when it execs
  ai_pids          AI agent roots found by the process sensor, e.g. interpreted agents (the kernel inherits them on fork)
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
    judges_exec = False             # exec is reported, not judged, in the kernel; the poll sensor judges command lines

    def __init__(self, enforce: bool):
        self.enforce = enforce
        self.events: list[dict] = []
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._registered: set[int] = set()

    def start(self, protected_paths: list[Path], allow_domains: list[str], ai_names: list[str] = ()) -> None:
        shutil.rmtree(PIN, ignore_errors=True)             # stale pins from a crashed run would swallow our updates
        args = [str(LOADER)] + (["--enforce"] if self.enforce else [])
        self._proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ready = self._proc.stderr.readline()               # "checkpoint-loader: attached (...)" or the load error
        if "attached" not in ready:
            self._proc.kill()
            raise RuntimeError(f"checkpoint-loader failed: {ready.strip() or self._proc.wait()}")
        threading.Thread(target=self._reader, daemon=True).start()
        for name in ai_names:                              # comm is at most 15 bytes + NUL
            _map_update("ai_comms", name.encode()[:15].ljust(16, b"\0"), b"\x01")
        n = self.protect(protected_paths)
        self.allow(allow_domains)
        log.info("kernel checkpoint attached (%s), %d credential files protected", "ENFORCE" if self.enforce else "MONITOR", n)

    def protect(self, roots: list[Path]) -> int:
        n = 0
        mounts = _mounts()
        for root in roots:
            files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()] if root.is_dir() else []
            for f in files:
                _map_update("protected_inodes", struct.pack("<QQ", _sb_dev(f, mounts), f.stat().st_ino), b"\x01")
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
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        shutil.rmtree(PIN, ignore_errors=True)


def _mounts() -> list[tuple[str, int]]:
    """(mount point, superblock dev) from mountinfo, longest mount point first."""
    out = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        f = line.split()
        major, minor = map(int, f[2].split(":"))
        out.append((f[4].replace("\\040", " "), (major << 20) | minor))   # kernel dev_t encoding: MKDEV
    return sorted(out, key=lambda m: len(m[0]), reverse=True)


def _sb_dev(path: Path, mounts: list[tuple[str, int]]) -> int:
    """The dev the kernel sees in file->f_inode->i_sb->s_dev. Not st_dev: on btrfs, stat() reports a per-subvolume
    anonymous device, while mountinfo carries the superblock's."""
    p = str(path.resolve())
    for mount_point, dev in mounts:
        if p == mount_point or p.startswith(mount_point.rstrip("/") + "/"):
            return dev
    st = path.stat()
    return (os.major(st.st_dev) << 20) | os.minor(st.st_dev)
