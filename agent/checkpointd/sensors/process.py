"""Portable user-space process and network sensor (macOS, Windows, Linux without eBPF).

Polls the process table every 50 ms, rebuilds each new process's lineage, and reports only processes
that descend from an AI agent. It can kill a malicious command but cannot stop it *before* exec;
on Linux the eBPF LSM sensor does that in the kernel (see agent/kernel/linux), and on macOS the
production build uses Endpoint Security AUTH_EXEC.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import time
from dataclasses import dataclass, field

import psutil

EXEC_RECHECK_S = 3.0
INTERPRETERS = {"python", "python3", "node", "bun", "deno", "ruby", "perl", "java", "sh", "bash", "zsh"}


@dataclass
class ExecEvent:
    pid: int
    cmdline: list[str]
    lineage: list[dict]                   # [self, parent, grandparent, ...]
    ai_root: dict
    ts: float = field(default_factory=time.time)


@dataclass
class EgressEvent:
    pid: int
    process: dict
    ip: str
    port: int
    ai_root: dict
    ts: float = field(default_factory=time.time)


def _info(p: psutil.Process) -> dict:
    with p.oneshot():
        try:
            cmd = p.cmdline()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            cmd = []
        try:
            user = p.username()
        except psutil.AccessDenied:
            user = "?"
        return {"pid": p.pid, "ppid": p.ppid(), "name": p.name(), "cmdline": " ".join(cmd)[:600], "user": user}


class ProcessSensor:
    name = "process-poll"

    def __init__(self, ai_patterns: list[str]):
        self.patterns = [x.lower() for x in ai_patterns if x]
        self.known: set[int] = set(psutil.pids())          # pre-existing processes are not re-judged
        self.ai_pids: dict[int, dict] = {}                  # tracked AI roots and their descendants -> root info
        self.judged: dict[int, tuple[str, float]] = {}      # AI-lineage pid -> (command line judged, start time)
        self.own = {os.getpid(), os.getppid()}
        for pid in list(self.known):
            self._maybe_track_existing(pid)

    def is_ai(self, info: dict) -> bool:
        argv = info["cmdline"].split()
        names = [info["name"].lower()]
        if argv:
            names.append(os.path.basename(argv[0]).lower())
            if os.path.basename(argv[0]).lower().rstrip("0123456789.") in INTERPRETERS and len(argv) > 1:
                names.append(os.path.basename(argv[1]).lower())
        return any(p in n for p in self.patterns for n in names)

    def _maybe_track_existing(self, pid: int) -> None:
        try:
            info = _info(psutil.Process(pid))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return
        if pid not in self.own and self.is_ai(info):
            self.ai_pids[pid] = info

    def poll(self) -> list[ExecEvent]:
        now_pids = set(psutil.pids())
        new = sorted(now_pids - self.known)
        self.known = now_pids
        for dead in [p for p in self.ai_pids if p not in now_pids]:
            del self.ai_pids[dead]
            self.judged.pop(dead, None)
        out = [ev for pid in new if pid not in self.own for ev in [self._judge_new(pid)] if ev]
        # fork/exec race: a process seen between fork() and exec() still shows its parent's command line,
        # so young AI-lineage processes are re-read and re-judged when their command line changes.
        now = time.time()
        for pid, (cmd, born) in list(self.judged.items()):
            if now - born > EXEC_RECHECK_S:
                continue
            try:
                proc = psutil.Process(pid)
                current = " ".join(proc.cmdline())[:600]
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            if current and current != cmd:
                ev = self._event(proc, self.ai_pids.get(pid))
                if ev:
                    out.append(ev)
        return out

    def _judge_new(self, pid: int) -> ExecEvent | None:
        try:
            proc = psutil.Process(pid)
            info = _info(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        ev = self._event(proc, None)
        if ev is None and self.is_ai(info):
            self.ai_pids[pid] = info                        # a new AI agent started: everything it spawns is tracked
        return ev

    def _event(self, proc: psutil.Process, root: dict | None) -> ExecEvent | None:
        """Build an ExecEvent if `proc` descends from an AI agent (root given or found by walking its parents)."""
        try:
            info = _info(proc)
            lineage = [info]
            root = root or self.ai_pids.get(info["ppid"])
            for parent in proc.parents()[:12]:
                pi = _info(parent)
                lineage.append(pi)
                if root is None and parent.pid not in self.own and (parent.pid in self.ai_pids or self.is_ai(pi)):
                    root = self.ai_pids.get(parent.pid, pi)
            born = proc.create_time()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        if root is None:
            return None
        self.ai_pids[proc.pid] = root
        self.judged[proc.pid] = (info["cmdline"], born)
        return ExecEvent(proc.pid, info["cmdline"].split(), lineage, root)


class EgressSensor:
    name = "net-poll"

    def __init__(self, procs: ProcessSensor, allow_domains: list[str]):
        self.procs = procs
        self.allow_domains = allow_domains
        self.allowed: set[str] = set()
        self._resolved_at = 0.0
        self._reported: set[tuple] = set()

    def _refresh(self) -> None:
        if time.time() - self._resolved_at < 600:
            return
        ips = set()
        for d in self.allow_domains:
            try:
                ips |= {ai[4][0] for ai in socket.getaddrinfo(d, 443)}
            except OSError:
                pass
        self.allowed, self._resolved_at = ips, time.time()

    def poll(self) -> list[EgressEvent]:
        self._refresh()
        out = []
        for pid, root in list(self.procs.ai_pids.items()):
            try:
                proc = psutil.Process(pid)
                conns = proc.net_connections(kind="inet")
                info = _info(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            for c in conns:
                if not c.raddr:
                    continue
                ip, port = c.raddr.ip, c.raddr.port
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if addr.is_loopback or addr.is_private or addr.is_link_local or ip in self.allowed:
                    continue
                key = (pid, ip, port)
                if key not in self._reported:
                    self._reported.add(key)
                    out.append(EgressEvent(pid, info, ip, port, root))
        return out
