"""Windows kernel checkpoint bridge: talks to the checkpoint.sys minifilter over its filter communication port.

The driver (agent/kernel/windows/checkpoint.c) tracks AI lineage in the kernel, fails AI-lineage opens of
protected credential paths, and asks this bridge about every process an AI agent creates *before it runs*:
  driver -> CP_NOTIFY (exec: image + command line)   bridge judges with the local engine -> CP_REPLY(Deny)
  driver -> CP_NOTIFY (file: protected path opened)  reported
  bridge -> CP_COMMAND  enforce mode, AI agent names and roots, protected NT path prefixes

Layouts mirror agent/kernel/windows/checkpoint_shared.h with fixed-width types, so they can be unit-tested on
any OS. Requires the driver to be loaded (test signing or an attestation-signed build) and admin rights.
"""
from __future__ import annotations

import ctypes
import logging
import os
import threading
from pathlib import Path
from typing import Callable

log = logging.getLogger("checkpointd.minifilter")

PORT_NAME = "\\CheckPointZeroPort"
MAX_PATH, MAX_CMDLINE = 260, 1024
NOTIFY_EXEC, NOTIFY_FILE = 1, 2
CMD_SET_ENFORCE, CMD_ADD_AI_ROOT, CMD_ADD_PROTECTED, CMD_CLEAR_PROTECTED, CMD_ADD_AI_NAME = 1, 2, 3, 4, 5
U32, U64 = ctypes.c_uint32, ctypes.c_uint64


class CP_NOTIFY(ctypes.Structure):
    _fields_ = [("Kind", U32), ("ProcessId", U32), ("ParentProcessId", U32), ("RootProcessId", U32),
                ("Denied", U32), ("Reserved", U32), ("ImagePath", ctypes.c_uint16 * MAX_PATH),
                ("CommandLine", ctypes.c_uint16 * MAX_CMDLINE)]


class FILTER_MESSAGE_HEADER(ctypes.Structure):
    _fields_ = [("ReplyLength", U32), ("MessageId", U64)]


class FILTER_REPLY_HEADER(ctypes.Structure):
    _fields_ = [("Status", ctypes.c_int32), ("MessageId", U64)]


class NotifyMessage(ctypes.Structure):
    _fields_ = [("Header", FILTER_MESSAGE_HEADER), ("Notify", CP_NOTIFY)]


class ReplyMessage(ctypes.Structure):
    _fields_ = [("Header", FILTER_REPLY_HEADER), ("Deny", U32)]


REPLY_SIZE = ctypes.sizeof(FILTER_REPLY_HEADER) + 4      # header + CP_REPLY, as the driver expects (not the padded size)


class CP_COMMAND(ctypes.Structure):
    _fields_ = [("Command", U32), ("Value", U32), ("Path", ctypes.c_uint16 * MAX_PATH)]


def wstr(arr) -> str:
    return bytes(arr).decode("utf-16-le", "replace").split("\0", 1)[0]


def command(kind: int, value: int = 0, path: str = "") -> CP_COMMAND:
    cmd = CP_COMMAND(kind, value)
    raw = path.encode("utf-16-le")[: (MAX_PATH - 1) * 2]
    ctypes.memmove(cmd.Path, raw, len(raw))
    return cmd


def nt_path(path: Path | str, dos_devices: dict[str, str]) -> str | None:
    """C:\\Users\\a\\.ssh -> \\Device\\HarddiskVolume3\\Users\\a\\.ssh (the form the minifilter sees)."""
    p = str(path)
    if len(p) < 2 or p[1] != ":":
        return None
    device = dos_devices.get(p[:2].upper())
    return device + p[2:].replace("/", "\\") if device else None


def _dos_devices() -> dict[str, str]:
    out = {}
    buf = ctypes.create_unicode_buffer(1024)
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if ctypes.windll.kernel32.QueryDosDeviceW(f"{letter}:", buf, len(buf)):
            out[f"{letter}:"] = buf.value
    return out


def _connect():
    handle = ctypes.c_void_p()
    hr = ctypes.windll.fltlib.FilterConnectCommunicationPort(ctypes.c_wchar_p(PORT_NAME), 0, None, 0, None,
                                                            ctypes.byref(handle))
    return handle if hr == 0 else None


def available() -> bool:
    if os.name != "nt":
        return False
    try:
        handle = _connect()
    except (AttributeError, OSError):
        return False
    if handle is None:
        return False
    ctypes.windll.kernel32.CloseHandle(handle)       # the port takes one client; start() reconnects
    return True


# judge(pid, ppid, root_pid, image, cmdline) -> (deny, record to report)
Judge = Callable[[int, int, int, str, str], "tuple[bool, dict | None]"]


class KernelCheckpoint:
    name = "minifilter"
    judges_exec = True              # the driver asks before every AI-lineage process starts

    def __init__(self, enforce: bool, judge: Judge, workers: int = 2):
        self.enforce = enforce
        self.judge = judge
        self.workers = workers
        self.events: list[dict] = []
        self._lock = threading.Lock()
        self._port = None
        self._registered: set[int] = set()
        self._running = False

    def start(self, protected_paths: list[Path], allow_domains: list[str], ai_names: list[str] = ()) -> None:
        self._port = _connect()
        if self._port is None:
            raise OSError("cannot connect to " + PORT_NAME + " (is checkpoint.sys loaded? fltmc filters)")
        self._running = True
        self.set_enforce(self.enforce)
        for name in ai_names:
            self._send(command(CMD_ADD_AI_NAME, path=name))
        self.protect(protected_paths)
        for _ in range(self.workers):
            threading.Thread(target=self._serve, daemon=True).start()
        log.info("minifilter connected (%s)", "ENFORCE" if self.enforce else "MONITOR")

    def _send(self, cmd: CP_COMMAND) -> bool:
        returned = U32()
        hr = ctypes.windll.fltlib.FilterSendMessage(self._port, ctypes.byref(cmd), ctypes.sizeof(cmd), None, 0,
                                                    ctypes.byref(returned))
        return hr == 0

    def protect(self, roots: list[Path]) -> int:
        self._send(command(CMD_CLEAR_PROTECTED))
        devices = _dos_devices()
        n = 0
        for root in roots:
            nt = nt_path(root, devices)
            if nt and self._send(command(CMD_ADD_PROTECTED, path=nt)):
                n += 1
        log.info("minifilter protecting %d credential paths", n)
        return n

    def allow(self, domains: list[str]) -> None:
        """Egress stays in user space on Windows (a WFP callout is the production path)."""

    def register_ai_root(self, pid: int) -> None:
        if pid not in self._registered and self._send(command(CMD_ADD_AI_ROOT, value=pid)):
            self._registered.add(pid)

    def set_enforce(self, enforce: bool) -> None:
        self.enforce = enforce
        self._send(command(CMD_SET_ENFORCE, value=1 if enforce else 0))

    def drain(self) -> list[dict]:
        with self._lock:
            out, self.events = self.events, []
        return out

    def _serve(self) -> None:
        msg = NotifyMessage()
        fltlib = ctypes.windll.fltlib
        while self._running:
            hr = fltlib.FilterGetMessage(self._port, ctypes.byref(msg.Header), ctypes.sizeof(msg), None)
            if hr != 0:
                if self._running:
                    log.error("FilterGetMessage failed: 0x%08x", hr & 0xFFFFFFFF)
                return
            evt = self.handle(msg.Notify)
            if msg.Header.ReplyLength:
                reply = ReplyMessage(FILTER_REPLY_HEADER(0, msg.Header.MessageId), 1 if evt.get("deny") else 0)
                fltlib.FilterReplyMessage(self._port, ctypes.byref(reply), REPLY_SIZE)
            with self._lock:
                self.events.append(evt)

    def handle(self, n: CP_NOTIFY) -> dict:
        """Turn one driver notification into an event; for exec, judge it (the reply is sent by the caller)."""
        image = wstr(n.ImagePath)
        base = {"pid": n.ProcessId, "ppid": n.ParentProcessId, "root_pid": n.RootProcessId,
                "comm": image.replace("\\", "/").rsplit("/", 1)[-1]}
        if n.Kind == NOTIFY_EXEC:
            cmdline = wstr(n.CommandLine) or image
            try:
                deny, record = self.judge(n.ProcessId, n.ParentProcessId, n.RootProcessId, image, cmdline)
            except Exception as exc:           # fail open
                log.error("exec judge failed: %s", exc)
                deny, record = False, None
            return {**base, "kind": "EXEC_JUDGED", "cmdline": cmdline, "path": image,
                    "deny": bool(deny and self.enforce), "judgement": record}
        return {**base, "kind": "FILE_DENY" if n.Denied else "FILE_SEEN", "denied": n.Denied, "path": image}

    def stop(self) -> None:
        self._running = False
        if self._port is not None:
            ctypes.windll.kernel32.CloseHandle(self._port)
            self._port = None
