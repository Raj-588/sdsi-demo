"""Linux BPF LSM kernel checkpoint, live in the kernel.

Needs root, a kernel with CONFIG_BPF_LSM and `bpf` in /sys/kernel/security/lsm, and `make` in agent/kernel/linux:
    sudo .venv/bin/python -m pytest -q tests/test_kernel_linux.py
"""
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from agent.checkpointd.sensors import linux_ebpf

pytestmark = pytest.mark.skipif(not linux_ebpf.available(), reason="needs root + BPF LSM + built checkpoint-loader")


def _secret(base: Path) -> Path:
    d = base / ".ssh"
    d.mkdir(parents=True, exist_ok=True)
    (d / "id_rsa").write_text("-----BEGIN PRIVATE KEY-----\n")
    return d / "id_rsa"


@pytest.fixture()
def kernel(tmp_path):
    secrets = [_secret(tmp_path)]
    home_base = Path.home() / ".cache" / "cpz-kernel-test"     # also a file on the root filesystem (btrfs on Fedora)
    secrets.append(_secret(home_base))
    k = linux_ebpf.KernelCheckpoint(enforce=True)
    k.start([s.parent for s in secrets], [], ai_names=["cpz_fake_agent"])
    yield k, secrets
    k.stop()
    subprocess.run(["rm", "-rf", str(home_base)])


def _as_ai(k, script: str) -> tuple[int, str, str]:
    """Run `script` in a shell that the kernel treats as an AI agent (registered before it does anything)."""
    p = subprocess.Popen(["bash", "-c", "read _; " + script], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True)
    k.register_ai_root(p.pid)
    out, err = p.communicate("go\n", timeout=30)
    return p.returncode, out, err


def _events(k, kind: str, n: int = 1, timeout: float = 3.0) -> list[dict]:
    got, deadline = [], time.time() + timeout
    while time.time() < deadline and len([e for e in got if e["kind"] == kind]) < n:
        got += k.drain()
        time.sleep(0.05)
    return [e for e in got if e["kind"] == kind]


@pytest.mark.parametrize("which", [0, 1], ids=["tmpfs", "home-fs"])
def test_ai_lineage_cannot_read_credentials(kernel, which):
    k, secrets = kernel
    secret = secrets[which]
    rc, out, err = _as_ai(k, f"cat {secret}")
    assert rc != 0 and "Operation not permitted" in err and "PRIVATE KEY" not in out
    assert "PRIVATE KEY" in secret.read_text()                   # not AI lineage: the agent itself can still read it
    ev = _events(k, "FILE_DENY")[0]
    assert ev["path"] == str(secret) and ev["denied"] == 1 and ev["comm"] == "cat"


def test_ai_agent_recognised_by_name_at_exec(kernel, tmp_path):
    """No user-space registration at all: the kernel marks the agent when it execs, so even an instant read fails."""
    k, secrets = kernel
    agent = tmp_path / "cpz_fake_agent"
    shutil.copy("/usr/bin/bash", agent)
    r = subprocess.run([str(agent), "-c", f"cat {secrets[0]}"], capture_output=True, text=True, timeout=10)
    assert r.returncode != 0 and "Operation not permitted" in r.stderr
    assert _events(k, "FILE_DENY")[0]["comm"] == "cat"


def test_grandchildren_inherit_lineage(kernel):
    k, secrets = kernel
    rc, out, err = _as_ai(k, f"bash -c 'python3 -c \"print(open(\\\"{secrets[0]}\\\").read())\"'")
    assert rc != 0 and "PermissionError" in err


def test_ai_lineage_egress_denied_in_kernel(kernel):
    k, _ = kernel
    rc, out, err = _as_ai(k, "python3 -c 'import socket; socket.create_connection((\"1.1.1.1\", 80), timeout=3)'")
    assert rc != 0 and "PermissionError" in err
    ev = _events(k, "NET_DENY")[0]
    assert ev["daddr"] == "1.1.1.1" and ev["dport"] == 80


def test_normal_work_is_untouched(kernel):
    k, _ = kernel
    rc, out, err = _as_ai(k, "cat /etc/hostname && python3 -c 'import socket\n"
                             "try: socket.create_connection((\"127.0.0.1\", 9), timeout=2)\n"
                             "except ConnectionRefusedError: print(\"loopback-ok\")'")
    assert rc == 0 and "loopback-ok" in out, err


def test_exec_in_ai_lineage_is_reported(kernel):
    k, _ = kernel
    _as_ai(k, "/usr/bin/true")
    assert any(e["path"] == "/usr/bin/true" for e in _events(k, "EXEC"))


def test_monitor_mode_reports_without_blocking(kernel):
    k, secrets = kernel
    k.set_enforce(False)
    rc, out, _ = _as_ai(k, f"cat {secrets[0]}")
    assert rc == 0 and "PRIVATE KEY" in out
    assert _events(k, "FILE_SEEN")[0]["denied"] == 0
