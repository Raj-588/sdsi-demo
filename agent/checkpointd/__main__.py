"""Run the endpoint agent.

    python -m agent.checkpointd --server http://127.0.0.1:8080 --watch ~/work --watch ~/Downloads

Flags override CHECKPOINTD_* environment variables.
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))                    # the agent ships with the shared detection engine in src/

from agent.checkpointd.config import AgentConfig  # noqa: E402
from agent.checkpointd.daemon import Checkpointd  # noqa: E402


def main() -> None:
    cfg = AgentConfig()
    ap = argparse.ArgumentParser(prog="checkpointd", description="CheckPoint Zero AI-EDR endpoint agent")
    ap.add_argument("--server", default=cfg.server)
    ap.add_argument("--enroll-token", default=cfg.enroll_token)
    ap.add_argument("--state-dir", type=Path, default=cfg.state_dir)
    ap.add_argument("--watch", action="append", type=Path, default=[], help="workspace to pre-scan (repeatable)")
    ap.add_argument("--ai-process", action="append", default=[],
                    help="process name that identifies an AI agent (repeatable; replaces the built-in list)")
    ap.add_argument("--ring", choices=["CANARY", "EARLY", "BROAD", "GA"], default=cfg.ring)
    ap.add_argument("--block-egress", action="store_true", default=cfg.block_egress)
    ap.add_argument("--heartbeat", type=float, default=cfg.heartbeat_s)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    cfg.server, cfg.enroll_token, cfg.state_dir = a.server, a.enroll_token, a.state_dir.expanduser()
    cfg.ring, cfg.block_egress, cfg.heartbeat_s = a.ring, a.block_egress, a.heartbeat
    if a.watch:
        cfg.watch_dirs = [p.expanduser().resolve() for p in a.watch]
    if a.ai_process:
        cfg.ai_processes = a.ai_process
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%H:%M:%S")
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    agent = Checkpointd(cfg)
    agent.start()
    agent.run_forever()


if __name__ == "__main__":
    main()
