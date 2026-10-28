"""Example: Samsung AI Pro pre-send hook (IDE plugin / CLI) — injection + IP/secret DLP before code leaves the device.

    python integrations/samsung/aipro_presend_hook.py --file path/to/module.c --prompt "Refactor this"
    exit code 0 = safe to send, 2 = blocked

The AI Pro request shape here is an assumption; adapt `platform_field_maps.SAMSUNG_AIPRO` in
config/ai_edr_policies.yaml to the real plugin payload.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ai_edr_client import AIEDRClient  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prompt", required=True)
    ap.add_argument("--file", action="append", default=[], help="workspace file sent as context (repeatable)")
    ap.add_argument("--with-diff", action="store_true", help="include `git diff` of the working tree")
    ap.add_argument("--tenant", default="samsung_sec_div")
    a = ap.parse_args()

    payload = {"prompt": a.prompt, "workspace_files": [{"path": f, "content": Path(f).read_text(errors="replace")} for f in a.file]}
    if a.with_diff:
        payload["diff"] = subprocess.run(["git", "diff"], capture_output=True, text=True).stdout
    v = AIEDRClient().inspect_payload("SAMSUNG_AIPRO", payload, {"X-AI-EDR-Tenant": a.tenant})
    cats = sorted({f["category"] for f in v["findings"] if f["severity"] in ("MEDIUM", "HIGH", "CRITICAL")})
    print(f"AI-EDR verdict: {v['verdict']}  severity={v['severity']}  categories={cats}")
    print(f"reason: {v['reason']}")
    return 2 if v["verdict"] == "BLOCKED" else 0


if __name__ == "__main__":
    sys.exit(main())
