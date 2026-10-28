"""Example: AI-EDR as a guard node inside a Samsung FabriX agent workflow (out-of-band hook, Mode 2).

    retrieve RAG chunks -> [AI-EDR guard node] -> LLM node -> answer

    python integrations/samsung/fabrix_workflow_guard.py

The FabriX request shape used here is an assumption (the real schema is internal); the gateway's
field map in config/ai_edr_policies.yaml is where it is adapted to the real one.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ai_edr_client import AIEDRBlocked, AIEDRClient  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def retrieve_chunks(query: str) -> list[dict]:
    """Stand-in for FabriX knowledge-base retrieval. One chunk carries an invisible Unicode-tag payload."""
    smuggled = (ROOT / "demo" / "files" / "fabrix_rag_chunk_smuggled.txt").read_text()
    return [{"title": "kb://travel-policy#chunk-11", "content": "Business class is allowed for flights over 6 hours."},
            {"title": "kb://travel-policy#chunk-12", "content": smuggled}]


def call_llm(request: dict) -> str:
    return f"(LLM would answer here using {len(request['context']['documents'])} clean chunks)"


def run(query: str, tenant: str) -> None:
    request = {"query": query, "prompt_template": "You are the Samsung travel-policy assistant.",
               "context": {"documents": retrieve_chunks(query)}, "user_id": "emp_11223"}
    headers = {"X-FabriX-Tenant-Id": tenant, "X-FabriX-Trace-Id": "fx-demo-001"}
    try:
        safe = AIEDRClient().guard("SAMSUNG_FABRIX", request, headers)
        print(f"[{tenant}] ALLOWED -> {call_llm(safe)}")
    except AIEDRBlocked as b:
        v = b.verdict
        print(f"[{tenant}] BLOCKED before the LLM node: {v['reason']} "
              f"(quarantine_id={v['quarantine_id']}, anomalies={v['anomalies']})")


if __name__ == "__main__":
    run("What is the travel policy for short flights?", "samsung_sec_div")   # BLOCK_AND_QUARANTINE tenant
    run("What is the travel policy for short flights?", "default")           # STRIP_AND_SANITIZE tenant
