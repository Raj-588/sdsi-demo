import base64
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "demo"))

from make_poisoned_files import (  # noqa: E402
    MALICIOUS_README,
    ONBOARDING_FAQ,
    RAG_CHUNK_SMUGGLED,
    WEB_PAGE,
    make_docx_poisoned,
    make_resume_pdf,
)
from src.ai_edr_guard.pipeline_orchestrator import AIEDRGuard  # noqa: E402
from src.schemas.canonical import (  # noqa: E402
    ActorContext,
    CanonicalAIEDRRequest,
    IndirectAttachment,
    InputVectors,
    PolicyMode,
    PolicyProfile,
    ProposedToolCall,
    SourcePlatform,
)


@pytest.fixture()
def guard(tmp_path):
    return AIEDRGuard(data_dir=tmp_path)


@pytest.fixture(scope="session")
def poisoned_pdf_b64():
    return base64.b64encode(make_resume_pdf(True)).decode()


@pytest.fixture(scope="session")
def clean_pdf_b64():
    return base64.b64encode(make_resume_pdf(False)).decode()


def make_req(prompt="", attachments=(), tools=(), mode=None, platform=SourcePlatform.OPENAI, tenant="default",
             session=None):
    actor = ActorContext(tenant_id=tenant)
    if session:
        actor.session_id = session
    return CanonicalAIEDRRequest(
        source_platform=platform, actor_context=actor,
        input_vectors=InputVectors(direct_user_prompt=prompt, indirect_attachments=list(attachments),
                                   proposed_tool_calls=list(tools)),
        policy_profile=PolicyProfile(mode=mode))


__all__ = ["make_req", "IndirectAttachment", "ProposedToolCall", "PolicyMode", "SourcePlatform", "MALICIOUS_README",
           "ONBOARDING_FAQ", "RAG_CHUNK_SMUGGLED", "WEB_PAGE", "make_docx_poisoned"]
