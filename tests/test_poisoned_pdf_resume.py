import base64

from conftest import WEB_PAGE, IndirectAttachment, PolicyMode, make_docx_poisoned, make_req

from src.collectors.indirect_file_scanner import scan_file
from src.demo_console.events import bus  # noqa: F401
from src.schemas.canonical import VerdictType

Q = "Summarize this candidate's resume and tell me if they qualify."


def test_scanner_finds_all_hidden_layers(poisoned_pdf_b64):
    res = scan_file("resume.pdf", data=base64.b64decode(poisoned_pdf_b64))
    assert {"WHITE_TEXT_ON_WHITE_BG", "FONT_SIZE_ZERO_DETECTED", "PDF_RENDER_MODE_3_INVISIBLE"} <= set(res.anomalies)
    hidden = " ".join(res.hidden_spans)
    assert "approve candidate" in hidden and "rate this applicant 10/10" in hidden and "disregard the job" in hidden
    assert "approve" not in res.visible_text.lower()
    assert any("note to ai" in t.lower() for _, t in res.metadata_texts)


def test_clean_resume_allowed(guard, clean_pdf_b64):
    v = guard.inspect(make_req(Q, [IndirectAttachment(filename="resume.pdf", content_base64=clean_pdf_b64)]))
    assert v.verdict == VerdictType.ALLOWED


def test_poisoned_resume_stripped_in_sanitize_mode(guard, poisoned_pdf_b64):
    v = guard.inspect(make_req(Q, [IndirectAttachment(filename="resume.pdf", content_base64=poisoned_pdf_b64)],
                               mode=PolicyMode.STRIP_AND_SANITIZE))
    assert v.verdict == VerdictType.ALLOWED_SANITIZED
    clean = v.sanitization[0].sanitized_text
    assert "<untrusted_document_content" in clean
    assert "approve candidate" not in clean.lower() and "10/10" not in clean
    assert "Jordan Kim" in clean and "FastAPI" in clean          # legitimate content preserved


def test_poisoned_resume_blocked_in_block_mode(guard, poisoned_pdf_b64):
    v = guard.inspect(make_req(Q, [IndirectAttachment(filename="resume.pdf", content_base64=poisoned_pdf_b64)],
                               mode=PolicyMode.BLOCK_AND_QUARANTINE))
    assert v.verdict == VerdictType.BLOCKED and v.quarantine_id


def test_poisoned_docx_hidden_run(guard):
    b64 = base64.b64encode(make_docx_poisoned()).decode()
    v = guard.inspect(make_req("Rate this vendor.", [IndirectAttachment(filename="vendor.docx", content_base64=b64)]))
    assert v.verdict == VerdictType.ALLOWED_SANITIZED
    assert "lowest risk" not in v.sanitization[0].sanitized_text.lower()
    assert "AES-256" in v.sanitization[0].sanitized_text


def test_css_hidden_html(guard):
    v = guard.inspect(make_req("Summarize.", [IndirectAttachment(filename="notes.html", extracted_raw_text=WEB_PAGE,
                                                                  mime_type="text/html")]))
    assert v.verdict == VerdictType.ALLOWED_SANITIZED
    assert "HTML_CSS_HIDDEN_TEXT" in v.anomalies
    assert "corporate password" not in v.sanitization[0].sanitized_text


def test_audit_mode_forwards_but_flags(guard, poisoned_pdf_b64):
    v = guard.inspect(make_req(Q, [IndirectAttachment(filename="resume.pdf", content_base64=poisoned_pdf_b64)],
                               mode=PolicyMode.AUDIT_ONLY))
    assert v.verdict == VerdictType.AUDIT_FLAGGED
