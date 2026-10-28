"""Stage 1 — Indirect Attack & File Poisoning Inspector (spec §4 Stage 1).

Extracts text from PDF / DOCX / HTML / Markdown / source files and separates what a
human would SEE from what only a parser (and therefore an LLM) would read:
white-on-white text, 0-1pt fonts, PDF render mode 3, zero opacity, off-page text,
DOCX hidden runs, CSS-hidden HTML, comments and document metadata.
"""
from __future__ import annotations

import base64
import binascii
import io
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import PurePosixPath


@dataclass
class ScanResult:
    filename: str
    mime_type: str
    full_text: str = ""                                  # everything a parser extracts
    visible_text: str = ""                               # what a human sees
    hidden_spans: list[str] = field(default_factory=list)
    metadata_texts: list[tuple[str, str]] = field(default_factory=list)   # (label, text)
    anomalies: list[str] = field(default_factory=list)
    error: str | None = None

    def add_anomaly(self, tag: str) -> None:
        if tag not in self.anomalies:
            self.anomalies.append(tag)


EXT_MIME = {
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".html": "text/html", ".htm": "text/html",
    ".md": "text/markdown", ".markdown": "text/markdown",
    ".txt": "text/plain", ".csv": "text/csv", ".json": "application/json",
}
CODE_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".kt", ".go", ".rs", ".c", ".cc", ".cpp",
             ".h", ".hpp", ".cs", ".rb", ".php", ".swift", ".sh", ".yaml", ".yml", ".toml", ".sql"}


def guess_mime(filename: str, data: bytes | None = None, declared: str | None = None) -> str:
    if data is not None:
        if data[:5] == b"%PDF-":
            return "application/pdf"
        if data[:2] == b"PK" and filename.lower().endswith(".docx"):
            return EXT_MIME[".docx"]
    if declared and declared not in ("application/octet-stream", ""):
        return declared
    ext = PurePosixPath(filename.lower()).suffix
    if ext in EXT_MIME:
        return EXT_MIME[ext]
    if ext in CODE_EXTS:
        return "text/x-source"
    return "text/plain"


def decode_b64(content_b64: str) -> bytes:
    if content_b64.startswith("data:") and "," in content_b64:
        content_b64 = content_b64.split(",", 1)[1]
    try:
        return base64.b64decode(content_b64, validate=False)
    except (binascii.Error, ValueError):
        return b""


# ----------------------------------------------------------------------------
# PDF
# ----------------------------------------------------------------------------

def _to_rgb(color, n_components: int) -> tuple[float, float, float]:
    if color is None:
        return (0.0, 0.0, 0.0)
    if isinstance(color, int):          # sRGB int from get_text("dict")
        return (((color >> 16) & 255) / 255, ((color >> 8) & 255) / 255, (color & 255) / 255)
    c = list(color)
    if n_components == 1 or len(c) == 1:
        return (c[0], c[0], c[0])
    if n_components == 4 or len(c) == 4:
        cy, m, y, k = c
        return ((1 - cy) * (1 - k), (1 - m) * (1 - k), (1 - y) * (1 - k))
    return (c[0], c[1], c[2])


def _close(a, b, tol: float = 0.06) -> bool:
    return all(abs(x - y) <= tol for x, y in zip(a, b))


def _background_at(fills: list[tuple], bbox) -> tuple[float, float, float]:
    """Colour of the last-drawn filled rectangle containing the span centre (default white)."""
    cx, cy = (bbox[0] + bbox[2]) / 2, (bbox[1] + bbox[3]) / 2
    bg = (1.0, 1.0, 1.0)
    for rect, rgb in fills:
        if rect[0] <= cx <= rect[2] and rect[1] <= cy <= rect[3]:
            bg = rgb
    return bg


def scan_pdf(data: bytes, res: ScanResult) -> None:
    import pymupdf

    doc = pymupdf.open(stream=data, filetype="pdf")
    visible_parts, full_parts = [], []
    for page in doc:
        page_rect = page.rect
        fills = []
        for d in page.get_drawings():
            if d.get("fill") is not None and d.get("rect") is not None:
                r = d["rect"]
                fills.append(((r.x0, r.y0, r.x1, r.y1), _to_rgb(d["fill"], len(d["fill"]))))

        page_hidden: list[str] = []
        page_visible: list[str] = []
        for span in page.get_texttrace():
            text = "".join(chr(c[0]) for c in span.get("chars", ()) if c[0] >= 0)
            if not text.strip():
                continue
            bbox = span.get("bbox", (0, 0, 0, 0))
            reasons = []
            if span.get("type") == 3:
                reasons.append("PDF_RENDER_MODE_3_INVISIBLE")
            if span.get("opacity", 1.0) is not None and span.get("opacity", 1.0) <= 0.05:
                reasons.append("ZERO_OPACITY_TEXT")
            if span.get("size", 12) <= 1.0:
                reasons.append("FONT_SIZE_ZERO_DETECTED")
            fg = _to_rgb(span.get("color"), span.get("colorspace", 3))
            if _close(fg, _background_at(fills, bbox)):
                reasons.append("WHITE_TEXT_ON_WHITE_BG" if _close(fg, (1, 1, 1)) else "TEXT_COLOR_MATCHES_BACKGROUND")
            if bbox[2] < page_rect.x0 or bbox[0] > page_rect.x1 or bbox[3] < page_rect.y0 or bbox[1] > page_rect.y1:
                reasons.append("TEXT_OUTSIDE_PAGE")
            if reasons:
                page_hidden.append(text)
                for r in reasons:
                    res.add_anomaly(r)
            else:
                page_visible.append(text)
        if page_hidden:
            res.hidden_spans.extend(_merge_fragments(page_hidden))
        visible_parts.append(" ".join(page_visible))
        full_parts.append(page.get_text())

        for annot in page.annots() or []:
            content = (annot.info or {}).get("content", "")
            if content.strip():
                res.metadata_texts.append((f"annotation:p{page.number + 1}", content))
                res.add_anomaly("PDF_ANNOTATION_TEXT")
        for widget in page.widgets() or []:
            if widget.field_value and str(widget.field_value).strip():
                res.metadata_texts.append((f"form:{widget.field_name}", str(widget.field_value)))

    for key, val in (doc.metadata or {}).items():
        if val and key in ("title", "subject", "keywords", "author", "creator", "producer") and len(val) > 3:
            res.metadata_texts.append((f"pdf_info:{key}", val))
    xmp = doc.get_xml_metadata() or ""
    if xmp.strip():
        stripped = re.sub(r"<[^>]+>", " ", xmp)
        stripped = re.sub(r"\s+", " ", stripped).strip()
        if stripped:
            res.metadata_texts.append(("pdf_xmp", stripped))
    if doc.embfile_count() > 0:
        res.add_anomaly("PDF_EMBEDDED_FILES")
    if b"/JavaScript" in data or b"/JS" in data:
        res.add_anomaly("PDF_JAVASCRIPT_ACTION")

    res.full_text = "\n".join(full_parts).strip()
    res.visible_text = "\n".join(visible_parts).strip()


def _merge_fragments(fragments: list[str]) -> list[str]:
    """texttrace splits lines into spans; join neighbouring hidden fragments into sentences."""
    joined = " ".join(f.strip() for f in fragments)
    joined = re.sub(r"\s+", " ", joined).strip()
    return [joined] if joined else []


# ----------------------------------------------------------------------------
# DOCX
# ----------------------------------------------------------------------------

def scan_docx(data: bytes, res: ScanResult) -> None:
    import docx
    from docx.shared import Pt

    d = docx.Document(io.BytesIO(data))
    visible, full, hidden = [], [], []
    for para in d.paragraphs:
        v_runs = []
        for run in para.runs:
            t = run.text
            if not t:
                continue
            reasons = []
            if run.font.hidden:
                reasons.append("DOCX_HIDDEN_RUN")
            if run.font.size is not None and run.font.size <= Pt(1):
                reasons.append("FONT_SIZE_ZERO_DETECTED")
            rgb = run.font.color.rgb if run.font.color is not None and run.font.color.type is not None else None
            if rgb is not None and str(rgb).upper() in ("FFFFFF", "FEFEFE", "FDFDFD"):
                reasons.append("WHITE_TEXT_ON_WHITE_BG")
            if reasons:
                hidden.append(t)
                for r in reasons:
                    res.add_anomaly(r)
            else:
                v_runs.append(t)
        visible.append("".join(v_runs))
        full.append(para.text)
    if hidden:
        res.hidden_spans.extend(_merge_fragments(hidden))
    cp = d.core_properties
    for key in ("title", "subject", "keywords", "comments", "category", "author"):
        val = getattr(cp, key, None)
        if val and len(str(val)) > 3:
            res.metadata_texts.append((f"docx_prop:{key}", str(val)))
    res.full_text = "\n".join(full).strip()
    res.visible_text = "\n".join(visible).strip()


# ----------------------------------------------------------------------------
# HTML / Markdown
# ----------------------------------------------------------------------------

_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em)?\s*(?:;|$)|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)"
    r"|color\s*:\s*(?:#fff(?:fff)?|white|rgba?\(\s*255\s*,\s*255\s*,\s*255)|left\s*:\s*-\d{3,}px|text-indent\s*:\s*-\d{3,}",
    re.I,
)
_VOID = {"br", "img", "hr", "meta", "input", "link", "source", "wbr", "area", "base", "col", "embed", "param", "track"}


class _HiddenHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack: list[bool] = []
        self.visible: list[str] = []
        self.hidden: list[str] = []
        self.comments: list[str] = []
        self.attr_texts: list[tuple[str, str]] = []
        self.anomalies: set[str] = set()
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        is_hidden = bool(self.stack and self.stack[-1])
        style = a.get("style") or ""
        if "hidden" in a or a.get("aria-hidden") == "true" and tag != "svg" or _HIDDEN_STYLE.search(style):
            is_hidden = True
            self.anomalies.add("HTML_CSS_HIDDEN_TEXT")
        for k in ("alt", "title", "aria-label", "content"):
            if a.get(k) and len(a[k]) > 20:
                self.attr_texts.append((f"html_attr:{tag}.{k}", a[k]))
        if tag in ("script", "style"):
            self._skip += 1
        if tag not in _VOID:
            self.stack.append(is_hidden)

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag not in _VOID and self.stack:
            self.stack.pop()

    def handle_data(self, data):
        if self._skip or not data.strip():
            return
        (self.hidden if self.stack and self.stack[-1] else self.visible).append(data.strip())

    def handle_comment(self, data):
        if data.strip():
            self.comments.append(data.strip())


def scan_html(text: str, res: ScanResult) -> None:
    p = _HiddenHTMLParser()
    p.feed(text)
    res.visible_text = " ".join(p.visible)
    res.full_text = " ".join(p.visible + p.hidden)
    if p.hidden:
        res.hidden_spans.extend(p.hidden)
    for c in p.comments:
        res.metadata_texts.append(("html_comment", c))
    if p.comments:
        res.add_anomaly("HTML_COMMENT_TEXT")
    res.metadata_texts.extend(p.attr_texts)
    for a in sorted(p.anomalies):
        res.add_anomaly(a)


def scan_markdown(text: str, res: ScanResult) -> None:
    comments = re.findall(r"<!--(.*?)-->", text, re.S)
    body = re.sub(r"<!--.*?-->", " ", text, flags=re.S)
    if re.search(r"<[a-zA-Z][^>]*>", body):
        sub = ScanResult(res.filename, "text/html")
        scan_html(body, sub)
        res.hidden_spans.extend(sub.hidden_spans)
        for a in sub.anomalies:
            res.add_anomaly(a)
    for c in comments:
        if c.strip():
            res.metadata_texts.append(("markdown_comment", c.strip()))
            res.add_anomaly("MARKDOWN_HTML_COMMENT")
    # link titles: [text](url "title")
    for title in re.findall(r"\]\([^)\s]+\s+\"([^\"]{20,})\"\)", text):
        res.metadata_texts.append(("markdown_link_title", title))
    res.full_text = text
    res.visible_text = body


_COMMENT_RE = re.compile(r"(?:#|//)\s?(.*)$|/\*(.*?)\*/|\"\"\"(.*?)\"\"\"", re.M | re.S)


def scan_source(text: str, res: ScanResult) -> None:
    res.full_text = text
    res.visible_text = text
    comments = [next(g for g in m.groups() if g) for m in _COMMENT_RE.finditer(text) if any(m.groups())]
    long_comments = [c.strip() for c in comments if len(c.strip()) > 25]
    if long_comments:
        res.metadata_texts.append(("code_comments", "\n".join(long_comments)))


# ----------------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------------

def scan_file(filename: str, *, data: bytes | None = None, text: str | None = None,
              mime_type: str | None = None) -> ScanResult:
    mime = guess_mime(filename, data, mime_type)
    res = ScanResult(filename=filename, mime_type=mime)
    try:
        if mime == "application/pdf" and data:
            scan_pdf(data, res)
        elif mime == EXT_MIME[".docx"] and data:
            scan_docx(data, res)
        else:
            if text is None:
                text = (data or b"").decode("utf-8", errors="replace")
            if mime == "text/html":
                scan_html(text, res)
            elif mime == "text/markdown":
                scan_markdown(text, res)
            elif mime == "text/x-source":
                scan_source(text, res)
            else:
                res.full_text = res.visible_text = text
                if "<!--" in text or re.search(r"<(div|span|p)[^>]+style=", text, re.I):
                    scan_markdown(text, res)
    except Exception as exc:  # parser failures are themselves suspicious
        res.error = f"{type(exc).__name__}: {exc}"
        res.add_anomaly("FILE_PARSE_ERROR")
        if text is not None:
            res.full_text = res.visible_text = text
    return res
