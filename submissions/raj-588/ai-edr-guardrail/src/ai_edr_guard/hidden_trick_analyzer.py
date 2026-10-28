"""Stage 3.1 — HiddenTrickAnalyzer: de-obfuscation & hidden trick unpacking (Falcon Layer B step 1).

For every segment it:
  * removes / decodes invisible Unicode (Tag chars U+E0000-E007F, zero-width, bidi overrides)
  * folds homoglyphs (Cyrillic/Greek look-alikes) and leetspeak, rejoins token-split words
  * finds Base64 / hex / URL-encoded / ROT13 payloads and emits them as DECODED segments
The normalized text replaces `segment.text` (what detectors match against); `raw_text`
is kept untouched for stripping and forensics.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from urllib.parse import unquote

from ..schemas.canonical import Segment, SegmentKind

ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿", "᠎", "­"}
BIDI = {"‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩", "‎", "‏"}

# Small confusables table (Unicode TR39 subset) for the scripts attackers actually use.
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ո": "n", "ս": "u", "ν": "v", "ο": "o", "α": "a", "ε": "e",
    "ι": "i", "κ": "k", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "А": "A", "В": "B", "Е": "E", "К": "K",
    "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "Ι": "I", "Ο": "O",
})
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

ANOMALY_WEIGHTS = {
    "UNICODE_TAG_SMUGGLING": 0.9,
    "BIDI_OVERRIDE": 0.5,
    "ZERO_WIDTH_CHARS": 0.35,
    "HOMOGLYPH_MIXED_SCRIPT": 0.5,
    "BASE64_PAYLOAD": 0.4,
    "HEX_PAYLOAD": 0.4,
    "URL_ENCODED_PAYLOAD": 0.3,
    "ROT13_PAYLOAD": 0.6,
    "TOKEN_SPLITTING": 0.4,
    "LEETSPEAK": 0.2,
    "WHITE_TEXT_ON_WHITE_BG": 0.8,
    "TEXT_COLOR_MATCHES_BACKGROUND": 0.8,
    "FONT_SIZE_ZERO_DETECTED": 0.8,
    "PDF_RENDER_MODE_3_INVISIBLE": 0.8,
    "ZERO_OPACITY_TEXT": 0.8,
    "TEXT_OUTSIDE_PAGE": 0.6,
    "DOCX_HIDDEN_RUN": 0.8,
    "HTML_CSS_HIDDEN_TEXT": 0.6,
    "HTML_COMMENT_TEXT": 0.2,
    "MARKDOWN_HTML_COMMENT": 0.2,
    "PDF_ANNOTATION_TEXT": 0.2,
    "PDF_JAVASCRIPT_ACTION": 0.5,
    "PDF_EMBEDDED_FILES": 0.3,
    "FILE_PARSE_ERROR": 0.3,
}

_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){16,}\b")
_URLENC = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
_SPLIT = re.compile(r"\b(?:[A-Za-z][\s.\-_*|+]){3,}[A-Za-z]\b")
_ROT13_HINTS = ("vtaber", "cerivbhf", "vafgehpgvbaf", "flfgrz cebzcg", "qvfertneq", "ehyrf")
MAX_DECODE_DEPTH = 3


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(ch.isprintable() or ch in "\n\t" for ch in s) / len(s)


def _looks_like_text(s: str) -> bool:
    return len(s) >= 8 and _printable_ratio(s) > 0.9 and " " in s and sum(c.isalpha() for c in s) / len(s) > 0.6


def _mixed_script_word(word: str) -> bool:
    scripts = set()
    for ch in word:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            scripts.add(name.split(" ")[0])
    return len(scripts & {"LATIN", "CYRILLIC", "GREEK"}) > 1


def normalize(text: str) -> tuple[str, list[str], list[tuple[str, str]]]:
    """Return (normalized_text, anomalies, decoded_payloads[(kind, text)])."""
    anomalies: list[str] = []
    decoded: list[tuple[str, str]] = []

    tag_chars = [ch for ch in text if 0xE0000 <= ord(ch) <= 0xE007F]
    if tag_chars:
        anomalies.append("UNICODE_TAG_SMUGGLING")
        hidden_ascii = "".join(chr(ord(ch) - 0xE0000) for ch in tag_chars if 0x20 <= ord(ch) - 0xE0000 <= 0x7E)
        if hidden_ascii.strip():
            decoded.append(("UNICODE_TAGS", hidden_ascii))
        text = "".join(ch for ch in text if not 0xE0000 <= ord(ch) <= 0xE007F)
    if any(ch in ZERO_WIDTH for ch in text):
        anomalies.append("ZERO_WIDTH_CHARS")
        text = "".join(ch for ch in text if ch not in ZERO_WIDTH)
    if any(ch in BIDI for ch in text):
        anomalies.append("BIDI_OVERRIDE")
        text = "".join(ch for ch in text if ch not in BIDI)

    # Encoded payloads are decoded before folding steps that would corrupt them (leet maps digits).
    for m in _B64.finditer(text):
        try:
            s = base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4)).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if _looks_like_text(s):
            anomalies.append("BASE64_PAYLOAD")
            decoded.append(("BASE64", s))
    for m in _HEX.finditer(text):
        try:
            s = bytes.fromhex(m.group(0)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _looks_like_text(s):
            anomalies.append("HEX_PAYLOAD")
            decoded.append(("HEX", s))
    for m in _URLENC.finditer(text):
        s = unquote(m.group(0))
        if _looks_like_text(s):
            anomalies.append("URL_ENCODED_PAYLOAD")
            decoded.append(("URL", s))
    text = unicodedata.normalize("NFKC", text)
    if any(_mixed_script_word(w) for w in re.findall(r"\w{3,}", text)):
        anomalies.append("HOMOGLYPH_MIXED_SCRIPT")
    text = text.translate(CONFUSABLES)

    def _unsplit(m: re.Match) -> str:
        return re.sub(r"[\s.\-_*|+]", "", m.group(0))
    rejoined = _SPLIT.sub(_unsplit, text)
    if rejoined != text:
        anomalies.append("TOKEN_SPLITTING")
        text = rejoined

    def _deleet(m: re.Match) -> str:
        w = m.group(0)
        return w.translate(LEET) if re.search(r"[A-Za-z]", w) and re.search(r"[013457@$]", w) else w
    deleeted = re.sub(r"[A-Za-z0-9@$]{4,}", _deleet, text)
    if deleeted != text and re.search(r"[A-Za-z][013457@$][A-Za-z]", text):
        anomalies.append("LEETSPEAK")
        text = deleeted

    low = text.lower()
    if "rot13" in low or "rot-13" in low or any(h in low for h in _ROT13_HINTS):
        anomalies.append("ROT13_PAYLOAD")
        decoded.append(("ROT13", codecs.decode(text, "rot13")))

    return text, list(dict.fromkeys(anomalies)), decoded


def analyze(segments: list[Segment]) -> list[Segment]:
    """Normalize segments in place and append DECODED child segments (recursively)."""
    queue = list(segments)
    depth = {s.segment_id: 0 for s in segments}
    while queue:
        seg = queue.pop(0)
        norm, anomalies, decoded = normalize(seg.raw_text)
        seg.text = norm
        seg.anomalies = list(dict.fromkeys(seg.anomalies + anomalies))
        if depth[seg.segment_id] >= MAX_DECODE_DEPTH:
            continue
        for kind, payload in decoded:
            child = Segment(
                segment_id=f"seg_{len(segments)}",
                kind=SegmentKind.DECODED,
                trust=seg.trust,
                text=payload,
                raw_text=payload,
                label=f"{seg.label}#decoded:{kind.lower()}",
                anomalies=[a for a in anomalies if a.endswith(("PAYLOAD", "SMUGGLING"))],
                parent_id=seg.parent_id or seg.segment_id,
                source_path=seg.source_path,
            )
            segments.append(child)
            depth[child.segment_id] = depth[seg.segment_id] + 1
            queue.append(child)
    return segments


def anomaly_score(anomalies: list[str]) -> float:
    if not anomalies:
        return 0.0
    # noisy-OR over individual anomaly weights
    p = 1.0
    for a in anomalies:
        p *= 1 - ANOMALY_WEIGHTS.get(a, 0.2)
    return round(1 - p, 4)
