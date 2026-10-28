"""Samsung AI Pro (aipro) adapter: /v1/aipro/*

Inspects developer prompts, IDE workspace context files and code diffs — for prompt injection
AND for proprietary-IP / secret leakage (DLP `proprietary_markers`, keys, tokens).
Field locations come from `platform_field_maps.SAMSUNG_AIPRO` (wire format not public).
"""
from __future__ import annotations

from ..schemas.canonical import SegmentKind, SourcePlatform
from ..settings import settings
from .samsung_fabrix_adapter import SamsungFabriXAdapter


class SamsungAIProAdapter(SamsungFabriXAdapter):
    platform = SourcePlatform.SAMSUNG_AIPRO
    prefix = "/v1/aipro"
    doc_kind = SegmentKind.FILE

    def upstream_base(self) -> str:
        return settings.aipro_base
