from ..schemas.canonical import SourcePlatform
from .anthropic_claude_adapter import AnthropicClaudeAdapter
from .base_adapter import BaseAdapter
from .google_gemini_adapter import GoogleGeminiAdapter
from .openai_chatgpt_adapter import OpenAIChatGPTAdapter
from .samsung_aipro_adapter import SamsungAIProAdapter
from .samsung_fabrix_adapter import SamsungFabriXAdapter

ADAPTERS: dict[SourcePlatform, BaseAdapter] = {
    SourcePlatform.OPENAI: OpenAIChatGPTAdapter(),
    SourcePlatform.GEMINI: GoogleGeminiAdapter(),
    SourcePlatform.CLAUDE_IDE: AnthropicClaudeAdapter(),
    SourcePlatform.ANTIGRAVITY_IDE: AnthropicClaudeAdapter(),
    SourcePlatform.SAMSUNG_FABRIX: SamsungFabriXAdapter(),
    SourcePlatform.SAMSUNG_AIPRO: SamsungAIProAdapter(),
}

__all__ = ["ADAPTERS", "BaseAdapter"]
