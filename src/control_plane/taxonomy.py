"""Maps AI-EDR attack categories to OWASP Top 10 for LLM Applications (2025) and MITRE ATLAS techniques.

Every Risk DB entry carries these IDs so detections line up with what SOC teams and auditors already use.
"""
from __future__ import annotations

TAXONOMY: dict[str, dict[str, str]] = {
    "INSTRUCTION_OVERRIDE":     {"owasp": "LLM01", "atlas": "AML.T0051.000", "name": "Direct prompt injection"},
    "ROLE_OVERRIDE":            {"owasp": "LLM01", "atlas": "AML.T0051.000", "name": "Role / persona override"},
    "JAILBREAK":                {"owasp": "LLM01", "atlas": "AML.T0054", "name": "LLM jailbreak"},
    "SYSTEM_PROMPT_EXTRACTION": {"owasp": "LLM07", "atlas": "AML.T0056", "name": "System prompt extraction"},
    "INDIRECT_PDF_POISONING":   {"owasp": "LLM01", "atlas": "AML.T0051.001", "name": "Indirect prompt injection"},
    "DATA_EXFILTRATION":        {"owasp": "LLM02", "atlas": "AML.T0057", "name": "Data exfiltration via LLM"},
    "TOOL_HIJACK":              {"owasp": "LLM06", "atlas": "AML.T0053", "name": "Agent tool hijack"},
    "SECRET_LEAK":              {"owasp": "LLM02", "atlas": "AML.T0057", "name": "Secret leakage"},
    "PII_LEAK":                 {"owasp": "LLM02", "atlas": "AML.T0057", "name": "Personal data leakage"},
    "IP_LEAK":                  {"owasp": "LLM02", "atlas": "AML.T0057", "name": "Proprietary data leakage"},
    "AGENT_EGRESS":             {"owasp": "LLM06", "atlas": "AML.T0057", "name": "Unapproved agent network egress"},
    "SECRET_ACCESS":            {"owasp": "LLM06", "atlas": "AML.T0053", "name": "Agent access to credentials"},
    # behavioral IOA categories (Tier 2)
    "INSTRUCTION_SUPERSEDE":    {"owasp": "LLM01", "atlas": "AML.T0051.000", "name": "Instruction supersede"},
    "SECRECY_DIRECTIVE":        {"owasp": "LLM01", "atlas": "AML.T0051.001", "name": "Hide-from-user directive"},
    "UNTRUSTED_IMPERATIVE":     {"owasp": "LLM01", "atlas": "AML.T0051.001", "name": "Command in untrusted content"},
    "SYSTEM_PROMPT_PROBE":      {"owasp": "LLM07", "atlas": "AML.T0056", "name": "System prompt probe"},
    "PRIV_ESCALATION":          {"owasp": "LLM06", "atlas": "AML.T0054", "name": "Privilege escalation claim"},
    "ROLEPLAY_FRAMING":         {"owasp": "LLM01", "atlas": "AML.T0054", "name": "Role-play jailbreak framing"},
    "JAILBREAK_TERM":           {"owasp": "LLM01", "atlas": "AML.T0054", "name": "Jailbreak terminology"},
    "TOOL_COERCION":            {"owasp": "LLM06", "atlas": "AML.T0053", "name": "Tool coercion"},
    "EXFIL_PATTERN":            {"owasp": "LLM02", "atlas": "AML.T0057", "name": "Exfiltration pattern"},
    "DANGEROUS_TOOL_ARGS":      {"owasp": "LLM06", "atlas": "AML.T0053", "name": "Dangerous tool arguments"},
    "TAINTED_TOOL_CALL":        {"owasp": "LLM06", "atlas": "AML.T0053", "name": "Tool call after tainted input"},
    "HIDDEN_CONTENT":           {"owasp": "LLM01", "atlas": "AML.T0051.001", "name": "Hidden content"},
    "SMUGGLING":                {"owasp": "LLM01", "atlas": "AML.T0051.001", "name": "Encoded / smuggled payload"},
}


def classify(category: str) -> dict[str, str]:
    return TAXONOMY.get(category, {"owasp": "LLM01", "atlas": "AML.T0051", "name": category.replace("_", " ").title()})


def language_of(text: str) -> str:
    if any("가" <= ch <= "힣" for ch in text):
        return "ko"
    return "en" if text.isascii() else "other"
