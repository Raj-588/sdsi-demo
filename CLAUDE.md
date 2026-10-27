# Claude Code Instructions

## Primary Objective
High-performance technical problem solving and software development with **Security as the highest priority** and **token-efficient execution**.

---

## 1. Security Standards (Highest Priority)

### Secrets & Credential Management
- **Zero Hardcoded Secrets**: Never hardcode API keys, passwords, bearer tokens, private keys, or credentials anywhere in the code.
- Always load sensitive credentials from environment variables (`process.env`, `os.environ`, `System.getenv()`, etc.) or secure secret managers.
- Ensure `.env` and any credential files are strictly excluded via `.gitignore`.

### Input Validation & Sanitization
- Strictly validate and sanitize all inputs at service, API, and function boundaries (data types, lengths, formats, ranges).
- Use strict schemas or allow-lists rather than block-lists.

### Vulnerability Mitigation (OWASP Top 10)
- **Injection**: Always use parameterized queries / ORM prepared statements for database operations (no string concatenation). Never pass unsanitized input to shell execution functions.
- **Path Traversal**: Validate and resolve canonical paths; never allow arbitrary file paths from user inputs.
- **XSS & SSRF**: Escape and sanitize HTML outputs; validate external target URLs against an approved allowlist.
- **Insecure Deserialization**: Avoid unsafe deserialization functions (`eval()`, `pickle.loads()`, `unserialize()`).

### Error Handling & Logging
- **Fail Closed**: In case of authentication or permission failures, deny access by default.
- Never leak stack traces, database schema details, system file paths, or sensitive user data in API error responses or logs.

---

## 2. Token Optimization & Communication Style

- **Concise & Direct**: Skip pleasantries, repetitive apologies, and conversational boilerplate.
- **Targeted Code Modifications**: When modifying existing files, output only the modified functions, code blocks, or unified diffs rather than reprinting entire unchanged files.
- **Focused Explanations**: Limit explanations to 1–2 bullet points explaining critical architectural or security decisions.
- **Minimal Dependencies**: Prefer built-in libraries or lightweight, established packages to reduce dependency bloat and vulnerability surface.

---

## 3. Code Quality & Architecture
- Write modular, readable, self-documenting code.
- Ensure all public functions and security-sensitive boundaries have clear unit tests.
- Handle edge cases, null checks, and timeouts gracefully.
