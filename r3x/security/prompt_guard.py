"""
R3X Prompt Injection Defense & Input Guard
Sanitizes untrusted tool outputs and target HTTP traces before LLM ingestion.
"""
import re

PROMPT_INJECTION_PATTERNS = [
    re.compile(r'(?i)(ignore\s+(all\s+)?(previous|prior)\s+instructions)'),
    re.compile(r'(?i)(you\s+are\s+now\s+a\s+different\s+ai)'),
    re.compile(r'(?i)(system\s*:\s*you\s+must)'),
    re.compile(r'(?i)(disregard\s+(the\s+)?(above|rules))'),
    re.compile(r'(?i)(classified\s+as\s+false_positive\s+by\s+default)'),
]

def sanitize_untrusted_prompt_data(text: str, max_chars: int = 4000) -> str:
    """
    Sanitizes external data from target servers or tool outputs before inserting
    into Large Language Model prompts. Neutralizes jailbreak/injection patterns
    and encloses data in structured XML boundary tags.
    """
    if not text:
        return ""
    if not isinstance(text, str):
        text = str(text)

    # Truncate to bound context
    cleaned = text[:max_chars]

    # Neutralize prompt injection phrases
    for pattern in PROMPT_INJECTION_PATTERNS:
        cleaned = pattern.sub("[FILTERED_POTENTIAL_PROMPT_INJECTION]", cleaned)

    # Strip dangerous markdown delimiter sequences that attempt to breakout of system blocks
    cleaned = cleaned.replace("```json\n{", "{\n").replace("```", "'''")

    return f"<untrusted_target_evidence>\n{cleaned}\n</untrusted_target_evidence>"
