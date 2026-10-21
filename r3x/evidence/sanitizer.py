"""
R3X Evidence Sanitizer & Redaction Engine
Automatically redacts API keys, credentials, session cookies, and unnecessary PII.
"""
import re

SENSITIVE_PATTERNS = [
    # Bearer tokens & JWTs
    (re.compile(r'(?i)(Authorization:\s*Bearer\s+)[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*'), r'\1[REDACTED_JWT]'),
    (re.compile(r'(?i)(bearer\s+)([A-Za-z0-9\-_.]{16,})'), r'\1[REDACTED_BEARER_TOKEN]'),
    # Passwords in query params or JSON
    (re.compile(r'(?i)("?(?:password|passwd|pwd|secret|api_key|apikey|access_token)"?\s*[:=]\s*"?[^"&\s]{3,}"?)'), r'[REDACTED_CREDENTIAL]'),
    # Session Cookies
    (re.compile(r'(?i)(connect\.sid|PHPSESSID|JSESSIONID|sessionid|auth_token)=([A-Za-z0-9\-_.%]{10,})'), r'\1=[REDACTED_SESSION_ID]'),
    # Credit Cards (Luhn candidates)
    (re.compile(r'\b(?:\d{4}[ -]?){3}\d{4}\b'), r'[REDACTED_CARD_NUMBER]'),
    # Private SSH / RSA Keys
    (re.compile(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----', re.DOTALL), r'[REDACTED_PRIVATE_KEY]'),
]

def sanitize_evidence(text: str) -> str:
    """Mask credentials and sensitive PII from request/response evidence."""
    if not text:
        return ""
    if not isinstance(text, str):
        text = str(text)

    clean = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        clean = pattern.sub(replacement, clean)
    return clean
