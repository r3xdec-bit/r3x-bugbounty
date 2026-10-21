"""
R3X Logging and Audit Recording with Automatic Redaction
"""
import logging
import re
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

console = Console()
error_console = Console(stderr=True)

# Secret patterns to automatically mask
SECRET_PATTERNS = [
    (re.compile(r'(?i)(api[_-]?key\s*[:=]\s*["\']?)([\w\-]{8,})(["\']?)'), r'\1[REDACTED_API_KEY]\3'),
    (re.compile(r'(?i)(bearer\s+)([\w\-\._]{16,})'), r'\1[REDACTED_BEARER]'),
    (re.compile(r'(?i)(password\s*[:=]\s*["\']?)([^"\'\s]{4,})(["\']?)'), r'\1[REDACTED_PASSWORD]\3'),
    (re.compile(r'(?i)(token\s*[:=]\s*["\']?)([\w\-]{8,})(["\']?)'), r'\1[REDACTED_TOKEN]\3'),
    (re.compile(r'(?i)(nvapi-[\w\-]{20,})'), r'[REDACTED_NVIDIA_KEY]'),
    (re.compile(r'(?i)(sk-[\w\-]{20,})'), r'[REDACTED_OPENAI_KEY]'),
    (re.compile(r'(?i)(AIzaSy[\w\-]{25,})'), r'[REDACTED_GEMINI_KEY]'),
]

def redact_secrets(text: str) -> str:
    """Mask known secret patterns from output text."""
    if not isinstance(text, str):
        text = str(text)
    sanitized = text
    for pattern, replacement in SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized

class RedactingFormatter(logging.Formatter):
    """Custom logging formatter that strips sensitive secrets."""
    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        return redact_secrets(original)

def get_logger(name: str = "r3x", log_file: Path | None = None) -> logging.Logger:
    """Obtain a logger instance with Rich terminal handler and audit file."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    # Rich Handler for Console
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        rich_tracebacks=True,
        markup=True
    )
    rich_handler.setLevel(logging.INFO)
    logger.addHandler(rich_handler)

    # Audit File Handler
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            RedactingFormatter("[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s")
        )
        logger.addHandler(file_handler)

    return logger

def audit_log(event_type: str, target: str, actor: str, details: str) -> None:
    """Record an audit trail event in the global security log."""
    from r3x.core.config import settings
    log_file = settings.audit_log_path
    log_file.parent.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now(UTC).isoformat()
    clean_details = redact_secrets(details)
    entry = f"{timestamp} | EVENT: {event_type} | ACTOR: {actor} | TARGET: {target} | {clean_details}\n"
    
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(entry)

logger = get_logger("r3x")
