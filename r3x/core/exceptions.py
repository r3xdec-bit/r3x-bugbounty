"""
R3X Custom Exceptions
"""

class R3XError(Exception):
    """Base exception for all R3X-BugBounty errors."""

class ScopeViolationError(R3XError):
    """Raised when an operation attempts to target an out-of-scope asset."""

class RateLimitExceededError(R3XError):
    """Raised when target or API rate limits are violated."""

class ProviderError(R3XError):
    """Raised when an AI provider returns an error or is unreachable."""

class KeyStoreError(R3XError):
    """Raised on keystore encryption, decryption, or storage failures."""

class AdapterError(R3XError):
    """Raised when Hermes or HexStrike integrations fail."""

class ToolExecutionError(R3XError):
    """Raised when an external security tool fails or violates safety rules."""

class EvidenceValidationError(R3XError):
    """Raised when evidence fails verification or hash integrity."""
