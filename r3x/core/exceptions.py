"""
R3X Custom Exceptions
"""

class R3XError(Exception):
    """Base exception for all R3X-BugBounty errors."""
    pass

class ScopeViolationError(R3XError):
    """Raised when an operation attempts to target an out-of-scope asset."""
    pass

class RateLimitExceededError(R3XError):
    """Raised when target or API rate limits are violated."""
    pass

class ProviderError(R3XError):
    """Raised when an AI provider returns an error or is unreachable."""
    pass

class KeyStoreError(R3XError):
    """Raised on keystore encryption, decryption, or storage failures."""
    pass

class AdapterError(R3XError):
    """Raised when Hermes or HexStrike integrations fail."""
    pass

class ToolExecutionError(R3XError):
    """Raised when an external security tool fails or violates safety rules."""
    pass

class EvidenceValidationError(R3XError):
    """Raised when evidence fails verification or hash integrity."""
    pass
