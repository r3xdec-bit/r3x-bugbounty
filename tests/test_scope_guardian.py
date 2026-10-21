import pytest

from r3x.core.exceptions import ScopeViolationError
from r3x.security.scope_guardian import ScopeGuardian


def test_scope_guardian_allowlist():
    guardian = ScopeGuardian()
    scope = {
        "target_domain": "example.com",
        "allowed_patterns": ["example.com", "*.example.com"],
        "excluded_patterns": ["*.gov", "logout"],
        "allow_subdomains": True
    }

    assert guardian.validate_target("https://example.com/api", scope_override=scope) is True
    assert guardian.validate_target("https://sub.example.com", scope_override=scope) is True

    with pytest.raises(ScopeViolationError):
        guardian.validate_target("https://unauthorized.org", scope_override=scope)

    with pytest.raises(ScopeViolationError):
        guardian.validate_target("https://agency.gov", scope_override=scope)

    with pytest.raises(ScopeViolationError):
        guardian.validate_target("https://example.com/logout", scope_override=scope)

def test_emergency_stop():
    guardian = ScopeGuardian()
    guardian.trigger_emergency_stop("Test Stop")
    assert guardian.is_emergency_stopped() is True

    with pytest.raises(ScopeViolationError):
        guardian.validate_target("https://example.com")

    guardian.reset_emergency_stop()
    assert guardian.is_emergency_stopped() is False
