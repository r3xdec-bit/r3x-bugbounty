"""
R3X Scope Guardian Agent & Security Enforcement Gate
Enforces Domain Allowlist, URL Exclusions, Redirect Safety, Rate Limiting, and Emergency Stop.
All security scans MUST pass through Scope Guardian before execution.
"""
import fnmatch
import socket
import time
from typing import Any
from urllib.parse import urlparse

from r3x.core.exceptions import ScopeViolationError
from r3x.core.logger import audit_log, logger
from r3x.memory.db import db


class ScopeGuardian:
    def __init__(self):
        self._emergency_stop: bool = False
        self._last_request_time: float = 0.0

    def trigger_emergency_stop(self, reason: str = "User initiated emergency stop") -> None:
        """Immediately halt all active scans and external requests."""
        self._emergency_stop = True
        logger.critical(f"EMERGENCY STOP TRIGGERED: {reason}")
        audit_log("EMERGENCY_STOP", "ALL", "ScopeGuardian", reason)

    def reset_emergency_stop(self) -> None:
        """Reset the emergency stop flag."""
        self._emergency_stop = False
        logger.info("Emergency stop flag reset.")

    def is_emergency_stopped(self) -> bool:
        return self._emergency_stop

    def validate_target(
        self,
        url_or_domain: str,
        project_id: str | None = None,
        scope_override: dict[str, Any] | None = None
    ) -> bool:
        """
        Evaluate if a target URL or host strictly resides within the authorized scope.
        Raises ScopeViolationError if unauthorized.
        """
        if self._emergency_stop:
            raise ScopeViolationError("Operation blocked: EMERGENCY STOP is active.")

        parsed = urlparse(url_or_domain)
        hostname = (parsed.hostname or url_or_domain).lower().strip()
        path = parsed.path.lower()

        # Load scope rules from project or override
        scope = scope_override
        if not scope and project_id:
            scope = db.get_scope(project_id)

        if not scope:
            # Default safety rule: Allow only explicit matching domain
            allowed = [hostname]
            excluded = ["*.gov", "*.mil", "logout", "delete", "destroy", "shutdown"]
            allow_subdomains = True
        else:
            allowed = scope.get("allowed_patterns", []) or [scope.get("target_domain", hostname)]
            excluded = scope.get("excluded_patterns", []) or []
            allow_subdomains = bool(scope.get("allow_subdomains", True))

        # 1. Check exclusions first (highest priority)
        for pattern in excluded:
            pattern = pattern.lower().strip()
            if fnmatch.fnmatch(hostname, pattern) or (pattern in path):
                audit_log("SCOPE_BLOCK", hostname, "ScopeGuardian", f"Matched excluded pattern: {pattern}")
                raise ScopeViolationError(f"Target '{hostname}' violates exclusion rule: '{pattern}'")

        # 2. Check allowlist
        is_allowed = False
        for pattern in allowed:
            pattern = pattern.lower().strip()
            if fnmatch.fnmatch(hostname, pattern):
                is_allowed = True
                break
            if allow_subdomains and (hostname.endswith("." + pattern) or pattern == hostname):
                is_allowed = True
                break

        if not is_allowed:
            audit_log("SCOPE_BLOCK", hostname, "ScopeGuardian", f"Not in allowlist: {allowed}")
            raise ScopeViolationError(
                f"Scope Violation! Target '{hostname}' is not authorized. Allowed scope: {allowed}"
            )

        # 3. Check for SSRF / private IP / localhost escapes unless explicitly testing local
        try:
            resolved_ip = socket.gethostbyname(hostname)
            if resolved_ip.startswith("127.") and not hostname.startswith("localhost") and not hostname.startswith("127."):
                raise ScopeViolationError(f"DNS resolved to loopback {resolved_ip} for non-local domain {hostname}")
        except socket.gaierror:
            pass  # Will be handled during network connection

        return True

    def check_redirect(self, original_url: str, redirected_url: str, project_id: str | None = None) -> bool:
        """
        Verify that an HTTP redirect does NOT escape the authorized domain.
        """
        orig_host = urlparse(original_url).hostname or ""
        redir_host = urlparse(redirected_url).hostname or ""

        if not redir_host:
            return True  # Relative path redirect is always safe within same host

        try:
            self.validate_target(redirected_url, project_id)
            return True
        except ScopeViolationError as e:
            logger.warning(f"Prevented out-of-scope redirect from {orig_host} to {redir_host}: {e}")
            audit_log("REDIRECT_BLOCK", redir_host, "ScopeGuardian", f"Escape attempted from {orig_host}")
            return False

    def throttle(self, max_rate_per_sec: int = 5) -> None:
        """Enforce request rate limiting."""
        if max_rate_per_sec <= 0:
            return
        interval = 1.0 / max_rate_per_sec
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < interval:
            time.sleep(interval - elapsed)
        self._last_request_time = time.time()

scope_guardian = ScopeGuardian()
