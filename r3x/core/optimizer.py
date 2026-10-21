"""
R3X Smart Scan Optimizer
Dynamically selects necessary scanner modules based on target profile to eliminate redundant requests.
"""
from typing import Any
from urllib.parse import urlparse

from r3x.core.logger import logger


class ScanOptimizer:
    def __init__(self):
        self._response_cache: dict[str, Any] = {}

    def optimize_scan_plan(self, target_url: str, scan_type: str = "quick") -> dict[str, bool]:
        """
        Determines which scanners to execute or skip based on protocol and target properties.
        Eliminates redundant checks (e.g., skips TLS on plain HTTP).
        """
        parsed = urlparse(target_url)
        is_https = (parsed.scheme == "https") or (parsed.port == 443)
        is_api_scan = (scan_type == "api")
        is_full_scan = (scan_type == "full")

        plan = {
            "run_dns_recon": True,
            "run_headers": True,
            "run_cors": True,
            "run_cookies": True,
            "run_tls": is_https,                  # Skip TLS on plain HTTP targets
            "run_api_schemas": is_api_scan or is_full_scan,
            "run_js_analysis": is_full_scan,
            "run_tech_fingerprint": True
        }

        skipped = [k for k, v in plan.items() if not v]
        if skipped:
            logger.info(f"ScanOptimizer: Intelligently skipped redundant scanners for {target_url}: {', '.join(skipped)}")

        return plan

    def get_cached_response(self, cache_key: str) -> Any:
        return self._response_cache.get(cache_key)

    def set_cached_response(self, cache_key: str, data: Any) -> None:
        self._response_cache[cache_key] = data

scan_optimizer = ScanOptimizer()
