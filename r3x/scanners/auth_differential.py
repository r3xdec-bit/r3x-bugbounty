"""
R3X Authenticated Differential Role Scanner
Audits authorization disparity and access control divergences (BOLA/BFLA)
between high-privileged, low-privileged, and unauthenticated sessions.
Operates strictly in non-destructive read-only auditing mode.
"""
from typing import Any
from urllib.parse import urlparse

import httpx

from r3x.core.config import settings
from r3x.core.logger import logger
from r3x.scanners.base import BaseScanner
from r3x.security.scope_guardian import scope_guardian


class AuthDifferentialScanner(BaseScanner):
    def audit_endpoint_access(
        self,
        endpoint_url: str,
        privileged_headers: dict[str, str],
        unprivileged_headers: dict[str, str] | None = None,
        scan_id: str = "diff-scan"
    ) -> list[dict[str, Any]]:
        """
        Compares response behavior across different privilege profiles:
        1. High Privilege (e.g., Admin / Primary User)
        2. Low Privilege (e.g., Secondary / Guest User)
        3. Unauthenticated (No credentials / Anonymous)
        """
        findings = []
        scope_guardian.validate_target(endpoint_url, project_id=self.project_id)
        scope_guardian.throttle(max_rate_per_sec=settings.network.rate_limit_per_second)

        logger.info(f"AuthDifferentialScanner: Auditing access control on {endpoint_url}")

        timeout = float(settings.network.timeout_seconds)
        verify_ssl = settings.network.verify_ssl

        with httpx.Client(timeout=timeout, verify=verify_ssl) as client:  # nosec B501
            # 1. Baseline Request: Privileged Context
            try:
                resp_priv = client.get(endpoint_url, headers=privileged_headers)
            except Exception as e:
                logger.warning(f"AuthDifferentialScanner: Privileged baseline probe failed: {e}")
                return findings

            # Only evaluate if privileged endpoint is actually accessible (200 OK)
            if resp_priv.status_code != 200:
                logger.info(f"AuthDifferentialScanner: Endpoint returned {resp_priv.status_code} for privileged user; skipping diff.")
                return findings

            priv_len = len(resp_priv.content)

            # 2. Unauthenticated Baseline Probe
            try:
                resp_anon = client.get(endpoint_url, headers={"User-Agent": settings.network.user_agent})
            except Exception as e:
                logger.warning(f"AuthDifferentialScanner: Anonymous probe failed: {e}")
                resp_anon = None

            if resp_anon and resp_anon.status_code == 200:
                anon_len = len(resp_anon.content)
                # If unauthenticated user receives full 200 OK with comparable body length
                len_ratio = min(priv_len, anon_len) / max(priv_len, anon_len) if max(priv_len, anon_len) > 0 else 1.0
                if len_ratio > 0.85:
                    raw_req = f"GET {urlparse(endpoint_url).path} HTTP/1.1\nHost: {urlparse(endpoint_url).netloc}\n(No Authorization)"
                    raw_resp = f"HTTP/1.1 200 OK\nContent-Length: {anon_len}\n\n{resp_anon.text[:500]}"
                    findings.append(self.record_finding(
                        scan_id=scan_id,
                        title=f"Broken Authentication: Sensitive Endpoint Accessible Anonymously ({urlparse(endpoint_url).path})",
                        severity="HIGH",
                        endpoint=endpoint_url,
                        technical_explanation=(
                            f"The endpoint '{endpoint_url}' returned HTTP 200 OK with {anon_len} bytes to an unauthenticated request, "
                            f"matching the authenticated privileged response ({priv_len} bytes) within {len_ratio * 100:.1f}% similarity. "
                            "This indicates missing authentication or broken access control filters."
                        ),
                        remediation="Enforce mandatory authentication middleware and deny anonymous access by default.",
                        cwe="CWE-306",
                        cvss=7.5,
                        status="CONFIRMED",
                        confidence_score=0.95,
                        request_raw=raw_req,
                        response_raw=raw_resp,
                        headers=dict(resp_anon.headers)
                    ))

            # 3. Low-Privilege / Cross-Role Differential Probe
            if unprivileged_headers:
                try:
                    resp_low = client.get(endpoint_url, headers=unprivileged_headers)
                except Exception as e:
                    logger.warning(f"AuthDifferentialScanner: Low-privilege probe failed: {e}")
                    resp_low = None

                if resp_low and resp_low.status_code == 200:
                    low_len = len(resp_low.content)
                    low_ratio = min(priv_len, low_len) / max(priv_len, low_len) if max(priv_len, low_len) > 0 else 1.0
                    if low_ratio > 0.90:
                        raw_req = f"GET {urlparse(endpoint_url).path} HTTP/1.1\nHost: {urlparse(endpoint_url).netloc}\nAuthorization: [LOW_PRIVILEGED_TOKEN]"
                        raw_resp = f"HTTP/1.1 200 OK\nContent-Length: {low_len}\n\n{resp_low.text[:500]}"
                        findings.append(self.record_finding(
                            scan_id=scan_id,
                            title=f"Potential BOLA/BFLA: Unprivileged Role Accesses Privileged Asset ({urlparse(endpoint_url).path})",
                            severity="CRITICAL",
                            endpoint=endpoint_url,
                            technical_explanation=(
                                f"An unprivileged session accessed the privileged endpoint '{endpoint_url}' and received HTTP 200 OK "
                                f"with data parity ({low_ratio * 100:.1f}%) compared to the administrative profile. "
                                "This indicates broken horizontal or vertical authorization boundaries."
                            ),
                            remediation="Implement strict server-side authorization gates verifying that the authenticated user owns or has explicit permission to access the requested resource ID.",
                            cwe="CWE-639",
                            cvss=8.6,
                            status="CONFIRMED",
                            confidence_score=0.92,
                            request_raw=raw_req,
                            response_raw=raw_resp,
                            headers=dict(resp_low.headers)
                        ))

        return findings
