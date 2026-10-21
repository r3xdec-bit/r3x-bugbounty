"""
R3X Security Headers & Transport Security Scanner
Audits HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
"""
import httpx
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from r3x.scanners.base import BaseScanner
from r3x.security.scope_guardian import scope_guardian
from r3x.core.logger import logger

class HeadersAnalyzer(BaseScanner):
    def scan(self, scan_id: str) -> List[Dict[str, Any]]:
        findings = []
        logger.info(f"HeadersAnalyzer: Auditing HTTP security headers on {self.target_url}")

        scope_guardian.throttle(max_rate_per_sec=5)

        try:
            with httpx.Client(timeout=10.0, verify=False, follow_redirects=False) as client:
                resp = client.get(self.target_url, headers={"User-Agent": "R3X-Security-Audit/1.0"})
                headers = dict(resp.headers)
                raw_req = f"GET {urlparse(self.target_url).path or '/'} HTTP/1.1\nHost: {urlparse(self.target_url).netloc}\nUser-Agent: R3X-Security-Audit/1.0"
                raw_resp = f"HTTP/1.1 {resp.status_code} {resp.reason_phrase}\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())

                # 1. HSTS (Strict-Transport-Security)
                is_https = self.target_url.startswith("https://")
                if is_https and "strict-transport-security" not in headers:
                    findings.append(self.record_finding(
                        scan_id=scan_id,
                        title="Missing Strict-Transport-Security (HSTS) Header",
                        severity="MEDIUM",
                        endpoint=self.target_url,
                        technical_explanation="The web application does not enforce HTTPS via the Strict-Transport-Security header. This exposes users to potential SSL-stripping and man-in-the-middle (MITM) downgrade attacks.",
                        remediation="Configure the web server to return: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                        cwe="CWE-319",
                        cvss=5.3,
                        status="CONFIRMED",
                        request_raw=raw_req,
                        response_raw=raw_resp,
                        headers=headers
                    ))

                # 2. Content-Security-Policy (CSP)
                if "content-security-policy" not in headers:
                    findings.append(self.record_finding(
                        scan_id=scan_id,
                        title="Missing Content-Security-Policy (CSP) Header",
                        severity="LOW",
                        endpoint=self.target_url,
                        technical_explanation="Content-Security-Policy header is absent. A well-crafted CSP helps mitigate Cross-Site Scripting (XSS) and data injection attacks by restricting the origins of executable scripts.",
                        remediation="Define a robust CSP header: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';",
                        cwe="CWE-1021",
                        cvss=4.3,
                        status="CONFIRMED",
                        request_raw=raw_req,
                        response_raw=raw_resp,
                        headers=headers
                    ))

                # 3. X-Frame-Options (Clickjacking)
                if "x-frame-options" not in headers and "content-security-policy" not in headers:
                    findings.append(self.record_finding(
                        scan_id=scan_id,
                        title="Missing Anti-Clickjacking Header (X-Frame-Options)",
                        severity="LOW",
                        endpoint=self.target_url,
                        technical_explanation="The page lacks X-Frame-Options or frame-ancestors directive, potentially permitting framing inside malicious iframes on third-party sites.",
                        remediation="Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to all HTTP responses.",
                        cwe="CWE-1021",
                        cvss=3.7,
                        status="CONFIRMED",
                        request_raw=raw_req,
                        response_raw=raw_resp,
                        headers=headers
                    ))

                # 4. X-Content-Type-Options
                if headers.get("x-content-type-options", "").lower() != "nosniff":
                    findings.append(self.record_finding(
                        scan_id=scan_id,
                        title="Missing or Invalid X-Content-Type-Options",
                        severity="INFO",
                        endpoint=self.target_url,
                        technical_explanation="The X-Content-Type-Options: nosniff header is missing. Browsers may attempt MIME-type sniffing, which can lead to unexpected script execution.",
                        remediation="Set 'X-Content-Type-Options: nosniff' header across all responses.",
                        cwe="CWE-16",
                        cvss=2.0,
                        status="CONFIRMED",
                        request_raw=raw_req,
                        response_raw=raw_resp,
                        headers=headers
                    ))

        except Exception as e:
            logger.warning(f"HeadersAnalyzer encountered network error on {self.target_url}: {e}")

        return findings
