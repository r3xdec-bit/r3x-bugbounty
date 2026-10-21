"""
R3X Cookie Security Checker
Audits Set-Cookie headers for HttpOnly, Secure, and SameSite attributes.
"""
import httpx
from typing import Dict, Any, List
from urllib.parse import urlparse

from r3x.scanners.base import BaseScanner
from r3x.security.scope_guardian import scope_guardian
from r3x.core.logger import logger

class CookieChecker(BaseScanner):
    def scan(self, scan_id: str) -> List[Dict[str, Any]]:
        findings = []
        logger.info(f"CookieChecker: Auditing cookie security flags on {self.target_url}")

        scope_guardian.throttle(max_rate_per_sec=5)
        try:
            with httpx.Client(timeout=8.0, verify=False) as client:
                resp = client.get(self.target_url, headers={"User-Agent": "R3X-Security-Audit/1.0"})
                raw_cookies = resp.headers.get_list("set-cookie")

                raw_req = f"GET / HTTP/1.1\nHost: {urlparse(self.target_url).netloc}"
                raw_resp = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"Set-Cookie: {c}" for c in raw_cookies)

                is_https = self.target_url.startswith("https://")

                for cookie_str in raw_cookies:
                    parts = [p.strip() for p in cookie_str.split(";")]
                    cookie_name = parts[0].split("=")[0] if "=" in parts[0] else parts[0]
                    lower_parts = [p.lower() for p in parts]

                    has_httponly = any("httponly" in p for p in lower_parts)
                    has_secure = any("secure" in p for p in lower_parts)
                    has_samesite = any("samesite" in p for p in lower_parts)

                    # 1. Missing HttpOnly
                    if not has_httponly:
                        findings.append(self.record_finding(
                            scan_id=scan_id,
                            title=f"Cookie '{cookie_name}' Missing HttpOnly Flag",
                            severity="MEDIUM",
                            endpoint=self.target_url,
                            technical_explanation=f"Cookie '{cookie_name}' was set without the 'HttpOnly' flag. If the application suffers from Cross-Site Scripting (XSS), attackers can access this cookie via document.cookie.",
                            remediation=f"Append '; HttpOnly' to the Set-Cookie directive for cookie '{cookie_name}'.",
                            cwe="CWE-1004",
                            cvss=5.3,
                            status="CONFIRMED",
                            request_raw=raw_req,
                            response_raw=raw_resp
                        ))

                    # 2. Missing Secure flag on HTTPS
                    if is_https and not has_secure:
                        findings.append(self.record_finding(
                            scan_id=scan_id,
                            title=f"Cookie '{cookie_name}' Missing Secure Flag over HTTPS",
                            severity="MEDIUM",
                            endpoint=self.target_url,
                            technical_explanation=f"Cookie '{cookie_name}' lacks the 'Secure' attribute. Web browsers will transmit this cookie over unencrypted HTTP connections if requested.",
                            remediation=f"Ensure '; Secure' is enabled for all cookies served over HTTPS.",
                            cwe="CWE-614",
                            cvss=5.0,
                            status="CONFIRMED",
                            request_raw=raw_req,
                            response_raw=raw_resp
                        ))

                    # 3. Missing SameSite flag
                    if not has_samesite:
                        findings.append(self.record_finding(
                            scan_id=scan_id,
                            title=f"Cookie '{cookie_name}' Missing SameSite Attribute",
                            severity="LOW",
                            endpoint=self.target_url,
                            technical_explanation=f"Cookie '{cookie_name}' does not specify SameSite (Lax or Strict), potentially exposing authenticated actions to Cross-Site Request Forgery (CSRF).",
                            remediation="Configure 'SameSite=Lax' or 'SameSite=Strict' on sensitive cookies.",
                            cwe="CWE-1275",
                            cvss=4.3,
                            status="CONFIRMED",
                            request_raw=raw_req,
                            response_raw=raw_resp
                        ))

        except Exception as e:
            logger.debug(f"CookieChecker error on {self.target_url}: {e}")

        return findings
