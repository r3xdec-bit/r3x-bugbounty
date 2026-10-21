"""
R3X CORS Security Analyzer
Evaluates Cross-Origin Resource Sharing misconfigurations and credential exposure.
"""
import httpx
from typing import Dict, Any, List
from urllib.parse import urlparse

from r3x.scanners.base import BaseScanner
from r3x.security.scope_guardian import scope_guardian
from r3x.core.logger import logger

class CORSAnalyzer(BaseScanner):
    def scan(self, scan_id: str) -> List[Dict[str, Any]]:
        findings = []
        logger.info(f"CORSAnalyzer: Auditing Cross-Origin Resource Sharing on {self.target_url}")

        test_origins = [
            "https://attacker-origin.domain",
            "null",
            f"https://{urlparse(self.target_url).hostname}.attacker.com"
        ]

        for origin in test_origins:
            scope_guardian.throttle(max_rate_per_sec=5)
            try:
                headers_in = {
                    "Origin": origin,
                    "User-Agent": "R3X-Security-Audit/1.0"
                }
                with httpx.Client(timeout=8.0, verify=False) as client:
                    resp = client.get(self.target_url, headers=headers_in)
                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"

                    raw_req = f"GET / HTTP/1.1\nHost: {urlparse(self.target_url).netloc}\nOrigin: {origin}"
                    raw_resp = f"HTTP/1.1 {resp.status_code}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}"

                    # Critical: Reflective origin with credentials enabled
                    if (acao == origin or acao == "*") and acac:
                        findings.append(self.record_finding(
                            scan_id=scan_id,
                            title="Critical CORS Misconfiguration (Reflected Origin with Credentials)",
                            severity="CRITICAL",
                            endpoint=self.target_url,
                            technical_explanation=f"The endpoint dynamically reflects arbitrary Origin '{origin}' in Access-Control-Allow-Origin while simultaneously enabling Access-Control-Allow-Credentials: true. An unauthorized attacker can read authenticated session data cross-origin.",
                            remediation="Implement an explicit whitelist of trusted origins and avoid dynamically reflecting unvalidated Origin headers when credentials are true.",
                            cwe="CWE-942",
                            cvss=8.8,
                            status="CONFIRMED",
                            request_raw=raw_req,
                            response_raw=raw_resp,
                            headers=dict(resp.headers)
                        ))
                        break  # Stop further CORS origin tests if critical is found

                    # High: Arbitrary Origin allowed for sensitive endpoint
                    elif acao == "*" and not acac:
                        findings.append(self.record_finding(
                            scan_id=scan_id,
                            title="Wildcard Access-Control-Allow-Origin (*)",
                            severity="LOW",
                            endpoint=self.target_url,
                            technical_explanation="The resource specifies Access-Control-Allow-Origin: *, allowing any website to read responses. While safe for public static assets, this may leak data if applied to private resources.",
                            remediation="If the endpoint returns private or scoped data, restrict Access-Control-Allow-Origin to authorized corporate domains.",
                            cwe="CWE-942",
                            cvss=3.7,
                            status="CONFIRMED",
                            request_raw=raw_req,
                            response_raw=raw_resp,
                            headers=dict(resp.headers)
                        ))
                        break

            except Exception as e:
                logger.debug(f"CORSAnalyzer test error for origin {origin}: {e}")

        return findings
