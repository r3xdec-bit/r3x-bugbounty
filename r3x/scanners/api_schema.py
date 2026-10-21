"""
R3X API Schema & Endpoint Security Scanner
Detects exposed Swagger/OpenAPI documentation, GraphQL introspection, and sensitive routes.
"""
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from r3x.core.config import settings
from r3x.core.logger import logger
from r3x.scanners.base import BaseScanner
from r3x.security.scope_guardian import scope_guardian

KNOWN_API_DOC_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/swagger-ui.html",
    "/swagger/index.html",
    "/docs",
    "/graphql",
    "/graphiql"
]

class APISchemaScanner(BaseScanner):
    def scan(self, scan_id: str) -> list[dict[str, Any]]:
        findings = []
        logger.info(f"APISchemaScanner: Checking for exposed API schemas on {self.target_url}")

        scope_guardian.throttle(max_rate_per_sec=5)

        for path in KNOWN_API_DOC_PATHS:
            target_ep = urljoin(self.target_url, path)
            try:
                scope_guardian.validate_target(target_ep, self.project_id)
            except Exception as e:
                logger.debug(f"Target scope validation for {target_ep} bypassed: {e}")
                continue

            try:
                scope_guardian.throttle(max_rate_per_sec=5)
                with httpx.Client(
                    timeout=6.0,
                    verify=settings.network.verify_ssl
                ) as client:  # nosec B501
                    resp = client.get(target_ep, headers={"User-Agent": "R3X-Security-Audit/1.0"})

                    if resp.status_code == 200:
                        ct = resp.headers.get("content-type", "").lower()
                        is_json = "json" in ct
                        is_html = "html" in ct

                        raw_req = f"GET {path} HTTP/1.1\nHost: {urlparse(self.target_url).netloc}"
                        raw_resp = f"HTTP/1.1 {resp.status_code}\nContent-Type: {ct}\nBody Preview: {resp.text[:300]}"

                        if ("swagger" in resp.text.lower() or "openapi" in resp.text.lower()) and (is_json or is_html):
                            findings.append(self.record_finding(
                                scan_id=scan_id,
                                title=f"Publicly Accessible API Documentation ({path})",
                                severity="LOW",
                                endpoint=target_ep,
                                technical_explanation=f"API documentation was found exposed publicly at '{path}'. This provides attackers with a comprehensive roadmap of endpoints, parameters, and models.",
                                remediation="Restrict public access to internal API documentation by enforcing authentication or disabling Swagger UI in production environments.",
                                cwe="CWE-200",
                                cvss=4.3,
                                status="CONFIRMED",
                                request_raw=raw_req,
                                response_raw=raw_resp,
                                headers=dict(resp.headers)
                            ))
                            break  # Avoid spamming multiple schema findings

                        elif "/graphql" in path:
                            findings.append(self.record_finding(
                                scan_id=scan_id,
                                title="GraphQL Endpoint Exposed",
                                severity="INFO",
                                endpoint=target_ep,
                                technical_explanation=f"A GraphQL endpoint was detected at '{path}'. Verify if introspection query is restricted.",
                                remediation="Ensure GraphQL introspection queries are disabled in production if not intended for public consumption.",
                                cwe="CWE-200",
                                cvss=2.0,
                                status="POTENTIAL",
                                request_raw=raw_req,
                                response_raw=raw_resp,
                                headers=dict(resp.headers)
                            ))

            except Exception as e:
                logger.debug(f"APISchemaScanner probe error on {target_ep}: {e}")

        return findings
