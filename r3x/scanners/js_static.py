"""
R3X JavaScript Static Analysis Scanner
Parses JavaScript files to extract internal API endpoints, hidden routes, and leaked credentials.
"""
import re
from typing import Any
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from r3x.core.config import settings
from r3x.core.logger import logger
from r3x.scanners.base import BaseScanner
from r3x.security.scope_guardian import scope_guardian

# Regex patterns for sensitive tokens embedded in client-side code
SECRET_PATTERNS = [
    ("Google API Key", re.compile(r'AIza[0-9A-Za-z-_]{35}')),
    ("Firebase Database URL", re.compile(r'https://[a-z0-9-]+\.firebaseio\.com')),
    ("AWS Access Key ID", re.compile(r'AKIA[0-9A-Z]{16}')),
    ("Stripe Publishable Key", re.compile(r'pk_live_[0-9a-zA-Z]{24}')),
    ("JWT / Bearer Token", re.compile(r'ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')),
]

# Regex for internal API routes
API_ENDPOINT_PATTERN = re.compile(r'["\'](/api/v?[0-9]?/[a-zA-Z0-9_\-\/]+)["\']')

class JSStaticAnalyzer(BaseScanner):
    def scan(self, scan_id: str) -> list[dict[str, Any]]:
        findings = []
        logger.info(f"JSStaticAnalyzer: Scraping and inspecting JavaScript files on {self.target_url}")

        scope_guardian.throttle(max_rate_per_sec=5)
        js_urls: set[str] = set()

        try:
            with httpx.Client(
                timeout=8.0,
                verify=settings.network.verify_ssl
            ) as client:  # nosec B501
                resp = client.get(self.target_url, headers={"User-Agent": "R3X-Security-Audit/1.0"})
                soup = BeautifulSoup(resp.text, "html.parser")
                for script in soup.find_all("script"):
                    src = script.get("src")
                    if src:
                        full_url = urljoin(self.target_url, src)
                        # Verify within authorized scope
                        try:
                            scope_guardian.validate_target(full_url, self.project_id)
                            js_urls.add(full_url)
                        except Exception as e:
                            logger.debug(f"Target scope validation for {full_url}: {e}")

                # Scan up to 5 discovered JS files
                for js_url in list(js_urls)[:5]:
                    scope_guardian.throttle(max_rate_per_sec=5)
                    try:
                        js_resp = client.get(js_url, headers={"User-Agent": "R3X-Security-Audit/1.0"})
                        content = js_resp.text

                        # 1. Search for leaked tokens
                        for token_name, pattern in SECRET_PATTERNS:
                            matches = pattern.findall(content)
                            if matches:
                                findings.append(self.record_finding(
                                    scan_id=scan_id,
                                    title=f"Potential Secret or Token Found in JavaScript ({token_name})",
                                    severity="HIGH",
                                    endpoint=js_url,
                                    technical_explanation=f"A pattern matching {token_name} was identified inside public client-side JavaScript. This may grant unauthorized access to third-party services.",
                                    remediation="Rotate the exposed token immediately and ensure sensitive credentials remain server-side.",
                                    cwe="CWE-798",
                                    cvss=7.5,
                                    status="POTENTIAL",
                                    confidence_score=0.80,
                                    request_raw=f"GET {js_url} HTTP/1.1",
                                    response_raw=f"Pattern matched in {js_url} (First 200 chars): {matches[0][:20]}..."
                                ))

                        # 2. Extract API Endpoints
                        endpoints = set(API_ENDPOINT_PATTERN.findall(content))
                        if endpoints:
                            endpoints_list = sorted(endpoints)[:10]
                            findings.append(self.record_finding(
                                scan_id=scan_id,
                                title=f"Discovered API Endpoints in JavaScript ({len(endpoints)} routes)",
                                severity="INFO",
                                endpoint=js_url,
                                technical_explanation=f"Static analysis discovered API routes embedded in JavaScript: {', '.join(endpoints_list[:5])}...",
                                remediation="Review API endpoints to verify authentication and access controls are strictly applied server-side.",
                                cwe="CWE-200",
                                cvss=0.0,
                                status="CONFIRMED",
                                request_raw=f"GET {js_url} HTTP/1.1",
                                response_raw=f"Endpoints: {', '.join(endpoints_list)}"
                            ))

                    except Exception as e:
                        logger.debug(f"Error fetching script {js_url}: {e}")

        except Exception as e:
            logger.debug(f"JSStaticAnalyzer error on {self.target_url}: {e}")

        return findings
