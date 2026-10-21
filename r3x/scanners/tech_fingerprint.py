"""
R3X Technology Fingerprinting & Version Disclosure Scanner
Identifies web servers, frameworks, and component versions.
"""
import re
from typing import Any
from urllib.parse import urlparse

import httpx

from r3x.core.config import settings
from r3x.core.logger import logger
from r3x.scanners.base import BaseScanner
from r3x.security.scope_guardian import scope_guardian


class TechFingerprinter(BaseScanner):
    def scan(self, scan_id: str) -> list[dict[str, Any]]:
        findings = []
        logger.info(f"TechFingerprinter: Analyzing stack signatures on {self.target_url}")

        scope_guardian.throttle(max_rate_per_sec=5)
        try:
            with httpx.Client(
                timeout=8.0,
                verify=settings.network.verify_ssl
            ) as client:  # nosec B501
                resp = client.get(self.target_url, headers={"User-Agent": "R3X-Security-Audit/1.0"})
                headers = dict(resp.headers)

                raw_req = f"GET / HTTP/1.1\nHost: {urlparse(self.target_url).netloc}"
                raw_resp = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())

                # 1. Server Banner Version Disclosure
                server_hdr = headers.get("server", "")
                if server_hdr and re.search(r'\d+\.\d+', server_hdr):
                    findings.append(self.record_finding(
                        scan_id=scan_id,
                        title=f"Detailed Web Server Version Disclosure ({server_hdr})",
                        severity="LOW",
                        endpoint=self.target_url,
                        technical_explanation=f"The 'Server' header exposes exact product version '{server_hdr}'. Attackers can leverage this information to correlate known public CVEs.",
                        remediation="Suppress the server banner or disable version broadcasting (e.g. 'server_tokens off' in Nginx, 'ServerTokens Prod' in Apache).",
                        cwe="CWE-200",
                        cvss=3.7,
                        status="CONFIRMED",
                        request_raw=raw_req,
                        response_raw=raw_resp,
                        headers=headers
                    ))

                # 2. X-Powered-By Header Disclosure
                powered_by = headers.get("x-powered-by", "")
                if powered_by:
                    findings.append(self.record_finding(
                        scan_id=scan_id,
                        title=f"Technology Stack Disclosure via X-Powered-By ({powered_by})",
                        severity="LOW",
                        endpoint=self.target_url,
                        technical_explanation=f"The application responds with 'X-Powered-By: {powered_by}', disclosing backend runtime technology.",
                        remediation="Remove the 'X-Powered-By' header in framework configuration (e.g. app.disable('x-powered-by') in Express.js).",
                        cwe="CWE-200",
                        cvss=3.5,
                        status="CONFIRMED",
                        request_raw=raw_req,
                        response_raw=raw_resp,
                        headers=headers
                    ))

        except Exception as e:
            logger.debug(f"TechFingerprinter error on {self.target_url}: {e}")

        return findings
