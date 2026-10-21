"""
R3X Web Security Agent
Audits HTTP response headers, CORS configurations, Cookie attributes, and TLS/SSL settings.
"""
from typing import Any

from r3x.agents.base import BaseAgent
from r3x.scanners.cookie_checker import CookieChecker
from r3x.scanners.cors_analyzer import CORSAnalyzer
from r3x.scanners.headers_analyzer import HeadersAnalyzer
from r3x.scanners.tls_inspect import TLSInspector


class WebSecurityAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="WebSecurityAgent",
            description="Audits HTTP security headers, CORS policies, Cookie flags, and TLS configurations."
        )

    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        target_url = context["target_url"]
        project_id = context.get("project_id", "default")
        scan_id = context["scan_id"]

        findings: list[dict[str, Any]] = []

        # 1. Headers
        headers_sc = HeadersAnalyzer(target_url, project_id)
        findings.extend(headers_sc.scan(scan_id))

        # 2. CORS
        cors_sc = CORSAnalyzer(target_url, project_id)
        findings.extend(cors_sc.scan(scan_id))

        # 3. Cookies
        cookie_sc = CookieChecker(target_url, project_id)
        findings.extend(cookie_sc.scan(scan_id))

        # 4. TLS/SSL
        tls_sc = TLSInspector(target_url, project_id)
        findings.extend(tls_sc.scan(scan_id))

        self.log_action(
            scan_id=scan_id,
            decision="Conducted comprehensive web application security baseline audit",
            input_summary=f"Target: {target_url}",
            output_summary=f"Produced {len(findings)} security findings"
        )

        return {"findings": findings}

web_security_agent = WebSecurityAgent()
