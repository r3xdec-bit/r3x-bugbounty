"""
R3X Authenticated Differential Access Control Agent
Evaluates authorization boundaries and BOLA/BFLA disparities across user profiles.
"""
from typing import Any

from r3x.agents.base import BaseAgent
from r3x.scanners.auth_differential import AuthDifferentialScanner


class AuthDifferentialAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="AuthDifferentialAgent",
            description="Audits authorization boundaries, role disparities, and BOLA/BFLA access control risks."
        )

    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        target_url = context["target_url"]
        project_id = context.get("project_id", "default")
        scan_id = context["scan_id"]
        privileged_headers = context.get("privileged_headers", {})
        unprivileged_headers = context.get("unprivileged_headers")

        findings: list[dict[str, Any]] = []

        if privileged_headers:
            scanner = AuthDifferentialScanner(target_url, project_id)
            findings.extend(scanner.audit_endpoint_access(
                endpoint_url=target_url,
                privileged_headers=privileged_headers,
                unprivileged_headers=unprivileged_headers,
                scan_id=scan_id
            ))

        self.log_action(
            scan_id=scan_id,
            decision="Executed differential access control audit across privilege profiles",
            input_summary=f"Target: {target_url}",
            output_summary=f"Identified {len(findings)} authorization disparity findings"
        )

        return {"findings": findings}


auth_differential_agent = AuthDifferentialAgent()
