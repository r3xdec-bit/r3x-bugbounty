"""
R3X API Security Agent
Specialized in auditing REST & GraphQL APIs, OpenAPI schemas, and endpoint access controls.
"""
from typing import Dict, Any, List
from r3x.agents.base import BaseAgent
from r3x.scanners.api_schema import APISchemaScanner

class APISecurityAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="APISecurityAgent",
            description="Audits REST and GraphQL APIs, discovers exposed OpenAPI schemas, and verifies controls."
        )

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        target_url = context["target_url"]
        project_id = context.get("project_id", "default")
        scan_id = context["scan_id"]

        scanner = APISchemaScanner(target_url, project_id)
        findings = scanner.scan(scan_id)

        self.log_action(
            scan_id=scan_id,
            decision="Evaluated API attack surface and documentation exposure",
            input_summary=f"Target: {target_url}",
            output_summary=f"Found {len(findings)} API findings"
        )

        return {"findings": findings}

api_security_agent = APISecurityAgent()
