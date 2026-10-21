"""
R3X JavaScript Analysis Agent
Inspects client-side JavaScript assets for hidden routes, endpoints, and credentials.
"""
from typing import Any

from r3x.agents.base import BaseAgent
from r3x.scanners.js_static import JSStaticAnalyzer


class JSAnalysisAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="JSAnalysisAgent",
            description="Inspects client-side scripts to extract hidden routes, API paths, and leaked tokens."
        )

    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        target_url = context["target_url"]
        project_id = context.get("project_id", "default")
        scan_id = context["scan_id"]

        scanner = JSStaticAnalyzer(target_url, project_id)
        findings = scanner.scan(scan_id)

        self.log_action(
            scan_id=scan_id,
            decision="Conducted static script inspection and endpoint extraction",
            input_summary=f"Target: {target_url}",
            output_summary=f"Extracted {len(findings)} findings/routes"
        )

        return {"findings": findings}

js_analysis_agent = JSAnalysisAgent()
