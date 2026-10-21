"""
R3X Report Generator Agent
Compiles findings into submission-ready vulnerability reports.
"""
from typing import Dict, Any
from r3x.agents.base import BaseAgent
from r3x.reports.generator import report_generator

class ReportGeneratorAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="ReportGeneratorAgent",
            description="Compiles verified findings and evidence into professional HTML/Markdown/JSON/PDF reports."
        )

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        project_id = context.get("project_id", "default")
        scan_id = context.get("scan_id")
        fmt = context.get("format", "html")

        out_path = report_generator.create_report(project_id=project_id, scan_id=scan_id, format_type=fmt)

        self.log_action(
            scan_id=scan_id,
            decision="Compiled security findings into final report",
            input_summary=f"Project: {project_id}, Format: {fmt}",
            output_summary=f"Report written to {out_path}"
        )

        return {"report_path": str(out_path)}

report_generator_agent = ReportGeneratorAgent()
