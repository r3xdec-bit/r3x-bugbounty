"""
R3X Reconnaissance Agent
Coordinates passive DNS intelligence, technology fingerprinting, and surface mapping.
"""
from typing import Any

from r3x.agents.base import BaseAgent
from r3x.scanners.passive_recon import PassiveReconScanner
from r3x.scanners.tech_fingerprint import TechFingerprinter


class ReconAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="ReconAgent",
            description="Executes passive reconnaissance, DNS mapping, and technology fingerprinting."
        )

    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        target_url = context["target_url"]
        project_id = context.get("project_id", "default")
        scan_id = context["scan_id"]

        findings: list[dict[str, Any]] = []

        # 1. DNS Recon
        dns_scanner = PassiveReconScanner(target_url, project_id)
        findings.extend(dns_scanner.scan(scan_id))

        # 2. Tech Fingerprint
        tech_scanner = TechFingerprinter(target_url, project_id)
        findings.extend(tech_scanner.scan(scan_id))

        self.log_action(
            scan_id=scan_id,
            decision="Conducted passive reconnaissance and technology fingerprinting",
            input_summary=f"Target: {target_url}",
            output_summary=f"Produced {len(findings)} discovery findings"
        )

        return {"findings": findings}

recon_agent = ReconAgent()
