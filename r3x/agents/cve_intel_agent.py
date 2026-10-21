"""
R3X CVE Intelligence Agent
Correlates identified software components and version numbers with known vulnerability databases.
"""
from typing import Dict, Any, List
from r3x.agents.base import BaseAgent
from r3x.mixer.models import TaskRole
from r3x.mixer.router import model_router

class CVEIntelligenceAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="CVEIntelligenceAgent",
            description="Correlates component fingerprints and version disclosures with vulnerability databases."
        )

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        target_url = context["target_url"]
        scan_id = context["scan_id"]
        findings = context.get("findings", [])

        cve_correlations = []
        tech_findings = [f for f in findings if "version disclosure" in f["finding"]["title"].lower()]

        for tf in tech_findings:
            title = tf["finding"]["title"]
            prompt = f"Analyze software component '{title}' on target {target_url}. Identify top known security considerations, past major CVE trends, or best-practice hardening guidelines. Keep answer concise."
            res = model_router.generate(
                role=TaskRole.CLASSIFICATION,
                messages=[{"role": "user", "content": prompt}]
            )
            cve_correlations.append({
                "component": title,
                "intelligence_summary": res["content"][:200]
            })

        self.log_action(
            scan_id=scan_id,
            decision="Evaluated component version intelligence and vulnerability correlations",
            input_summary=f"Evaluated {len(tech_findings)} components",
            output_summary=f"Synthesized intelligence for {len(cve_correlations)} components"
        )

        return {"cve_correlations": cve_correlations}

cve_intel_agent = CVEIntelligenceAgent()
