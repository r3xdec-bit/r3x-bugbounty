"""
R3X False Positive Verification Agent
Performs dual-model consensus verification on identified security issues.
"""
from typing import Any

from r3x.agents.base import BaseAgent
from r3x.mixer.cross_verify import dual_verifier


class FalsePositiveVerificationAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="FalsePositiveVerificationAgent",
            description="Filters out false positives and verifies critical findings using dual-model consensus."
        )

    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        scan_id = context["scan_id"]
        findings_records = context.get("findings", [])

        verified_records = []
        for item in findings_records:
            f = item.get("finding", {})
            e = item.get("evidence", {})

            # For High or Critical severity findings, run cross-model consensus
            if f.get("severity") in ["CRITICAL", "HIGH"]:
                consensus = dual_verifier.verify_finding(
                    finding_id=f.get("id", ""),
                    title=f.get("title", ""),
                    endpoint=f.get("endpoint", ""),
                    severity=f.get("severity", ""),
                    evidence_snippet=e.get("response_raw", "")[:500]
                )
                f["status"] = consensus["final_status"]
                f["confidence_score"] = consensus["confidence_score"]
                f["technical_explanation"] += f"\n\n[Verification Consensus: {consensus['consensus_notes']}]"

            verified_records.append(item)

        self.log_action(
            scan_id=scan_id,
            decision="Evaluated finding confidence and cross-model consensus",
            input_summary=f"Evaluated {len(findings_records)} findings",
            output_summary=f"Completed verification on {len(verified_records)} findings"
        )

        return {"verified_findings": verified_records}

verification_agent = FalsePositiveVerificationAgent()
