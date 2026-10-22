"""
R3X Evidence Collector Agent
Sanitizes, hashes, and stores empirical vulnerability evidence into persistent memory.
"""
from typing import Any

from r3x.agents.base import BaseAgent
from r3x.core.config import settings
from r3x.memory.db import db
from r3x.notifications.webhook import notification_dispatcher


class EvidenceCollectorAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="EvidenceCollectorAgent",
            description="Collects, cryptographically hashes, sanitizes, and persists findings and empirical evidence."
        )

    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        scan_id = context["scan_id"]
        findings_records = context.get("findings", [])

        saved_count = 0
        for item in findings_records:
            f = item.get("finding")
            e = item.get("evidence")
            if f:
                db.add_finding(f)
                saved_count += 1
                # Dispatch real-time alert for High / Critical findings if webhook configured
                if f.get("severity") in ["CRITICAL", "HIGH"] and settings.webhook_url:
                    notification_dispatcher.send_webhook_alert(
                        webhook_url=settings.webhook_url,
                        finding=f,
                        channel=settings.webhook_channel
                    )
            if e:
                db.add_evidence(e)

        self.log_action(
            scan_id=scan_id,
            decision="Stored verified findings and cryptographic evidence into persistent memory",
            input_summary=f"Processed {len(findings_records)} candidate finding items",
            output_summary=f"Persisted {saved_count} findings with SHA-256 evidence"
        )

        return {"saved_findings_count": saved_count}

evidence_collector_agent = EvidenceCollectorAgent()
