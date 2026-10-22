"""
R3X Multi-Channel Notification Dispatcher
Sends real-time security alerts to Slack, Discord, and Telegram webhooks.
Automatically redacts sensitive credentials before transmitting payloads.
"""
from typing import Any

import httpx

from r3x.core.config import settings
from r3x.core.logger import logger
from r3x.evidence.sanitizer import sanitize_evidence


class NotificationDispatcher:
    def __init__(self):
        pass

    def format_finding_payload(self, finding: dict[str, Any], channel: str = "generic") -> dict[str, Any]:
        """
        Formats security finding into structured JSON payload for target webhook provider.
        """
        title = sanitize_evidence(finding.get("title", "Security Finding"))
        severity = finding.get("severity", "MEDIUM").upper()
        endpoint = sanitize_evidence(finding.get("endpoint", ""))
        cvss = finding.get("cvss", 0.0)
        cwe = finding.get("cwe", "N/A")
        explanation = sanitize_evidence(finding.get("technical_explanation", "")[:300])

        if channel == "slack":
            color = "#e11d48" if severity in ["CRITICAL", "HIGH"] else "#eab308"
            return {
                "attachments": [
                    {
                        "color": color,
                        "title": f"[{severity}] {title} (CVSS: {cvss})",
                        "text": f"• *Endpoint:* `{endpoint}`\n• *CWE:* {cwe}\n• *Details:* {explanation}",
                        "footer": "R3X-BugBounty Framework",
                    }
                ]
            }

        elif channel == "discord":
            color_int = 14753096 if severity in ["CRITICAL", "HIGH"] else 15381256
            return {
                "embeds": [
                    {
                        "title": f"🚨 [{severity}] {title}",
                        "color": color_int,
                        "fields": [
                            {"name": "Endpoint", "value": f"`{endpoint}`", "inline": True},
                            {"name": "CVSS v3.1", "value": str(cvss), "inline": True},
                            {"name": "CWE", "value": str(cwe), "inline": True},
                            {"name": "Analysis", "value": explanation, "inline": False},
                        ],
                        "footer": {"text": "R3X-BugBounty Security Framework"}
                    }
                ]
            }

        elif channel == "telegram":
            text = (
                f"🚨 *[{severity}] {title}*\n\n"
                f"• *Endpoint:* `{endpoint}`\n"
                f"• *CVSS:* {cvss} | *CWE:* {cwe}\n\n"
                f"{explanation}"
            )
            return {"text": text, "parse_mode": "Markdown"}

        # Generic default
        return {
            "severity": severity,
            "title": title,
            "endpoint": endpoint,
            "cvss": cvss,
            "cwe": cwe,
            "details": explanation
        }

    def send_webhook_alert(
        self,
        webhook_url: str,
        finding: dict[str, Any],
        channel: str = "generic"
    ) -> bool:
        """
        Dispatches sanitized finding notification to external webhook.
        """
        if not webhook_url:
            logger.debug("NotificationDispatcher: No webhook URL provided, alert skipped.")
            return False

        payload = self.format_finding_payload(finding, channel=channel)
        logger.info(f"NotificationDispatcher: Sending {finding.get('severity')} alert via {channel} webhook")

        try:
            with httpx.Client(timeout=8.0, verify=settings.network.verify_ssl) as client:  # nosec B501
                resp = client.post(webhook_url, json=payload)
                if resp.status_code in (200, 204):
                    logger.info("NotificationDispatcher: Alert delivered successfully.")
                    return True
                else:
                    logger.warning(f"NotificationDispatcher: Webhook delivery failed (HTTP {resp.status_code})")
                    return False
        except Exception as e:
            logger.error(f"NotificationDispatcher: Error delivering webhook alert: {e}")
            return False


notification_dispatcher = NotificationDispatcher()
