"""
R3X AI Mixer Agent
Monitors multi-provider performance, token quotas, latency, and key health.
"""
from typing import Any

from r3x.agents.base import BaseAgent
from r3x.memory.db import db
from r3x.mixer.key_store import key_store


class AIMixerAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="AIMixerAgent",
            description="Manages multi-provider LLM routing, token allocation, load-balancing, and key quotas."
        )

    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        scan_id = context.get("scan_id")
        summary = key_store.get_status_summary()
        usage = db.get_api_usage_summary()

        self.log_action(
            scan_id=scan_id,
            decision="Tracked AI provider routing and token consumption",
            input_summary=f"Active providers: {summary['active_providers']}",
            output_summary=f"Total calls: {usage['total_calls']}, Cost: ${usage['total_cost_usd']:.4f}"
        )

        return {"mixer_summary": summary, "usage": usage}

ai_mixer_agent = AIMixerAgent()
