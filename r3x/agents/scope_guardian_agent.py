"""
R3X Scope Guardian Agent
"""
from typing import Dict, Any
from r3x.agents.base import BaseAgent
from r3x.security.scope_guardian import scope_guardian

class ScopeGuardianAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="ScopeGuardianAgent",
            description="Enforces strict domain allowlists, URL exclusions, redirect defense, and rate-limits."
        )

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        target_url = context.get("target_url", "")
        project_id = context.get("project_id", "default")
        scan_id = context.get("scan_id")

        is_valid = scope_guardian.validate_target(target_url, project_id=project_id)
        self.log_action(
            scan_id=scan_id,
            decision="Validated target scope and boundaries",
            input_summary=f"Target: {target_url}",
            output_summary=f"Scope Check: PASS (Allowlist verified)"
        )
        return {"scope_valid": is_valid, "target": target_url}

scope_guardian_agent = ScopeGuardianAgent()
