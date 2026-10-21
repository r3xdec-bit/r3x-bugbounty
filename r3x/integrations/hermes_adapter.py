"""
R3X Hermes Agent Adapter
Connects and coordinates with NousResearch/hermes-agent.
Preserves original Hermes files and interfaces via standard decoupled protocol.
"""
import os
import json
import httpx
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

from r3x.core.config import settings
from r3x.core.logger import logger
from r3x.core.exceptions import AdapterError
from r3x.mixer.models import TaskRole
from r3x.mixer.router import model_router
from r3x.memory.db import db

class HermesAdapter:
    def __init__(self, endpoint: Optional[str] = None):
        self.endpoint = endpoint or settings.hermes_endpoint
        self._is_online: Optional[bool] = None

    def check_status(self) -> Tuple[bool, str]:
        """Verify Hermes Agent connectivity."""
        try:
            r = httpx.get(f"{self.endpoint}/health", timeout=1.0)
            if r.status_code == 200:
                self._is_online = True
                return True, f"Hermes Daemon Active ({self.endpoint})"
        except Exception:
            pass

        # Check local repository installation
        local_repo = Path("hermes-agent")
        if local_repo.exists() and (local_repo / "README.md").exists():
            return False, "Hermes repo cloned locally, daemon not running (using autonomous internal planner)"

        return False, "Hermes offline (using autonomous internal planner)"

    def create_security_plan(
        self,
        target_url: str,
        scope_rules: Dict[str, Any],
        scan_type: str = "quick",
        past_scan_history: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Hermes creates an adaptive, prioritized security assessment plan.
        """
        logger.info(f"Hermes Agent: Synthesizing assessment plan for {target_url} (Mode: {scan_type})")

        # 1. Try remote Hermes Agent endpoint
        try:
            payload = {
                "action": "plan",
                "target": target_url,
                "scope": scope_rules,
                "scan_type": scan_type,
                "history": past_scan_history or []
            }
            resp = httpx.post(f"{self.endpoint}/api/plan", json=payload, timeout=5.0)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            logger.debug("Hermes HTTP endpoint unavailable. Activating internal Hermes AI Planner.")

        # 2. Autonomous Hermes Orchestration Prompt
        prompt = f"""
You are the Hermes Master Orchestrator for R3X-BugBounty.
Formulate a strictly non-destructive, authorized security testing plan for target: {target_url}
Scan Profile: {scan_type}
Scope Boundaries: {json.dumps(scope_rules)}
Previous Scan History Context: {json.dumps(past_scan_history or [])}

Plan must include:
1. Reconnaissance phase (passive subdomain, DNS, tech stack).
2. Web Security Audit (TLS, HTTP security headers, CORS, Cookie security).
3. Specialized checks (API endpoints discovery, JavaScript static analysis, CVE correlation).
4. Safety Constraints: strict domain validation, non-destructive payloads only.

Provide response in structured JSON with keys:
{{
  "plan_id": "string",
  "recommended_agents": ["ReconAgent", "WebSecurityAgent", "APISecurityAgent", "JSAnalysisAgent", "CVEIntelligenceAgent"],
  "stages": [
    {{"stage_num": 1, "agent": "string", "tasks": ["string"], "non_destructive": true}}
  ],
  "reasoning": "string"
}}
"""
        messages = [
            {"role": "system", "content": "You are the Hermes AI Orchestration Engine. Output strict JSON only."},
            {"role": "user", "content": prompt}
        ]

        res = model_router.generate(role=TaskRole.DEEP_REASONING, messages=messages)
        content = res["content"]

        try:
            import re
            m = re.search(r'\{.*\}', content, re.DOTALL)
            if m:
                plan = json.loads(m.group(0))
                db.log_agent_action(
                    scan_id=None,
                    agent_name="HermesMasterOrchestrator",
                    decision="Formulated assessment execution plan",
                    in_sum=f"Target: {target_url}, Mode: {scan_type}",
                    out_sum=f"Plan stages: {len(plan.get('stages', []))}"
                )
                return plan
        except Exception as e:
            logger.warning(f"Error parsing Hermes plan JSON: {e}")

        # Deterministic Default Plan
        return {
            "plan_id": f"hermes-plan-{scan_type}",
            "recommended_agents": ["ScopeGuardianAgent", "ReconAgent", "WebSecurityAgent", "CVEIntelligenceAgent", "EvidenceCollectorAgent"],
            "stages": [
                {"stage_num": 1, "agent": "ScopeGuardianAgent", "tasks": ["Validate allowlist and boundaries"], "non_destructive": True},
                {"stage_num": 2, "agent": "ReconAgent", "tasks": ["DNS & Technology stack fingerprinting"], "non_destructive": True},
                {"stage_num": 3, "agent": "WebSecurityAgent", "tasks": ["TLS, Security Headers, CORS audit"], "non_destructive": True},
                {"stage_num": 4, "agent": "EvidenceCollectorAgent", "tasks": ["Sanitize traces & hash proof"], "non_destructive": True}
            ],
            "reasoning": "Standard verified non-destructive bug bounty assessment flow."
        }

    def analyze_and_select_next_test(self, current_findings: List[Dict[str, Any]], target_url: str) -> Dict[str, Any]:
        """
        Evaluate discovered technologies or vulnerabilities to dynamically trigger the next specialized agent.
        """
        logger.info("Hermes Agent: Analyzing findings to select next optimal testing vector...")
        discovered_types = set()
        for f in current_findings:
            title = f.get("title", "").lower()
            endpoint = f.get("endpoint", "").lower()
            if "api" in title or "api" in endpoint or "/v1" in endpoint or "/v2" in endpoint:
                discovered_types.add("API")
            if ".js" in endpoint or "javascript" in title:
                discovered_types.add("JAVASCRIPT")
            if "outdated" in title or "cve" in title:
                discovered_types.add("CVE")

        next_action = {
            "trigger_api_agent": "API" in discovered_types,
            "trigger_js_agent": "JAVASCRIPT" in discovered_types,
            "trigger_cve_agent": "CVE" in discovered_types,
            "recommendation": "Continue with standard verification and evidence collection."
        }

        if next_action["trigger_api_agent"]:
            next_action["recommendation"] = "Discovered API surface: Dispatching APISecurityAgent for schema validation."
        elif next_action["trigger_js_agent"]:
            next_action["recommendation"] = "Discovered JavaScript assets: Dispatching JSAnalysisAgent for endpoint extraction."

        return next_action

hermes_adapter = HermesAdapter()
